from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request
from models import Transaction, User, Device, db, FraudAlert
from services.fraud_engine import FraudEngine
from services.email_service import send_email_otp, generate_otp, send_fraud_alert, send_detailed_transaction_alert
from services.security_suite import SecuritySuite
from services.geo_service import GeoService
from services.security_service import SecurityService
from datetime import datetime, timedelta
from threading import Thread
import uuid
import re
from extensions import limiter
from models import Notification

tx_bp = Blueprint('tx', __name__)

def get_user_trust_limit():
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
        if user_id:
            user = User.query.get(user_id)
            if user:
                if user.trust_score >= 80: return "100 per hour"
                return "20 per hour"
    except: pass
    return "20 per minute"

@tx_bp.route('/pay', methods=['POST'])
@jwt_required()
@limiter.limit(get_user_trust_limit)
def process_payment():
    data = request.json
    
    # --- 1. GET REAL IP & SENDER ---
    real_ip = GeoService.get_real_ip()
    sender_id = get_jwt_identity()
    
    # --- NEW: PROCESS BEHAVIORAL DATA (Bot Detection) ---
    behavior_data = data.get('behavior_data', {})
    bot_risk_score = SecuritySuite.analyze_behavior(behavior_data)
    
    # --- 2. PREPARE DATA & IDENTIFY RECEIVER (Updated Logic) ---
    tx_type = data.get('transaction_type', 'card').lower()
    
    # Flexible Receiver Extraction
    if tx_type in ['card', 'wallet', 'debit_card', 'credit_card']:
        receiver_acc = data.get('merchant_id') or data.get('receiver_account')
    elif tx_type == 'upi':
        receiver_acc = data.get('upi_id') or data.get('receiver_account')
    else:
        receiver_acc = data.get('receiver_account')
    
    amount_str = data.get('amount')
    
    # Basic Validation
    if not receiver_acc: return jsonify({"error": "Receiver account required"}), 400
    if not amount_str: return jsonify({"error": "Amount required"}), 400
    
    try:
        amount = float(amount_str)
        if amount <= 0: raise ValueError
    except:
        return jsonify({"error": "Invalid amount"}), 400
    
    # Resolve Receiver User (if internal)
    receiver_user_id = None
    temp_receiver = None
    
    if tx_type == 'upi':
        temp_receiver = User.query.filter_by(upi_id=receiver_acc).first()
    elif tx_type == 'online_banking':
        temp_receiver = User.query.filter_by(account_number=receiver_acc).first()
    
    if temp_receiver:
        receiver_user_id = temp_receiver.id
    
    # --- 3. START ATOMIC DB TRANSACTION ---
    try:
        # 🔒 DEADLOCK PREVENTION: Sort IDs
        ids_to_lock = sorted([uid for uid in [sender_id, receiver_user_id] if uid])
        locked_users = {}
        
        for uid in ids_to_lock:
            u = User.query.with_for_update().get(uid)
            locked_users[uid] = u
        
        user = locked_users.get(sender_id)
        receiver_user = locked_users.get(receiver_user_id)
        
        if not user: return jsonify({"error": "User not found"}), 404
        
        # 🛑 LOGIC CHECKS
        if user.balance < amount:
            db.session.rollback()
            return jsonify({"error": f"Insufficient Balance. Current: {user.balance}"}), 400
        
        if receiver_user and receiver_user.id == user.id:
            db.session.rollback()
            return jsonify({"error": "Self-transfer is not allowed."}), 400
        
        # Regex Validation
        if tx_type == 'upi' and not re.match(r'^[\w\.\-]+@[\w\-]+$', receiver_acc):
            db.session.rollback()
            return jsonify({"error": "Invalid UPI ID"}), 400
        
        # Strict 16-digit check for cards (Only if it's strictly a card type)
        elif tx_type in ['card', 'debit_card', 'credit_card'] and not re.match(r'^\d{16}$', receiver_acc):
            db.session.rollback()
            return jsonify({"error": "Invalid Card Number (Must be 16 digits)"}), 400
        
        # --- 4. FRAUD ANALYSIS ---
        app_instance = current_app._get_current_object()
        tx_uuid = str(uuid.uuid4())
        
        # Geo & Location Data
        geo_details = GeoService.get_ip_details(real_ip)
        location_str = "Unknown Location"
        ip_country_mismatch = 0
        is_hosting_ip = 0
        curr_lat = data.get('lat', 0.0)
        curr_lon = data.get('lon', 0.0)
        
        if geo_details:
            location_str = f"{geo_details.get('city', 'Unknown')}, {geo_details.get('country', 'Unknown')}"
            is_hosting_ip = 1 if geo_details.get('is_vpn') else 0
            
            # Use IP location if Frontend GPS is missing (0.0)
            if float(curr_lat) == 0.0 or float(curr_lon) == 0.0:
                curr_lat = geo_details.get('lat', 0.0)
                curr_lon = geo_details.get('lon', 0.0)
            
            if user.home_ip:
                home_geo = GeoService.get_ip_details(user.home_ip)
                if home_geo and home_geo.get('country') != geo_details.get('country'):
                    ip_country_mismatch = 1
        
        current_tx_data = {
            "amount": amount, "receiver": receiver_acc, "transaction_type": tx_type,
            "ip_address": real_ip, "location_lat": float(curr_lat), "location_lon": float(curr_lon),
            "device_id": data.get('device_id', 'unknown'),
            "is_hosting_ip": is_hosting_ip,
            "ip_country_mismatch": ip_country_mismatch,
            "behavior_score": bot_risk_score
        }
        
        # Create Pending Transaction Record
        new_tx = Transaction(
            id=tx_uuid, user_id=sender_id, amount=amount,
            receiver_account=receiver_acc, transaction_type=tx_type,
            ip_address=real_ip,
            location_lat=float(curr_lat), location_lon=float(curr_lon),
            device_id=data.get('device_id', 'unknown'), status='PENDING'
        )
        
        db.session.add(new_tx)
        
        # 🤖 AI Prediction
        risk_score, features, explanation = FraudEngine.analyze_transaction(user, current_tx_data)
        new_tx.risk_score = risk_score
        new_tx.risk_reason = explanation
        
        # --- 5. DECISION LOGIC ---
        action = "ALLOW"
        message = "Transaction Successful"
        
        if risk_score > 0.75:
            # 🔴 BLOCK
            new_tx.status = "FAILED"
            action = "BLOCK"
            message = "Transaction Declined (High Risk)."
            
            new_alert = FraudAlert(transaction_id=tx_uuid, alert_level="CRITICAL", description=explanation)
            db.session.add(new_alert)
            
            user_notif = Notification(
                user_id=user.id,
                title="🚨 Transaction Blocked",
                message=f"We blocked a transfer of ₹{amount} due to security risk: {explanation}",
                type="DANGER"
            )
            db.session.add(user_notif)
            
            # if features.get('failed_count_1h', 0) > 5:
            #     user.is_locked = True
            #     message += " Account Locked."
            
            # Send Detailed Alert (Blocked)
            tx_alert_data = {
                "status": "BLOCKED",
                "amount": amount,
                "reason": explanation,
                "location": location_str,
                "receiver": receiver_acc
            }
            Thread(target=send_detailed_transaction_alert, args=(app_instance, user.email, tx_alert_data)).start()
            
        elif risk_score > 0.25:
            # 🟡 VERIFY - Check if 2FA is enabled
            action = "VERIFY"
            
            if user.is_2fa_enabled:
                # User has 2FA enabled - require 2FA verification
                new_tx.status = "PENDING_2FA"
                message = "2FA verification required. Please enter your authenticator code."
            else:
                # No 2FA - fall back to email OTP
                new_tx.status = "PENDING_OTP"
                message = "Email OTP verification required."
                
                otp = generate_otp()
                user.email_otp = otp
                user.email_otp_expiry = datetime.utcnow() + timedelta(minutes=5)
                
                Thread(target=send_email_otp, args=(app_instance, user.email, otp, amount, receiver_acc)).start()
            
        else:
            # 🟢 SUCCESS
            new_tx.status = "SUCCESS"
            user.balance -= amount
            
            if receiver_user:
                receiver_user.balance += amount
                message += f" Sent to {receiver_user.email}"
            
            user.total_tx_count += 1
            user.average_spending = (user.average_spending * 0.9) + (amount * 0.1)
            SecuritySuite.update_trust_score(user)

            # Send Detailed Alert (Success)
            tx_alert_data = {
                "status": "SUCCESS",
                "amount": amount,
                "reason": "Verified Transaction",
                "location": location_str,
                "receiver": receiver_acc
            }
            Thread(target=send_detailed_transaction_alert, args=(app_instance, user.email, tx_alert_data)).start()
        
        # --- 6. COMMIT TRANSACTION ---
        db.session.commit()
        
        return jsonify({
            "status": new_tx.status, "action": action, "risk_score": risk_score,
            "message": message, "transaction_id": tx_uuid, "new_balance": user.balance
        }), 200
        
    except Exception as e:
        # 🟢 CRITICAL FIX: If transaction exists (was added), marked it as FAILED/ERROR and commit instead of rollback
        if 'new_tx' in locals() and new_tx:
            try:
                new_tx.status = 'FAILED'
                new_tx.risk_reason = f"System Error: {str(e)}"
                db.session.commit()
            except:
                db.session.rollback()
        else:
            db.session.rollback()
            
        print(f"Transaction Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Processing failed. Please try again.", "message": str(e)}), 500

# ✅ FIXED: Changed from optional=True to required JWT
@tx_bp.route('/history', methods=['GET', 'OPTIONS'])
@jwt_required()  # ✅ Changed from @jwt_required(optional=True)
def get_transaction_history():
    """Get user's transaction history with pagination"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        user_id = get_jwt_identity()
        
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        status_filter = request.args.get('status', None)
        
        # Build query
        query = Transaction.query.filter_by(user_id=user_id)
        
        if status_filter:
            query = query.filter_by(status=status_filter)
        
        # Order by most recent first
        query = query.order_by(Transaction.timestamp.desc())
        
        # Paginate
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        
        # Format results
        transactions = []
        for tx in pagination.items:
            transactions.append({
                'id': tx.id,
                'amount': float(tx.amount),
                'transaction_type': tx.transaction_type,
                'receiver_account': tx.receiver_account,
                'status': tx.status,
                'risk_score': float(tx.risk_score) if tx.risk_score else 0,
                'risk_reason': tx.risk_reason,
                'timestamp': tx.timestamp.isoformat() if tx.timestamp else None,
                'date': tx.timestamp.strftime('%Y-%m-%d %H:%M:%S') if tx.timestamp else None,
                'ip_address': tx.ip_address,
                'location_lat': float(tx.location_lat) if tx.location_lat else None,
                'location_lon': float(tx.location_lon) if tx.location_lon else None,
                'device_id': tx.device_id
            })
        
        return jsonify({
            'transactions': transactions,
            'page': pagination.page,
            'per_page': pagination.per_page,
            'total': pagination.total,
            'pages': pagination.pages,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev
        }), 200
        
    except Exception as e:
        print(f"❌ Transaction history error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Failed to fetch transactions', 'message': str(e)}), 500

@tx_bp.route('/verify-otp', methods=['POST'])
@jwt_required()
def verify_otp():
    user_id = get_jwt_identity()
    data = request.json
    
    try:
        user = User.query.with_for_update().get(user_id)
        
        if not user.email_otp or user.email_otp != data.get('otp') or user.email_otp_expiry < datetime.utcnow():
            db.session.rollback()
            return jsonify({"error": "Invalid/Expired OTP"}), 400
        
        user.email_otp = None
        tx = Transaction.query.get(data.get('transaction_id'))
        
        if tx and tx.user_id == user_id and tx.status == 'PENDING_OTP':
            if user.balance < tx.amount:
                db.session.rollback()
                return jsonify({"error": "Insufficient Balance"}), 400
            
            tx.status = 'SUCCESS'
            user.balance -= tx.amount
            
            # Find receiver again to Credit
            if tx.transaction_type == 'upi':
                receiver = User.query.filter_by(upi_id=tx.receiver_account).first()
                if receiver: receiver.balance += tx.amount
            elif tx.transaction_type == 'online_banking':
                receiver = User.query.filter_by(account_number=tx.receiver_account).first()
                if receiver: receiver.balance += tx.amount
            
            user.total_tx_count += 1
            SecuritySuite.update_trust_score(user)
            
            db.session.commit()
            return jsonify({"status": "SUCCESS", "message": "Transaction Approved", "new_balance": user.balance}), 200
        
        db.session.rollback()
        return jsonify({"error": "Invalid State"}), 400
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ OTP verification error: {str(e)}")
        return jsonify({"error": "System Error", "message": str(e)}), 500

@tx_bp.route('/resend-otp', methods=['POST'])
@jwt_required()
def resend_otp():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    new_otp_code = generate_otp()
    user.email_otp = new_otp_code
    user.email_otp_expiry = datetime.utcnow() + timedelta(minutes=5)
    db.session.commit()
    
    app_instance = current_app._get_current_object()
    Thread(target=send_email_otp, args=(app_instance, user.email, new_otp_code)).start()
    
    return jsonify({"message": "New OTP sent successfully"}), 200

# ✅ TRAVEL NOTICE ENDPOINT
@tx_bp.route('/travel-notice', methods=['POST', 'OPTIONS'])
@jwt_required()
def submit_travel_notice():
    """Submit a travel notice to prevent false fraud flags when transacting from abroad"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        data = request.json or {}
        country_code = data.get('country_code', '')
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        
        if not country_code:
            return jsonify({"error": "Country code is required"}), 400
        
        # Store travel notice (you can add a TravelNotice model later for persistence)
        # For now, we'll just log it and update user's expected country
        if hasattr(user, 'travel_country'):
            user.travel_country = country_code
        
        # Create a notification for the user
        travel_notif = Notification(
            user_id=user.id,
            title="✈️ Travel Notice Registered",
            message=f"Your travel notice for {country_code.upper()} has been registered. Transactions from this region will not be flagged as suspicious.",
            type="INFO"
        )
        db.session.add(travel_notif)
        db.session.commit()
        
        # Log the action
        SecuritySuite.log_action(user_id, "TRAVEL_NOTICE", f"Travel notice submitted for {country_code}", request.remote_addr)
        
        return jsonify({
            "message": f"Travel notice for {country_code.upper()} has been registered successfully",
            "country": country_code.upper()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Travel notice error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Failed to submit travel notice", "message": str(e)}), 500

# ✅ 2FA VERIFICATION FOR TRANSACTIONS
@tx_bp.route('/verify-2fa', methods=['POST'])
@jwt_required()
def verify_2fa_transaction():
    """Verify a pending transaction using 2FA TOTP code"""
    user_id = get_jwt_identity()
    data = request.json
    
    try:
        import pyotp
        
        user = User.query.with_for_update().get(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        if not user.is_2fa_enabled or not user.totp_secret:
            return jsonify({"error": "2FA is not enabled for this account"}), 400
        
        totp_code = data.get('totp_code', '')
        transaction_id = data.get('transaction_id')
        
        if not totp_code or not transaction_id:
            return jsonify({"error": "TOTP code and transaction ID are required"}), 400
        
        # Verify TOTP
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(totp_code, valid_window=1):
            db.session.rollback()
            return jsonify({"error": "Invalid 2FA code"}), 400
        
        # Find the pending transaction
        tx = Transaction.query.get(transaction_id)
        
        if not tx or tx.user_id != user_id:
            db.session.rollback()
            return jsonify({"error": "Transaction not found"}), 404
        
        if tx.status != 'PENDING_2FA':
            db.session.rollback()
            return jsonify({"error": f"Transaction is not pending 2FA verification (status: {tx.status})"}), 400
        
        # Check balance
        if user.balance < tx.amount:
            db.session.rollback()
            return jsonify({"error": "Insufficient Balance"}), 400
        
        # Complete the transaction
        tx.status = 'SUCCESS'
        user.balance -= tx.amount
        
        # Credit receiver if internal transfer
        if tx.transaction_type == 'upi':
            receiver = User.query.filter_by(upi_id=tx.receiver_account).first()
            if receiver: receiver.balance += tx.amount
        elif tx.transaction_type == 'online_banking':
            receiver = User.query.filter_by(account_number=tx.receiver_account).first()
            if receiver: receiver.balance += tx.amount
        
        user.total_tx_count += 1
        SecuritySuite.update_trust_score(user)
        
        db.session.commit()
        return jsonify({
            "status": "SUCCESS", 
            "message": "Transaction verified and approved via 2FA", 
            "new_balance": user.balance
        }), 200
        
    except ImportError:
        return jsonify({"error": "2FA module not available"}), 500
    except Exception as e:
        db.session.rollback()
        print(f"❌ 2FA verification error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Verification failed", "message": str(e)}), 500
