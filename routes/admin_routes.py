from flask import Blueprint, jsonify, request, make_response
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import User, Transaction, FraudRule, IPWhitelist, Dispute, Notification, AuditLog, db, UnlockRequest
from sqlalchemy import func, case, extract
import csv
import io
from datetime import datetime, timedelta


admin_bp = Blueprint('admin', __name__)

# --- HELPER: PERMISSION CHECK ---
def check_admin():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    return user and user.role == 'ADMIN'

# --- 1. DASHBOARD & STATS ---
@admin_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_stats():
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    total_users = User.query.count()
    total_tx = Transaction.query.count()
    blocked_tx = Transaction.query.filter_by(status='FAILED').count()
    fraud_rate = (blocked_tx / total_tx * 100) if total_tx > 0 else 0
    
    # Enhanced Stats
    locked_accounts = User.query.filter_by(is_locked=True).count()
    high_risk_users = User.query.filter(User.trust_score < 30).count()
    
    # Fraud Alerts
    from models import FraudAlert
    total_fraud_alerts = FraudAlert.query.count()
    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    fraud_alerts_today = FraudAlert.query.filter(FraudAlert.created_at >= today_start).count()
    
    # Fraud Rings (simplified count of IPs with multiple users)
    fraud_rings_count = db.session.query(Transaction.ip_address).group_by(
        Transaction.ip_address
    ).having(func.count(func.distinct(Transaction.user_id)) >= 2).count()
    
    return jsonify({
        "total_users": total_users,
        "total_transactions": total_tx,
        "blocked_transactions": blocked_tx,
        "fraud_rate": round(fraud_rate, 2),
        "locked_accounts": locked_accounts,
        "high_risk_users": high_risk_users,
        "total_fraud_alerts": total_fraud_alerts,
        "fraud_alerts_today": fraud_alerts_today,
        "fraud_rings_detected": fraud_rings_count
    }), 200

# --- 2. TRANSACTION MANAGEMENT ---
@admin_bp.route('/transactions', methods=['GET'])
@jwt_required()
def get_all_transactions():
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    status = request.args.get('status')
    search = request.args.get('search')
    
    query = Transaction.query.order_by(Transaction.timestamp.desc())
    
    if search:
        query = query.join(User).filter(
            (User.email.ilike(f"%{search}%")) | 
            (Transaction.id.ilike(f"%{search}%"))
        )

    if status:
        query = query.filter(Transaction.status == status)
        
    txs = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        "total": txs.total,
        "pages": txs.pages,
        "transactions": [{
            "id": t.id,
            "user": t.user.email,
            "amount": t.amount,
            "status": t.status,
            "risk_score": t.risk_score,
            "risk_reason": t.risk_reason,
            "date": t.timestamp.isoformat()
        } for t in txs.items]
    }), 200

# --- 3. USER MANAGEMENT ---

@admin_bp.route('/audit-logs', methods=['GET'])
@jwt_required()
def get_audit_logs():
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    return jsonify([{
        "user_id": l.user_id,
        "action": l.action,
        "details": l.details,
        "ip": l.ip_address,
        "time": l.timestamp
    } for l in logs]), 200

# --- 4. DISPUTE RESOLUTION ---
@admin_bp.route('/disputes', methods=['GET'])
@jwt_required()
def get_disputes():
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    disputes = Dispute.query.filter_by(status='OPEN').all()
    return jsonify([{
        "id": d.id,
        "tx_id": d.transaction_id,
        "user": d.user.email,
        "reason": d.reason,
        "description": d.description,
        "amount": d.transaction.amount
    } for d in disputes]), 200

@admin_bp.route('/disputes/resolve', methods=['POST'])
@jwt_required()
def resolve_dispute():
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    data = request.json
    dispute = Dispute.query.get(data.get('dispute_id'))
    if not dispute: return jsonify({"error": "Dispute not found"}), 404
    
    decision = data.get('decision') # 'REFUND', 'REJECT'
    
    if decision == 'REFUND':
        dispute.status = 'RESOLVED'
        dispute.transaction.status = 'REFUNDED'
        dispute.user.balance += dispute.transaction.amount
        
        notif = Notification(user_id=dispute.user_id, title="Dispute Resolved", message=f"Refund of ${dispute.transaction.amount} issued.", type="SUCCESS")
        db.session.add(notif)
    else:
        dispute.status = 'REJECTED'
        
    dispute.admin_comment = data.get('comment')
    db.session.commit()
    return jsonify({"message": f"Dispute {decision}"}), 200

# --- 5. ADVANCED FRAUD TOOLS ---
@admin_bp.route('/whitelist', methods=['POST'])
@jwt_required()
def whitelist_ip():
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    data = request.json
    ip = data.get('ip')
    if IPWhitelist.query.filter_by(ip_address=ip).first():
        return jsonify({"message": "IP already whitelisted"}), 200
        
    new_wl = IPWhitelist(ip_address=ip, description=data.get('description'))
    db.session.add(new_wl)
    db.session.commit()
    return jsonify({"message": "IP Whitelisted"}), 201

@admin_bp.route('/risk/merchants', methods=['GET'])
@jwt_required()
def get_high_risk_merchants():
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    suspicious_query = db.session.query(
        Transaction.receiver_account,
        func.count(Transaction.id).label('total_attempts'),
        func.sum(case((Transaction.risk_score > 0.8, 1), else_=0)).label('fraud_count'),
        func.avg(Transaction.risk_score).label('avg_score')
    ).group_by(Transaction.receiver_account).all()
    
    results = []
    for row in suspicious_query:
        if row.fraud_count >= 3 or (row.total_attempts > 5 and row.avg_score > 0.7):
            merchant_user = None
            if '@' in row.receiver_account:
                merchant_user = User.query.filter_by(upi_id=row.receiver_account).first()
            else:
                merchant_user = User.query.filter_by(account_number=row.receiver_account).first()
            
            status = "Active"
            if merchant_user and merchant_user.is_locked:
                status = "Already Blocked"
                
            results.append({
                "account": row.receiver_account,
                "owner_email": merchant_user.email if merchant_user else "External/Unknown",
                "fraud_received": row.fraud_count,
                "status": status,
                "suggestion": "BLOCK" if status == "Active" else "REVIEW"
            })
            
    return jsonify(results), 200

@admin_bp.route('/fraud-ring/<user_id>', methods=['GET'])
@jwt_required()
def get_fraud_ring(user_id):
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    user_ips = [t.ip_address for t in Transaction.query.filter_by(user_id=user_id).distinct(Transaction.ip_address).all()]
    linked_users = []
    if user_ips:
        potential = Transaction.query.filter(Transaction.ip_address.in_(user_ips)).distinct(Transaction.user_id).all()
        linked_users = [t.user_id for t in potential if t.user_id != user_id]
        
    return jsonify({
        "suspect_user": user_id,
        "linked_users_count": len(linked_users),
        "linked_user_ids": linked_users
    }), 200

# --- 6. UNLOCK REQUESTS ---
@admin_bp.route('/unlock-requests', methods=['GET'])
@jwt_required()
def get_unlock_requests():
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    requests = UnlockRequest.query.filter_by(status='PENDING').order_by(UnlockRequest.request_date.desc()).all()
    return jsonify([{
        "request_id": r.id,
        "user_email": r.email,
        "reason": r.reason,
        "date": r.request_date,
        "trust_score": r.user.trust_score
    } for r in requests]), 200

@admin_bp.route('/unlock-requests/resolve', methods=['POST'])
@jwt_required()
def resolve_unlock_request():
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json
    req_id = data.get('request_id')

    # --- FIX: Check if ID is provided ---
    if not req_id:
        return jsonify({"error": "Missing request_id"}), 400
    # -----------------------------------
    
    req = UnlockRequest.query.get(req_id)
    if not req: return jsonify({"error": "Request not found"}), 404
    
    decision = data.get('decision') 
    
    if decision == 'APPROVE':
        req.status = 'APPROVED'
        req.user.is_locked = False
        req.user.trust_score = 50 
    else:
        req.status = 'REJECTED'
        
    db.session.commit()
    return jsonify({"message": f"Request {decision}D"}), 200

# --- 7. DYNAMIC RULE ENGINE ---
@admin_bp.route('/rules', methods=['GET'])
@jwt_required()
def get_rules():
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    rules = FraudRule.query.all()
    return jsonify([{
        "id": r.id,
        "field": r.field,
        "operator": r.operator,
        "value": r.value,
        "action": r.action,
        "is_active": r.is_active
    } for r in rules]), 200

@admin_bp.route('/rules', methods=['POST'])
@jwt_required()
def add_rule():
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    data = request.json
    
    new_rule = FraudRule(
        field=data.get('field'),
        operator=data.get('operator'),
        value=data.get('value'),
        action=data.get('action', 'BLOCK'),
        is_active=True
    )
    db.session.add(new_rule)
    db.session.commit()
    return jsonify({"message": "Rule Created Successfully", "id": new_rule.id}), 201

@admin_bp.route('/rules/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_rule(id):
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    rule = FraudRule.query.get(id)
    if not rule: return jsonify({"error": "Rule not found"}), 404
    
    db.session.delete(rule)
    db.session.commit()
    return jsonify({"message": "Rule Deleted"}), 200

# --- 8. USER MANAGEMENT LIST ---
@admin_bp.route('/users', methods=['GET'])
@jwt_required()
def list_users():
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search')
    
    query = User.query
    if search:
        query = query.filter(User.email.ilike(f"%{search}%"))
        
    users = query.paginate(page=page, per_page=per_page)
    
    return jsonify({
        "total": users.total,
        "pages": users.pages,
        "users": [{
            "id": u.id,
            "email": u.email,
            "role": u.role,
            "balance": u.balance,
            "is_locked": u.is_locked,
            "trust_score": u.trust_score,
            "risk_level": "HIGH" if u.trust_score < 30 else "LOW"
        } for u in users.items]
    }), 200

# --- 10. SEND NOTIFICATION (ADMIN MSG) ---
@admin_bp.route('/notify-user', methods=['POST'])
@jwt_required()
def send_notification():
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json
    user_email = data.get('email')
    message = data.get('message')
    title = data.get('title', "Admin Message")
    
    user = User.query.filter_by(email=user_email).first()
    if not user: return jsonify({"error": "User not found"}), 404
    
    notif = Notification(
        user_id=user.id,
        title=title,
        message=message,
        type="ADMIN_ALERT" 
    )
    db.session.add(notif)
    db.session.commit()
    
    return jsonify({"message": f"Notification sent to {user_email}"}), 201

# ... (Keep existing imports)
from services.security_suite import SecuritySuite # Ensure this is imported

# --- A. NEW: TRANSACTION DETAIL VIEW ---
@admin_bp.route('/transactions/<transaction_id>', methods=['GET'])
@jwt_required()
def get_transaction_details(transaction_id):
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    tx = Transaction.query.get(transaction_id)
    if not tx: return jsonify({"error": "Transaction not found"}), 404
    
    return jsonify({
        "id": tx.id,
        "user_email": tx.user.email,
        "amount": tx.amount,
        "receiver_account": tx.receiver_account,
        "type": tx.transaction_type,
        "status": tx.status,
        "risk_score": tx.risk_score,
        "risk_reason": tx.risk_reason,
        "timestamp": tx.timestamp.isoformat(),
        # Drill-down details
        "ip_address": tx.ip_address,
        "device_id": tx.device_id,
        "location": {
            "lat": tx.location_lat,
            "lon": tx.location_lon
        },
        "is_flagged_incorrect": tx.is_flagged_incorrect
    }), 200

# --- C. UPDATE: AUDIT LOGGING FOR ADMIN ACTIONS ---

@admin_bp.route('/transaction-action', methods=['POST'])
@jwt_required()
def transaction_action():
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    admin_id = get_jwt_identity() # Get the ID of the Admin performing the action
    
    data = request.json
    tx = Transaction.query.get(data.get('tx_id'))
    if not tx: return jsonify({"error": "Transaction not found"}), 404
    
    action = data.get('action') # 'BLOCK', 'ALLOW', 'REFUND'
    previous_status = tx.status
    
    if action == 'BLOCK':
        tx.status = 'FAILED'
    elif action == 'ALLOW':
        tx.status = 'SUCCESS'
    elif action == 'REFUND':
        if tx.status == 'SUCCESS':
            # ... (Existing refund logic) ...
            receiver = None
            if tx.transaction_type == 'upi':
                receiver = User.query.filter_by(upi_id=tx.receiver_account).first()
            elif tx.transaction_type == 'online_banking':
                receiver = User.query.filter_by(account_number=tx.receiver_account).first()
            
            if receiver and receiver.balance >= tx.amount:
                receiver.balance -= tx.amount
                
            tx.user.balance += tx.amount
            tx.status = 'REFUNDED'
            
    db.session.commit()
    
    # LOG THE ADMIN ACTION
    SecuritySuite.log_action(
        admin_id, 
        f"ADMIN_TX_{action}", 
        f"Admin changed Tx {tx.id} from {previous_status} to {tx.status}", 
        request.remote_addr
    )
    
    return jsonify({"message": f"Transaction {action}ED"}), 200

@admin_bp.route('/user-action', methods=['POST'])
@jwt_required()
def user_action():
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    admin_id = get_jwt_identity()
    
    data = request.json
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if not user: return jsonify({"error": "User not found"}), 404
    
    action = data.get('action') # 'LOCK', 'UNLOCK'
    if action == 'LOCK':
        user.is_locked = True
    elif action == 'UNLOCK':
        user.is_locked = False
        user.trust_score = 50 
        
    db.session.commit()
    
    # LOG THE ADMIN ACTION
    SecuritySuite.log_action(
        admin_id, 
        f"ADMIN_USER_{action}", 
        f"Admin performed {action} on user {email}", 
        request.remote_addr
    )
    
    return jsonify({"message": f"User {action}ED"}), 200

# --- 11. GLOBAL FRAUD RING SCAN (New) ---
@admin_bp.route('/system/fraud-rings', methods=['GET'])
@jwt_required()
def scan_fraud_rings():
    """
    Graph Analysis: Finds clusters of users sharing the same IP address.
    Useful for detecting 'Click Farms' or 'Family Fraud'.
    """
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    # SQL: SELECT ip_address, COUNT(DISTINCT user_id) FROM transactions GROUP BY ip HAVING count > 2
    suspicious_ips = db.session.query(
        Transaction.ip_address,
        func.count(func.distinct(Transaction.user_id)).label('user_count')
    ).group_by(Transaction.ip_address).having(func.count(func.distinct(Transaction.user_id)) >= 2).all() # Threshold: 2 users
    
    rings = []
    for row in suspicious_ips:
        # Get details of users in this ring
        users_in_ring = db.session.query(User.email, User.id).join(Transaction).filter(Transaction.ip_address == row.ip_address).distinct().all()
        
        rings.append({
            "ip_address": row.ip_address,
            "distinct_users": row.user_count,
            "users": [{"email": u.email, "id": u.id} for u in users_in_ring],
            "risk_level": "CRITICAL" if row.user_count > 5 else "HIGH"
        })
        
    return jsonify({"fraud_rings": rings, "total_rings": len(rings)}), 200

# --- 12. ANALYTICS ENDPOINTS ---

@admin_bp.route('/analytics/risk-distribution', methods=['GET', 'OPTIONS'])
@jwt_required(optional=True)
def get_risk_distribution():
    """Get distribution of risk scores across all transactions"""
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    # Define risk score buckets
    buckets = [
        (0.0, 0.2, "Very Low"),
        (0.2, 0.4, "Low"),
        (0.4, 0.6, "Medium"),
        (0.6, 0.8, "High"),
        (0.8, 1.0, "Critical")
    ]
    
    result = []
    for min_score, max_score, label in buckets:
        count = Transaction.query.filter(
            Transaction.risk_score >= min_score,
            Transaction.risk_score < max_score
        ).count()
        result.append({
            "range": label,
            "count": count,
            "min": min_score,
            "max": max_score
        })
    
    # Handle exactly 1.0 scores
    critical_count = Transaction.query.filter(Transaction.risk_score == 1.0).count()
    if critical_count > 0:
        result[-1]["count"] += critical_count
    
    return jsonify(result), 200

@admin_bp.route('/analytics/alerts-timeline', methods=['GET', 'OPTIONS'])
@jwt_required(optional=True)
def get_alerts_timeline():
    """Get fraud alerts over last 30 days grouped by day"""
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    from models import FraudAlert
    from sqlalchemy import extract
    
    # Get last 30 days
    thirty_days_ago = datetime.now() - timedelta(days=30)
    
    alerts_by_day = db.session.query(
        func.date(FraudAlert.created_at).label('date'),
        func.count(FraudAlert.id).label('count')
    ).filter(
        FraudAlert.created_at >= thirty_days_ago
    ).group_by(func.date(FraudAlert.created_at)).all()
    
    # Create a dict for easy lookup
    alerts_dict = {str(row.date): row.count for row in alerts_by_day}
    
    # Fill in all 30 days (including days with 0 alerts)
    result = []
    for i in range(30):
        date = (datetime.now() - timedelta(days=29-i)).date()
        result.append({
            "date": str(date),
            "count": alerts_dict.get(str(date), 0)
        })
    
    return jsonify(result), 200

@admin_bp.route('/analytics/transaction-volume', methods=['GET', 'OPTIONS'])
@jwt_required(optional=True)
def get_transaction_volume():
    """Get transaction volume by hour of day (for heatmap)"""
    # Allow OPTIONS without auth for CORS preflight
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    # Get transactions grouped by hour
    volume_by_hour = db.session.query(
        extract('hour', Transaction.timestamp).label('hour'),
        func.count(Transaction.id).label('count')
    ).group_by(extract('hour', Transaction.timestamp)).all()
    
    # Create result for all 24 hours
    result = []
    volume_dict = {int(row.hour) if row.hour is not None else 0: row.count for row in volume_by_hour}
    
    for hour in range(24):
        result.append({
            "hour": hour,
            "label": f"{hour:02d}:00",
            "count": volume_dict.get(hour, 0)
        })
    
    return jsonify(result), 200

@admin_bp.route('/analytics/fraud-categories', methods=['GET', 'OPTIONS'])
@jwt_required(optional=True)
def get_fraud_categories():
    """Get breakdown of fraud types/categories"""
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    from models import FraudAlert
    
    # Get fraud alerts grouped by alert_level
    categories = db.session.query(
        FraudAlert.alert_level,
        func.count(FraudAlert.id).label('count')
    ).group_by(FraudAlert.alert_level).all()
    
    # Also get high-risk transactions
    high_risk_tx = Transaction.query.filter(Transaction.risk_score > 0.7).count()
    
    result = []
    for cat in categories:
        result.append({
            "category": cat.alert_level or "Unknown",
            "count": cat.count
        })
    
    # Add high-risk transactions category if not already there
    if high_risk_tx > 0:
        result.append({
            "category": "High Risk TX",
            "count": high_risk_tx
        })
    
    # If no data, return sample
    if not result:
        result = [
            {"category": "No Data", "count": 0}
        ]
    
    return jsonify(result), 200

@admin_bp.route('/analytics/geo-distribution', methods=['GET', 'OPTIONS'])
@jwt_required(optional=True)
def get_geo_distribution():
    """Get geographic distribution of transactions"""
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    # Offline reverse geocoding using reverse-geocoder (no internet needed!)
    import reverse_geocoder as rg
    from functools import lru_cache
    
    @lru_cache(maxsize=100)
    def get_location_name(lat, lon):
        """Reverse geocode coordinates to city, country - OFFLINE"""
        try:
            if lat is None or lon is None:
                return "Unknown"
            
            # Skip obviously invalid coordinates
            if abs(lat) > 90 or abs(lon) > 180 or (lat == 0 and lon == 0):
                return f"{lat:.2f}°, {lon:.2f}°"
            
            # Use reverse-geocoder (offline, no API calls!)
            results = rg.search([(lat, lon)])
            
            if results and len(results) > 0:
                location = results[0]
                city = location.get('name', 'Unknown City')
                country = location.get('cc', 'Unknown')  # country code
                
                # Map common country codes to full names
                country_names = {
                    'IN': 'India', 'US': 'United States', 'GB': 'United Kingdom',
                    'CN': 'China', 'JP': 'Japan', 'DE': 'Germany', 'FR': 'France',
                    'IT': 'Italy', 'ES': 'Spain', 'AU': 'Australia', 'CA': 'Canada',
                    'BR': 'Brazil', 'MX': 'Mexico', 'RU': 'Russia', 'ZA': 'South Africa'
                }
                country_full = country_names.get(country, country)
                
                return f"{city}, {country_full}"
            else:
                return f"{lat:.2f}°, {lon:.2f}°"
        except Exception as e:
            # Silently fail and return coordinates
            return f"{lat:.2f}°, {lon:.2f}°"
    
    # Get transactions with location data
    geo_data = db.session.query(
        Transaction.location_lat,
        Transaction.location_lon,
        func.count(Transaction.id).label('count')
    ).filter(
        Transaction.location_lat.isnot(None),
        Transaction.location_lon.isnot(None)
    ).group_by(
        Transaction.location_lat,
        Transaction.location_lon
    ).limit(100).all()  # Limit to top 100 locations
    
    result = []
    for row in geo_data:
        location_name = get_location_name(row.location_lat, row.location_lon)
        result.append({
            "location": location_name,
            "lat": row.location_lat,
            "lon": row.location_lon,
            "count": row.count
        })
    
    return jsonify(result), 200

# --- 13. INTELLIGENCE ENDPOINTS ---

@admin_bp.route('/intelligence/ip-analysis', methods=['GET'])
@jwt_required()
def get_ip_intelligence():
    """Analyze IP addresses for suspicious patterns"""
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    # Get IPs shared by multiple users
    shared_ips = db.session.query(
        Transaction.ip_address,
        func.count(func.distinct(Transaction.user_id)).label('user_count'),
        func.count(Transaction.id).label('tx_count'),
        func.avg(Transaction.risk_score).label('avg_risk')
    ).group_by(Transaction.ip_address).having(
        func.count(func.distinct(Transaction.user_id)) >= 2
    ).order_by(func.count(func.distinct(Transaction.user_id)).desc()).limit(50).all()
    
    result = []
    for row in shared_ips:
        # Get user emails for this IP
        users = db.session.query(User.email).join(Transaction).filter(
            Transaction.ip_address == row.ip_address
        ).distinct().limit(10).all()
        
        result.append({
            "ip_address": row.ip_address,
            "user_count": row.user_count,
            "transaction_count": row.tx_count,
            "avg_risk_score": round(float(row.avg_risk or 0), 2),
            "users": [u.email for u in users],
            "risk_level": "CRITICAL" if row.user_count > 5 else "HIGH" if row.user_count > 2 else "MEDIUM"
        })
    
    return jsonify(result), 200

@admin_bp.route('/intelligence/device-analysis', methods=['GET'])
@jwt_required()
def get_device_intelligence():
    """Analyze devices for suspicious patterns"""
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    from models import Device
    
    # Get devices shared by multiple users
    shared_devices = db.session.query(
        Transaction.device_id,
        func.count(func.distinct(Transaction.user_id)).label('user_count'),
        func.count(Transaction.id).label('tx_count')
    ).filter(
        Transaction.device_id.isnot(None)
    ).group_by(Transaction.device_id).having(
        func.count(func.distinct(Transaction.user_id)) >= 2
    ).order_by(func.count(func.distinct(Transaction.user_id)).desc()).limit(50).all()
    
    result = []
    for row in shared_devices:
        # Get users for this device
        users = db.session.query(User.email).join(Transaction).filter(
            Transaction.device_id == row.device_id
        ).distinct().limit(5).all()
        
        result.append({
            "device_id": row.device_id[:50] + "..." if len(row.device_id) > 50 else row.device_id,
            "user_count": row.user_count,
            "transaction_count": row.tx_count,
            "users": [u.email for u in users],
            "risk_level": "CRITICAL" if row.user_count > 3 else "HIGH"
        })
    
    return jsonify(result), 200

@admin_bp.route('/intelligence/high-risk-users', methods=['GET'])
@jwt_required()
def get_high_risk_users():
    """Get list of high-risk users"""
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    # Get users with low trust score or locked status
    high_risk = User.query.filter(
        (User.trust_score < 30) | (User.is_locked == True)
    ).order_by(User.trust_score.asc()).limit(100).all()
    
    result = []
    for user in high_risk:
        # Get transaction stats for this user
        tx_count = Transaction.query.filter_by(user_id=user.id).count()
        failed_tx = Transaction.query.filter_by(user_id=user.id, status='FAILED').count()
        avg_risk = db.session.query(func.avg(Transaction.risk_score)).filter_by(user_id=user.id).scalar() or 0
        
        result.append({
            "id": user.id,
            "email": user.email,
            "trust_score": user.trust_score,
            "is_locked": user.is_locked,
            "total_transactions": tx_count,
            "failed_transactions": failed_tx,
            "avg_risk_score": round(float(avg_risk), 2),
            "risk_category": "CRITICAL" if user.trust_score < 10 else "HIGH" if user.trust_score < 30 else "MEDIUM"
        })
    
    return jsonify(result), 200

# --- 14. ADDITIONAL MANAGEMENT ENDPOINTS ---

@admin_bp.route('/fraud-alerts', methods=['GET'])
@jwt_required()
def get_fraud_alerts():
    """Get all fraud alerts with pagination"""
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    from models import FraudAlert
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    alerts = FraudAlert.query.order_by(FraudAlert.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        "total": alerts.total,
        "pages": alerts.pages,
        "alerts": [{
            "id": a.id,
            "transaction_id": a.transaction_id,
            "alert_level": a.alert_level or "UNKNOWN",
            "description": a.description or "No description",
            "is_resolved": a.is_resolved,
            "created_at": a.created_at.isoformat() if a.created_at else datetime.utcnow().isoformat(),
            "transaction": {
                "amount": a.transaction.amount if a.transaction else 0,
                "user_email": a.transaction.user.email if a.transaction else "Unknown"
            } if a.transaction else None
        } for a in alerts.items]
    }), 200

@admin_bp.route('/suspicious-transactions', methods=['GET'])
@jwt_required()
def get_suspicious_transactions():
    """Get transactions with high risk scores"""
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    min_risk = request.args.get('min_risk', 0.7, type=float)
    
    suspicious = Transaction.query.filter(
        Transaction.risk_score >= min_risk
    ).order_by(Transaction.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        "total": suspicious.total,
        "pages": suspicious.pages,
        "transactions": [{
            "id": t.id,
            "user_email": t.user.email,
            "amount": t.amount,
            "risk_score": t.risk_score,
            "risk_reason": t.risk_reason,
            "status": t.status,
            "timestamp": t.timestamp.isoformat(),
            "ip_address": t.ip_address,
            "device_id": t.device_id[:50] + "..." if t.device_id and len(t.device_id) > 50 else t.device_id
        } for t in suspicious.items]
    }), 200

@admin_bp.route('/support-tickets/all', methods=['GET'])
@jwt_required()
def get_all_support_tickets():
    """Get all support tickets for admin review"""
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    from models import SupportTicket
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    status_filter = request.args.get('status')
    
    query = SupportTicket.query.order_by(SupportTicket.created_at.desc())
    
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    tickets = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        "total": tickets.total,
        "pages": tickets.pages,
        "tickets": [{
            "id": t.id,
            "user_id": t.user_id,
            "user_email": User.query.get(t.user_id).email if User.query.get(t.user_id) else "Unknown",
            "subject": t.subject,
            "description": t.description,
            "status": t.status,
            "created_at": t.created_at.isoformat()
        } for t in tickets.items]
    }), 200
