from flask import Blueprint, jsonify, request, make_response
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import User, Transaction, FraudRule, IPWhitelist, Dispute, Notification, AuditLog, db, UnlockRequest, FraudAlert, SupportTicket
from sqlalchemy import func, case
from sqlalchemy.orm import joinedload
import csv
import io
from datetime import datetime, timedelta
from services.email_service import send_admin_action_alert # Added Import



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
    
    # OPTIMIZED: Single aggregated query instead of 3 separate queries
    stats = db.session.query(
        func.count(func.distinct(User.id)).label('total_users'),
        func.count(Transaction.id).label('total_tx'),
        func.sum(case((Transaction.status == 'FAILED', 1), else_=0)).label('blocked_tx')
    ).outerjoin(Transaction, User.id == Transaction.user_id).first()
    
    # Additional Metrics
    total_users = stats.total_users or 0
    total_tx = stats.total_tx or 0
    blocked_tx = stats.blocked_tx or 0
    fraud_rate = (blocked_tx / total_tx * 100) if total_tx > 0 else 0
    
    # 1. Alert Stats
    today = datetime.utcnow().date()
    total_alerts = FraudAlert.query.count()
    alerts_today = FraudAlert.query.filter(func.date(FraudAlert.created_at) == today).count()
    
    # 2. Key Risk Indicators
    locked_accounts = User.query.filter_by(is_locked=True).count()
    high_risk_users = User.query.filter(User.trust_score < 50).count()
    
    # 3. Fraud Rings (Unique IPs with > 2 users)
    suspicious_ips = db.session.query(Transaction.ip_address)\
        .group_by(Transaction.ip_address)\
        .having(func.count(func.distinct(Transaction.user_id)) >= 2).count()
    
    return jsonify({
        "total_users": total_users,
        "total_transactions": total_tx,
        "blocked_transactions": blocked_tx,
        "fraud_rate": round(fraud_rate, 2),
        "total_fraud_alerts": total_alerts,
        "fraud_alerts_today": alerts_today,
        "locked_accounts": locked_accounts,
        "high_risk_users": high_risk_users,
        "fraud_rings_detected": suspicious_ips
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
    
    # OPTIMIZED: Use joinedload to eagerly load user relationship
    # This prevents N+1 query problem - loads all users in a single JOIN query
    query = Transaction.query.options(joinedload(Transaction.user)).order_by(Transaction.timestamp.desc())
    
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
        
        # 📧 SEND NOTIFICATION
        app_instance = current_app._get_current_object()
        send_admin_action_alert(app_instance, req.user.email, 'ACCOUNT_UNLOCKED', "Appeal Approved")
        
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

    # 📧 SEND NOTIFICATION
    app_instance = current_app._get_current_object()
    action_type = 'ACCOUNT_LOCKED' if action == 'LOCK' else 'ACCOUNT_UNLOCKED'
    reason = "Administrative Decision"
    send_admin_action_alert(app_instance, user.email, action_type, reason)
    
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

# --- 12. DATA FOR ALERTS & LOGS PAGE ---

@admin_bp.route('/suspicious-transactions', methods=['GET'])
@jwt_required()
def get_suspicious_transactions():
    """Get transactions with high risk scores"""
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    txs = Transaction.query.filter(Transaction.risk_score > 0.7)\
        .order_by(Transaction.timestamp.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        "transactions": [{
            "id": t.id,
            "user": t.user.email,
            "amount": t.amount,
            "risk_score": t.risk_score,
            "timestamp": t.timestamp.isoformat()
        } for t in txs.items],
        "pages": txs.pages,
        "total": txs.total
    }), 200


@admin_bp.route('/fraud-alerts', methods=['GET'])
@jwt_required()
def get_fraud_alerts():
    """Get all fraud alerts"""
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    alerts = FraudAlert.query.order_by(FraudAlert.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        "alerts": [{
            "id": a.id,
            "level": a.alert_level,
            "description": a.description,
            "created_at": a.created_at.isoformat(),
            "is_resolved": a.is_resolved
        } for a in alerts.items],
        "pages": alerts.pages,
        "total": alerts.total
    }), 200

@admin_bp.route('/support-tickets/all', methods=['GET'])
@jwt_required()
def get_all_support_tickets():
    """Get all support tickets"""
    if not check_admin(): return jsonify({"error": "Unauthorized"}), 403
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    tickets = SupportTicket.query.order_by(SupportTicket.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        "tickets": [{
            "id": t.id,
            "user": t.user.email,
            "subject": t.subject,
            "status": t.status,
            "created_at": t.created_at.isoformat()
        } for t in tickets.items],
        "pages": tickets.pages,
        "total": tickets.total
    }), 200