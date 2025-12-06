from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import Dispute, Transaction, Notification, db, User, UnlockRequest, SupportTicket, FAQ
from services.security_suite import SecuritySuite

support_bp = Blueprint('support', __name__)

@support_bp.route('/request-unlock', methods=['POST'])
def request_unlock():
    """
    Public endpoint for locked users to appeal their ban.
    Does not require JWT since they can't login.
    """
    data = request.json
    email = data.get('email')
    reason = data.get('reason')
    
    if not email or not reason:
        return jsonify({"error": "Email and Reason are required"}), 400
        
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
        
    if not user.is_locked:
        return jsonify({"message": "Account is active. No unlock needed."}), 200
        
    # Check if a pending request already exists
    existing = UnlockRequest.query.filter_by(user_id=user.id, status='PENDING').first()
    if existing:
        return jsonify({"error": "You already have a pending request."}), 400
        
    # Create Request
    new_req = UnlockRequest(user_id=user.id, email=email, reason=reason)
    db.session.add(new_req)
    db.session.commit()
    
    # Log it (pass user_id specifically since we don't have JWT context)
    SecuritySuite.log_action(user.id, "UNLOCK_REQUESTED", "User appealed ban", request.remote_addr)
    
    return jsonify({"message": "Request submitted. Admin will review."}), 201

# --- DISPUTE ENDPOINTS ---

@support_bp.route('/disputes', methods=['POST'])
@jwt_required()
def create_dispute():
    user_id = get_jwt_identity()
    data = request.json
    tx_id = data.get('transaction_id')
    
    # Check ownership
    tx = Transaction.query.filter_by(id=tx_id, user_id=user_id).first()
    if not tx: return jsonify({"error": "Transaction not found"}), 404
    
    # Prevent double dispute
    if Dispute.query.filter_by(transaction_id=tx_id).first():
        return jsonify({"error": "Dispute already open for this transaction"}), 400
    
    new_dispute = Dispute(
        user_id=user_id,
        transaction_id=tx_id,
        reason=data.get('reason', 'UNAUTHORIZED'),
        description=data.get('description')
    )
    
    # Auto-Flag transaction if user claims unauthorized
    if data.get('reason') == 'UNAUTHORIZED':
        tx.risk_reason += " | User Disputed: Unauthorized"
    
    db.session.add(new_dispute)
    db.session.commit()
    
    SecuritySuite.log_action(user_id, "DISPUTE_FILED", f"Reason: {data.get('reason')}", request.remote_addr)
    return jsonify({"message": "Dispute filed. Admin will review."}), 201

@support_bp.route('/disputes', methods=['GET'])
@jwt_required()
def get_my_disputes():
    user_id = get_jwt_identity()
    disputes = Dispute.query.filter_by(user_id=user_id).order_by(Dispute.created_at.desc()).all()
    
    return jsonify([{
        "id": d.id,
        "transaction_id": d.transaction_id,
        "amount": d.transaction.amount,
        "reason": d.reason,
        "status": d.status,
        "date": d.created_at
    } for d in disputes]), 200

# --- NOTIFICATION ENDPOINTS ---

@support_bp.route('/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    user_id = get_jwt_identity()
    notifs = Notification.query.filter_by(user_id=user_id).order_by(Notification.created_at.desc()).limit(20).all()
    return jsonify([{
        "id": n.id,
        "title": n.title,
        "message": n.message,
        "type": n.type,
        "is_read": n.is_read,
        "time": n.created_at
    } for n in notifs]), 200

@support_bp.route('/notifications/read-all', methods=['POST'])
@jwt_required()
def mark_all_read():
    user_id = get_jwt_identity()
    Notification.query.filter_by(user_id=user_id, is_read=False).update({"is_read": True})
    db.session.commit()
    return jsonify({"message": "Marked all as read"}), 200

# --- SUPPORT TICKET ENDPOINTS ---

@support_bp.route('/ticket', methods=['POST'])
@jwt_required()
def raise_ticket():
    user_id = get_jwt_identity()
    data = request.json
    
    new_ticket = SupportTicket(
        user_id=user_id,
        subject=data.get('subject'),
        description=data.get('description')
    )
    db.session.add(new_ticket)
    db.session.commit()
    
    return jsonify({"message": "Support ticket raised successfully", "ticket_id": new_ticket.id}), 201

@support_bp.route('/tickets', methods=['GET'])
@jwt_required()
def get_my_tickets():
    """
    FIX: This endpoint was missing, causing the CORS/404 Error.
    Returns all support tickets for the current user.
    """
    user_id = get_jwt_identity()
    tickets = SupportTicket.query.filter_by(user_id=user_id).order_by(SupportTicket.created_at.desc()).all()
    
    return jsonify([{
        "id": t.id,
        "subject": t.subject,
        "status": t.status,
        "created_at": t.created_at
    } for t in tickets]), 200

@support_bp.route('/ticket/<int:id>', methods=['GET'])
@jwt_required()
def track_ticket(id):
    user_id = get_jwt_identity()
    ticket = SupportTicket.query.filter_by(id=id, user_id=user_id).first()
    
    if not ticket:
        return jsonify({"error": "Ticket not found"}), 404
        
    return jsonify({
        "id": ticket.id,
        "subject": ticket.subject,
        "status": ticket.status,
        "created_at": ticket.created_at
    }), 200

@support_bp.route('/faq', methods=['GET'])
def get_faqs():
    faqs = FAQ.query.all()
    return jsonify([{"question": f.question, "answer": f.answer} for f in faqs]), 200