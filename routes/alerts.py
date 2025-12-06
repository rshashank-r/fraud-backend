from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, Alert

alerts_bp = Blueprint('alerts', __name__)

@alerts_bp.route('/', methods=['GET'])
@jwt_required()
def list_alerts():
    user_id = get_jwt_identity()
    # Fetch latest 20 alerts
    alerts = Alert.query.filter_by(user_id=user_id).order_by(Alert.created_at.desc()).limit(20).all()
    
    return jsonify([{
        "id": a.id,
        "message": a.message,
        "type": a.type,
        "is_read": a.is_read,
        "timestamp": a.created_at
    } for a in alerts]), 200

@alerts_bp.route('/read-all', methods=['PUT'])
@jwt_required()
def mark_all_read():
    user_id = get_jwt_identity()
    
    # Update all unread alerts for this user
    Alert.query.filter_by(user_id=user_id, is_read=False).update({'is_read': True})
    db.session.commit()
    
    return jsonify({"message": "All alerts marked as read"}), 200