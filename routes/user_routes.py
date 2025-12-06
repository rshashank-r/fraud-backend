from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import User, Transaction, db
from services.security_suite import SecuritySuite
from werkzeug.security import check_password_hash
import datetime

user_bp = Blueprint('user', __name__)

# ✅ FIXED: Added /profile route that frontend expects
@user_bp.route('/profile', methods=['GET', 'OPTIONS'])
@jwt_required()
def get_user_profile():
    """Get user profile - matches frontend /api/users/profile"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        return jsonify({
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name if hasattr(user, 'full_name') else user.email.split('@')[0],
            "phone_number": user.phone_number,
            "account_number": user.account_number,
            "upi_id": user.upi_id if hasattr(user, 'upi_id') else None,
            "role": user.role,
            "balance": float(user.balance) if user.balance else 0,
            "trust_score": user.trust_score or 100,
            "is_locked": user.is_locked,
            "is_2fa_enabled": user.is_2fa_enabled if hasattr(user, 'is_2fa_enabled') else False,
            "created_at": user.created_at.isoformat() if hasattr(user, 'created_at') and user.created_at else None
        }), 200
    except Exception as e:
        print(f"❌ Profile fetch error: {str(e)}")
        return jsonify({"error": "Failed to fetch profile"}), 500

# --- 2. User Profile Management ---
@user_bp.route('/me', methods=['GET'])
@jwt_required()
def get_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user: return jsonify({"error": "User not found"}), 404
    
    return jsonify({
        "id": user.id,
        "email": user.email,
        "phone": user.phone_number,
        "role": user.role,
        "trust_score": getattr(user, 'trust_score', 50),
        "is_locked": user.is_locked
    }), 200

@user_bp.route('/me', methods=['PUT'])
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    data = request.json
    
    if 'phone_number' in data: user.phone_number = data['phone_number']
    if 'email' in data: user.email = data['email']
    
    db.session.commit()
    return jsonify({"message": "Profile updated successfully"}), 200

# --- 3. Account Management ---
@user_bp.route('/accounts', methods=['GET'])
@jwt_required()
def list_accounts():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    return jsonify([{
        "account_id": user.account_number,
        "type": "Savings",
        "balance": user.balance,
        "status": "Active" if not user.is_locked else "Frozen"
    }]), 200

@user_bp.route('/accounts/<id>/balance', methods=['GET'])
@jwt_required()
def get_balance(id):
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    return jsonify({"balance": user.balance}), 200

@user_bp.route('/accounts/<id>/transactions', methods=['GET'])
@jwt_required()
def get_account_transactions(id):
    user_id = get_jwt_identity()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    txs = Transaction.query.filter_by(user_id=user_id)\
        .order_by(Transaction.timestamp.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        "total": txs.total,
        "pages": txs.pages,
        "transactions": [{
            "id": t.id,
            "amount": t.amount,
            "type": t.transaction_type,
            "status": t.status,
            "date": t.timestamp
        } for t in txs.items]
    }), 200

# --- 4. SECURITY CONTROLS (Manual Freeze/Unfreeze) ---
@user_bp.route('/security/freeze', methods=['POST'])
@jwt_required()
def freeze_account():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    user.is_locked = True
    db.session.commit()
    
    SecuritySuite.log_action(user_id, "USER_SELF_FREEZE", "User manually froze account", request.remote_addr)
    return jsonify({"message": "Account Frozen. No transactions allowed."}), 200

@user_bp.route('/security/unfreeze', methods=['POST'])
@jwt_required()
def unfreeze_account():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    data = request.json
    password = data.get('password')
    
    if not password or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid Password. Cannot unfreeze."}), 401
    
    user.is_locked = False
    db.session.commit()
    
    SecuritySuite.log_action(user_id, "USER_SELF_UNFREEZE", "User manually unfroze account", request.remote_addr)
    return jsonify({"message": "Account Unfrozen. You can now transact."}), 200
