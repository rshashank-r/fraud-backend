from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import Transaction, User
from extensions import db

accounts_bp = Blueprint('accounts', __name__)

@accounts_bp.route('/<account_id>/transactions', methods=['GET', 'OPTIONS'])
@jwt_required(optional=True)
def get_account_transactions(account_id):
    """Get transactions for a specific account"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        user_id = get_jwt_identity()
        
        # Verify the account belongs to the user
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Check if account_id matches user's ID or account number
        if str(user.id) != account_id and str(user.account_number) != account_id:
            return jsonify({"error": "Unauthorized access"}), 403
        
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        # Query transactions
        pagination = Transaction.query.filter_by(user_id=user_id)\
            .order_by(Transaction.timestamp.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)
        
        # Format results
        transactions = []
        for tx in pagination.items:
            transactions.append({
                'id': tx.id,
                'amount': float(tx.amount),
                'transaction_type': tx.transaction_type,
                'receiver_account': tx.receiver_account,
                'status': tx.status,
                'timestamp': tx.timestamp.isoformat() if tx.timestamp else None,
                'date': tx.timestamp.strftime('%Y-%m-%d') if tx.timestamp else None,
                'risk_score': float(tx.risk_score) if tx.risk_score else 0,
                'risk_reason': tx.risk_reason,
                'ip_address': tx.ip_address,
                'location_lat': float(tx.location_lat) if tx.location_lat else None,
                'location_lon': float(tx.location_lon) if tx.location_lon else None
            })
        
        return jsonify({
            'transactions': transactions,
            'page': pagination.page,
            'per_page': pagination.per_page,
            'total': pagination.total,
            'pages': pagination.pages
        }), 200
        
    except Exception as e:
        print(f"❌ Get account transactions error: {str(e)}")
        return jsonify({
            "error": "Failed to fetch transactions",
            "message": str(e)
        }), 500


@accounts_bp.route('/<account_id>', methods=['GET', 'OPTIONS'])
@jwt_required(optional=True)
def get_account_details(account_id):
    """Get account details"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Check authorization
        if str(user.id) != account_id and str(user.account_number) != account_id:
            return jsonify({"error": "Unauthorized access"}), 403
        
        return jsonify({
            'account_id': str(user.id),
            'account_number': user.account_number,
            'email': user.email,
            'balance': float(user.balance),
            'trust_score': user.trust_score,
            'is_locked': user.is_locked,
            'total_transactions': user.total_tx_count
        }), 200
        
    except Exception as e:
        print(f"❌ Get account details error: {str(e)}")
        return jsonify({"error": "Failed to fetch account details"}), 500
