from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, User, Transaction, Beneficiary
import uuid
from datetime import datetime

transfer_bp = Blueprint('transfers', __name__)

@transfer_bp.route('/transfers/verify-beneficiary', methods=['POST'])
@jwt_required()
def verify_beneficiary():
    data = request.json
    account = data.get('account_number')
    ifsc = data.get('ifsc')
    
    # 1. Check Internal Users
    internal_user = User.query.filter_by(account_number=account).first()
    if internal_user:
        return jsonify({"valid": True, "name": "Internal User (Verified)"}), 200
        
    # 2. Check Saved Beneficiaries
    ben = Beneficiary.query.filter_by(account_number=account, ifsc_code=ifsc).first()
    if ben:
        return jsonify({"valid": True, "name": ben.name}), 200
        
    # 3. Mock External API check
    if len(account) > 5:
        return jsonify({"valid": True, "name": "External Bank User"}), 200
        
    return jsonify({"valid": False, "error": "Invalid Beneficiary Details"}), 400

@transfer_bp.route('/transfers/internal', methods=['POST'])
@jwt_required()
def transfer_internal():
    user_id = get_jwt_identity()
    data = request.json
    sender = User.query.get(user_id)
    
    receiver_acc = data.get('to_account')
    amount = float(data.get('amount'))
    
    receiver = User.query.filter_by(account_number=receiver_acc).first()
    if not receiver:
        return jsonify({"error": "Receiver account not found"}), 404
        
    if sender.balance < amount:
        return jsonify({"error": "Insufficient Funds"}), 400
        
    # Atomic Transaction
    try:
        sender.balance -= amount
        receiver.balance += amount
        
        tx = Transaction(
            id=str(uuid.uuid4()),
            user_id=sender.id,
            amount=amount,
            receiver_account=receiver_acc,
            transaction_type="INTERNAL_TRANSFER",
            status="SUCCESS",
            ip_address=request.remote_addr
        )
        db.session.add(tx)
        db.session.commit()
        return jsonify({"message": "Transfer Successful", "tx_id": tx.id}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@transfer_bp.route('/transfers/external', methods=['POST'])
@jwt_required()
def transfer_external():
    user_id = get_jwt_identity()
    data = request.json
    sender = User.query.get(user_id)
    amount = float(data.get('amount'))
    
    if sender.balance < amount:
        return jsonify({"error": "Insufficient Funds"}), 400
        
    # Mock External Transfer (IMPS/NEFT)
    try:
        sender.balance -= amount
        tx = Transaction(
            id=str(uuid.uuid4()),
            user_id=sender.id,
            amount=amount,
            receiver_account=data.get('to_account'),
            transaction_type="EXTERNAL_TRANSFER",
            status="SUCCESS", # In real world, might be PENDING
            ip_address=request.remote_addr
        )
        db.session.add(tx)
        db.session.commit()
        return jsonify({"message": "External Transfer Initiated", "tx_id": tx.id}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@transfer_bp.route('/transfers/<id>/status', methods=['GET'])
@jwt_required()
def transfer_status(id):
    tx = Transaction.query.get(id)
    if not tx: return jsonify({"error": "Transaction not found"}), 404
    return jsonify({"id": tx.id, "status": tx.status, "timestamp": tx.timestamp}), 200