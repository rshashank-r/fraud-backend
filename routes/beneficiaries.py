from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, Beneficiary

beneficiary_bp = Blueprint('beneficiary', __name__)

@beneficiary_bp.route('/beneficiaries', methods=['GET'])
@jwt_required()
def list_beneficiaries():
    user_id = get_jwt_identity()
    bens = Beneficiary.query.filter_by(user_id=user_id).all()
    return jsonify([{
        "id": b.id,
        "name": b.name,
        "account": b.account_number,
        "bank": b.bank_name
    } for b in bens]), 200

@beneficiary_bp.route('/beneficiaries', methods=['POST'])
@jwt_required()
def add_beneficiary():
    user_id = get_jwt_identity()
    data = request.json
    
    new_ben = Beneficiary(
        user_id=user_id,
        name=data['name'],
        account_number=data['account_number'],
        bank_name=data['bank_name'],
        ifsc_code=data['ifsc_code']
    )
    db.session.add(new_ben)
    db.session.commit()
    return jsonify({"message": "Beneficiary added successfully"}), 201

@beneficiary_bp.route('/beneficiaries/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_beneficiary(id):
    user_id = get_jwt_identity()
    ben = Beneficiary.query.filter_by(id=id, user_id=user_id).first()
    
    if not ben: return jsonify({"error": "Beneficiary not found"}), 404
    
    db.session.delete(ben)
    db.session.commit()
    return jsonify({"message": "Beneficiary removed"}), 200

@beneficiary_bp.route('/beneficiaries/<int:id>', methods=['PUT'])
@jwt_required()
def update_beneficiary(id):
    user_id = get_jwt_identity()
    ben = Beneficiary.query.filter_by(id=id, user_id=user_id).first()
    
    if not ben: return jsonify({"error": "Beneficiary not found"}), 404
    
    data = request.json
    if 'name' in data: ben.name = data['name']
    if 'account_number' in data: ben.account_number = data['account_number']
    if 'bank_name' in data: ben.bank_name = data['bank_name']
    if 'ifsc_code' in data: ben.ifsc_code = data['ifsc_code']
    
    db.session.commit()
    return jsonify({"message": "Beneficiary updated"}), 200