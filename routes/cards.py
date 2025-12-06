from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db
from models import Card
import random
from datetime import datetime, timedelta

cards_bp = Blueprint('cards', __name__)

def generate_card_number():
    """Generate a random 16-digit virtual card number"""
    # Using BIN range for virtual cards (not real)
    prefix = '4532'  # Visa virtual card prefix
    middle = ''.join([str(random.randint(0, 9)) for _ in range(8)])
    last = ''.join([str(random.randint(0, 9)) for _ in range(4)])
    return f"{prefix}{middle}{last}"

def generate_cvv():
    """Generate random 3-digit CVV"""
    return ''.join([str(random.randint(0, 9)) for _ in range(3)])

def generate_expiry():
    """Generate expiry date 3 years from now"""
    future = datetime.now() + timedelta(days=365*3)
    return future.strftime('%m/%y')

# ✅ GET ALL CARDS
@cards_bp.route('/', methods=['GET', 'OPTIONS'])
@jwt_required()
def get_cards():
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        user_id = get_jwt_identity()
        cards = Card.query.filter_by(user_id=user_id).all()
        
        return jsonify([{
            "id": c.id,
            "card_number": c.card_number,
            "card_number_masked": f"•••• •••• •••• {c.card_number[-4:]}",
            "is_locked": c.is_locked,
            "expiry_date": c.expiry_date,
            "type": c.type,
            "created_at": c.created_at.isoformat() if hasattr(c, 'created_at') and c.created_at else None
        } for c in cards]), 200
    except Exception as e:
        print(f"❌ Get cards error: {str(e)}")
        return jsonify({"error": "Failed to fetch cards"}), 500

# ✅ CREATE VIRTUAL CARD (AUTO-GENERATED)
@cards_bp.route('/create-virtual', methods=['POST', 'OPTIONS'])
@jwt_required()
def create_virtual_card():
    """Create a new virtual card with auto-generated details"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        user_id = get_jwt_identity()
        data = request.json or {}
        
        # Generate card details
        card_number = generate_card_number()
        cvv = generate_cvv()
        expiry = generate_expiry()
        pin = data.get('pin', '1234')  # User can set PIN or use default
        card_type = data.get('type', 'VIRTUAL')
        card_name = data.get('name', f'Virtual Card {random.randint(1000, 9999)}')
        
        # Create card
        new_card = Card(
            user_id=user_id,
            card_number=card_number,
            expiry_date=expiry,
            cvv_hash=generate_password_hash(cvv, method='pbkdf2:sha256'),
            pin_hash=generate_password_hash(pin, method='pbkdf2:sha256'),
            type=card_type,
            name=card_name if hasattr(Card, 'name') else None
        )
        
        db.session.add(new_card)
        db.session.commit()
        
        return jsonify({
            "message": "Virtual card created successfully",
            "card": {
                "id": new_card.id,
                "card_number": card_number,
                "card_number_masked": f"•••• •••• •••• {card_number[-4:]}",
                "expiry_date": expiry,
                "cvv": cvv,  # Show once on creation
                "type": card_type,
                "name": card_name
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        print(f"❌ Create virtual card error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Failed to create card", "message": str(e)}), 500

# ✅ ADD EXISTING CARD (MANUAL)
@cards_bp.route('/', methods=['POST'])
@jwt_required()
def add_card():
    user_id = get_jwt_identity()
    data = request.json
    
    # Validation
    required_fields = ['card_number', 'expiry_date', 'cvv', 'pin']
    for field in required_fields:
        if not data.get(field):
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    # Check for duplicates
    if Card.query.filter_by(card_number=data.get('card_number')).first():
        return jsonify({"error": "Card already registered"}), 400
    
    # Create card
    new_card = Card(
        user_id=user_id,
        card_number=data.get('card_number'),
        expiry_date=data.get('expiry_date'),
        cvv_hash=generate_password_hash(data.get('cvv'), method='pbkdf2:sha256'),
        pin_hash=generate_password_hash(data.get('pin'), method='pbkdf2:sha256'),
        type=data.get('type', 'DEBIT')
    )
    
    db.session.add(new_card)
    db.session.commit()
    
    return jsonify({"message": "Card added successfully", "id": new_card.id}), 201

# ✅ LOCK CARD
@cards_bp.route('/<int:id>/lock', methods=['POST', 'OPTIONS'])
@jwt_required()
def lock_card(id):
    if request.method == 'OPTIONS':
        return '', 200
    
    user_id = get_jwt_identity()
    card = Card.query.filter_by(id=id, user_id=user_id).first()
    
    if not card: 
        return jsonify({"error": "Card not found"}), 404
    
    card.is_locked = True
    db.session.commit()
    
    return jsonify({"message": "Card locked successfully"}), 200

# ✅ UNLOCK CARD
@cards_bp.route('/<int:id>/unlock', methods=['POST', 'OPTIONS'])
@jwt_required()
def unlock_card(id):
    if request.method == 'OPTIONS':
        return '', 200
    
    user_id = get_jwt_identity()
    card = Card.query.filter_by(id=id, user_id=user_id).first()
    
    if not card: 
        return jsonify({"error": "Card not found"}), 404
    
    card.is_locked = False
    db.session.commit()
    
    return jsonify({"message": "Card unlocked successfully"}), 200

# ✅ DELETE CARD
@cards_bp.route('/<int:id>', methods=['DELETE', 'OPTIONS'])
@jwt_required()
def delete_card(id):
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        user_id = get_jwt_identity()
        card = Card.query.filter_by(id=id, user_id=user_id).first()
        
        if not card:
            return jsonify({"error": "Card not found"}), 404
        
        db.session.delete(card)
        db.session.commit()
        
        return jsonify({"message": "Card deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to delete card"}), 500

# ✅ CHANGE PIN
@cards_bp.route('/<int:id>/change-pin', methods=['POST', 'OPTIONS'])
@jwt_required()
def change_pin(id):
    if request.method == 'OPTIONS':
        return '', 200
    
    user_id = get_jwt_identity()
    data = request.json
    old_pin = data.get('old_pin')
    new_pin = data.get('new_pin')
    
    card = Card.query.filter_by(id=id, user_id=user_id).first()
    if not card: 
        return jsonify({"error": "Card not found"}), 404
    
    # Verify old PIN
    if not check_password_hash(card.pin_hash, old_pin):
        return jsonify({"error": "Incorrect current PIN"}), 400
    
    # Set new PIN
    card.pin_hash = generate_password_hash(new_pin, method='pbkdf2:sha256')
    db.session.commit()
    
    return jsonify({"message": "PIN changed successfully"}), 200
