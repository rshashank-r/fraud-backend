"""
Nonce Manager Service
Prevents replay attacks by tracking and validating transaction nonces
"""

from models import db
from datetime import datetime, timedelta
import uuid
import hashlib

class UsedNonce(db.Model):
    """Model for tracking used nonces"""
    __tablename__ = 'used_nonces'
    id = db.Column(db.Integer, primary_key=True)
    nonce = db.Column(db.String(36), unique=True, nullable=False, index=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    used_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)

class NonceManager:
    """
    Transaction nonce system to prevent replay attacks.
    Each transaction request must include a unique nonce.
    """
    
    DEFAULT_EXPIRY_SECONDS = 300  # 5 minutes
    
    @staticmethod
    def generate_nonce():
        """
        Generate a unique nonce (UUID v4).
        
        Returns:
            str: UUID nonce
        """
        return str(uuid.uuid4())
    
    @staticmethod
    def validate_nonce(nonce, user_id, expiry_seconds=DEFAULT_EXPIRY_SECONDS):
        """
        Validate and mark nonce as used.
        
        Args:
            nonce: str (UUID)
            user_id: str
            expiry_seconds: int (default 300 = 5 min)
            
        Returns:
            tuple: (is_valid: bool, error_message: str or None)
        """
        if not nonce:
            return False, "Nonce is required"
        
        # Check if nonce already used
        existing = UsedNonce.query.filter_by(nonce=nonce).first()
        
        if existing:
            if existing.user_id != user_id:
                return False, "Nonce belongs to different user"
            
            # Check if expired (someone trying to reuse old nonce)
            if existing.expires_at < datetime.utcnow():
                return False, "Nonce has expired"
            
            # Nonce exists and not expired = replay attack
            return False, "Nonce already used (possible replay attack)"
        
        # Nonce is valid - mark as used
        try:
            expires_at = datetime.utcnow() + timedelta(seconds=expiry_seconds)
            used_nonce = UsedNonce(
                nonce=nonce,
                user_id=user_id,
                expires_at=expires_at
            )
            db.session.add(used_nonce)
            db.session.commit()
            return True, None
        except Exception as e:
            db.session.rollback()
            return False, f"Failed to store nonce: {str(e)}"
    
    @staticmethod
    def cleanup_expired(days_old=1):
        """
        Clean up expired nonces (should be run periodically).
        
        Args:
            days_old: int (delete nonces older than this many days)
            
        Returns:
            int: Number of nonces deleted
        """
        cutoff = datetime.utcnow() - timedelta(days=days_old)
        deleted = UsedNonce.query.filter(UsedNonce.expires_at < cutoff).delete()
        db.session.commit()
        return deleted
    
    @staticmethod
    def calculate_transaction_hash(user_id, amount, receiver, timestamp, nonce):
        """
        Calculate unique transaction hash to prevent tampering.
        
        Args:
            user_id: str
            amount: float
            receiver: str
            timestamp: datetime
            nonce: str
            
        Returns:
            str: SHA-256 hash (64 characters)
        """
        # Create deterministic string from transaction data
        data_string = f"{user_id}|{amount}|{receiver}|{timestamp.isoformat()}|{nonce}"
        
        # Calculate SHA-256 hash
        hash_object = hashlib.sha256(data_string.encode())
        return hash_object.hexdigest()
    
    @staticmethod
    def verify_transaction_hash(transaction_id, user_id, amount, receiver, timestamp, nonce):
        """
        Verify transaction hasn't been tampered with.
        
        Args:
            transaction_id: str (transaction UUID)
            user_id: str
            amount: float
            receiver: str
            timestamp: datetime
            nonce: str
            
        Returns:
            tuple: (is_valid: bool, expected_hash: str)
        """
        from models import Transaction
        
        # Calculate expected hash
        expected_hash = NonceManager.calculate_transaction_hash(
            user_id, amount, receiver, timestamp, nonce
        )
        
        # Get transaction from database
        transaction = Transaction.query.get(transaction_id)
        
        if not transaction:
            return False, expected_hash
        
        # Compare hashes
        if hasattr(transaction, 'tx_hash'):
            return transaction.tx_hash == expected_hash, expected_hash
        
        return True, expected_hash  # No hash stored, can't verify
