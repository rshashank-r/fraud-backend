"""
Honeypot Accounts Service
Creates decoy accounts to detect and trap attackers
"""

from models import db
import random
import string

class HoneypotAccount(db.Model):
    """Model for honeypot accounts"""
    __tablename__ = 'honeypot_accounts'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    account_number = db.Column(db.String(20), unique=True)
    upi_id = db.Column(db.String(50), unique=True)
    cardholder_name = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=db.func.now())
    attack_count = db.Column(db.Integer, default=0)
    last_attack_at = db.Column(db.DateTime)

class HoneypotService:
    """
    Manages honeypot/decoy accounts to detect attackers.
    Any interaction with these accounts triggers alerts.
    """
    
    @staticmethod
    def create_honeypot(email=None, account_number=None, upi_id=None):
        """
        Create a new honeypot account.
        
        Args:
            email: str (optional, will generate if not provided)
            account_number: str (optional)
            upi_id: str (optional)
            
        Returns:
            HoneypotAccount object
        """
        if not email:
            # Generate realistic-looking email
            names = ['admin', 'support', 'test', 'demo', 'info', 'contact']
            domains = ['fraudguard.com', 'example.com', 'test.com']
            email = f"{random.choice(names)}{random.randint(1, 999)}@{random.choice(domains)}"
        
        if not account_number:
            account_number = str(random.randint(1000000000, 9999999999))
        
        if not upi_id:
            upi_id = f"{random.randint(1000000000, 9999999999)}@fraudguard"
        
        honeypot = HoneypotAccount(
            email=email,
            account_number=account_number,
            upi_id=upi_id,
            cardholder_name=f"Test User {random.randint(1, 100)}"
        )
        
        db.session.add(honeypot)
        db.session.commit()
        
        return honeypot
    
    @staticmethod
    def is_honeypot(email=None, account_number=None, upi_id=None):
        """
        Check if account is a honeypot.
        
        Args:
            email: str (optional)
            account_number: str (optional)
            upi_id: str (optional)
            
        Returns:
            HoneypotAccount or None
        """
        query = HoneypotAccount.query
        
        if email:
            honeypot = query.filter_by(email=email).first()
            if honeypot:
                return honeypot
        
        if account_number:
            honeypot = query.filter_by(account_number=account_number).first()
            if honeypot:
                return honeypot
        
        if upi_id:
            honeypot = query.filter_by(upi_id=upi_id).first()
            if honeypot:
                return honeypot
        
        return None
    
    @staticmethod
    def record_attack(honeypot_id, attacker_ip, attack_type, details):
        """
        Record an attack on a honeypot account.
        
        Args:
            honeypot_id: int
            attacker_ip: str
            attack_type: str ('login_attempt', 'transaction_attempt', 'enumeration')
            details: str
            
        Returns:
            bool: Success status
        """
        honeypot = HoneypotAccount.query.get(honeypot_id)
        
        if not honeypot:
            return False
        
        honeypot.attack_count += 1
        honeypot.last_attack_at = db.func.now()
        
        # Log security event
        from services.security_events import SecurityEventLogger
        SecurityEventLogger.log_event(
            event_type='HONEYPOT_TRIGGERED',
            severity='CRITICAL',
            details=f"Honeypot {honeypot.email} attacked. Type: {attack_type}. Details: {details}",
            ip_address=attacker_ip
        )
        
        # Blacklist the IP
        from services.ip_reputation import IPReputationService
        IPReputationService.blacklist_ip(
            attacker_ip,
            f"Honeypot attack: {attack_type}"
        )
        
        db.session.commit()
        return True
