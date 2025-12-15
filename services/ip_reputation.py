"""
IP Reputation Service
Tracks and scores IP address trustworthiness
"""

from models import db
from datetime import datetime

class IPReputation(db.Model):
    """Model for IP reputation tracking"""
    __tablename__ = 'ip_reputation'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True, nullable=False, index=True)
    reputation_score = db.Column(db.Integer, default=500)  # 0-1000
    fraud_attempts = db.Column(db.Integer, default=0)
    successful_transactions = db.Column(db.Integer, default=0)
    failed_logins = db.Column(db.Integer, default=0)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_blacklisted = db.Column(db.Boolean, default=False)
    blacklist_reason = db.Column(db.String(255))
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)

class IPReputationService:
    """Manages IP reputation scores"""
    
    @staticmethod
    def get_reputation(ip_address):
        """Get reputation score for an IP (0-1000)"""
        ip_rep = IPReputation.query.filter_by(ip_address=ip_address).first()
        
        if not ip_rep:
            # Create new entry with neutral score
            ip_rep = IPReputation(ip_address=ip_address, reputation_score=500)
            db.session.add(ip_rep)
            db.session.commit()
            return 500
        
        ip_rep.last_seen = datetime.utcnow()
        db.session.commit()
        
        return ip_rep.reputation_score
    
    @staticmethod
    def update_reputation(ip_address, event_type):
        """
        Update IP reputation based on event.
        
        Args:
            ip_address: str
            event_type: str ('success', 'fraud', 'failed_login')
        """
        ip_rep = IPReputation.query.filter_by(ip_address=ip_address).first()
        
        if not ip_rep:
            ip_rep = IPReputation(ip_address=ip_address)
            db.session.add(ip_rep)
        
        if event_type == 'success':
            ip_rep.successful_transactions += 1
            ip_rep.reputation_score = min(1000, ip_rep.reputation_score + 10)
            
        elif event_type == 'fraud':
            ip_rep.fraud_attempts += 1
            ip_rep.reputation_score = max(0, ip_rep.reputation_score - 100)
            
            # Auto-blacklist after 3 fraud attempts
            if ip_rep.fraud_attempts >= 3:
                ip_rep.is_blacklisted = True
                ip_rep.blacklist_reason = "Multiple fraud attempts"
                
        elif event_type == 'failed_login':
            ip_rep.failed_logins += 1
            ip_rep.reputation_score = max(0, ip_rep.reputation_score - 20)
        
        ip_rep.last_seen = datetime.utcnow()
        db.session.commit()
        
        return ip_rep.reputation_score
    
    @staticmethod
    def blacklist_ip(ip_address, reason):
        """Permanently blacklist an IP"""
        ip_rep = IPReputation.query.filter_by(ip_address=ip_address).first()
        
        if not ip_rep:
            ip_rep = IPReputation(ip_address=ip_address)
            db.session.add(ip_rep)
        
        ip_rep.is_blacklisted = True
        ip_rep.blacklist_reason = reason
        ip_rep.reputation_score = 0
        db.session.commit()
    
    @staticmethod
    def is_blacklisted(ip_address):
        """Check if IP is blacklisted"""
        ip_rep = IPReputation.query.filter_by(ip_address=ip_address).first()
        return ip_rep.is_blacklisted if ip_rep else False
