"""
Security Event Logging Service
Centralized logging for security-related events
"""

from models import db
from datetime import datetime

class SecurityEvent(db.Model):
    """Model for security events"""
    __tablename__ = 'security_events'
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True, index=True)
    severity = db.Column(db.String(20), nullable=False)  # INFO, WARNING, CRITICAL
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    device_id = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    resolved = db.Column(db.Boolean, default=False)
    resolved_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True)
    resolution_notes = db.Column(db.Text, nullable=True)

class SecurityEventLogger:
    """
    Centralized security event logging service.
    Logs critical security events for monitoring and forensics.
    """
    
    EVENT_TYPES = {
        'LOGIN_ANOMALY': 'Unusual login pattern detected',
        'DEVICE_MISMATCH': 'Login from unrecognized device',
        'RULE_OVERRIDE': 'Admin overrode fraud rule decision',
        'ACCOUNT_FREEZE': 'Account frozen due to high risk',
        'VELOCITY_ABUSE': 'Rapid transaction attempts',
        'IMPOSSIBLE_TRAVEL': 'Geographically impossible activity',
        'BOT_DETECTED': 'Automated bot behavior identified',
        'REPLAY_ATTACK': 'Duplicate nonce or transaction hash',
        'SUSPICIOUS_IP': 'Login from suspicious IP address',
        'FAILED_2FA': 'Multiple failed 2FA attempts',
        'PASSWORD_BREACH': 'Password found in breach database',
        'HIGH_RISK_TRANSACTION': 'Transaction with elevated risk score',
        'FRAUD_RING_DETECTED': 'Multiple users sharing IP/device',
        'NEW_DEVICE_LOGIN': 'Login from previously unseen device',
        'FOREIGN_COUNTRY_LOGIN': 'Login from foreign country',
        'ACCOUNT_TAKEOVER_ATTEMPT': 'Potential account takeover detected'
    }
    
    @staticmethod
    def log_event(event_type, severity, details, user_id=None, ip_address=None, device_id=None):
        """
        Log a security event.
        
        Args:
            event_type: str (must be in EVENT_TYPES)
            severity: str ('INFO', 'WARNING', 'CRITICAL')
            details: str (detailed description)
            user_id: str (optional)
            ip_address: str (optional)
            device_id: str (optional)
            
        Returns:
            SecurityEvent: Created event object
        """
        if event_type not in SecurityEventLogger.EVENT_TYPES:
            event_type = 'UNKNOWN_EVENT'
        
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            details=details,
            user_id=user_id,
            ip_address=ip_address,
            device_id=device_id
        )
        
        db.session.add(event)
        db.session.commit()
        
        # If CRITICAL, could trigger additional alerts here
        if severity == 'CRITICAL':
            SecurityEventLogger._handle_critical_event(event)
        
        return event
    
    @staticmethod
    def _handle_critical_event(event):
        """
        Handle critical security events (could send alerts, etc.)
        
        Args:
            event: SecurityEvent object
        """
        # TODO: Send admin notifications, trigger alerts, etc.
        print(f"🚨 CRITICAL SECURITY EVENT: {event.event_type} - {event.details}")
    
    @staticmethod
    def get_events(filters=None, limit=100):
        """
        Retrieve security events with optional filters.
        
        Args:
            filters: dict with optional keys:
                - event_type: str
                - severity: str
                - user_id: str
                - resolved: bool
                - start_date: datetime
                - end_date: datetime
            limit: int (max events to return)
            
        Returns:
            list: SecurityEvent objects
        """
        query = SecurityEvent.query
        
        if filters:
            if 'event_type' in filters:
                query = query.filter_by(event_type=filters['event_type'])
            if 'severity' in filters:
                query = query.filter_by(severity=filters['severity'])
            if 'user_id' in filters:
                query = query.filter_by(user_id=filters['user_id'])
            if 'resolved' in filters:
                query = query.filter_by(resolved=filters['resolved'])
            if 'start_date' in filters:
                query = query.filter(SecurityEvent.timestamp >= filters['start_date'])
            if 'end_date' in filters:
                query = query.filter(SecurityEvent.timestamp <= filters['end_date'])
        
        return query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
    
    @staticmethod
    def resolve_event(event_id, resolved_by_user_id, notes):
        """
        Mark a security event as resolved.
        
        Args:
            event_id: int
            resolved_by_user_id: str
            notes: str
            
        Returns:
            bool: Success status
        """
        event = SecurityEvent.query.get(event_id)
        
        if not event:
            return False
        
        event.resolved = True
        event.resolved_by = resolved_by_user_id
        event.resolution_notes = notes
        db.session.commit()
        
        return True
    
    @staticmethod
    def get_statistics():
        """
        Get security event statistics.
        
        Returns:
            dict: Event counts by type and severity
        """
        from sqlalchemy import func
        
        # Count by severity
        severity_counts = db.session.query(
            SecurityEvent.severity,
            func.count(SecurityEvent.id)
        ).group_by(SecurityEvent.severity).all()
        
        # Count by event type (top 10)
        type_counts = db.session.query(
            SecurityEvent.event_type,
            func.count(SecurityEvent.id)
        ).group_by(SecurityEvent.event_type)\
         .order_by(func.count(SecurityEvent.id).desc())\
         .limit(10).all()
        
        # Count unresolved critical events
        critical_unresolved = SecurityEvent.query.filter_by(
            severity='CRITICAL',
            resolved=False
        ).count()
        
        return {
            'severity': dict(severity_counts),
            'top_event_types': dict(type_counts),
            'critical_unresolved': critical_unresolved
        }
