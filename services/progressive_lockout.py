"""
Progressive Lockout Service
Implements escalating account lockouts from soft->hard->permanent
"""

from models import db, User
from datetime import datetime, timedelta

class ProgressiveLockout:
    """
    Escalating lockout system:
    - Level 0: No lockout
    - Level 1: Soft lock (rate limits reduced 90%, 24hr duration)
    - Level 2: Hard lock (all transactions blocked, 7-day duration, can request unlock)
    - Level 3: Permanent ban (requires admin review)
    """
    
    SOFT_LOCK_DURATION_HOURS = 24
    HARD_LOCK_DURATION_DAYS = 7
    
    @staticmethod
    def _ensure_lockout_fields(user):
        """Ensure user has lockout fields (for backward compatibility)"""
        if not hasattr(user, 'lockout_level'):
            user.lockout_level = 0
        if not hasattr(user, 'lockout_expires_at'):
            user.lockout_expires_at = None
        if not hasattr(user, 'lockout_reason'):
            user.lockout_reason = None
    
    @staticmethod
    def apply_lockout(user_id, level, reason):
        """
        Apply lockout to user account.
        
        Args:
            user_id: str
            level: int (1=soft, 2=hard, 3=permanent)
            reason: str
            
        Returns:
            dict: Lockout details
        """
        user = User.query.get(user_id)
        
        if not user:
            return None
        
        ProgressiveLockout._ensure_lockout_fields(user)
        
        user.lockout_level = level
        user.lockout_reason = reason
        
        if level == 1:  # Soft lock
            user.lockout_expires_at = datetime.utcnow() + timedelta(hours=ProgressiveLockout.SOFT_LOCK_DURATION_HOURS)
            message = f"Soft lockout applied for 24 hours. Reason: {reason}"
            
        elif level == 2:  # Hard lock
            user.is_locked = True
            user.lockout_expires_at = datetime.utcnow() + timedelta(days=ProgressiveLockout.HARD_LOCK_DURATION_DAYS)
            message = f"Hard lockout applied for 7 days. Reason: {reason}"
            
        elif level == 3:  # Permanent ban
            user.is_locked = True
            user.lockout_expires_at = None  # No expiry
            message = f"Permanent ban applied. Reason: {reason}"
        
        db.session.commit()
        
        # Log security event
        from services.security_events import SecurityEventLogger
        SecurityEventLogger.log_event(
            event_type='PROGRESSIVE_LOCKOUT',
            severity='CRITICAL' if level >= 2 else 'WARNING',
            details=f"Level {level} lockout applied to user {user.email}. Reason: {reason}",
            user_id=user_id
        )
        
        return {
            'level': level,
            'expires_at': user.lockout_expires_at,
            'reason': reason,
            'message': message
        }
    
    @staticmethod
    def escalate_lockout(user_id, violation_type):
        """
        Escalate lockout level based on violation.
        
        Args:
            user_id: str
            violation_type: str
            
        Returns:
            dict: New lockout details
        """
        user = User.query.get(user_id)
        
        if not user:
            return None
        
        ProgressiveLockout._ensure_lockout_fields(user)
        
        current_level = user.lockout_level or 0
        new_level = min(3, current_level + 1)  # Escalate by 1, max 3
        
        return ProgressiveLockout.apply_lockout(user_id, new_level, violation_type)
    
    @staticmethod
    def check_lockout_expired(user_id):
        """
        Check if lockout has expired and auto-unlock if needed.
        
        Args:
            user_id: str
            
        Returns:
            bool: True if lockout was lifted
        """
        user = User.query.get(user_id)
        
        if not user:
            return False
        
        ProgressiveLockout._ensure_lockout_fields(user)
        
        # Check if lockout has expiry and if it's passed
        if user.lockout_expires_at and user.lockout_expires_at < datetime.utcnow():
            # Lift lockout
            user.lockout_level = 0
            user.lockout_expires_at = None
            
            # For hard locks, also unlock account
            if user.is_locked:
                user.is_locked = False
            
            db.session.commit()
            return True
        
        return False
    
    @staticmethod
    def get_lockout_status(user_id):
        """
        Get current lockout status.
        
        Args:
            user_id: str
            
        Returns:
            dict: Lockout status details
        """
        user = User.query.get(user_id)
        
        if not user:
            return None
        
        ProgressiveLockout._ensure_lockout_fields(user)
        
        # Check if expired
        ProgressiveLockout.check_lockout_expired(user_id)
        
        level_names = {
            0: 'None',
            1: 'Soft Lock',
            2: 'Hard Lock',
            3: 'Permanent Ban'
        }
        
        return {
           'level': user.lockout_level or 0,
            'level_name': level_names.get(user.lockout_level or 0, 'Unknown'),
            'expires_at': user.lockout_expires_at,
            'reason': user.lockout_reason,
            'is_active': (user.lockout_level or 0) > 0
        }
