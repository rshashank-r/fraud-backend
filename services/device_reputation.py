"""
Device Reputation Service
Tracks and scores device trustworthiness based on behavior patterns
"""

from models import Device, db
from datetime import datetime

class DeviceReputationService:
    """
    Manages device reputation scores (0-1000 scale)
    Threshold: 500 = trusted
    """
    
    # Score adjustments
    SUCCESSFUL_LOGIN_BONUS = 10
    FAILED_LOGIN_PENALTY = 20
    FRAUD_ATTEMPT_PENALTY = 100
    SUCCESS_TRANSACTION_BONUS = 5
    
    @staticmethod
    def get_reputation(device_id, user_id):
        """
        Get reputation score for a device.
        
        Args:
            device_id: str (device fingerprint)
            user_id: str
            
        Returns:
            int: Reputation score (0-1000)
        """
        device = Device.query.filter_by(
            user_id=user_id,
            device_fingerprint=device_id
        ).first()
        
        if not device:
            return 500  # Neutral score for new devices
        
        # Ensure reputation_score column exists (may not if DB not migrated)
        if not hasattr(device, 'reputation_score'):
            return 500
        
        return device.reputation_score or 500
    
    @staticmethod
    def update_reputation(device_id, user_id, event_type):
        """
        Update device reputation based on event.
        
        Args:
            device_id: str
            user_id: str
            event_type: str ('login_success', 'login_failed', 'fraud_attempt', 'transaction_success')
        """
        device = Device.query.filter_by(
            user_id=user_id,
            device_fingerprint=device_id
        ).first()
        
        if not device:
            # Create new device entry
            device = Device(
                user_id=user_id,
                device_fingerprint=device_id,
                reputation_score=500,
                failed_attempts=0,
                success_count=0
            )
            db.session.add(device)
        
        # Ensure columns exist
        if not hasattr(device, 'reputation_score'):
            device.reputation_score = 500
        if not hasattr(device, 'failed_attempts'):
            device.failed_attempts = 0
        if not hasattr(device, 'success_count'):
            device.success_count = 0
        
        # Adjust score based on event
        if event_type == 'login_success':
            device.reputation_score = min(1000, device.reputation_score + DeviceReputationService.SUCCESSFUL_LOGIN_BONUS)
            device.success_count += 1
            device.failed_attempts = 0  # Reset on successful login
            
        elif event_type == 'login_failed':
            device.reputation_score = max(0, device.reputation_score - DeviceReputationService.FAILED_LOGIN_PENALTY)
            device.failed_attempts += 1
            device.last_failure_at = datetime.utcnow()
            
        elif event_type == 'fraud_attempt':
            device.reputation_score = max(0, device.reputation_score - DeviceReputationService.FRAUD_ATTEMPT_PENALTY)
            device.is_trusted = False
            
        elif event_type == 'transaction_success':
            device.reputation_score = min(1000, device.reputation_score + DeviceReputationService.SUCCESS_TRANSACTION_BONUS)
            device.success_count += 1
        
        device.last_used_at = datetime.utcnow()
        db.session.commit()
        
        return device.reputation_score
    
    @staticmethod
    def is_trusted(device_id, user_id):
        """
        Check if device is trusted (reputation >= 500)
        
        Args:
            device_id: str
            user_id: str
            
        Returns:
            bool
        """
        reputation = DeviceReputationService.get_reputation(device_id, user_id)
        return reputation >= 500
    
    @staticmethod
    def blacklist_device(device_id, user_id, reason):
        """
        Permanently blacklist a device (set reputation to 0)
        
        Args:
            device_id: str
            user_id: str
            reason: str
        """
        device = Device.query.filter_by(
            user_id=user_id,
            device_fingerprint=device_id
        ).first()
        
        if device:
            device.reputation_score = 0
            device.is_trusted = False
            db.session.commit()
