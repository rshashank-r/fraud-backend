"""
Enhanced Session Fingerprinting Service
Tracks detailed browser/device fingerprints to detect session hijacking
"""

from models import db
from datetime import datetime
import hashlib
import json

class DeviceFingerprint(db.Model):
    """Enhanced device fingerprint model"""
    __tablename__ = 'device_fingerprints'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    fingerprint_hash = db.Column(db.String(64), index=True)  # SHA-256
    browser_name = db.Column(db.String(50))
    browser_version = db.Column(db.String(20))
    os_name = db.Column(db.String(50))
    os_version = db.Column(db.String(20))
    timezone = db.Column(db.String(50))
    screen_resolution = db.Column(db.String(20))
    canvas_fingerprint = db.Column(db.String(64))  # Canvas fingerprint hash
    webgl_fingerprint = db.Column(db.String(64))   # WebGL fingerprint hash
    language = db.Column(db.String(10))
    platform = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime, default=datetime.utcnow)
    is_valid = db.Column(db.Boolean, default=True)
    usage_count = db.Column(db.Integer, default=0)

class SessionFingerprintService:
    """
    Advanced session fingerprinting to detect hijacking and identity spoofing.
    """
    
    @staticmethod
    def create_fingerprint(user_id, fingerprint_data):
        """
        Create or update device fingerprint.
        
        Args:
            user_id: str
            fingerprint_data: dict with keys:
                - browser_name, browser_version
                - os_name, os_version
                - timezone, screen_resolution
                - canvas_fingerprint, webgl_fingerprint
                - language, platform
                
        Returns:
            DeviceFingerprint object
        """
        # Calculate hash from fingerprint data
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        fingerprint_hash = hashlib.sha256(fingerprint_str.encode()).hexdigest()
        
        # Check if fingerprint already exists
        existing = DeviceFingerprint.query.filter_by(
            user_id=user_id,
            fingerprint_hash=fingerprint_hash
        ).first()
        
        if existing:
            # Update last used
            existing.last_used = datetime.utcnow()
            existing.usage_count += 1
            db.session.commit()
            return existing
        
        # Create new fingerprint
        fingerprint = DeviceFingerprint(
            user_id=user_id,
            fingerprint_hash=fingerprint_hash,
            browser_name=fingerprint_data.get('browser_name'),
            browser_version=fingerprint_data.get('browser_version'),
            os_name=fingerprint_data.get('os_name'),
            os_version=fingerprint_data.get('os_version'),
            timezone=fingerprint_data.get('timezone'),
            screen_resolution=fingerprint_data.get('screen_resolution'),
            canvas_fingerprint=fingerprint_data.get('canvas_fingerprint'),
            webgl_fingerprint=fingerprint_data.get('webgl_fingerprint'),
            language=fingerprint_data.get('language'),
            platform=fingerprint_data.get('platform'),
            usage_count=1
        )
        
        db.session.add(fingerprint)
        db.session.commit()
        
        return fingerprint
    
    @staticmethod
    def verify_fingerprint(user_id, current_fingerprint_data):
        """
        Verify if current session fingerprint matches any known fingerprints.
        Detects potential session hijacking.
        
        Args:
            user_id: str
            current_fingerprint_data: dict
            
        Returns:
            dict: {
                'is_valid': bool,
                'is_known_device': bool,
                'risk_score': float,
                'suspicious_factors': list
            }
        """
        fingerprint_str = json.dumps(current_fingerprint_data, sort_keys=True)
        fingerprint_hash = hashlib.sha256(fingerprint_str.encode()).hexdigest()
        
        # Check if exact match exists
        exact_match = DeviceFingerprint.query.filter_by(
            user_id=user_id,
            fingerprint_hash=fingerprint_hash
        ).first()
        
        if exact_match:
            return {
                'is_valid': True,
                'is_known_device': True,
                'risk_score': 0.0,
                'suspicious_factors': []
            }
        
        # Check for partial matches (browser/OS changed but other factors same)
        all_user_fingerprints = DeviceFingerprint.query.filter_by(user_id=user_id).all()
        
        suspicious_factors = []
        risk_score = 0.3  # Unknown device base risk
        
        if not all_user_fingerprints:
            # First time login from any device
            return {
                'is_valid': True,
                'is_known_device': False,
                'risk_score': 0.2,
                'suspicious_factors': ['First device enrollment']
            }
        
        # Analyze differences
        most_recent = max(all_user_fingerprints, key=lambda x: x.last_used)
        
        # Check timezone consistency
        if current_fingerprint_data.get('timezone') != most_recent.timezone:
            risk_score += 0.3
            suspicious_factors.append(f"Timezone changed: {most_recent.timezone} → {current_fingerprint_data.get('timezone')}")
        
        # Check screen resolution (unusual to change frequently)
        if current_fingerprint_data.get('screen_resolution') != most_recent.screen_resolution:
            risk_score += 0.2
            suspicious_factors.append("Screen resolution mismatch")
        
        # Check browser/OS combination
        if current_fingerprint_data.get('browser_name') != most_recent.browser_name:
            risk_score += 0.1
            suspicious_factors.append("Different browser")
        
        # Canvas fingerprint should be very stable
        if current_fingerprint_data.get('canvas_fingerprint') and \
           current_fingerprint_data.get('canvas_fingerprint') != most_recent.canvas_fingerprint:
            risk_score += 0.4
            suspicious_factors.append("Canvas fingerprint mismatch (possible spoofing)")
        
        risk_score = min(1.0, risk_score)
        
        return {
            'is_valid': risk_score < 0.7,  # Threshold for session hijacking suspicion
            'is_known_device': False,
            'risk_score': risk_score,
            'suspicious_factors': suspicious_factors
        }
    
    @staticmethod
    def invalidate_fingerprint(fingerprint_id):
        """Mark a fingerprint as invalid (e.g., after detected hijacking)"""
        fingerprint = DeviceFingerprint.query.get(fingerprint_id)
        
        if fingerprint:
            fingerprint.is_valid = False
            db.session.commit()
            return True
        
        return False
