"""
Risk-Based Authentication Service
Implements adaptive authentication strength based on real-time risk assessment.
"""

from datetime import datetime, timedelta
from models import User, Device, Transaction, db
from services.geo_service import GeoService
from sqlalchemy import func
import random

def is_mobile_device(login_data):
    """Helper to detect if login is from mobile device"""
    device_id = login_data.get('device_id', '')
    os_name = login_data.get('os_name', '')
    
    mobile_indicators = ['android', 'iphone', 'ipad', 'mobile', 'ios']
    return any(indicator in device_id.lower() or indicator in os_name.lower() 
               for indicator in mobile_indicators)

class RiskAuthenticator:
    """
    Dynamic authentication system that adjusts security requirements
    based on contextual risk factors.
    
    Risk Levels:
    - 0.0 - 0.2: ALLOW (no friction)
    - 0.2 - 0.5: OTP (email verification)
    - 0.5 - 0.8: OTP_DEVICE (email + device verification)
    - 0.8 - 1.0: FREEZE (account locked)
    """
    
    # Configurable thresholds
    ALLOW_THRESHOLD = 0.2
    OTP_THRESHOLD = 0.5
    DEVICE_THRESHOLD = 0.8
    
    @staticmethod
    def calculate_login_risk(user, login_data):
        """
        Calculate comprehensive risk score for login attempt.
        
        Args:
            user: User model instance
            login_data: dict with keys:
                - ip_address: str
                - device_id: str (fingerprint)
                - location_lat: float
                - location_lon: float
                - timestamp: datetime (optional)
        
        Returns:
            tuple: (risk_score: float, risk_factors: list)
        """
        risk_score = 0.0
        risk_factors = []
        
        ip_address = login_data.get('ip_address')
        device_id = login_data.get('device_id')
        current_time = login_data.get('timestamp', datetime.utcnow())
        curr_lat = login_data.get('location_lat', 0.0)
        curr_lon = login_data.get('location_lon', 0.0)
        
        # --- 0. CRITICAL SECURITY CHECKS (REFINED DETECTION) ---
        # Only using the most reliable detection methods to avoid false positives
        
        suspicious_signals = []
        
        # A. Developer Tools Detection (explicit detection - most reliable)
        developer_tools_enabled = login_data.get('developer_tools_enabled', False)
        if developer_tools_enabled:
            suspicious_signals.append("Developer tools explicitly enabled")
        
        # B. Emulator Detection
        is_emulator = login_data.get('is_emulator', False)
        if is_emulator:
            suspicious_signals.append("Emulator/automated browser detected")
        
        # C. Rooted/Jailbroken Device Detection
        is_rooted = login_data.get('is_rooted', False)
        if is_rooted:
            suspicious_signals.append("Rooted/jailbroken device detected")
        
        # BLOCK if ANY critical security threat is detected
        if len(suspicious_signals) > 0:
            risk_score = 1.0
            risk_factors = suspicious_signals
            return risk_score, risk_factors
        
        # --- 1. NEW DEVICE CHECK ---
        if device_id:
            known_device = Device.query.filter_by(
                user_id=user.id, 
                device_fingerprint=device_id
            ).first()
            
            if not known_device:
                risk_score += 0.3
                risk_factors.append("New device")
            elif not known_device.is_trusted:
                risk_score += 0.15
                risk_factors.append("Untrusted device")
        
        # --- 2. UNUSUAL LOCATION ---
        if ip_address and ip_address != user.home_ip:
            geo_details = GeoService.get_ip_details(ip_address)
            
            if geo_details and user.home_ip:
                home_geo = GeoService.get_ip_details(user.home_ip)
                
                if home_geo and geo_details.get('country') != home_geo.get('country'):
                    risk_score += 0.4
                    risk_factors.append(f"Foreign country login ({geo_details.get('country')})")
                elif geo_details.get('city') != home_geo.get('city'):
                    risk_score += 0.2
                    risk_factors.append("Different city")
            
            # VPN/Proxy detection (Allowed but high risk)
            if geo_details and geo_details.get('is_vpn'):
                risk_score += 0.45
                risk_factors.append("VPN or proxy detected - High risk")
        
        # --- 3. IMPOSSIBLE TRAVEL ---
        if user.last_login_at and curr_lat != 0.0 and curr_lon != 0.0:
            last_tx = Transaction.query.filter_by(user_id=user.id)\
                .order_by(Transaction.timestamp.desc()).first()
            
            if last_tx and last_tx.location_lat and last_tx.location_lon:
                from services.fraud_engine import FraudEngine
                distance = FraudEngine.calculate_distance(
                    last_tx.location_lat, last_tx.location_lon,
                    curr_lat, curr_lon
                )
                
                if distance:
                    time_diff_hours = (current_time - user.last_login_at).total_seconds() / 3600
                    if time_diff_hours > 0:
                        speed_kmh = distance / time_diff_hours
                        if speed_kmh > 800:  # Impossible travel speed
                            risk_score += 0.6
                            risk_factors.append(f"Impossible travel ({int(speed_kmh)} km/h)")
                        elif speed_kmh > 500:
                            risk_score += 0.3
                            risk_factors.append(f"Suspicious travel speed ({int(speed_kmh)} km/h)")
        
        # --- 4. TIME OF DAY RISK ---
        hour = current_time.hour
        if hour >= 23 or hour < 5:  # Late night (11 PM - 5 AM)
            risk_score += 0.15
            risk_factors.append("Late night login")
        
        # --- 5. RECENT FAILED LOGIN ATTEMPTS ---
        from models import AuditLog
        one_hour_ago = current_time - timedelta(hours=1)
        
        failed_attempts = AuditLog.query.filter(
            AuditLog.user_id == user.id,
            AuditLog.action == 'LOGIN_FAILED',
            AuditLog.timestamp >= one_hour_ago
        ).count()
        
        if failed_attempts >= 5:
            risk_score += 0.5
            risk_factors.append(f"Multiple failed attempts ({failed_attempts})")
        elif failed_attempts >= 3:
            risk_score += 0.25
            risk_factors.append(f"Recent failed attempts ({failed_attempts})")
        
        # --- 6. ACCOUNT AGE & TRUST SCORE ---
        account_age_days = (current_time - user.created_at).days
        
        if account_age_days < 1:  # Brand new account
            risk_score += 0.2
            risk_factors.append("New account (< 24 hours)")
        
        if user.trust_score < 30:  # Low trust user
            risk_score += 0.3
            risk_factors.append(f"Low trust score ({user.trust_score})")
        elif user.trust_score >= 80:  # High trust bonus
            risk_score -= 0.15
            risk_factors.append(f"High trust score ({user.trust_score})")
        
        # --- 7. IP REPUTATION (if implemented) ---
        try:
            from models import IPReputation
            ip_rep = IPReputation.query.filter_by(ip_address=ip_address).first()
            
            if ip_rep:
                if ip_rep.is_blacklisted:
                    risk_score += 0.8
                    risk_factors.append("Blacklisted IP")
                elif ip_rep.reputation_score < 200:
                    risk_score += 0.4
                    risk_factors.append(f"Low IP reputation ({ip_rep.reputation_score})")
        except:
            pass  # IPReputation table may not exist yet
        
        # --- 8. LOCKED ACCOUNT CHECK ---
        if user.is_locked:
            risk_score = 1.0
            risk_factors = ["Account is locked"]
        
        # Cap the risk score at 1.0
        risk_score = min(risk_score, 1.0)
        
        # Add small entropy for variance
        if risk_score > 0.1:
            risk_score += random.uniform(0.01, 0.03)
            risk_score = min(risk_score, 1.0)
        
        return risk_score, risk_factors
    
    @staticmethod
    def get_auth_requirement(risk_score):
        """
        Determine authentication requirement based on risk score.
        
        Args:
            risk_score: float (0.0 - 1.0)
        
        Returns:
            str: 'ALLOW', 'OTP', 'OTP_DEVICE', or 'FREEZE'
        """
        if risk_score >= RiskAuthenticator.DEVICE_THRESHOLD:
            return 'FREEZE'
        elif risk_score >= RiskAuthenticator.OTP_THRESHOLD:
            return 'OTP_DEVICE'
        elif risk_score >= RiskAuthenticator.ALLOW_THRESHOLD:
            return 'OTP'
        else:
            return 'ALLOW'
    
    @staticmethod
    def create_auth_challenge(user, requirement, app_instance):
        """
        Create appropriate authentication challenge.
        
        Args:
            user: User model instance
            requirement: str ('OTP', 'OTP_DEVICE', 'FREEZE')
            app_instance: Flask app instance for email sending
        
        Returns:
            dict: Challenge details
        """
        if requirement == 'FREEZE':
            # Lock the account
            user.is_locked = True
            db.session.commit()
            
            # Log security event
            from services.security_suite import SecuritySuite
            SecuritySuite.log_action(
                user.id,
                'ACCOUNT_FREEZE_RISK',
                'Account frozen due to high login risk',
                'system'
            )
            
            return {
                'type': 'FREEZE',
                'message': 'Account has been temporarily frozen due to suspicious activity. Please contact support.',
                'requires_action': False
            }
        
        elif requirement == 'OTP_DEVICE':
            # Generate OTP
            from services.email_service import generate_otp, send_email_otp
            otp = generate_otp()
            user.email_otp = otp
            user.email_otp_expiry = datetime.utcnow() + timedelta(minutes=5)
            db.session.commit()
            
            # Send OTP email
            from threading import Thread
            Thread(target=send_email_otp, args=(
                app_instance, 
                user.email, 
                otp, 
                "LOGIN",
                ""
            )).start()
            
            return {
                'type': 'OTP_DEVICE',
                'message': 'Email OTP sent. Device verification required.',
                'requires_action': True,
                'challenge_id': user.id
            }
        
        elif requirement == 'OTP':
            # Generate OTP
            from services.email_service import generate_otp, send_email_otp
            otp = generate_otp()
            user.email_otp = otp
            user.email_otp_expiry = datetime.utcnow() + timedelta(minutes=5)
            db.session.commit()
            
            # Send OTP email
            from threading import Thread
            Thread(target=send_email_otp, args=(
                app_instance, 
                user.email, 
                otp, 
                "LOGIN",
                ""
            )).start()
            
            return {
                'type': 'OTP',
                'message': 'Email OTP sent for verification.',
                'requires_action': True,
                'challenge_id': user.id
            }
        
        else:  # ALLOW
            return {
                'type': 'ALLOW',
                'message': 'Login approved',
                'requires_action': False
            }
    
    @staticmethod
    def verify_challenge(user, challenge_type, challenge_data):
        """
        Verify authentication challenge response.
        
        Args:
            user: User model instance
            challenge_type: str ('OTP', 'OTP_DEVICE')
            challenge_data: dict with verification data
        
        Returns:
            tuple: (success: bool, message: str)
        """
        if challenge_type == 'OTP' or challenge_type == 'OTP_DEVICE':
            provided_otp = challenge_data.get('otp')
            
            if not user.email_otp:
                return False, "No OTP found. Please request a new one."
            
            if user.email_otp_expiry < datetime.utcnow():
                return False, "OTP has expired. Please request a new one."
            
            if user.email_otp != provided_otp:
                return False, "Invalid OTP code."
            
            # OTP is valid, clear it
            user.email_otp = None
            user.email_otp_expiry = None
            
            # If OTP_DEVICE, also verify device fingerprint
            if challenge_type == 'OTP_DEVICE':
                device_id = challenge_data.get('device_id')
                
                if not device_id:
                    return False, "Device verification required."
                
                # Register this device as trusted
                existing_device = Device.query.filter_by(
                    user_id=user.id,
                    device_fingerprint=device_id
                ).first()
                
                if not existing_device:
                    new_device = Device(
                        user_id=user.id,
                        device_fingerprint=device_id,
                        is_trusted=True,
                        device_name=challenge_data.get('device_name', 'Unknown Device')
                    )
                    db.session.add(new_device)
                else:
                    existing_device.is_trusted = True
                    existing_device.last_used_at = datetime.utcnow()
            
            db.session.commit()
            return True, "Authentication successful"
        
        return False, "Invalid challenge type"
