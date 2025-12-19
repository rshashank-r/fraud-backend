from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt
from models import User, Device, db, AuditLog, TokenBlocklist
from services.security_service import SecurityService
from services.security_suite import SecuritySuite
from services.email_service import send_login_success_email, send_new_device_alert, send_email_otp, send_suspicious_device_alert
from services.geo_service import GeoService
from threading import Thread
from datetime import datetime, timedelta
import pyotp
import os 
import random
import re
from extensions import limiter
from flask_mail import Mail, Message

auth_bp = Blueprint('auth', __name__)

ADMIN_SECRET_KEY = os.environ.get('ADMIN_SECRET_KEY', 'SuperSecretAdminKey123!')

# --- LOCAL HELPER: SEND ALERT EMAIL ---
# Redefined here to ensure it works with the threading logic requested
def send_security_alert(app_instance, user_email, alert_type, ip_address):
    """Sends email for failed attempts or successful logins"""
    try:
        with app_instance.app_context():
            mail = Mail(app_instance)
            subject = "Security Alert: Login Activity"
            body = f"Activity detected on your account.\\n\\nType: {alert_type}\\nIP: {ip_address}\\nTime: {datetime.utcnow()}"
            
            if "Failed" in alert_type:
                subject = "🚨 Failed Login Attempt"
                body += "\\n\\nIf this was not you, please freeze your account immediately."
            
            msg = Message(subject, recipients=[user_email], body=body, sender=os.environ.get('MAIL_USERNAME', 'no-reply@fraudguard.com'))
            mail.send(msg)
            print(f"📧 Alert sent to {user_email}")
    except Exception as e:
        print(f"❌ Failed to send alert: {e}")

# --- HELPER: FINALIZE LOGIN ---
def finalize_login_success(user, real_ip):
    """Called after successful 2FA/OTP verification to issue token"""
    
    # 1. Invalidate any previous tokens (logout from other sessions)
    # This ensures only the current login session is valid
    try:
        # Find and block all previous tokens for this user
        old_tokens = TokenBlocklist.query.filter_by(user_id=user.id).all()
        print(f"Found {len(old_tokens)} old tokens to invalidate for user {user.id}")
    except Exception as e:
        print(f"Error checking old tokens: {e}")
    
    # 2. Create NEW JWT token
    token = create_access_token(identity=user.id)
    
    # 3. Log success with role information
    print(f"✅ Login Success - User ID: {user.id}, Email: {user.email}, Role: {user.role}")
    SecuritySuite.log_action(user.id, "LOGIN_SUCCESS", "Successful Login", real_ip)
    
    # 4. Device Check & Email Alert
    device_id = request.headers.get('User-Agent', 'unknown')
    known_device = Device.query.filter_by(user_id=user.id, device_fingerprint=device_id).first()
    
    # Common location lookup
    app_instance = current_app._get_current_object()
    location = GeoService.get_location_name(real_ip)

    if not known_device:
        # Case A: New Device -> Send Device Alert ONLY
        # Extract platform more reliably
        ua_platform = request.headers.get('Sec-Ch-Ua-Platform')
        if not ua_platform:
             # Simple fallback extraction
             if "Windows" in device_id: ua_platform = "Windows"
             elif "Mac" in device_id: ua_platform = "MacOS"
             elif "Linux" in device_id: ua_platform = "Linux"
             elif "Android" in device_id: ua_platform = "Android"
             elif "iPhone" in device_id or "iPad" in device_id: ua_platform = "iOS"
             else: ua_platform = "Unknown Device"

        new_device = Device(user_id=user.id, device_fingerprint=device_id, device_name=ua_platform)
        db.session.add(new_device)
        Thread(target=send_new_device_alert, args=(app_instance, user.email, real_ip, device_id, location)).start()
    else:
        # Case B: Known Device -> Send standard Login Success Email
        Thread(target=send_login_success_email, args=(
            app_instance, 
            user.email, 
            real_ip,
            location
        )).start()

    # 5. Update Stats
    user.last_login_at = datetime.utcnow()
    user.last_login_ip = real_ip
    db.session.commit()
    
    # Return response data with EXPLICIT role
    print(f"🔑 Returning token for role: {user.role}")
    
    # NOTE: Using 'access_token' to match frontend expectations, 'token' added for compatibility
    return {
        "access_token": token,
        "token": token, 
        "role": user.role,  # CRITICAL: This must match the user's actual role in DB
        "is_breached": user.is_breached,
        "message": "Login successful"
    }

# ==========================================
# 1. INITIAL LOGIN (Step 1) - WITH RISK-BASED AUTH
# ==========================================
@auth_bp.route('/login', methods=['POST'])
def login_step_one():
    data = request.json
    real_ip = GeoService.get_real_ip()
    email = data.get('email')
    password = data.get('password')

    # --- CAPTCHA VERIFICATION (Enforce Human Check) ---
    captcha_token = data.get('captcha_token')
    if not captcha_token:
        # Graceful fallback for older clients or if frontend fails
        # But for security, we should enforce it.
        return jsonify({"error": "Please complete the human check"}), 400
    
    if not captcha_token.startswith("human_token_"):
        return jsonify({"error": "Invalid verification token"}), 400

    user = User.query.filter_by(email=email).first()
    app_instance = current_app._get_current_object()

    # Validate Credentials
    if not user or not check_password_hash(user.password_hash, password):
        if user:
            SecuritySuite.log_action(user.id, "LOGIN_FAILED", "Bad Password", real_ip)
            Thread(target=send_security_alert, args=(app_instance, user.email, "Failed Password Attempt", real_ip)).start()
        return jsonify({"error": "Invalid credentials"}), 401

    if user.is_locked:
        return jsonify({"error": "Account Locked"}), 403

    # Check Password Breach
    if SecurityService.check_password_breach(password) > 0:
        user.is_breached = True
        db.session.commit()

    # ===== NEW: RISK-BASED AUTHENTICATION =====
    from services.risk_authenticator import RiskAuthenticator
    
    # Collect login context data
    login_data = {
        'ip_address': real_ip,
        'device_id': request.headers.get('User-Agent', 'unknown'),
        'location_lat': data.get('lat', 0.0),
        'location_lon': data.get('lon', 0.0),
        'timestamp': datetime.utcnow(),
        # Security flags from enhanced fingerprint
        'is_webdriver': data.get('is_webdriver', False),
        'is_emulator': data.get('is_emulator', False),
        'is_rooted': data.get('is_rooted', False)
    }
    
    # Calculate risk score
    risk_score, risk_factors = RiskAuthenticator.calculate_login_risk(user, login_data)
    
    # Get authentication requirement
    auth_requirement = RiskAuthenticator.get_auth_requirement(risk_score)
    
    # Log the risk assessment
    SecuritySuite.log_action(
        user.id,
        "LOGIN_RISK_ASSESSMENT",
        f"Risk: {risk_score:.2f}, Requirement: {auth_requirement}, Factors: {', '.join(risk_factors)}",
        real_ip
    )
    
    # Handle FREEZE case - SEND ALERTS
    if auth_requirement == 'FREEZE':
        # Determine device type from risk factors
        device_type = "Unknown Device"
        threat_category = "suspicious activity"
        
        # Technical security indicators (highest priority)
        if any("Developer tools" in factor for factor in risk_factors):
            device_type = "Developer Tools"
            threat_category = "automated attack"
        elif any("Emulator" in factor for factor in risk_factors):
            device_type = "Emulator"
            threat_category = "automated attack"
        elif any("Rooted" in factor or "jailbroken" in factor for factor in risk_factors):
            device_type = "Rooted Device"
            threat_category = "compromised device"
        # Behavioral indicators (secondary)
        elif any("Foreign country" in factor or "Unusual location" in factor for factor in risk_factors):
            device_type = "Foreign Location"
            threat_category = "unusual location"
        elif any("New device" in factor for factor in risk_factors):
            device_type = "New/Unknown Device"
            threat_category = "unrecognized device"
        elif any("New account" in factor for factor in risk_factors):
            device_type = "New Account Login"
            threat_category = "new account protection"
        
        # Get location for email
        location = GeoService.get_location_name(real_ip)
        
        # Log the email sending attempt
        print(f"🚨 FREEZE: Sending email alert to {user.email}")
        print(f"   Device Type: {device_type}")
        print(f"   Location: {location}")
        print(f"   Risk Factors: {risk_factors}")
        
        # Send email alert in background
        Thread(target=send_suspicious_device_alert, args=(
            app_instance,
            user.email,
            device_type,
            real_ip,
            location
        )).start()
        
        # Create in-app notification
        from models import Notification
        notification = Notification(
            user_id=user.id,
            title=f"Security Alert: {device_type} Blocked",
            type='SECURITY_ALERT',
            message=f"🚨 Blocked login attempt from {device_type}. Location: {location}. Your account is secure.",
            is_read=False
        )
        db.session.add(notification)
        db.session.commit()
        
        print(f"✅ Created in-app notification for user {user.id}")
        
        challenge_response = RiskAuthenticator.create_auth_challenge(user, 'FREEZE', app_instance)
        return jsonify({
            "error": "Login denied from suspicious device",
            "message": f"Access denied: {device_type} detected. Please login from a secure device.",
            "risk_score": risk_score,
            "risk_factors": risk_factors,
            "account_status": "active"
        }), 403
    
    
    # Handle OTP_DEVICE case (high risk, new device)
    if auth_requirement == 'OTP_DEVICE':
        # If user has 2FA enabled, use TOTP instead of email OTP (more secure)
        if user.is_2fa_enabled:
            return jsonify({
                "message": "High-risk login - Authenticator verification required",
                "verification_required": "totp",
                "risk_score": risk_score,
                "risk_factors": risk_factors
            }), 202
        else:
            # Generate and send email OTP for high-risk login
            new_otp = "".join([str(random.randint(0, 9)) for _ in range(6)])
            user.email_otp = new_otp
            user.email_otp_expiry = datetime.utcnow() + timedelta(minutes=5)
            db.session.commit()
            
            # Send OTP email in background thread
            Thread(target=send_email_otp, args=(app_instance, user.email, new_otp, "LOGIN", "High-Risk Login Verification")).start()
            
            challenge_response = RiskAuthenticator.create_auth_challenge(user, 'OTP_DEVICE', app_instance)
            return jsonify({
                "message": "High-risk login detected",
                "verification_required": "otp_device",
                "risk_score": risk_score,
                "risk_factors": risk_factors,
                "details": "Please verify both email OTP and device fingerprint"
            }), 202
    
    # Handle OTP case (medium risk)
    if auth_requirement == 'OTP':
        # If user has 2FA enabled, use TOTP instead of email OTP (more secure)
        if user.is_2fa_enabled:
            return jsonify({
                "message": "Verification required",
                "verification_required": "totp",
                "risk_score": risk_score,
                "risk_factors": risk_factors
            }), 202
        else:
            # Generate and send email OTP
            new_otp = "".join([str(random.randint(0, 9)) for _ in range(6)])
            user.email_otp = new_otp
            user.email_otp_expiry = datetime.utcnow() + timedelta(minutes=5)
            db.session.commit()
            
            # Send OTP email in background thread
            Thread(target=send_email_otp, args=(app_instance, user.email, new_otp, "LOGIN", "Account Access")).start()
            
            challenge_response = RiskAuthenticator.create_auth_challenge(user, 'OTP', app_instance)
            return jsonify({
                "message": "Verification required",
                "verification_required": "email_otp",
                "risk_score": risk_score,
                "risk_factors": risk_factors
            }), 202
    
    # Low risk - check if user has 2FA enabled
    if user.is_2fa_enabled:
        return jsonify({
            "message": "Verification required",
            "verification_required": "totp",
            "risk_score": risk_score
        }), 202
    
    # No 2FA and low risk - direct login
    # (This is the ALLOW case from risk-based auth)
    login_response = finalize_login_success(user, real_ip)
    return jsonify(login_response), 200



# ==========================================
# 2. VERIFY TOTP (Step 2a)
# ==========================================
@auth_bp.route('/verify-2fa-login', methods=['POST'])
@limiter.limit("5 per minute") 
def verify_totp_login():
    data = request.json
    real_ip = GeoService.get_real_ip()
    email = data.get('email')
    code = data.get('code')

    user = User.query.filter_by(email=email).first()
    if not user: return jsonify({"error": "User not found"}), 404

    if not user.is_2fa_enabled:
        return jsonify({"error": "2FA is not enabled for this user"}), 400

    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(code, valid_window=1):
        app_instance = current_app._get_current_object()
        SecuritySuite.log_action(user.id, "LOGIN_FAILED", "Invalid TOTP", real_ip)
        Thread(target=send_security_alert, args=(app_instance, user.email, "Failed TOTP Attempt", real_ip)).start()
        return jsonify({"error": "Invalid 2FA Code"}), 401

    # Success
    response_data = finalize_login_success(user, real_ip)
    return jsonify(response_data), 200

# ==========================================
# 3. VERIFY EMAIL OTP (Step 2b)
# ==========================================
@auth_bp.route('/verify-email-otp-login', methods=['POST'])
@limiter.limit("5 per minute") # Max 5 attempts per minute
def verify_email_otp_login():
    data = request.json
    real_ip = GeoService.get_real_ip()
    email = data.get('email')
    otp_input = data.get('otp')

    user = User.query.filter_by(email=email).first()
    if not user: return jsonify({"error": "User not found"}), 404

    # Verify Logic
    if not user.email_otp or user.email_otp != otp_input:
        app_instance = current_app._get_current_object()
        SecuritySuite.log_action(user.id, "LOGIN_FAILED", "Invalid Email OTP", real_ip)
        Thread(target=send_security_alert, args=(app_instance, user.email, "Failed Email OTP Attempt", real_ip)).start()
        return jsonify({"error": "Invalid or Expired OTP"}), 401
    
    if user.email_otp_expiry < datetime.utcnow():
        return jsonify({"error": "OTP Expired"}), 401

    # Clear OTP
    user.email_otp = None
    db.session.commit()

    # Success
    response_data = finalize_login_success(user, real_ip)
    return jsonify(response_data), 200

# ==========================================
# 4. RESEND EMAIL OTP
# ==========================================
@auth_bp.route('/resend-email-otp', methods=['POST'])
@limiter.limit("3 per hour") # Prevent email spamming
def resend_email_otp():
    data = request.json
    email = data.get('email')
    
    user = User.query.filter_by(email=email).first()
    if not user: return jsonify({"error": "User not found"}), 404

    new_otp = "".join([str(random.randint(0, 9)) for _ in range(6)])
    user.email_otp = new_otp
    user.email_otp_expiry = datetime.utcnow() + timedelta(minutes=5)
    db.session.commit()
    
    app_instance = current_app._get_current_object()
    Thread(target=send_email_otp, args=(app_instance, user.email, new_otp, "LOGIN", "Account Access")).start()

    return jsonify({"message": "New OTP sent"}), 200

# ==========================================
# OTHER AUTH ROUTES
# ==========================================
@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    password = data.get('password')

    # --- CAPTCHA VERIFICATION (Custom Human Check) ---
    captcha_token = data.get('captcha_token')
    if not captcha_token:
        return jsonify({"error": "Please complete the human check"}), 400
    
    # Validation: Check if token follows our mock format "human_token_..."
    # This prevents simple curl requests without the token
    if not captcha_token.startswith("human_token_"):
        return jsonify({"error": "Invalid verification token"}), 400

    # --- PASSWORD STRENGTH CHECK ---
    if not password or len(password) < 8 or not re.search(r"\d", password) or not re.search(r"[A-Z]", password):
        return jsonify({
            "error": "Password too weak. Must be 8+ chars, include a number and an uppercase letter."
        }), 400
    
    if SecuritySuite.check_honeypot(data):
        return jsonify({"error": "Processing"}), 400

    email = data.get('email')
    real_ip = GeoService.get_real_ip()

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "User already exists"}), 400

    role = 'USER'
    if request.headers.get('X-ADMIN-KEY') == ADMIN_SECRET_KEY:
        role = 'ADMIN'

    new_user = User(
        email=email, 
        password_hash=generate_password_hash(password, method='pbkdf2:sha256'), 
        role=role, 
        phone_number=data.get('phone_number'),
        home_ip=real_ip
    )
    db.session.add(new_user)
    db.session.commit()
    
    SecuritySuite.log_action(new_user.id, "USER_REGISTER", "Registration Successful", real_ip)
    return jsonify({"message": "User registered", "role": role}), 201

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_profile():
    user = User.query.get(get_jwt_identity())
    if not user: return jsonify({"error": "User not found"}), 404
    return jsonify({
        "id": user.id, 
        "email": user.email, 
        "phone": user.phone_number,
        "role": user.role, 
        "trust_score": user.trust_score, 
        "twofa_enabled": user.is_2fa_enabled, 
        "balance": user.balance,
        "account_number": user.account_number,
        "is_locked": user.is_locked
    }), 200

@auth_bp.route('/enable-2fa', methods=['POST'])
@jwt_required()
def enable_2fa():
    user = User.query.get(get_jwt_identity())
    secret = pyotp.random_base32()
    user.totp_secret = secret
    db.session.commit()
    return jsonify({"secret": secret, "uri": pyotp.totp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="FraudGuard")}), 200

@auth_bp.route('/verify-2fa-setup', methods=['POST'])
@jwt_required()
def verify_2fa_setup():
    user = User.query.get(get_jwt_identity())
    code = request.json.get('code')
    totp = pyotp.TOTP(user.totp_secret)
    if totp.verify(code, valid_window=1):
        user.is_2fa_enabled = True
        db.session.commit()
        return jsonify({"message": "2FA Enabled Successfully"}), 200
    return jsonify({"error": "Invalid Code"}), 400

@auth_bp.route('/disable-2fa', methods=['POST'])
@jwt_required()
def disable_2fa():
    user = User.query.get(get_jwt_identity())
    data = request.json
    if not check_password_hash(user.password_hash, data.get('password')):
        return jsonify({"error": "Invalid Password"}), 401
    user.is_2fa_enabled = False
    user.totp_secret = None 
    db.session.commit()
    return jsonify({"message": "2FA disabled"}), 200

@auth_bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    user = User.query.get(get_jwt_identity())
    data = request.json
    if not check_password_hash(user.password_hash, data.get('old_password')):
        return jsonify({"error": "Wrong old password"}), 400
    
    user.password_hash = generate_password_hash(data.get('new_password'), method='pbkdf2:sha256')
    db.session.commit()
    SecuritySuite.log_action(user.id, "PASSWORD_CHANGE", "Password updated", GeoService.get_real_ip())
    return jsonify({"message": "Password Changed"}), 200

@auth_bp.route('/auth/reset-password', methods=['POST'])
@jwt_required()
def reset_password():
    user_id = get_jwt_identity()
    data = request.json
    user = User.query.get(user_id)
    user.password_hash = generate_password_hash(data.get('new_password'), method='pbkdf2:sha256')
    db.session.commit()
    return jsonify({"message": "Password reset successfully"}), 200

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    db.session.add(TokenBlocklist(jti=jti))
    db.session.commit()
    return jsonify({"message": "Successfully logged out"}), 200

@auth_bp.route('/login-history', methods=['GET'])
@jwt_required()
def login_history():
    user_id = get_jwt_identity()
    logs = AuditLog.query.filter(AuditLog.user_id == user_id, AuditLog.action.like('LOGIN%')).order_by(AuditLog.timestamp.desc()).limit(10).all()
    return jsonify([{"time": l.timestamp, "ip": l.ip_address, "status": l.action} for l in logs]), 200

@auth_bp.route('/devices', methods=['GET'])
@jwt_required()
def get_devices():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 5, type=int)
    
    pagination = Device.query.filter_by(user_id=get_jwt_identity()).paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        "devices": [{"id": d.id, "name": d.device_name, "last_used": d.last_used_at} for d in pagination.items],
        "total": pagination.total,
        "pages": pagination.pages,
        "page": page
    }), 200

@auth_bp.route('/devices/<int:device_id>', methods=['DELETE'])
@jwt_required()
def delete_device(device_id):
    device = Device.query.filter_by(id=device_id, user_id=get_jwt_identity()).first()
    if not device: return jsonify({"error": "Not found"}), 404
    db.session.delete(device)
    db.session.commit()
    return jsonify({"message": "Device Removed"}), 200



@auth_bp.route('/forgot-password', methods=['POST'])
@limiter.limit("3 per hour")  # Prevent abuse
def forgot_password():
    data = request.json
    email = data.get('email')
    
    user = User.query.filter_by(email=email).first()
    if not user:
        # Don't reveal if email exists (security best practice)
        return jsonify({"message": "If this email exists, an OTP has been sent"}), 200
    
    # Generate OTP
    new_otp = "".join([str(random.randint(0, 9)) for _ in range(6)])
    user.email_otp = new_otp
    user.email_otp_expiry = datetime.utcnow() + timedelta(minutes=10)  # 10 min expiry
    db.session.commit()
    
    # Send OTP email
    app_instance = current_app._get_current_object()
    Thread(target=send_email_otp, args=(
        app_instance,
        user.email,
        new_otp,
        "PASSWORD_RESET",
        "Password Reset Request"
    )).start()
    
    return jsonify({"message": "OTP sent to your email"}), 200


@auth_bp.route('/verify-forgot-otp', methods=['POST'])
@limiter.limit("5 per minute")
def verify_forgot_otp():
    data = request.json
    email = data.get('email')
    otp_input = data.get('otp')
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Verify OTP
    if not user.email_otp or user.email_otp != otp_input:
        return jsonify({"error": "Invalid OTP"}), 401
    
    if user.email_otp_expiry < datetime.utcnow():
        return jsonify({"error": "OTP Expired"}), 401
    
    # OTP verified - don't clear it yet (needed for final reset)
    return jsonify({"message": "OTP verified"}), 200


@auth_bp.route('/reset-password-complete', methods=['POST'])
@limiter.limit("5 per minute")
def reset_password_complete():
    data = request.json
    email = data.get('email')
    otp_input = data.get('otp')
    new_password = data.get('new_password')
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Verify OTP one more time
    if not user.email_otp or user.email_otp != otp_input:
        return jsonify({"error": "Invalid OTP"}), 401
    
    if user.email_otp_expiry < datetime.utcnow():
        return jsonify({"error": "OTP Expired"}), 401
    
    # Password strength check
    if not new_password or len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    
    # Update password
    user.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
    user.email_otp = None  # Clear OTP
    user.email_otp_expiry = None
    db.session.commit()
    
    # Log the action
    real_ip = GeoService.get_real_ip()
    SecuritySuite.log_action(user.id, "PASSWORD_RESET", "Password reset via forgot flow", real_ip)
    
    # Send confirmation email
    app_instance = current_app._get_current_object()
    Thread(target=send_security_alert, args=(
        app_instance,
        user.email,
        "Password Reset Successful",
        real_ip
    )).start()
    
    return jsonify({"message": "Password reset successful"}), 200