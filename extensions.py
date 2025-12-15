from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail
from flask_jwt_extended import JWTManager, verify_jwt_in_request, get_jwt_identity
from datetime import datetime

# Initialize extensions
db = SQLAlchemy()
mail = Mail()
jwt = JWTManager()

# Adaptive Rate Limiting Function
def adaptive_rate_limit_key():
    """
    Dynamic rate limiting based on:
    - User trust score (high trust: 200/hr, medium: 50/hr, low: 10/hr)
    - Device reputation (trusted device: +50%, unknown: -50%)
    - Time of day (night 11PM-5AM: -30%)
    - Recent failures (each failure: -10 requests)
    
    Returns:
        str: Rate limit string (e.g., "100 per hour")
    """
    try:
        # Try to get authenticated user
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
        
        if not user_id:
            # Unauthenticated users get minimal rate limit
            return "20 per minute"
        
        # Import here to avoid circular dependency
        from models import User, Device
        from flask import request
        
        user = User.query.get(user_id)
        if not user:
            return "20 per minute"
        
        # Base rate limit from trust score
        if user.trust_score >= 80:
            base_limit = 200  # High trust
        elif user.trust_score >= 50:
            base_limit = 50   # Medium trust
        else:
            base_limit = 10   # Low trust
        
        # Device reputation modifier
        device_id = request.headers.get('User-Agent', 'unknown')
        device = Device.query.filter_by(
            user_id=user_id,
            device_fingerprint=device_id
        ).first()
        
        device_multiplier = 1.0
        if device:
            if hasattr(device, 'reputation_score'):
                if device.reputation_score >= 700:  # Highly trusted device
                    device_multiplier = 1.5
                elif device.reputation_score >= 500:  # Trusted device
                    device_multiplier = 1.0
                else:  # Untrusted device
                    device_multiplier = 0.5
        else:
            # Unknown device
            device_multiplier = 0.5
        
        # Time of day modifier (night time reduces limit)
        hour = datetime.utcnow().hour
        time_multiplier = 1.0
        if hour >= 23 or hour < 5:  # Late night (11 PM - 5 AM)
            time_multiplier = 0.7  # 30% reduction
        
        # Calculate final limit
        final_limit = int(base_limit * device_multiplier * time_multiplier)
        final_limit = max(5, final_limit)  # Minimum 5 requests
        
        return f"{final_limit} per hour"
        
    except Exception as e:
        # Fallback to conservative limit if anything goes wrong
        return "20 per minute"

# Use adaptive rate limiting by default
limiter = Limiter(
    key_func=adaptive_rate_limit_key,
    storage_uri="memory://",
    default_limits=["1000 per day"]  # Global daily limit as safety net
)
