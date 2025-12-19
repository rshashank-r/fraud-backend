"""
Server-Side CAPTCHA Challenge Service
Generates custom challenges that require human interaction to solve
"""
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from extensions import db
from models import CaptchaChallenge

class CaptchaService:
    
    @staticmethod
    def generate_challenge():
        """
        Generate a CAPTCHA challenge with server-side verification
        Returns challenge data that frontend must solve
        """
        # Generate unique challenge ID
        challenge_id = secrets.token_hex(16)
        
        # Generate timestamp
        timestamp = str(int(time.time()))
        
        # Generate random math problem (simple but requires computation)
        num1 = secrets.randbelow(50) + 1
        num2 = secrets.randbelow(50) + 1
        
        # Store expected answer (hashed)
        answer = num1 + num2
        answer_hash = hashlib.sha256(f"{answer}:{challenge_id}".encode()).hexdigest()
        
        # Store challenge in database with 5-minute expiry
        challenge = CaptchaChallenge(
            challenge_id=challenge_id,
            answer_hash=answer_hash,
            timestamp=timestamp,
            expiry=datetime.utcnow() + timedelta(minutes=5),
            is_used=False
        )
        
        db.session.add(challenge)
        db.session.commit()
        
        return {
            "challenge_id": challenge_id,
            "question": f"What is {num1} + {num2}?",
            "timestamp": timestamp
        }
    
    @staticmethod
    def verify_challenge(challenge_id, user_answer):
        """
        Verify CAPTCHA challenge answer
        Returns True if valid, False otherwise
        """
        if not challenge_id or user_answer is None:
            return False
        
        # Find challenge in database
        challenge = CaptchaChallenge.query.filter_by(
            challenge_id=challenge_id,
            is_used=False
        ).first()
        
        if not challenge:
            return False
        
        # Check if expired
        if challenge.expiry < datetime.utcnow():
            db.session.delete(challenge)
            db.session.commit()
            return False
        
        # Verify answer hash
        try:
            answer_str = str(int(user_answer))
            computed_hash = hashlib.sha256(f"{answer_str}:{challenge_id}".encode()).hexdigest()
            
            if computed_hash == challenge.answer_hash:
                # Mark as used (one-time use)
                challenge.is_used = True
                db.session.commit()
                return True
        except (ValueError, TypeError):
            pass
        
        return False
    
    @staticmethod
    def cleanup_expired():
        """
        Remove expired challenges (call periodically)
        """
        expired = CaptchaChallenge.query.filter(
            CaptchaChallenge.expiry < datetime.utcnow()
        ).all()
        
        for challenge in expired:
            db.session.delete(challenge)
        
        db.session.commit()
        return len(expired)
