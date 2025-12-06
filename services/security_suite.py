from models import User, Transaction, AuditLog, db
from datetime import datetime
from sqlalchemy import func

class SecuritySuite:

    # --- 1. HONEY POT (Anti-Bot) ---
    @staticmethod
    def check_honeypot(data):
        """
        Checks hidden fields. If filled, it's a bot.
        The Frontend must send a field 'website_url' hidden via CSS.
        Real users won't see it, but dumb bots will autofill it.
        """
        if data.get('website_url'): 
            return True # Caught a bot!
        return False

    # --- 2. BEHAVIORAL BIOMETRICS (Bot Detection) ---
    @staticmethod
    def analyze_behavior(behavior_data):
        """
        Analyzes typing speed and mouse movements to detect automation.
        Expected input: { "avg_typing_speed_ms": 120, "mouse_path_variance": 0.5 }
        Returns: A risk score from 0.0 (Human) to 1.0 (Bot)
        """
        if not behavior_data: return 0.0 # No data provided, assume neutral
        
        risk = 0.0
        
        # Key Press Latency: Bots type instantly (0-20ms per key), Humans take >50ms
        typing_speed = behavior_data.get('avg_typing_speed_ms', 100)
        if typing_speed < 20:
            risk += 0.8 # Very suspicious
        elif typing_speed < 50:
            risk += 0.4 # Suspicious
            
        # Mouse Path: Humans move in curves, Bots move in straight lines (Low variance)
        # Variance 0 = Perfect straight line (Bot)
        mouse_var = behavior_data.get('mouse_path_variance', 1.0)
        if mouse_var < 0.05:
            risk += 0.8
        elif mouse_var < 0.2:
            risk += 0.3
            
        return min(risk, 1.0)

    # --- 3. GRAPH-BASED LINK ANALYSIS (Fraud Rings) ---
    @staticmethod
    def find_linked_accounts(current_user_id, device_id, ip_address):
        """
        Finds other users sharing the same Device or IP.
        This mimics Graph Database logic using relational queries.
        Returns: List of linked User IDs.
        """
        links = set()
        
        # 1. Device Links: Who else used this specific device?
        if device_id and device_id != 'unknown_device':
            linked_by_device = db.session.query(Transaction.user_id).filter(
                Transaction.device_id == device_id,
                Transaction.user_id != current_user_id
            ).distinct().all()
            for u in linked_by_device:
                links.add(u[0])
        
        # 2. IP Links: Who else used this IP? (Risky if it's a residential IP)
        # Note: In production, filter out known public IPs (Coffee shops, Airports)
        if ip_address:
            linked_by_ip = db.session.query(Transaction.user_id).filter(
                Transaction.ip_address == ip_address,
                Transaction.user_id != current_user_id
            ).distinct().all()
            for u in linked_by_ip:
                links.add(u[0])
        
        return list(links)

    # --- 4. TRUST SCORE CALCULATOR ---
    @staticmethod
    def update_trust_score(user):
        """
        Recalculates User Trust Score (0-100) based on security posture.
        This runs after Login or successful Transactions.
        """
        score = 50 # Baseline Score
        
        # A. Security Settings (Bonus)
        if user.is_2fa_enabled: score += 20
        if not user.is_breached: score += 10
        if user.phone_number: score += 5
        
        # B. Negative History (Penalty)
        if user.is_locked: score -= 40 # Locked users tank their score
        
        # C. Transaction History (Reward)
        # Good behavior over time increases trust
        successful_tx_count = Transaction.query.filter_by(user_id=user.id, status='SUCCESS').count()
        score += min(successful_tx_count, 15) # Cap bonus at 15 points
        
        # D. Recent Failures (Penalty)
        # Check last 5 transactions
        recent_fails = Transaction.query.filter_by(user_id=user.id, status='FAILED').order_by(Transaction.timestamp.desc()).limit(5).all()
        score -= (len(recent_fails) * 5)
        
        # Cap Score limits
        user.trust_score = max(0, min(100, score))
        db.session.commit()
        
        return user.trust_score

    # --- 5. AUDIT LOGGER (Compliance) ---
    @staticmethod
    def log_action(user_id, action, details, ip_address):
        """
        Creates an immutable record of an event.
        """
        try:
            new_log = AuditLog(
                user_id=user_id,
                action=action,
                details=details,
                ip_address=ip_address,
                timestamp=datetime.utcnow()
            )
            db.session.add(new_log)
            db.session.commit()
        except Exception as e:
            print(f"⚠️ Audit Log Failed: {e}") # Don't crash the app if logging fails