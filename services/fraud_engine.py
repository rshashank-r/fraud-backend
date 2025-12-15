import pandas as pd
import threading
import random
from datetime import datetime, timedelta
from math import radians, cos, sin, asin, sqrt
from models import Transaction, Device, FraudRule, IPWhitelist, User
from extensions import db
from sqlalchemy import func, desc

# Try importing XGBoost
try:
    import xgboost as xgb
except ImportError:
    xgb = None
    print("⚠️ XGBoost not installed. AI Fraud Engine will run in heuristic mode.")

class FraudEngine:
    _model = None
    _lock = threading.Lock()
    
    # ✅ CONFIGURABLE THRESHOLDS
    HIGH_VALUE_THRESHOLD = 50000  # Transactions above this require verification
    RAPID_TX_THRESHOLD = 3  # Number of transactions in short window to flag
    RAPID_TX_WINDOW_MINUTES = 10  # Window for detecting rapid transactions
    SAME_AMOUNT_THRESHOLD = 2  # Same amount to different receivers in window
    
    @classmethod
    def load_model(cls):
        """Loads the XGBoost model safely (singleton pattern)."""
        # Skip if already loaded
        if cls._model is not None:
            return
            
        if xgb:
            with cls._lock:
                # Double-check after acquiring lock
                if cls._model is None:
                    try:
                        cls._model = xgb.Booster()
                        cls._model.load_model('fraud_model_xgb.json')
                        print("    ✓ XGBoost model initialized")
                    except Exception as e:
                        print(f"    ⚠️ Model load failed: {e}")
                        print("    → Running in heuristic mode")
        else:
            print("    ℹ️ XGBoost not available, using heuristic mode")

    @staticmethod
    def calculate_distance(lat1, lon1, lat2, lon2):
        """Haversine distance in KM. Returns None if invalid coordinates."""
        if not lat1 or not lat2 or not lon1 or not lon2: return None
        if float(lat1) == 0.0 and float(lon1) == 0.0: return None
        if float(lat2) == 0.0 and float(lon2) == 0.0: return None
        
        try:
            lon1, lat1, lon2, lat2 = map(radians, [float(lon1), float(lat1), float(lon2), float(lat2)])
            dlon = lon2 - lon1 
            dlat = lat2 - lat1 
            a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
            c = 2 * asin(sqrt(a)) 
            return c * 6371
        except: return None

    @staticmethod
    def generate_explanation(features, risk_score, rules_triggered):
        """Generates a human-readable explanation."""
        if rules_triggered:
            return f"⛔ Rules Triggered: {', '.join(rules_triggered)}"
            
        reasons = []
        
        # High value transaction
        if features.get('is_high_value'):
            reasons.append(f"High Value Transaction (₹{features['amount']:,.0f})")
        
        # Rapid consecutive transactions
        if features.get('rapid_tx_count', 0) >= 3:
            reasons.append(f"Rapid Transactions ({features['rapid_tx_count']} in {FraudEngine.RAPID_TX_WINDOW_MINUTES}min)")
        
        # Same amount pattern
        if features.get('same_amount_count', 0) >= 2:
            reasons.append(f"Same Amount Pattern ({features['same_amount_count']} similar)")
        
        if features.get('is_new_user') and features.get('velocity_1h', 0) > 3:
            reasons.append(f"New User Velocity ({features['velocity_1h']} tx/hr)")
        elif features.get('velocity_1h', 0) > 10: 
            reasons.append(f"High Velocity ({features['velocity_1h']} tx/hr)")
            
        if features.get('amt_ratio', 0) > 8.0: 
            reasons.append(f"Amount Spike ({features['amt_ratio']:.1f}x avg)")
            
        if features.get('travel_speed', 0) > 500: 
            reasons.append(f"Impossible Travel ({int(features['travel_speed'])} km/h)")
            
        if features.get('ip_country_mismatch'):
            reasons.append("IP Location Mismatch")
        
        if features.get('no_location'):
            reasons.append("Location Not Provided")
            
        if not reasons and risk_score > 0.5: 
            reasons.append("AI Pattern Match")
            
        return " | ".join(reasons) if reasons else "Standard Check"

    @classmethod
    def analyze_transaction(cls, user, current_tx_data):
        cls.load_model()
        
        # --- 1. CONTEXT & DATA PREP ---
        curr_ip = current_tx_data.get('ip_address')
        curr_amt = float(current_tx_data['amount'])
        curr_time = datetime.utcnow()
        receiver = current_tx_data.get('receiver', '')
        
        # Whitelist Check (Instant Safe)
        if IPWhitelist.query.filter_by(ip_address=curr_ip).first():
            return 0.0, {}, "Whitelisted IP"

        # User Context
        account_age_days = (curr_time - user.created_at).days
        # ✅ NEW USER DEFINITION: < 48 Hours OR < 15 Total Transactions
        is_new_user = 1 if (account_age_days < 2 or user.total_tx_count < 15) else 0
        
        # Spending History (Robust Avg)
        avg_spending = user.average_spending
        if avg_spending < 100: avg_spending = 500.0
        amt_ratio = curr_amt / avg_spending

        # --- 2. HISTORICAL AGGREGATES ---
        one_hour_ago = curr_time - timedelta(hours=1)
        one_day_ago = curr_time - timedelta(hours=24)
        seven_days_ago = curr_time - timedelta(days=7)
        rapid_window = curr_time - timedelta(minutes=cls.RAPID_TX_WINDOW_MINUTES)

        # Aggregate Query
        stats = db.session.query(
            func.count(Transaction.id).filter(Transaction.timestamp >= one_hour_ago).label('vel_1h'),
            func.count(Transaction.id).filter(Transaction.timestamp >= one_day_ago).label('vel_24h'),
            func.count(Transaction.id).filter(Transaction.timestamp >= one_hour_ago, Transaction.status == 'FAILED').label('failed_1h'),
            func.sum(Transaction.amount).filter(Transaction.timestamp >= seven_days_ago).label('sum_7d'),
            func.count(Transaction.id).filter(Transaction.timestamp >= seven_days_ago).label('count_7d')
        ).filter(Transaction.user_id == user.id).first()

        vel_1h = stats.vel_1h or 0
        vel_24h = stats.vel_24h or 0
        failed_1h = stats.failed_1h or 0
        sum_7d = stats.sum_7d or 0.0
        count_7d = stats.count_7d or 0

        # ✅ NEW: Rapid Transaction Detection
        rapid_tx_count = Transaction.query.filter(
            Transaction.user_id == user.id,
            Transaction.timestamp >= rapid_window,
            Transaction.status.in_(['SUCCESS', 'PENDING', 'PENDING_OTP'])
        ).count()
        
        # ✅ NEW: Same Amount to Different Receivers Detection
        same_amount_txs = Transaction.query.filter(
            Transaction.user_id == user.id,
            Transaction.timestamp >= rapid_window,
            Transaction.amount == curr_amt,
            Transaction.status.in_(['SUCCESS', 'PENDING', 'PENDING_OTP'])
        ).all()
        
        # Count unique receivers with same amount
        unique_receivers_same_amt = set([tx.receiver_account for tx in same_amount_txs])
        same_amount_count = len(unique_receivers_same_amt)

        # --- 3. LOCATION INTELLIGENCE ---
        last_tx = Transaction.query.filter_by(user_id=user.id)\
            .order_by(desc(Transaction.timestamp)).first()
            
        travel_speed = 0.0
        ip_changed = 0
        
        # ✅ NEW: Check if location is provided
        curr_lat = current_tx_data.get('location_lat', 0.0)
        curr_lon = current_tx_data.get('location_lon', 0.0)
        no_location = 1 if (float(curr_lat) == 0.0 and float(curr_lon) == 0.0) else 0
        
        if last_tx:
            if last_tx.ip_address != curr_ip: ip_changed = 1
            
            dist_km = cls.calculate_distance(
                last_tx.location_lat, last_tx.location_lon, 
                curr_lat, curr_lon
            )
            
            if dist_km is not None:
                time_diff_hours = max((curr_time - last_tx.timestamp).total_seconds() / 3600, 0.05)
                travel_speed = dist_km / time_diff_hours
            else:
                travel_speed = 0.0

        # --- 4. FEATURE VECTOR ---
        raw_type = current_tx_data.get('transaction_type', 'card').lower()
        is_high_value = 1 if curr_amt >= cls.HIGH_VALUE_THRESHOLD else 0
        
        features = {
            'amount': curr_amt,
            'is_new_user': is_new_user,
            'account_age_days': account_age_days,
            'amt_ratio': amt_ratio,
            'velocity_1h': vel_1h,
            'velocity_24h': vel_24h,
            'failed_count_1h': failed_1h,
            'sum_7d': sum_7d,
            'count_7d': count_7d,
            'travel_speed': travel_speed,
            'ip_changed': ip_changed,
            'is_hosting_ip': current_tx_data.get('is_hosting_ip', 0),
            'ip_country_mismatch': current_tx_data.get('ip_country_mismatch', 0),
            'device_changed': 1 if not Device.query.filter_by(user_id=user.id, device_fingerprint=current_tx_data.get('device_id')).first() else 0,
            
            # ✅ NEW FEATURES
            'is_high_value': is_high_value,
            'rapid_tx_count': rapid_tx_count,
            'same_amount_count': same_amount_count,
            'no_location': no_location,
            
            # ✅ AI MODEL FEATURES (Required)
            'is_night': 1 if (curr_time.hour >= 23 or curr_time.hour < 5) else 0,
            'category_risk': 1.0 if is_high_value else 0.0,

            # One-Hot Encoding
            'type_bank_transfer': 1 if raw_type in ['online_banking', 'bank_transfer'] else 0,
            'type_card': 1 if raw_type in ['card', 'credit_card'] else 0,
            'type_debit_card': 1 if raw_type == 'debit_card' else 0,
            'type_mobile': 1 if raw_type in ['upi', 'mobile'] else 0,
        }

        # --- 5. DYNAMIC RULE ENGINE ---
        active_rules = FraudRule.query.filter_by(is_active=True).all()
        rules_triggered = []
        heuristic_score = 0.0

        for rule in active_rules:
            try:
                if rule.field in features:
                    val = features[rule.field]
                    threshold = float(rule.value)
                    
                    hit = False
                    if rule.operator == '>' and val > threshold: hit = True
                    elif rule.operator == '<' and val < threshold: hit = True
                    elif rule.operator == '==' and val == threshold: hit = True
                    
                    if hit:
                        if rule.action == 'BLOCK': 
                            return 1.0, features, f"Blocked by Rule: {rule.field} {rule.operator} {rule.value}"
                        elif rule.action == 'FLAG':
                            heuristic_score += 0.3
                            rules_triggered.append(f"{rule.field}")
            except:
                continue

        # --- 6. ENHANCED HEURISTIC SCORING ---
        
        # ✅ A. HIGH VALUE TRANSACTIONS - Always require verification
        if is_high_value:
            heuristic_score += 0.35  # Push towards OTP verification
            rules_triggered.append("High Value")
        
        # ✅ B. RAPID CONSECUTIVE TRANSACTIONS
        if rapid_tx_count >= cls.RAPID_TX_THRESHOLD:
            heuristic_score += 0.4
            rules_triggered.append("Rapid Transactions")
        
        # ✅ C. SAME AMOUNT TO DIFFERENT RECEIVERS (Split Payment Detection)
        if same_amount_count >= cls.SAME_AMOUNT_THRESHOLD:
            heuristic_score += 0.45
            rules_triggered.append("Same Amount Pattern")
        
        # ✅ D. NO LOCATION PROVIDED - Suspicious
        if no_location:
            heuristic_score += 0.25
            rules_triggered.append("No Location")
        
        # E. Velocity Risk
        if is_new_user and vel_1h > 3: 
            heuristic_score += 0.45  # Force Verification
            rules_triggered.append("New User High Velocity")
        elif vel_1h > 10: 
            heuristic_score += 0.3
            
        # ✅ NEW: New User Amount Spike / First Large Transaction
        if is_new_user and (amt_ratio > 3.0 or curr_amt > 5000):
            heuristic_score += 0.4  # Force Verification
            rules_triggered.append("New User Large Transaction")
        
        # F. Amount Spike (Only for significant amounts)
        if amt_ratio > 10.0 and curr_amt > 5000:
            heuristic_score += 0.4
            
        # G. Travel Risk
        if travel_speed > 800: heuristic_score += 0.8
        
        # H. Infrastructure Risk
        if features['is_hosting_ip']: heuristic_score += 0.2
        if features['ip_country_mismatch']: heuristic_score += 0.3
        if features['device_changed']: heuristic_score += 0.15

        # ✅ I. VERY HIGH VALUE (above 1 lakh) - Almost always verify
        if curr_amt >= 100000:
            heuristic_score = max(heuristic_score, 0.5)  # Minimum 50% risk for high amounts

        # ✅ J. NIGHT TIME TRANSACTION (11 PM - 5 AM)
        hour = curr_time.hour
        if hour >= 23 or hour < 5:
            heuristic_score += 0.25
            rules_triggered.append("Late Night Activity")

        # ✅ K. ENTROPY (Dynamic Variance)
        # Adds small fluctuation (0.01 - 0.04) so identical transactions don't look static
        entropy = random.uniform(0.01, 0.04)
        if heuristic_score > 0.1:
            heuristic_score += entropy

        # --- 7. AI MODEL PREDICTION ---
        ai_score = 0.0
        if cls._model:
            try:
                FEATURE_ORDER = [
                    'amount', 'velocity_1h', 'velocity_24h', 'amt_ratio', 
                    'is_night', 'travel_speed', 'ip_changed', 'is_hosting_ip', 'ip_country_mismatch', 
                    'sum_7d', 'count_7d', 'device_changed', 
                    'category_risk', 'failed_count_1h', 'type_bank_transfer', 'type_card', 
                    'type_debit_card', 'type_mobile'
                ]
                input_df = pd.DataFrame([features])
                for col in FEATURE_ORDER:
                    if col not in input_df.columns: input_df[col] = 0
                input_df = input_df[FEATURE_ORDER]
                
                dmatrix = xgb.DMatrix(input_df)
                ai_score = float(cls._model.predict(dmatrix)[0])
            except Exception as e:
                print(f"AI Model Error: {e}")

        # --- 8. FINAL SCORE ---
        if cls._model:
            final_score = (heuristic_score * 0.4) + (ai_score * 0.6)
        else:
            final_score = heuristic_score

        final_score = min(final_score, 1.0)
        
        explanation = cls.generate_explanation(features, final_score, rules_triggered)
        return final_score, features, explanation
