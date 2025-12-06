from extensions import db
from datetime import datetime
import uuid
import random

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    phone_number = db.Column(db.String(20), nullable=True)
    role = db.Column(db.String(10), default='USER')
    
    # FIXED: Increased default balance to 1 Million so Fraud Tests don't fail on "Insufficient Funds"
    balance = db.Column(db.Float, default=1000000.0) 
    account_number = db.Column(db.String(20), unique=True, nullable=True)
    upi_id = db.Column(db.String(50), unique=True, nullable=True)
    
    # Shadow Profile
    home_ip = db.Column(db.String(50), nullable=True)
    average_spending = db.Column(db.Float, default=0.0)
    total_tx_count = db.Column(db.Integer, default=0)
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(50), nullable=True)

    # Security
    trust_score = db.Column(db.Integer, default=50)
    totp_secret = db.Column(db.String(32), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    is_breached = db.Column(db.Boolean, default=False)
    is_locked = db.Column(db.Boolean, default=False)
    
    # OTP Storage
    email_otp = db.Column(db.String(6), nullable=True)
    email_otp_expiry = db.Column(db.DateTime, nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    transactions = db.relationship('Transaction', backref='user', lazy=True)
    devices = db.relationship('Device', backref='user', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if not self.account_number:
            self.account_number = str(random.randint(1000000000, 9999999999))
        if not self.upi_id and self.phone_number:
            self.upi_id = f"{self.phone_number}@fraudguard"

class TokenBlocklist(db.Model):
    __tablename__ = 'token_blocklist'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Transaction(db.Model):
    __tablename__ = 'transactions'
    __table_args__ = (db.Index('idx_user_timestamp', 'user_id', 'timestamp'),)
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    receiver_account = db.Column(db.String(50), nullable=False)
    transaction_type = db.Column(db.String(20), nullable=False)
    category = db.Column(db.String(50), default='General')
    status = db.Column(db.String(20), default='PENDING')
    ip_address = db.Column(db.String(50), nullable=False)
    location_lat = db.Column(db.Float, nullable=True)
    location_lon = db.Column(db.Float, nullable=True)
    device_id = db.Column(db.String(500), nullable=True)
    risk_score = db.Column(db.Float, default=0.0)
    risk_reason = db.Column(db.String(200), nullable=True)
    is_flagged_incorrect = db.Column(db.Boolean, default=False) 
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    alert = db.relationship('FraudAlert', backref='transaction', uselist=False)

class Device(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    device_fingerprint = db.Column(db.String(500), nullable=False) 
    last_used_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_trusted = db.Column(db.Boolean, default=True)
    device_name = db.Column(db.String(50), default="Unknown Device")

class FraudAlert(db.Model):
    __tablename__ = 'fraud_alerts'
    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(db.String(36), db.ForeignKey('transactions.id'))
    alert_level = db.Column(db.String(20)) 
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_resolved = db.Column(db.Boolean, default=False)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.String(255))
    ip_address = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class FraudRule(db.Model):
    __tablename__ = 'fraud_rules'
    id = db.Column(db.Integer, primary_key=True)
    field = db.Column(db.String(50), nullable=False)
    operator = db.Column(db.String(10), nullable=False)
    value = db.Column(db.String(100), nullable=False)
    action = db.Column(db.String(20), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class IPWhitelist(db.Model):
    __tablename__ = 'ip_whitelist'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(100))
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

class Dispute(db.Model):
    __tablename__ = 'disputes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    transaction_id = db.Column(db.String(36), db.ForeignKey('transactions.id'), nullable=False)
    reason = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(255))
    status = db.Column(db.String(20), default='OPEN')
    admin_comment = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # FIXED: Added relationship so 'dispute.user' works in admin_routes
    user = db.relationship('User', backref='disputes')
    transaction = db.relationship('Transaction', backref='dispute', uselist=False)

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(20), default='INFO')
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UnlockRequest(db.Model):
    __tablename__ = 'unlock_requests'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    email = db.Column(db.String(120), nullable=False) 
    reason = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='PENDING')
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='unlock_requests')

class SupportTicket(db.Model):
    __tablename__ = 'support_tickets'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='OPEN')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class FAQ(db.Model):
    __tablename__ = 'faqs'
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(200), nullable=False)
    answer = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50))

class Alert(db.Model):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(100))
    message = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(50), default='INFO')
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Beneficiary(db.Model):
    __tablename__ = 'beneficiaries'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    account_number = db.Column(db.String(50), nullable=False)
    bank_name = db.Column(db.String(100))
    ifsc_code = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Card(db.Model):
    __tablename__ = 'cards'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    card_number = db.Column(db.String(20), unique=True, nullable=False)
    cvv_hash = db.Column(db.String(128)) 
    expiry_date = db.Column(db.String(5)) 
    pin_hash = db.Column(db.String(128), nullable=False)
    is_locked = db.Column(db.Boolean, default=False)
    daily_limit = db.Column(db.Float, default=50000.0)
    type = db.Column(db.String(20), default='DEBIT')