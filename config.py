import os

class Config:
    # CRITICAL: No fallback defaults for security-critical variables
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY environment variable must be set")
    
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    if not SQLALCHEMY_DATABASE_URI:
        raise ValueError("DATABASE_URL environment variable must be set")
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,  # Checks connection before use (The main fix)
        "pool_recycle": 300,    # Recycle connections every 5 minutes
        "pool_timeout": 30,     # Wait up to 30s for a connection
        "pool_size": 10,        # Keep 10 connections open
        "max_overflow": 20,     # Allow temporary spikes
    }
    
    # Mail Settings
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    
    # Validate mail config
    if not MAIL_USERNAME or not MAIL_PASSWORD:
        print("⚠️ WARNING: Email service not configured. Set MAIL_USERNAME and MAIL_PASSWORD.")
    
    # Brevo API Key
    BREVO_API_KEY = os.environ.get('BREVO_API_KEY')