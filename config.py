import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your_super_secret_key_change_me')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'enter the main database url')
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
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'enter the main email') 
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', 'enter the main email password') # Use App Password
    
    # Brevo API Key
    BREVO_API_KEY = os.environ.get('BREVO_API_KEY')