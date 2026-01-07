import os
from typing import Optional


class Config:
    """Base configuration with common settings."""
    
    # ===== CRITICAL SETTINGS =====
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY environment variable must be set")
    
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    if not SQLALCHEMY_DATABASE_URI:
        raise ValueError("DATABASE_URL environment variable must be set")
    
    # ===== DATABASE SETTINGS =====
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,  # Check connection before use
        "pool_recycle": 300,    # Recycle connections every 5 minutes
        "pool_timeout": 30,     # Wait up to 30s for a connection
        "pool_size": 10,        # Keep 10 connections open
        "max_overflow": 20,     # Allow temporary spikes
    }
    
    # ===== EMAIL SETTINGS =====
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    BREVO_API_KEY = os.environ.get('BREVO_API_KEY')
    
    # Validate mail config
    if not MAIL_USERNAME or not MAIL_PASSWORD:
        print("⚠️ WARNING: Email service not configured. Set MAIL_USERNAME and MAIL_PASSWORD.")
    
    # ===== JWT SETTINGS =====
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES', 900))  # 15 minutes
    JWT_REFRESH_TOKEN_EXPIRES = int(os.environ.get('JWT_REFRESH_TOKEN_EXPIRES', 2592000))  # 30 days
    
    # ===== SECURITY SETTINGS =====
    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_SECURE = True  # HTTPS only
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # ===== RATE LIMITING =====
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL', 'memory://')
    RATELIMIT_ENABLED = True
    
    # ===== FRAUD DETECTION =====
    FRAUD_MODEL_PATH = os.environ.get('FRAUD_MODEL_PATH', 'fraud_model_xgb.json')
    FRAUD_THRESHOLD = float(os.environ.get('FRAUD_THRESHOLD', 0.7))
    
    # ===== APPLICATION SETTINGS =====
    ENV = os.environ.get('FLASK_ENV', 'production')
    DEBUG = False
    TESTING = False
    
    @staticmethod
    def validate():
        """Validate critical configuration settings."""
        errors = []
        
        if not Config.SECRET_KEY:
            errors.append("SECRET_KEY is required")
        
        if not Config.SQLALCHEMY_DATABASE_URI:
            errors.append("DATABASE_URL is required")
        
        if errors:
            raise ValueError(f"Configuration errors: {', '.join(errors)}")
    
    @classmethod
    def init_app(cls, app):
        """Initialize application with this configuration."""
        cls.validate()
        app.logger.info(f"Loaded configuration: {cls.__name__}")


class DevelopmentConfig(Config):
    """Development environment configuration."""
    DEBUG = True
    ENV = 'development'
    
    # Less strict in development
    SESSION_COOKIE_SECURE = False  # Allow HTTP in dev
    
    # More verbose logging
    SQLALCHEMY_ECHO = False  # Set to True for SQL query logging
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        app.logger.info("🔧 Development mode enabled")


class ProductionConfig(Config):
    """Production environment configuration."""
    DEBUG = False
    ENV = 'production'
    
    # Strict security in production
    SESSION_COOKIE_SECURE = True
    WTF_CSRF_ENABLED = True
    
    # Optimized database settings for production
    SQLALCHEMY_ENGINE_OPTIONS = {
        **Config.SQLALCHEMY_ENGINE_OPTIONS,
        "pool_size": 20,  # More connections in production
        "max_overflow": 40,
    }
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        app.logger.info("🚀 Production mode enabled")
        
        # Ensure critical settings in production
        if not cls.MAIL_USERNAME or not cls.MAIL_PASSWORD:
            app.logger.warning("Email service not configured in production!")


class TestingConfig(Config):
    """Testing environment configuration."""
    TESTING = True
    ENV = 'testing'
    DEBUG = True
    
    # Use in-memory SQLite for tests
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL', 'sqlite:///:memory:')
    
    # Disable CSRF for easier testing
    WTF_CSRF_ENABLED = False
    
    # Disable rate limiting in tests
    RATELIMIT_ENABLED = False
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        app.logger.info("🧪 Testing mode enabled")


class StagingConfig(ProductionConfig):
    """Staging environment configuration (production-like)."""
    ENV = 'staging'
    
    # Same as production but with different logging
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        app.logger.info("🎭 Staging mode enabled")


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'staging': StagingConfig,
    'default': DevelopmentConfig
}


def get_config(env: Optional[str] = None) -> Config:
    """
    Get configuration for specified environment.
    
    Args:
        env: Environment name (development, production, testing, staging)
    
    Returns:
        Configuration class for the specified environment
    """
    env = env or os.environ.get('FLASK_ENV', 'production')
    return config.get(env, config['default'])
