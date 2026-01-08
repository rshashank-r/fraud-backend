import os
from dotenv import load_dotenv
load_dotenv()
from flask import Flask, jsonify
from flask_cors import CORS
from config import Config, get_config
from extensions import db, limiter, mail, jwt
from models import TokenBlocklist
from flask_migrate import Migrate
from services.fraud_engine import FraudEngine

# Import Blueprints
from routes.auth_routes import auth_bp
from routes.tx_routes import tx_bp
from routes.admin_routes import admin_bp
from routes.transfer_routes import transfer_bp
from routes.support_routes import support_bp
from routes.analytics import analytics_bp
from routes.cards import cards_bp
from routes.beneficiaries import beneficiary_bp
from routes.user_routes import user_bp
from routes.accounts import accounts_bp
from routes.alerts import alerts_bp
from routes.admin_security_routes import admin_security_bp
from routes.admin_analytics import admin_analytics_bp

# Professional Error Handling & Logging
from utils.errors import APIError
from utils.logger import setup_logging, log_request_info

# API Documentation
from flasgger import Swagger


def create_app(config_name=None):
    """
    Application factory pattern.
    
    Args:
        config_name: Configuration environment name (development, production, testing, staging)
    
    Returns:
        Configured Flask application instance
    """
    app = Flask(__name__)
    
    # Load configuration based on environment
    config_name = config_name or os.environ.get('FLASK_ENV', 'production')
    config_class = get_config(config_name)  # Fixed: use module function, not Config.get_config
    app.config.from_object(config_class)
    
    # Initialize configuration
    config_class.init_app(app)

    # --- FIXED CORS CONFIGURATION ---
    allowed_origins = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://192.168.0.103:3000",
        "https://fraud-guard.netlify.app",
        "https://fraud-guard.netlify.app/",  # Both with and without trailing slash
    ]

    # Add Production URL from environment
    prod_url = os.environ.get("FRONTEND_URL")
    if prod_url:
        allowed_origins.append(prod_url)
        allowed_origins.append(prod_url.rstrip('/'))  # Add without trailing slash

    # ✅ CRITICAL FIX: Use resources parameter to apply CORS to all /api/* routes
    CORS(app,
         resources={r"/api/*": {
             "origins": allowed_origins,
             "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
             "allow_headers": [
                 "content-type", 
                 "authorization", 
                 "x-device-id", 
                 "x-device-confidence", 
                 "x-is-vpn", 
                 "x-is-emulator", 
                 "x-is-webdriver",
                 "x-client-screen",
                 "x-client-timezone",
                 "x-admin-key"
             ],
             "supports_credentials": True,
             "expose_headers": ["Content-Type", "Authorization"]
         }},
         supports_credentials=True
    )

    # Initialize Extensions
    db.init_app(app)
    limiter.init_app(app)
    mail.init_app(app)
    jwt.init_app(app)
    migrate = Migrate(app, db)

    # Setup Professional Logging
    setup_logging(app)
    log_request_info(app)
    app.logger.info("FraudGuard API starting up...")

    # Setup API Documentation (Swagger)
    swagger_config = {
        "headers": [],
        "specs": [{
            "endpoint": 'apispec',
            "route": '/api/docs/apispec.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }],
        "static_url_path": "/flasgger_static",
        "swagger_ui": True,
        "specs_route": "/api/docs",
        "title": "FraudGuard API Documentation",
        "version": "2.0.0",
        "description": "AI-Powered Fraud Detection & Prevention System",
        "termsOfService": "",
        "contact": {
            "name": "FraudGuard API Support",
            "email": "support@fraudguard.com"
        }
    }
    
    swagger_template = {
        "securityDefinitions": {
            "Bearer": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": "JWT Authorization header using the Bearer scheme. Example: 'Bearer {token}'"
            }
        },
        "security": [{"Bearer": []}],
        "info": {
            "title": "FraudGuard API",
            "description": "Comprehensive fraud detection and prevention API with risk-based authentication",
            "version": "2.0.0"
        }
    }
    
    Swagger(app, config=swagger_config, template=swagger_template)
    app.logger.info("API Documentation initialized at /api/docs")

    # Token Blocklist Check
    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        jti = jwt_payload["jti"]
        token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()
        return token is not None

    # Register Blueprints
    # Register Blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(tx_bp, url_prefix='/api/tx')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    app.register_blueprint(transfer_bp, url_prefix='/api/transfers')
    app.register_blueprint(support_bp, url_prefix='/api/support')
    app.register_blueprint(analytics_bp, url_prefix='/api/analytics')
    app.register_blueprint(cards_bp, url_prefix='/api/cards')
    app.register_blueprint(beneficiary_bp, url_prefix='/api/beneficiaries')
    app.register_blueprint(user_bp, url_prefix='/api/users')
    app.register_blueprint(accounts_bp, url_prefix='/api/accounts')
    app.register_blueprint(alerts_bp, url_prefix='/api/alerts')
    app.register_blueprint(admin_security_bp, url_prefix='/api/admin')
    app.register_blueprint(admin_analytics_bp, url_prefix='/api/admin/analytics')



    @app.before_request
    def handle_preflight():
        from flask import request
        if request.method == "OPTIONS":
            response = app.make_default_options_response()
            return response

    # Enhanced Security Headers
    @app.after_request
    def add_security_headers(response):
        """Add comprehensive security headers to all responses."""
        # Content Security Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "  # Allow inline scripts for Swagger UI
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' data: https://fonts.gstatic.com; "
            "connect-src 'self' https://fraud-backend.onrender.com https://fraud-backend-y9xq.onrender.com; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        response.headers['Content-Security-Policy'] = csp
        
        # Strict Transport Security (HSTS) - Force HTTPS
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'
        
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # XSS Protection
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer Policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Permissions Policy (formerly Feature Policy)
        response.headers['Permissions-Policy'] = (
            'accelerometer=(), '
            'camera=(), '
            'geolocation=(self), '
            'gyroscope=(), '
            'magnetometer=(), '
            'microphone=(), '
            'payment=(), '
            'usb=()'
        )
        
        return response

    # Professional Error Handlers
    @app.errorhandler(APIError)
    def handle_api_error(error):
        """Handle all custom API errors."""
        app.logger.error(f"API Error: {error.message}", extra={'error_type': error.__class__.__name__})
        response = jsonify(error.to_dict())
        response.status_code = error.status_code
        return response

    @app.errorhandler(429)
    def ratelimit_handler(e):
        app.logger.warning(f"Rate limit exceeded: {str(e.description)}")
        return jsonify({
            'error': 'RateLimitError',
            'message': 'Too many requests. Please slow down.',
            'details': str(e.description)
        }), 429

    @app.errorhandler(500)
    def internal_error(e):
        app.logger.exception("Internal server error occurred")
        return jsonify({
            'error': 'InternalServerError',
            'message': 'An unexpected error occurred. Please try again later.'
        }), 500

    @app.errorhandler(404)
    def not_found_error(e):
        return jsonify({
            'error': 'NotFoundError',
            'message': 'The requested resource was not found.'
        }), 404

    @app.errorhandler(400)
    def bad_request_error(e):
        return jsonify({
            'error': 'ValidationError',
            'message': 'Invalid request data.',
            'details': str(e)
        }), 400

    @app.route('/')
    def home():
        app.logger.info("Health check endpoint accessed")
        return jsonify({
            "service": "FraudGuard API",
            "status": "operational",
            "version": "2.0.0",
            "environment": app.config.get('ENV', 'production'),
            "cors_origins": allowed_origins
        }), 200

    @app.route('/health')
    def health_check():
        """Detailed health check endpoint."""
        try:
            # Test database connection
            from sqlalchemy import text
            db.session.execute(text('SELECT 1'))
            db_status = "healthy"
        except Exception as e:
            db_status = "unhealthy"
            app.logger.error(f"Database health check failed: {str(e)}")
        
        return jsonify({
            "status": "healthy" if db_status == "healthy" else "degraded",
            "checks": {
                "database": db_status,
                "api": "healthy"
            }
        }), 200 if db_status == "healthy" else 503

    # Initialize DB
    with app.app_context():
        db.create_all()

    return app

app = create_app()

# Load model only once (not in reloader process)
# Flask's debug mode spawns a reloader process that would load the model twice
if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or not os.environ.get('WERKZEUG_RUN_MAIN'):
    # This ensures model loads only once, even in debug mode
    if not hasattr(FraudEngine, '_model_loaded'):
        with app.app_context():
            try:
                print("⏳ Pre-loading Fraud Model...")
                FraudEngine.load_model()
                FraudEngine._model_loaded = True
                print("✅ Model Loaded!")
            except Exception as e:
                print(f"⚠️ Warning: Could not load Fraud Model: {e}")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 7860)))
