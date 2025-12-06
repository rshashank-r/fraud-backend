import os
from flask import Flask, jsonify
from flask_cors import CORS
from config import Config
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

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # --- FIXED CORS CONFIGURATION ---
    allowed_origins = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://192.168.0.103:3000"
    ]

    # Add Production URL
    prod_url = os.environ.get("FRONTEND_URL")
    if prod_url:
        allowed_origins.append(prod_url)

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


    # ✅ ADDITIONAL FIX: Add global OPTIONS handler
    @app.before_request
    def handle_preflight():
        from flask import request
        if request.method == "OPTIONS":
            response = app.make_default_options_response()
            return response

    # Error Handlers
    @app.errorhandler(429)
    def ratelimit_handler(e):
        return jsonify(error="ratelimit exceeded", message=str(e.description)), 429

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify(error="Internal Server Error"), 500

    @app.route('/')
    def home():
        return jsonify({
            "message": "FraudGuard API is Running!",
            "status": "Live",
            "cors_origins": allowed_origins
        }), 200

    # Initialize DB & Load Model
    with app.app_context():
        db.create_all()
        try:
            print("⏳ Pre-loading Fraud Model...")
            FraudEngine.load_model()
            print("✅ Model Loaded!")
        except Exception as e:
            print(f"⚠️ Warning: Could not load Fraud Model: {e}")

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)
