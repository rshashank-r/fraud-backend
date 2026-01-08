---
title: Fraud Backend
emoji: 🛡️
colorFrom: blue
colorTo: red
sdk: docker
pinned: false
app_port: 7860
---
# FraudGuard Backend 🛡️

A robust Flask-based backend for the FraudGuard real-time transaction monitoring system. Features an advanced Fraud Engine with AI capabilities, risk-based authentication, enhanced device security, and comprehensive transaction management.

## 🚀 Key Features

### **Fraud Detection Engine**
- **AI-Powered Analysis**: XGBoost model with 18+ feature evaluation
- **Dynamic Rules**: Admin-configurable fraud rules with real-time execution
- **Risk Scoring**: Hybrid approach (60% AI + 40% heuristic)
- **Velocity Checks**: Transaction frequency and amount spike detection
- **Geographic Intelligence**: IP geolocation, impossible travel detection

### **Enhanced Device Security** 🆕
- **Developer Tools Detection**: Block login attempts with browser DevTools enabled
- **Emulator/Bot Detection**: WebDriver, automation framework, and headless browser blocking
- **Rooted Device Detection**: Prevent access from compromised (rooted/jailbroken) devices
- **VPN Risk Scoring**: High-risk scoring (+0.45) requiring additional verification
- **Security Alerts**: Automated email and in-app notifications for suspicious device attempts

### **Risk-Based Authentication (RBA)**
- **Adaptive MFA**: Dynamic authentication requirements based on real-time risk assessment
- **10+ Risk Factors**: New device, foreign country, impossible travel, VPN, late night login, failed attempts
- **Smart Decision Engine**: ALLOW | OTP | OTP_DEVICE | FREEZE based on risk score
- **Device Reputation**: Trust scoring (0-1000) for known devices
- **IP Reputation**: Automatic blacklisting for malicious IPs

### **Security Services**
- **Session Fingerprinting**: Canvas, WebGL, browser, and OS-level device identification
- **Nonce Manager**: Replay attack prevention with UUID-based transaction validation
- **Progressive Lockout**: 3-level escalation (Soft Lock → Hard Lock → Permanent Ban)
- **Behavioral Biometrics**: Typing speed and mouse movement analysis for bot detection
- **Graph-Based Detection**: Fraud ring identification through shared IP/device analysis

### **Notification System**
- **Email Alerts**: Brevo (Sendinblue) integration for OTP, fraud alerts, and security notifications
- **Device-Specific Messaging**: Tailored alerts for different threat types
- **In-App Notifications**: Real-time security alerts in user dashboard
- **Transaction Updates**: Detailed email reports for success, failure, and blocks

## 🛠️ Setup & Installation

### 1. **Install Dependencies**
```bash
pip install -r requirements.txt
```

### 2. **Environment Variables**
Create a `.env` file:
```env
# Database
DATABASE_URL=postgresql://user:pass@host/dbname

# Security
JWT_SECRET_KEY=your_jwt_secret_key_here
ADMIN_SECRET_KEY=your_admin_secret_key_here

# Email (Brevo/Sendinblue)
BREVO_API_KEY=your_brevo_api_key_here
MAIL_USERNAME=noreply@yourdomain.com

# Optional
CORS_ORIGINS=http://localhost:3000,https://yourfrontend.com
```

### 3. **Database Setup**
```bash
# Initialize database
python reset_db.py

# Seed initial data (users, rules, etc.)
python seed.py
```

### 4. **Run Server**
```bash
# Development
python app.py

# Production (with Gunicorn)
gunicorn -w 4 -b 0.0.0.0:5000 app:create_app()
```

Server runs on `http://localhost:5000`

## 🏗️ System Architecture
```mermaid
graph TD
    Client[Web Client]
    
    subgraph LoadBalancer [Nginx/Gunicorn]
        LB[Request Handling]
    end

    subgraph App [Flask Application]
        Auth[Auth Service]
        Tx[Transaction Service]
        Admin[Admin Service]
        
        subgraph Security [Security Suite]
            RBA[Risk Authenticator]
            FP[Fingerprinting]
            Bot[Bot Detection]
        end
        
        subgraph Engine [Fraud Engine]
            XGB[XGBoost Model]
            Rules[Rule Engine]
            Scoring[Risk Scorer]
        end
    end
    
    subgraph Data [Data Persistence]
        DB[(PostgreSQL)]
        Redis[(Redis Cache)]
    end
    
    subgraph External [External Services]
        Brevo[Brevo Email]
        Geo[GeoLite2 DB]
    end

    Client --> |REST API| LB
    LB --> App
    
    Auth --> Security
    Tx --> Engine
    
    Engine --> XGB
    Engine --> Rules
    
    App --> DB
    App --> Redis
    App --> External
```

## 📂 Project Structure

```
fraud-backend/
├── app.py                      # Application entry point
├── config.py                   # Configuration management
├── models/                     # Database models
│   └── __init__.py            # User, Transaction, Device, etc.
├── routes/                     # API Blueprints
│   ├── auth_routes.py         # Authentication & RBA
│   ├── tx_routes.py           # Transaction processing
│   ├── admin_routes.py        # Admin dashboard
│   └── admin_security_routes.py # Security management
├── services/                   # Business logic
│   ├── fraud_engine.py        # AI fraud detection
│   ├── risk_authenticator.py # RBA engine
│   ├── email_service.py       # Email notifications
│   ├── session_fingerprint.py # Device fingerprinting
│   ├── device_reputation.py   # Device trust scoring
│   ├── ip_reputation.py       # IP trust scoring
│   ├── nonce_manager.py       # Replay attack prevention
│   ├── progressive_lockout.py # Account lockout management
│   ├── security_suite.py      # Bot detection, trust scoring
│   ├── security_events.py     # Event logging
│   └── geo_service.py         # IP geolocation
└── fraud_model_xgb.json       # Pre-trained XGBoost model
```

## 🔑 Key APIs

### **Authentication**
- `POST /api/auth/login` - Risk-based login with device checks
- `POST /api/auth/verify-2fa-login` - TOTP verification
- `POST /api/auth/verify-email-otp-login` - Email OTP verification
- `POST /api/auth/register` - User registration
- `GET /api/auth/me` - Get user profile
- `POST /api/auth/enable-2fa` - Enable TOTP 2FA

### **Transactions**
- `POST /api/tx/pay` - Process payment (fraud checks applied)
- `GET /api/tx/history` - Transaction history (paginated)
- `POST /api/tx/verify-otp` - Verify transaction OTP
- `POST /api/tx/resend-otp` - Resend OTP

### **Admin Dashboard**
- `GET /api/admin/dashboard/stats` - System statistics
- `GET /api/admin/transactions` - All transactions (filterable)
- `GET /api/admin/users` - User management
- `GET /api/admin/fraud-rules` - Fraud rule management
- `POST /api/admin/fraud-rules` - Create new rule

### **Security Management** 🆕
- `GET /api/admin/security-events` - Security event logs
- `GET /api/admin/ip-reputation` - IP reputation scores
- `POST /api/admin/ip-reputation/blacklist` - Blacklist IP
- `GET /api/admin/honeypots` - Bot trap monitoring

## 🔒 Security Features

### **Device Security Checks**
| Check | Detection Method | Action |
|-------|-----------------|--------|
| Developer Tools | Window size delta, debugger timing | LOGIN DENIED |
| Emulator/Bot | WebDriver flag, automation detection | LOGIN DENIED |
| Rooted Device | OS indicators, root patterns | LOGIN DENIED |
| VPN/Proxy | Datacenter IP, hosting provider | HIGH RISK (+0.45) |

### **Risk Score Thresholds**
- **0.0 - 0.2**: ✅ ALLOW (instant approval)
- **0.2 - 0.5**: 📧 OTP (email verification required)
- **0.5 - 0.8**: 🔐 OTP_DEVICE (email + new device verification)
- **0.8 - 1.0**: 🚫 FREEZE (account temporarily frozen)

## 🌐 Deployment

### **Production URL**: `https://fraud-backend-y9xq.onrender.com`

### **Render Deployment**
1. Connect GitHub repository to Render
2. Set environment variables in Render dashboard
3. Deploy with build command: `pip install -r requirements.txt`
4. Start command: `gunicorn -w 4 app:create_app()`

## ⚠️ Troubleshooting

- **500 Error on Transaction**: Ensure `fraud_model_xgb.json` matches feature engineeringin `fraud_engine.py`
- **Email Errors**: Use Brevo API key (not SMTP). Verify `BREVO_API_KEY` is set
- **Database Connection**: Check `DATABASE_URL` format: `postgresql://user:pass@host/db`
- **CORS Issues**: Add frontend URL to `CORS_ORIGINS` environment variable
- **Model Loading Error**: ML model loads once on startup (not in reloader process)

## 📊 Performance

- **Response Time**: < 200ms for fraud analysis
- **Model Inference**: ~10ms per transaction
- **Database Queries**: Optimized with indexes on user_id, ip_address, device_id
- **Concurrent Requests**: Supports 100+ concurrent transactions (with Gunicorn)

## 📝 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Pull requests welcome! Please ensure:
- All tests pass
- Code follows PEP 8 style guide
- New features include documentation
- Security features are thoroughly tested
