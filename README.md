# FraudGuard Backend 🛡️

A robust Flask-based backend for the FraudGuard real-time transaction monitoring system. It features an advanced Fraud Engine with AI capabilities, dynamic rule execution, and comprehensive transaction management.

## 🚀 Features

- **Fraud Engine 2.0**:
  - **Dynamic Rules**: Time-based risk (Night Mode), velocity checks, and entropy-based scoring.
  - **AI Integration**: XGBoost model support for advanced anomaly detection.
  - **New User Protection**: Stricter verification rules for accounts < 48 hours old.
- **Transaction Management**: 
  - Real-time blocking and holding (PENDING_2FA, PENDING_OTP).
  - Robust persistence (failed transactions are saved for history).
- **Admin Dashboard API**: Endpoints for full system oversight (Transactions, Users, Stats).
- **Security**: JWT Authentication, Rate Limiting, and Client Fingerprinting checks.

## 🛠️ Setup & Installation

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Environment Variables**:
   Create a `.env` file in this directory:
   ```env
   DATABASE_URL=postgresql://user:pass@host/dbname
   JWT_SECRET_KEY=your_jwt_secret
   ADMIN_SECRET_KEY=your_admin_secret_key
   MAIL_SERVER=smtp.gmail.com
   MAIL_PORT=587
   MAIL_USERNAME=your_email@gmail.com
   MAIL_PASSWORD=your_app_password
   ```

3. **Database Initialization**:
   ```bash
   # Initialize DB (if needed)
   python reset_db.py
   # Seed initial data
   python seed.py
   ```

4. **Run the Server**:
   ```bash
   python app.py
   ```
   Server runs on `http://localhost:5000`.

## 📂 Project Structure

- `app.py`: Main entry point.
- `routes/`: API Blueprints (`tx_routes`, `auth_routes`, `admin_routes`).
- `services/`: Core logic (`fraud_engine.py`, `email_service.py`, `geo_service.py`).
- `models/`: Database schemas (`Transaction`, `User`, `FraudRule`).

## 🔑 Key APIs

- **POST /api/tx/pay**: Main transaction endpoint (Fraud Checks applied here).
- **GET /api/tx/history**: Fetch user transaction history (Filtered, Paginated).
- **POST /api/auth/login**: User/Admin login (returns JWT).
- **GET /api/alerts**: Fetch fraud alerts.

## ⚠️ Troubleshooting

- **500 Error on Pay**: Ensure `fraud_model_xgb.json` matches the feature list in `fraud_engine.py`.
- **Email Errors**: specific ports (587) and app passwords are required for Gmail.
