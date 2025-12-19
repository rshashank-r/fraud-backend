from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import User, Transaction, AuditLog, Notification
from extensions import db
from datetime import datetime, timedelta
from sqlalchemy import func, extract
import random

admin_analytics_bp = Blueprint('admin_analytics', __name__)


def require_admin():
    """Helper to check if current user is admin"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user or user.role != 'ADMIN':
        return jsonify({"error": "Admin access required"}), 403
    return None


@admin_analytics_bp.route('/risk-distribution', methods=['GET'])
@jwt_required()
def get_risk_distribution():
    """Get distribution of transactions by risk level"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    try:
        # Get transactions from last 30 days
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        
        total_tx = Transaction.query.filter(
            Transaction.timestamp >= thirty_days_ago
        ).count()
        
        # Distribution by risk score ranges
        low_risk = Transaction.query.filter(
            Transaction.timestamp >= thirty_days_ago,
            Transaction.risk_score < 0.3
        ).count()
        
        medium_risk = Transaction.query.filter(
            Transaction.timestamp >= thirty_days_ago,
            Transaction.risk_score >= 0.3,
            Transaction.risk_score < 0.7
        ).count()
        
        high_risk = Transaction.query.filter(
            Transaction.timestamp >= thirty_days_ago,
            Transaction.risk_score >= 0.7
        ).count()
        
        return jsonify([
            {"name": "Low Risk", "value": low_risk, "color": "#10b981"},
            {"name": "Medium Risk", "value": medium_risk, "color": "#f59e0b"},
            {"name": "High Risk", "value": high_risk, "color": "#ef4444"}
        ]), 200
        
    except Exception as e:
        print(f"❌ Risk distribution error: {str(e)}")
        return jsonify({"error": "Failed to fetch risk distribution"}), 500


@admin_analytics_bp.route('/alerts-timeline', methods=['GET'])
@jwt_required()
def get_alerts_timeline():
    """Get security alerts timeline for last 7 days"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    try:
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        
        # Get daily alert counts
        daily_alerts = db.session.query(
            func.date(AuditLog.timestamp).label('date'),
            func.count(AuditLog.id).label('count')
        ).filter(
            AuditLog.timestamp >= seven_days_ago,
            AuditLog.action.in_(['LOGIN_FAILED', 'ACCOUNT_LOCKED', 'SUSPICIOUS_ACTIVITY'])
        ).group_by(func.date(AuditLog.timestamp)).all()
        
        # Fill in missing days
        result = []
        for i in range(7):
            date = (datetime.utcnow() - timedelta(days=6-i)).strftime('%Y-%m-%d')
            count = next((a.count for a in daily_alerts if str(a.date) == date), 0)
            result.append({
                "date": date,
                "alerts": count
            })
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"❌ Alerts timeline error: {str(e)}")
        return jsonify({"error": "Failed to fetch alerts timeline"}), 500


@admin_analytics_bp.route('/transaction-volume', methods=['GET'])
@jwt_required()
def get_transaction_volume():
    """Get transaction volume over last 30 days"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    try:
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        
        daily_volume = db.session.query(
            func.date(Transaction.timestamp).label('date'),
            func.count(Transaction.id).label('count'),
            func.sum(Transaction.amount).label('total')
        ).filter(
            Transaction.timestamp >= thirty_days_ago
        ).group_by(func.date(Transaction.timestamp)).all()
        
        result = []
        for vol in daily_volume:
            result.append({
                "date": str(vol.date),
                "count": vol.count,
                "total": float(vol.total) if vol.total else 0
            })
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"❌ Transaction volume error: {str(e)}")
        return jsonify({"error": "Failed to fetch transaction volume"}), 500


@admin_analytics_bp.route('/fraud-categories', methods=['GET'])
@jwt_required()
def get_fraud_categories():
    """Get distribution of fraud by category"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    try:
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        
        # Get flagged/blocked transactions grouped by type
        fraud_by_type = db.session.query(
            Transaction.transaction_type,
            func.count(Transaction.id).label('count')
        ).filter(
            Transaction.timestamp >= thirty_days_ago,
            Transaction.status.in_(['FLAGGED', 'BLOCKED'])
        ).group_by(Transaction.transaction_type).all()
        
        result = []
        colors = ['#ef4444', '#f59e0b', '#8b5cf6', '#3b82f6', '#10b981']
        for idx, fraud in enumerate(fraud_by_type):
            result.append({
                "category": fraud.transaction_type or "Unknown",
                "count": fraud.count,
                "color": colors[idx % len(colors)]
            })
        
        # If no fraud detected, return placeholder data
        if not result:
            result = [
                {"category": "Account Takeover", "count": 0, "color": "#ef4444"},
                {"category": "Card Fraud", "count": 0, "color": "#f59e0b"},
                {"category": "Identity Theft", "count": 0, "color": "#8b5cf6"}
            ]
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"❌ Fraud categories error: {str(e)}")
        return jsonify({"error": "Failed to fetch fraud categories"}), 500


@admin_analytics_bp.route('/geo-distribution', methods=['GET'])
@jwt_required()
def get_geo_distribution():
    """Get geographic distribution of transactions"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    try:
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        
        # Get transactions with location data
        geo_data = db.session.query(
            Transaction.location,
            func.count(Transaction.id).label('count')
        ).filter(
            Transaction.timestamp >= thirty_days_ago,
            Transaction.location.isnot(None)
        ).group_by(Transaction.location).all()
        
        result = []
        for geo in geo_data[:10]:  # Top 10 locations
            result.append({
                "location": geo.location or "Unknown",
                "count": geo.count
            })
        
        # If no data, return placeholder
        if not result:
            result = [
                {"location": "Mumbai, India", "count": 0},
                {"location": "Delhi, India", "count": 0},
                {"location": "Bangalore, India", "count": 0}
            ]
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"❌ Geo distribution error: {str(e)}")
        return jsonify({"error": "Failed to fetch geo distribution"}), 500
