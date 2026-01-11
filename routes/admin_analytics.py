from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import User, Transaction, AuditLog, Notification
from extensions import db
from datetime import datetime, timedelta
from sqlalchemy import func, extract, case
import random
from functools import wraps
import time

admin_analytics_bp = Blueprint('admin_analytics', __name__)

# Simple in-memory cache
_cache = {}
_cache_timestamps = {}

def cache_result(ttl_seconds=300):
    """Decorator to cache function results for specified TTL"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache_key = f"{func.__name__}"
            current_time = time.time()
            
            # Check if cache is valid
            if cache_key in _cache and cache_key in _cache_timestamps:
                if current_time - _cache_timestamps[cache_key] < ttl_seconds:
                    return _cache[cache_key]
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            _cache[cache_key] = result
            _cache_timestamps[cache_key] = current_time
            return result
        return wrapper
    return decorator


def require_admin():
    """Helper to check if current user is admin"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user or user.role != 'ADMIN':
        return jsonify({"error": "Admin access required"}), 403
    return None


@admin_analytics_bp.route('/risk-distribution', methods=['GET'])
@jwt_required()
@cache_result(ttl_seconds=300)  # Cache for 5 minutes
def get_risk_distribution():
    """Get distribution of transactions by risk level"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    try:
        # Get transactions from last 30 days - OPTIMIZED: Single query with CASE
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        
        # Use a single aggregated query instead of 4 separate queries
        result = db.session.query(
            func.sum(case((Transaction.risk_score < 0.3, 1), else_=0)).label('low_risk'),
            func.sum(case(((Transaction.risk_score >= 0.3) & (Transaction.risk_score < 0.7), 1), else_=0)).label('medium_risk'),
            func.sum(case((Transaction.risk_score >= 0.7, 1), else_=0)).label('high_risk')
        ).filter(
            Transaction.timestamp >= thirty_days_ago
        ).first()
        
        low_risk = result.low_risk or 0
        medium_risk = result.medium_risk or 0
        high_risk = result.high_risk or 0
        
        return jsonify([
            {"range": "Low", "count": low_risk, "color": "#10b981"},
            {"range": "Medium", "count": medium_risk, "color": "#f59e0b"},
            {"range": "High", "count": high_risk, "color": "#ef4444"}
        ]), 200
        
    except Exception as e:
        print(f"❌ Risk distribution error: {str(e)}")
        return jsonify({"error": "Failed to fetch risk distribution"}), 500


@admin_analytics_bp.route('/alerts-timeline', methods=['GET'])
@jwt_required()
@cache_result(ttl_seconds=300)  # Cache for 5 minutes
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
                "count": count
            })
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"❌ Alerts timeline error: {str(e)}")
        return jsonify({"error": "Failed to fetch alerts timeline"}), 500


@admin_analytics_bp.route('/transaction-volume', methods=['GET'])
@jwt_required()
@cache_result(ttl_seconds=300)  # Cache for 5 minutes
def get_transaction_volume():
    """Get transaction volume over last 30 days"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    try:
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        
        # OPTIMIZED: Added limit to prevent excessive data
        daily_volume = db.session.query(
            func.date(Transaction.timestamp).label('date'),
            func.count(Transaction.id).label('count'),
            func.sum(Transaction.amount).label('total')
        ).filter(
            Transaction.timestamp >= thirty_days_ago
        ).group_by(func.date(Transaction.timestamp))\
         .order_by(func.date(Transaction.timestamp).desc())\
         .limit(30).all()  # Limit to 30 days max
        
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
@cache_result(ttl_seconds=300)  # Cache for 5 minutes
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
            Transaction.status.in_(['FLAGGED', 'BLOCKED', 'FAILED'])
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
@cache_result(ttl_seconds=300)  # Cache for 5 minutes
def get_geo_distribution():
    """Get geographic distribution of transactions"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    try:
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        
        # Get transactions with location data
        geo_data = db.session.query(
            Transaction.location_name,
            func.count(Transaction.id).label('count')
        ).filter(
            Transaction.timestamp >= thirty_days_ago,
            Transaction.location_name.isnot(None)
        ).group_by(Transaction.location_name).all()
        
        result = []
        for geo in geo_data[:10]:  # Top 10 locations
            result.append({
                "location": geo.location_name or "Unknown",
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
