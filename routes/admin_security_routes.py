"""
Admin Security Routes
New endpoints for managing security features
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import User, db, Device, Transaction
from sqlalchemy import func, desc
from services.security_events import SecurityEventLogger, SecurityEvent
from services.ip_reputation import IPReputationService, IPReputation
from services.honeypot_service import HoneypotService
from services.progressive_lockout import ProgressiveLockout
from datetime import datetime, timedelta

admin_security_bp = Blueprint('admin_security', __name__)

def require_admin():
    """Helper to check if user is admin"""
    user = User.query.get(get_jwt_identity())
    if not user or user.role != 'ADMIN':
        return jsonify({"error": "Admin access required"}), 403
    return None

# ===== SECURITY EVENTS =====

@admin_security_bp.route('/security-events', methods=['GET'])
@jwt_required()
def get_security_events():
    """Get security events with optional filters"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    # Parse filters
    event_type = request.args.get('event_type')
    severity = request.args.get('severity')
    user_id = request.args.get('user_id')
    resolved = request.args.get('resolved', type=bool)
    limit = request.args.get('limit', 100, type=int)
    
    filters = {}
    if event_type:
        filters['event_type'] = event_type
    if severity:
        filters['severity'] = severity
    if user_id:
        filters['user_id'] = user_id
    if resolved is not None:
        filters['resolved'] = resolved
    
    events = SecurityEventLogger.get_events(filters, limit)
    
    return jsonify({
        'events': [{
            'id': e.id,
            'event_type': e.event_type,
            'severity': e.severity,
            'details': e.details,
            'user_id': e.user_id,
            'ip_address': e.ip_address,
            'timestamp': e.timestamp.isoformat(),
            'resolved': e.resolved
        } for e in events]
    }), 200

@admin_security_bp.route('/security-events/<int:event_id>/resolve', methods=['POST'])
@jwt_required()
def resolve_security_event(event_id):
    """Mark security event as resolved"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    data = request.json
    notes = data.get('notes', '')
    
    admin_id = get_jwt_identity()
    success = SecurityEventLogger.resolve_event(event_id, admin_id, notes)
    
    if success:
        return jsonify({"message": "Event resolved"}), 200
    return jsonify({"error": "Event not found"}), 404

@admin_security_bp.route('/security-events/stats', methods=['GET'])
@jwt_required()
def get_security_stats():
    """Get security event statistics"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    stats = SecurityEventLogger.get_statistics()
    return jsonify(stats), 200

# ===== IP REPUTATION =====

@admin_security_bp.route('/ip-reputation', methods=['GET'])
@jwt_required()
def get_ip_reputation_list():
    """Get list of IP reputations"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    show_blacklisted = request.args.get('blacklisted_only', False, type=bool)
    
    query = IPReputation.query
    
    if show_blacklisted:
        query = query.filter_by(is_blacklisted=True)
    
    pagination = query.order_by(IPReputation.reputation_score.asc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'ips': [{
            'id': ip.id,
            'ip_address': ip.ip_address,
            'reputation_score': ip.reputation_score,
            'fraud_attempts': ip.fraud_attempts,
            'is_blacklisted': ip.is_blacklisted,
            'blacklist_reason': ip.blacklist_reason,
            'last_seen': ip.last_seen.isoformat() if ip.last_seen else None
        } for ip in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'page': page
    }), 200

@admin_security_bp.route('/ip-reputation/blacklist', methods=['POST'])
@jwt_required()
def blacklist_ip():
    """Manually blacklist an IP address"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    data = request.json
    ip_address = data.get('ip_address')
    reason = data.get('reason', 'Manual admin blacklist')
    
    if not ip_address:
        return jsonify({"error": "IP address required"}), 400
    
    IPReputationService.blacklist_ip(ip_address, reason)
    
    return jsonify({"message": f"IP {ip_address} blacklisted"}), 200

# ===== HONEYPOT MANAGEMENT =====

@admin_security_bp.route('/honeypots', methods=['GET'])
@jwt_required()
def get_honeypots():
    """Get list of honeypot accounts"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    from services.honeypot_service import HoneypotAccount
    
    honeypots = HoneypotAccount.query.all()
    
    return jsonify({
        'honeypots': [{
            'id': h.id,
            'email': h.email,
            'account_number': h.account_number,
            'upi_id': h.upi_id,
            'attack_count': h.attack_count,
            'last_attack_at': h.last_attack_at.isoformat() if h.last_attack_at else None
        } for h in honeypots]
    }), 200

@admin_security_bp.route('/honeypots', methods=['POST'])
@jwt_required()
def create_honeypot():
    """Create a new honeypot account"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    data = request.json
    honeypot = HoneypotService.create_honeypot(
        email=data.get('email'),
        account_number=data.get('account_number'),
        upi_id=data.get('upi_id')
    )
    
    return jsonify({
        "message": "Honeypot created",
        "honeypot": {
            'email': honeypot.email,
            'account_number': honeypot.account_number,
            'upi_id': honeypot.upi_id
        }
    }), 201

# ===== PROGRESSIVE LOCKOUT MANAGEMENT =====

@admin_security_bp.route('/users/<user_id>/lockout', methods=['POST'])
@jwt_required()
def apply_user_lockout(user_id):
    """Apply lockout to a user"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    data = request.json
    level = data.get('level', 1)
    reason = data.get('reason', 'Admin lockout')
    
    result = ProgressiveLockout.apply_lockout(user_id, level, reason)
    
    if result:
        return jsonify(result), 200
    return jsonify({"error": "User not found"}), 404

@admin_security_bp.route('/users/<user_id>/lockout/status', methods=['GET'])
@jwt_required()
def get_lockout_status(user_id):
    """Get lockout status for a user"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    status = ProgressiveLockout.get_lockout_status(user_id)
    
    if status:
        return jsonify(status), 200
    return jsonify({"error": "User not found"}), 404

# ===== DASHBOARD METRICS =====

@admin_security_bp.route('/dashboard/metrics', methods=['GET'])
@jwt_required()
def get_dashboard_metrics():
    """Get SOC dashboard metrics"""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    
    # Security event counts (last 24 hours)
    day_ago = datetime.utcnow() - timedelta(days=1)
    recent_events = SecurityEvent.query.filter(SecurityEvent.timestamp >= day_ago).count()
    critical_events = SecurityEvent.query.filter(
        SecurityEvent.severity == 'CRITICAL',
        SecurityEvent.resolved == False
    ).count()
    
    # IP reputation stats
    blacklisted_ips = IPReputation.query.filter_by(is_blacklisted=True).count()
    low_rep_ips = IPReputation.query.filter(IPReputation.reputation_score < 200).count()
    
    # User lockouts
    from sqlalchemy import or_
    locked_users = User.query.filter(
        or_(User.is_locked == True, User.lockout_level > 0)
    ).count()
    
    # Honeypot attacks
    from services.honeypot_service import HoneypotAccount
    honeypot_attacks = db.session.query(db.func.sum(HoneypotAccount.attack_count)).scalar() or 0
    
    return jsonify({
        'recent_events_24h': recent_events,
        'critical_unresolved': critical_events,
        'blacklisted_ips': blacklisted_ips,
        'low_reputation_ips': low_rep_ips,
        'locked_users': locked_users,
        'honeypot_attacks_total': honeypot_attacks
    }), 200

# ===== INTELLIGENCE ROUTES =====

@admin_security_bp.route('/intelligence/high-risk-users', methods=['GET'])
@jwt_required()
def get_high_risk_users():
    """Get high risk users based on trust score"""
    admin_check = require_admin()
    if admin_check: return admin_check
    
    users = User.query.filter(User.trust_score < 50).order_by(User.trust_score.asc()).limit(10).all()
    
    return jsonify([{
        "id": u.id,
        "email": u.email,
        "trust_score": u.trust_score,
        "is_locked": u.is_locked,
        "role": u.role
    } for u in users]), 200

@admin_security_bp.route('/intelligence/ip-analysis', methods=['GET'])
@jwt_required()
def ip_analysis():
    """Get IP analysis statistics"""
    admin_check = require_admin()
    if admin_check: return admin_check
    
    # Top suspicious IPs from transactions
    suspicious_ips = db.session.query(
        Transaction.ip_address,
        func.count(Transaction.id).label('tx_count'),
        func.sum(Transaction.amount).label('total_amount')
    ).group_by(Transaction.ip_address).order_by(desc('tx_count')).limit(10).all()
    
    return jsonify([{
        "ip": ip.ip_address,
        "count": ip.tx_count,
        "volume": ip.total_amount
    } for ip in suspicious_ips]), 200

@admin_security_bp.route('/intelligence/device-analysis', methods=['GET'])
@jwt_required()
def device_analysis():
    """Get device analysis statistics"""
    admin_check = require_admin()
    if admin_check: return admin_check
    
    # Device trust distribution
    total_devices = Device.query.count()
    trusted = Device.query.filter_by(is_trusted=True).count()
    untrusted = total_devices - trusted
    
    return jsonify({
        "total": total_devices,
        "trusted": trusted,
        "untrusted": untrusted,
        "ratio": round(trusted/total_devices, 2) if total_devices > 0 else 0
    }), 200
