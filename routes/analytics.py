from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import func
from extensions import db
from models import Transaction, User
from datetime import datetime, timedelta
from sqlalchemy import extract

analytics_bp = Blueprint('analytics', __name__)

# ✅ FIXED: Changed from optional=True to required JWT
@analytics_bp.route('/dashboard', methods=['GET', 'OPTIONS'])
@jwt_required()  # ✅ Changed from @jwt_required(optional=True)
def get_dashboard():
    """Main dashboard endpoint"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        current_month = datetime.now().month
        current_year = datetime.now().year
        
        # Statistics
        total_tx = Transaction.query.filter_by(user_id=user_id).count()
        
        monthly_spend = db.session.query(func.sum(Transaction.amount))\
            .filter(
                Transaction.user_id == user_id,
                Transaction.status == 'SUCCESS',
                extract('month', Transaction.timestamp) == current_month,
                extract('year', Transaction.timestamp) == current_year
            ).scalar() or 0
        
        pending_tx = Transaction.query.filter_by(user_id=user_id, status='PENDING').count()
        failed_tx = Transaction.query.filter_by(user_id=user_id, status='FAILED').count()
        
        return jsonify({
            "balance": float(user.balance) if user.balance else 0,
            "total_transactions": total_tx,
            "monthly_spending": float(monthly_spend),
            "pending_transactions": pending_tx,
            "failed_transactions": failed_tx,
            "trust_score": user.trust_score or 100,
            "account_status": "locked" if user.is_locked else "active"
        }), 200
        
    except Exception as e:
        print(f"❌ Dashboard error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Failed to fetch dashboard data", "message": str(e)}), 500

@analytics_bp.route('/dashboard/monthly-expenses', methods=['GET', 'OPTIONS'])
@jwt_required()  # ✅ Changed from @jwt_required(optional=True)
def get_monthly_expenses():
    """Get monthly expenses by category"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        user_id = get_jwt_identity()
        
        # Get current month transactions
        current_month = datetime.now().month
        current_year = datetime.now().year
        
        # Query transactions grouped by transaction_type
        expenses = db.session.query(
            Transaction.transaction_type,
            func.sum(Transaction.amount).label('total')
        ).filter(
            Transaction.user_id == user_id,
            extract('month', Transaction.timestamp) == current_month,
            extract('year', Transaction.timestamp) == current_year,
            Transaction.status == 'SUCCESS'
        ).group_by(Transaction.transaction_type).all()
        
        # If no data, return sample categories with 0
        if not expenses or len(expenses) == 0:
            return jsonify([
                {'category': 'UPI', 'amount': 0, 'percentage': 0, 'color': '#3b82f6'},
                {'category': 'Card', 'amount': 0, 'percentage': 0, 'color': '#8b5cf6'},
                {'category': 'Online Banking', 'amount': 0, 'percentage': 0, 'color': '#10b981'},
                {'category': 'Others', 'amount': 0, 'percentage': 0, 'color': '#f59e0b'}
            ]), 200
        
        # Calculate total for percentages
        total_spending = sum([float(exp.total) for exp in expenses])
        
        # Category mapping with colors
        category_colors = {
            'upi': {'name': 'UPI', 'color': '#3b82f6'},
            'card': {'name': 'Card', 'color': '#8b5cf6'},
            'debit_card': {'name': 'Debit Card', 'color': '#8b5cf6'},
            'credit_card': {'name': 'Credit Card', 'color': '#a855f7'},
            'online_banking': {'name': 'Online Banking', 'color': '#10b981'},
            'wallet': {'name': 'Wallet', 'color': '#f59e0b'},
            'transfer': {'name': 'Transfer', 'color': '#06b6d4'}
        }
        
        result = []
        for expense in expenses:
            tx_type = (expense.transaction_type or 'others').lower()
            category_info = category_colors.get(tx_type, {'name': 'Others', 'color': '#64748b'})
            amount = float(expense.total)
            percentage = (amount / total_spending * 100) if total_spending > 0 else 0
            
            result.append({
                'category': category_info['name'],
                'amount': round(amount, 2),
                'percentage': round(percentage, 2),
                'color': category_info['color']
            })
        
        # Sort by amount (highest first)
        result.sort(key=lambda x: x['amount'], reverse=True)
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"❌ Monthly expenses error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': 'Failed to fetch expenses',
            'message': str(e)
        }), 500

@analytics_bp.route('/yearly-summary', methods=['GET'])
@jwt_required()
def get_yearly_summary():
    """Get yearly transaction summary grouped by month"""
    try:
        user_id = get_jwt_identity()
        current_year = datetime.now().year
        
        # Query monthly sums
        monthly_data = db.session.query(
            extract('month', Transaction.timestamp).label('month'),
            func.sum(Transaction.amount).label('total')
        ).filter(
            Transaction.user_id == user_id,
            extract('year', Transaction.timestamp) == current_year,
            Transaction.status == 'SUCCESS'
        ).group_by(extract('month', Transaction.timestamp)).all()
        
        # Initialize all months with 0
        months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
        result = [{'name': m, 'amount': 0} for m in months]
        
        # Fill data
        for data in monthly_data:
            month_idx = int(data.month) - 1
            if 0 <= month_idx < 12:
                result[month_idx]['amount'] = float(data.total)
                
        return jsonify(result), 200
    except Exception as e:
        print(f"❌ Yearly summary error: {str(e)}")
        return jsonify({"error": "Failed to fetch yearly summary"}), 500
