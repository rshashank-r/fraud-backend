"""
Database Index Migration Script
Adds critical indexes to improve query performance for admin panel
"""
from extensions import db
from sqlalchemy import text
import sys

def add_indexes():
    """Add performance-critical indexes to the database"""
    
    indexes = [
        {
            "name": "idx_transaction_timestamp",
            "table": "transaction",
            "column": "timestamp",
            "description": "Index for time-based queries"
        },
        {
            "name": "idx_transaction_timestamp_status",
            "table": "transaction",
            "columns": ["timestamp", "status"],
            "description": "Composite index for filtered time-based queries"
        },
        {
            "name": "idx_transaction_risk_score",
            "table": "transaction",
            "column": "risk_score",
            "description": "Index for risk-based filtering"
        },
        {
            "name": "idx_transaction_user_id",
            "table": "transaction",
            "column": "user_id",
            "description": "Index for user-based queries"
        },
        {
            "name": "idx_auditlog_timestamp",
            "table": "audit_log",
            "column": "timestamp",
            "description": "Index for audit log time-based queries"
        },
        {
            "name": "idx_notification_created_at",
            "table": "notification",
            "column": "created_at",
            "description": "Index for notification time-based queries"
        }
    ]
    
    try:
        print("🔧 Starting database index migration...")
        
        for idx in indexes:
            try:
                # Check if index exists
                check_query = text(f"""
                    SELECT COUNT(*) 
                    FROM pg_indexes 
                    WHERE indexname = '{idx['name']}'
                """)
                
                result = db.session.execute(check_query).scalar()
                
                if result > 0:
                    print(f"✅ Index {idx['name']} already exists, skipping...")
                    continue
                
                # Create index
                if 'columns' in idx:
                    # Composite index
                    columns = ', '.join(idx['columns'])
                    create_query = text(f"""
                        CREATE INDEX {idx['name']} 
                        ON {idx['table']} ({columns})
                    """)
                else:
                    # Single column index
                    create_query = text(f"""
                        CREATE INDEX {idx['name']} 
                        ON {idx['table']} ({idx['column']})
                    """)
                
                print(f"📝 Creating index: {idx['name']} - {idx['description']}")
                db.session.execute(create_query)
                db.session.commit()
                print(f"✅ Successfully created index: {idx['name']}")
                
            except Exception as e:
                print(f"⚠️ Warning: Could not create index {idx['name']}: {str(e)}")
                db.session.rollback()
                continue
        
        print("\n🎉 Database index migration completed!")
        print("📊 Verifying indexes...")
        
        # Verify indexes
        verify_query = text("""
            SELECT indexname, tablename 
            FROM pg_indexes 
            WHERE indexname LIKE 'idx_%'
            ORDER BY tablename, indexname
        """)
        
        results = db.session.execute(verify_query).fetchall()
        print(f"\n✅ Found {len(results)} custom indexes:")
        for idx_name, table_name in results:
            print(f"   - {table_name}.{idx_name}")
        
        return True
        
    except Exception as e:
        print(f"❌ Migration failed: {str(e)}")
        db.session.rollback()
        return False

if __name__ == "__main__":
    from app import app
    
    with app.app_context():
        success = add_indexes()
        sys.exit(0 if success else 1)
