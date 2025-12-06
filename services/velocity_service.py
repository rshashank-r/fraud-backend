from datetime import datetime, timedelta

# In-memory storage replacement for Redis
# Structure: { "user_id": { "count": 1, "expires_at": datetime } }
MEMORY_STORE = {}

class VelocityService:
    @staticmethod
    def increment_and_check(user_id, limit_per_minute=5):
        """
        Checks velocity using python dictionary instead of Redis.
        """
        now = datetime.utcnow()
        record = MEMORY_STORE.get(user_id)

        # 1. If record doesn't exist or has expired, start new window
        if not record or now > record['expires_at']:
            MEMORY_STORE[user_id] = {
                "count": 1,
                "expires_at": now + timedelta(minutes=1)
            }
            return False, 1

        # 2. Check if limit is reached
        if record['count'] >= limit_per_minute:
            return True, record['count'] # Limit Exceeded

        # 3. Increment count
        record['count'] += 1
        return False, record['count']

    @staticmethod
    def reset_counter(user_id):
        if user_id in MEMORY_STORE:
            del MEMORY_STORE[user_id]