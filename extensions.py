from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail
from flask_jwt_extended import JWTManager

# Initialize extensions
db = SQLAlchemy()
mail = Mail()
jwt = JWTManager()

# Use memory storage (No Redis)
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")