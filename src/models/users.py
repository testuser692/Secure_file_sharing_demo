from datetime import datetime
from flask_login import UserMixin


def get_db():
    from config import db
    return db

class User(get_db().Model, UserMixin):
    __tablename__ = 'users'
    
    id = get_db().Column(get_db().Integer, primary_key=True)
    email = get_db().Column(get_db().String(120), unique=True, nullable=False)
    username = get_db().Column(get_db().String(60), unique=True, nullable=False)  # Added username column
    password = get_db().Column(get_db().String(60), nullable=False)
    first_name = get_db().Column(get_db().String(50), nullable=False)
    last_name = get_db().Column(get_db().String(50), nullable=False)
    phone_number = get_db().Column(get_db().String(20), nullable=True)
    is_active = get_db().Column(get_db().Boolean, default=False)  # Changed default to False
    created_at = get_db().Column(get_db().DateTime, nullable=False, default=datetime.utcnow)
    modified_at = get_db().Column(get_db().DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    biometric_data = get_db().Column(get_db().LargeBinary, nullable=True)



class OTP(get_db().Model):
    id = get_db().Column(get_db().Integer, primary_key=True)
    user_id = get_db().Column(get_db().Integer, get_db().ForeignKey('users.id'), nullable=False)
    otp = get_db().Column(get_db().String(255), nullable=False)
    created_at = get_db().Column(get_db().DateTime, nullable=False, default=datetime.utcnow)