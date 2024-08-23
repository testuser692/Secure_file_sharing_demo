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



class EncryptedFile(get_db().Model):
    id = get_db().Column(get_db().Integer, primary_key=True)
    user_id = get_db().Column(get_db().Integer, get_db().ForeignKey('users.id'), nullable=False)
    email = get_db().Column(get_db().String(120), nullable=False)
    filename = get_db().Column(get_db().String(120), nullable=False)
    file_size = get_db().Column(get_db().Integer, nullable=False)
    file_type = get_db().Column(get_db().Text, nullable=False)
    encrypted_content = get_db().Column(get_db().LargeBinary, nullable=False)
    symmetric_key = get_db().Column(get_db().String(256), nullable=False)
    timestamp = get_db().Column(get_db().DateTime, default=datetime.utcnow)

    def __init__(self, email, user_id, filename, file_size, file_type, encrypted_content, symmetric_key):
        self.email = email
        self.user_id = user_id  
        self.filename = filename
        self.file_size = file_size
        self.file_type = file_type
        self.encrypted_content = encrypted_content
        self.symmetric_key = symmetric_key
