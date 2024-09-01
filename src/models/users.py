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
    is_active = get_db().Column(get_db().Boolean, default=False)  
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

class Chat(get_db().Model):
    id = get_db().Column(get_db().Integer, primary_key=True)
    user_id = get_db().Column(get_db().Integer, get_db().ForeignKey('users.id'), nullable=False)
    user = get_db().relationship('User', backref=get_db().backref('chats', lazy=True))
    chat_list = get_db().Column(get_db().JSON, nullable=False, default=list)

    def save_to_db(self):
        get_db().session.add(self)
        get_db().session.commit()

class Message(get_db().Model):
    __tablename__ = 'messages'
    id = get_db().Column(get_db().Integer, primary_key=True)
    room_id = get_db().Column(get_db().String(50), nullable=False, unique=True)
    messages = get_db().relationship('ChatMessage', backref='message', lazy=True)

    def save_to_db(self):
        get_db().session.add(self)
        get_db().session.commit()
class ChatMessage(get_db().Model):
    id = get_db().Column(get_db().Integer, primary_key=True)
    content = get_db().Column(get_db().String(400))
    timestamp = get_db().Column(get_db().String(20), nullable=False)
    sender_id = get_db().Column(get_db().Integer, nullable=False)
    sender_username = get_db().Column(get_db().String(50), nullable=False)
    room_id = get_db().Column(get_db().String(50), get_db().ForeignKey('messages.room_id'), nullable=False)

    def save_to_db(self):
        get_db().session.add(self)
        get_db().session.commit()