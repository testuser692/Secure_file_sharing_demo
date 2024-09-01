from flask import Flask
from flask_mail import Mail
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from config.settings import DevelopmentConfig
import os
from datetime import date
from flask_socketio import SocketIO
from flask_cors import CORS

datetoday = date.today().strftime("%m_%d_%y")
datetoday2 = date.today().strftime("%d-%B-%Y")

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'users.login'
login_manager.login_message_category = 'info'
mail = Mail()
socket = SocketIO()
cors = CORS()

def create_app(config_class=DevelopmentConfig):
    from src.models.users import User  # Only import User model

    app = Flask(__name__, template_folder='templates')
    app.config.from_object(config_class)
    jwt = JWTManager(app)

    db.init_app(app)
    mail.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    socket.init_app(app, cors_allowed_origins="*")
    cors.init_app(app)

     # Configuration for folders
    UPLOAD_FOLDER = 'uploads'
    ENCRYPTED_FOLDER = 'encrypted_files'

    # Ensure upload and encrypted folders exist
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['ENCRYPTED_FOLDER'] = ENCRYPTED_FOLDER

    from src.views.users import users as users_blueprint
    app.register_blueprint(users_blueprint)
    
    from src.views.chat import views
    app.register_blueprint(views)


    return app,socket

@login_manager.user_loader
def load_user(id):
    from src.models.users import User
    return User.query.get(int(id))
