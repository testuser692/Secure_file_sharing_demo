import time
import io
import pickle
import random
import hashlib
import logging as logger
from http import HTTPStatus
from flask import current_app
from datetime import timedelta
from dotenv import load_dotenv
from flask_mail import  Message
from config import db, bcrypt, mail
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.utils import secure_filename
from src.controller.users_controller import *
from itsdangerous import URLSafeTimedSerializer 
from cryptography.hazmat.primitives import padding
from src.models.users import User,OTP,EncryptedFile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask_jwt_extended import create_access_token ,verify_jwt_in_request,decode_token,get_jwt
from flask import Blueprint, request, render_template, redirect, url_for, session,flash,send_file

load_dotenv()


users = Blueprint('users', __name__)

@users.route('/user_registration', methods=['POST', 'GET'])
def user_registration():
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            phone_number = request.form.get('contact_no')
            profile_image = request.files.get('profile_image')

            logger.info(f"Received registration data: {request.form}")

            if not email or not password:
                logger.warning("Email or password is missing.")
                return render_template(
                    'registerasuser.html',
                    response={'status': HTTPStatus.BAD_REQUEST, 'message': 'Email and password are required.'}
                ), HTTPStatus.BAD_REQUEST

            is_valid, validation_message = validate_password_strength(password)
            if not is_valid:
                logger.warning(f"Password validation failed: {validation_message}")
                return render_template(
                    'registerasuser.html',
                    response={'status': HTTPStatus.BAD_REQUEST, 'message': validation_message}
                ), HTTPStatus.BAD_REQUEST

            existing_user = get_user_by_email(email)
            if existing_user:
                logger.warning("User already exists.")
                return render_template(
                    'registerasuser.html',
                    response={'status': HTTPStatus.BAD_REQUEST, 'message': 'User already exists.'}
                ), HTTPStatus.BAD_REQUEST

            try:
                # Generate the username
                random_number = random.randint(1000, 9999)
                username = f"{first_name.lower()}{last_name.lower()}{random_number}"

                user = create_user(email, password, first_name, last_name, phone_number, username=username, is_active=False)

                if not user:
                    db.session.rollback()
                    logger.error("User creation failed.")
                    return render_template(
                        'registerasuser.html',
                        response={'status': HTTPStatus.INTERNAL_SERVER_ERROR, 'message': 'An error occurred while creating the user.'}
                    ), HTTPStatus.INTERNAL_SERVER_ERROR

                if profile_image:
                    profile_image_path = save_profile_image(profile_image)
                    user.biometric_data = profile_image.read()

                db.session.commit()
                logger.info("User creation successful.")

                # Generate email confirmation token
                s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
                token = s.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])
                confirm_url = url_for('users.confirm_email', token=token, _external=True)
                msg = Message("Email Confirmation Request", sender=os.getenv('EMAIL_USER'), recipients=[email])
                msg.html = f"""
                    <html>
                    <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
                        <div style="max-width: 600px; margin: auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);">
                        <h2 style="text-align: center; color: #333;">Confirm Your Email Address</h2>
                        <p style="font-size: 16px; color: #555;">
                            Hello,
                        </p>
                        <p style="font-size: 16px; color: #555;">
                            Thank you for signing up with SecureApp! To complete your registration, please confirm your email address by clicking the link below:
                        </p>
                        <p style="text-align: center;">
                            <a href="{confirm_url}" style="display: inline-block; padding: 12px 24px; font-size: 16px; color: #ffffff; background-color: #007bff; border-radius: 4px; text-decoration: none;">Confirm Email</a>
                        </p>
                        <p style="font-size: 16px; color: #555;">
                            If you did not make this request, simply ignore this email and no changes will be made.
                        </p>
                        <p style="font-size: 16px; color: #555;">
                            Regards,<br>
                            The SecureApp Team
                        </p>
                        </div>
                    </body>
                    </html>
                """
                try:
                    mail.send(msg)
                    response = generate_response(
                        success=True,
                        status=HTTPStatus.OK,
                        message='If an account with that email exists, a confirmation email has been sent.'
                    )

                    return redirect(url_for('users.login'))
                except Exception as e:
                    response = generate_response(
                        status=HTTPStatus.INTERNAL_SERVER_ERROR,
                        message='Failed to send email.',
                        errors=str(e)
                    )
                    return render_template('registerasuser.html', response=response), HTTPStatus.INTERNAL_SERVER_ERROR

            except SQLAlchemyError as e:
                db.session.rollback()
                logger.exception("SQLAlchemy error occurred during registration.")
                return render_template(
                    'registerasuser.html',
                    response={'status': HTTPStatus.INTERNAL_SERVER_ERROR, 'message': 'An error occurred during registration.', 'errors': str(e)}
                ), HTTPStatus.INTERNAL_SERVER_ERROR

        except Exception as e:
            logger.exception("Exception occurred during registration.")
            return render_template(
                'registerasuser.html',
                response={'status': HTTPStatus.INTERNAL_SERVER_ERROR, 'message': 'An error occurred during registration.', 'errors': str(e)}
            ), HTTPStatus.INTERNAL_SERVER_ERROR

    return render_template('registerasuser.html'), HTTPStatus.OK

@users.route('/confirm_email/<token>', methods=['GET', 'POST'])
def confirm_email(token):
    response = generate_response()
    try:
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            email = s.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
        except Exception as e:
            response = generate_response(
                status=HTTPStatus.BAD_REQUEST,
                message='The confirmation link is invalid or has expired.',
                errors=str(e)
            )
            return render_template('confirm_email.html', response=response), HTTPStatus.BAD_REQUEST

        user = get_user_by_email(email)
        if user:
            if user.is_active:
                response = generate_response(
                    success=True,
                    status=HTTPStatus.OK,
                    message='Your email has already been confirmed!'
                )
                return render_template('confirm_email.html', response=response), HTTPStatus.OK

            # Activate the user account
            user.is_active = True
            db.session.commit()

            # Send email with generated username
            try:          
                msg = Message("Account Activated", sender=os.getenv('EMAIL_USER'), recipients=[email])
                msg.html = f"""
                    <html>
                        <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
                            <div style="max-width: 600px; margin: auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
                                <h2 style="color: #333333; text-align: center;">Account Activated</h2>
                                <p style="color: #555555; font-size: 16px;">
                                    Dear <strong>{user.first_name}</strong>,
                                </p>
                                <p style="color: #555555; font-size: 16px;">
                                    Congratulations! Your account has been successfully activated.
                                </p>
                                <p style="color: #555555; font-size: 16px;">
                                    Your username is: <strong>{user.username}</strong>
                                </p>
                                <p style="color: #555555; font-size: 16px;">
                                    Thank you for registering with us. We're excited to have you on board!
                                </p>
                                <p style="color: #555555; font-size: 16px;">
                                    Best regards,<br>
                                    <strong>The SecureApp Team</strong>
                                </p>
                            </div>
                        </body>
                    </html>
                """
                mail.send(msg)

                response = generate_response(
                    success=True,
                    status=HTTPStatus.OK,
                    message='Your email has been confirmed and your account is now active. A confirmation email with your username has been sent.'
                )
            except Exception as e:
                response = generate_response(
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                    message='Email confirmation was successful, but failed to send the username email.',
                    errors=str(e)
                )
                return render_template('confirm_email.html', response=response), HTTPStatus.INTERNAL_SERVER_ERROR

            return render_template('confirm_email.html', response=response), HTTPStatus.OK
        else:
            response = generate_response(
                status=HTTPStatus.NOT_FOUND,
                message='User does not exist.'
            )
            return render_template('confirm_email.html', response=response), HTTPStatus.NOT_FOUND
    except Exception as e:
        response = generate_response(
            status=HTTPStatus.INTERNAL_SERVER_ERROR,
            message='An error occurred during email confirmation.',
            errors=str(e)
        )
        return render_template('confirm_email.html', response=response), HTTPStatus.INTERNAL_SERVER_ERROR


@users.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    response = generate_response()
    try:
        if request.method == 'POST':
            data = request.form  
            email = data.get('email')

            if not email or not validate_email_format(email):
                response = generate_response(
                    status=HTTPStatus.BAD_REQUEST,
                    message='Invalid email format.'
                )
                return render_template('forgot_password.html', response=response), HTTPStatus.BAD_REQUEST

            user = get_user_by_email(email)
            if user:
                s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
                token = s.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])
                reset_url = url_for('users.reset_password', token=token, _external=True)
                msg = Message("Password Reset Request", sender=os.getenv('EMAIL_USER'), recipients=[email])
                msg.html = f"""
                    <html>
                        <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
                            <div style="max-width: 600px; margin: auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
                                <h2 style="color: #333333; text-align: center;">Password Reset Request</h2>
                                <p style="color: #555555; font-size: 16px;">
                                    To reset your password, click the button below:
                                </p>
                                <p style="text-align: center;">
                                    <a href="{reset_url}" style="display: inline-block; padding: 10px 20px; font-size: 16px; color: #ffffff; background-color: #007bff; text-decoration: none; border-radius: 5px;">
                                        Reset Password
                                    </a>
                                </p>
                                <p style="color: #555555; font-size: 16px;">
                                    If the button above doesn't work, you can also reset your password by clicking on the following link: <a href="{reset_url}" style="color: #007bff;">{reset_url}</a>
                                </p>
                                <p style="color: #555555; font-size: 16px;">
                                    If you did not request a password reset, please ignore this email. No changes will be made to your account.
                                </p>
                                <p style="color: #555555; font-size: 16px;">
                                    If you have any questions, feel free to contact our support team.
                                </p>
                                <p style="color: #555555; font-size: 16px;">
                                    Best regards,<br>
                                    <strong>The Support Team</strong>
                                </p>
                            </div>
                        </body>
                    </html>
                """
                try:
                    mail.send(msg)
                    response = generate_response(
                        success=True,
                        status=HTTPStatus.OK,
                        message='If an account with that email exists, a password reset email has been sent.'
                    )
                    return render_template('forgot_password.html', response=response), HTTPStatus.OK
                except Exception as e:
                    response = generate_response(
                        status=HTTPStatus.INTERNAL_SERVER_ERROR,
                        message='Failed to send email.',
                        errors=str(e)
                    )
                    return render_template('forgot_password.html', response=response), HTTPStatus.INTERNAL_SERVER_ERROR
            else:
                response = generate_response(
                    status=HTTPStatus.NOT_FOUND,
                    message='No account found with that email address.'
                )
                return render_template('forgot_password.html', response=response), HTTPStatus.NOT_FOUND
    except Exception as e:
        response = generate_response(
            status=HTTPStatus.INTERNAL_SERVER_ERROR,
            message='An error occurred while processing your request.',
            errors=str(e)
        )
        return render_template('forgot_password.html', response=response), HTTPStatus.INTERNAL_SERVER_ERROR

    return render_template('forgot_password.html', response=response), HTTPStatus.OK


@users.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    response = generate_response()
    if request.method == 'POST':
        try:
            data = request.form
            new_password = data.get('password')

            if not validate_password_strength(new_password):
                response = generate_response(
                    status=HTTPStatus.BAD_REQUEST,
                    message='Password does not meet strength requirements.'
                )
                return render_template('reset_password.html', response=response), HTTPStatus.BAD_REQUEST

            s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
            try:
                email = s.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
            except Exception as e:
                response = generate_response(
                    status=HTTPStatus.BAD_REQUEST,
                    message='The reset link is invalid or has expired.',
                    errors=str(e)
                )
                return render_template('reset_password.html', response=response), HTTPStatus.BAD_REQUEST

            user = get_user_by_email(email)
            if user:
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                user.password = hashed_password
                db.session.commit()
                response = generate_response(
                    success=True,
                    status=HTTPStatus.OK,
                    message='Your password has been updated!'
                )
                return render_template('reset_password.html', response=response), HTTPStatus.OK
            else:
                response = generate_response(
                    status=HTTPStatus.NOT_FOUND,
                    message='User does not exist.'
                )
                return render_template('reset_password.html', response=response), HTTPStatus.NOT_FOUND
        except Exception as e:
            response = generate_response(
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
                message='An error occurred during password reset.',
                errors=str(e)
            )
            return render_template('reset_password.html', response=response), HTTPStatus.INTERNAL_SERVER_ERROR

    return render_template('reset_password.html', response=response)
   
@users.route('/change_password', methods=['GET', 'POST'])
def change_password():
    response = generate_response()
    # JWT verification
    try:
        access_token = session.get('access_token')
        if not access_token:
            response = generate_response(
                status=HTTPStatus.UNAUTHORIZED,
                message='Access token not found in session.'
            )
            return render_template('change_password.html', response=response), HTTPStatus.UNAUTHORIZED

        try:
            # Manually verify the JWT token from the session
            verify_jwt_in_request(optional=True)
            decoded_token = decode_token(access_token)
        except Exception as e:
            response = generate_response(
                status=HTTPStatus.UNAUTHORIZED,
                message='Invalid token or authentication required.'
            )
            return render_template('change_password.html', response=response), HTTPStatus.UNAUTHORIZED

        # Get the current user identity
        current_user_id = decoded_token['sub']
        logger.info(f"current_user: {current_user_id}")
    except Exception as e:
        response = generate_response(
            status=HTTPStatus.INTERNAL_SERVER_ERROR,
            message='An error occurred during JWT verification.',
            errors=str(e)
        )
        logger.error(f"Exception occurred during JWT verification: {str(e)}")
        return render_template('change_password.html', response=response), HTTPStatus.INTERNAL_SERVER_ERROR

    if request.method == 'POST':
        try:
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_new_password = request.form.get('confirm_new_password')

            # Check for missing data
            if not current_password or not new_password or not confirm_new_password:
                print(True)
                response = generate_response(
                    status=HTTPStatus.BAD_REQUEST,
                    message='Missing required fields.'
                )
                return render_template('change_password.html', response=response), HTTPStatus.BAD_REQUEST
            
            user = get_user_by_id(current_user_id['id'])
            # user = User.query.filter_by(id=current_user_id['id']).first_or_404()
            # Check if user exists and current password is correct
            if user and bcrypt.check_password_hash(user.password, current_password):
                print("if the current password and new password")
                # Validate new password strength
                if not validate_password_strength(new_password):
                    response = generate_response(
                        status=HTTPStatus.BAD_REQUEST,
                        message='New password does not meet strength requirements.'
                    )
                    return render_template('change_password.html', response=response), HTTPStatus.BAD_REQUEST
                
                # Check if new password and confirm password match
                if new_password != confirm_new_password:
                    response = generate_response(
                        status=HTTPStatus.BAD_REQUEST,
                        message='New password and confirm password do not match.'
                    )
                    return render_template('change_password.html', response=response), HTTPStatus.BAD_REQUEST
                
                # Update user password
                if update_user_password(user, new_password):
                    response = generate_response(
                        success=True,
                        status=HTTPStatus.OK,
                        message='Password changed successfully.'
                    )
                    logger.info(f"Password changed successfully for user {current_user_id}.")
                    return render_template('change_password.html', response=response), HTTPStatus.OK
                else:
                    response = generate_response(
                        status=HTTPStatus.INTERNAL_SERVER_ERROR,
                        message='An error occurred while updating the password.'
                    )
                    logger.error(f"Failed to update password for user {current_user_id}.")
                    return render_template('change_password.html', response=response), HTTPStatus.INTERNAL_SERVER_ERROR
            else:
                response = generate_response(
                    status=HTTPStatus.UNAUTHORIZED,
                    message='Current password is incorrect.'
                )
                logger.warning(f"Invalid current password attempt for user {current_user_id}.")
                return render_template('change_password.html', response=response), HTTPStatus.UNAUTHORIZED
        except Exception as e:
            response = generate_response(
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
                message='An error occurred during the password change process.',
                errors=str(e)
            )
            logger.error(f"Exception occurred during password change: {str(e)}")
            return render_template('change_password.html', response=response), HTTPStatus.INTERNAL_SERVER_ERROR
    
    return render_template('change_password.html', response=response), HTTPStatus.OK


@users.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        logger.info("Entered login POST method")
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            logger.info(f"Received email: {email}")

            if not email or not password:
                response = generate_response(
                    status=HTTPStatus.BAD_REQUEST,
                    message='Missing required fields.'
                )
                return render_template('login.html', response=response), HTTPStatus.BAD_REQUEST

            if not validate_email_format(email):
                response = generate_response(
                    status=HTTPStatus.BAD_REQUEST,
                    message='Invalid email format.'
                )
                return render_template('login.html', response=response), HTTPStatus.BAD_REQUEST

            user = User.query.filter_by(email=email).first()
            if user:
                if not user.is_active:
                    response = generate_response(
                        status=HTTPStatus.UNAUTHORIZED,
                        message='Account not activated. Please verify your email first.'
                    )
                    logger.warning(f"Attempted login with unactivated account: {email}.")
                    return render_template('login.html', response=response), HTTPStatus.UNAUTHORIZED

                if bcrypt.check_password_hash(user.password, password):
                    otp = random.randint(100000, 999999)
                    otp_hash = hashlib.sha256(str(otp).encode()).hexdigest()
                    otp_entry = OTP(user_id=user.id, otp=otp_hash, created_at=datetime.utcnow())
                    db.session.add(otp_entry)
                    db.session.commit()

                    msg = Message("Email Confirmation OTP", sender=os.getenv('EMAIL_USER'), recipients=[email])
                    msg.html = f"""
                            <html>
                                <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
                                    <div style="max-width: 600px; margin: auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
                                        <h2 style="color: #333333; text-align: center;">Email Confirmation OTP</h2>
                                        <p style="color: #555555; font-size: 16px; text-align: center;">
                                            Your OTP for email verification is:
                                        </p>
                                        <div style="text-align: center; margin: 20px 0;">
                                            <div style="display: inline-block; background-color: #007bff; color: #ffffff; padding: 15px 20px; border-radius: 5px;">
                                                <h1 style="margin: 0; font-size: 36px;">{otp}</h1>
                                            </div>
                                        </div>
                                        <p style="color: #555555; font-size: 16px; text-align: center;">
                                            <span style="display: inline-block; vertical-align: middle;">
                                                
                                            This OTP will expire in <strong>10 minutes</strong>.
                                        </p>
                                        <p style="color: #555555; font-size: 16px; text-align: center;">
                                            If you did not request this OTP, please disregard this email. No changes will be made to your account.
                                        </p>
                                        <p style="color: #555555; font-size: 16px; text-align: center;">
                                            Thank you,<br>
                                            <strong>The SecureApp Team</strong>
                                        </p>
                                    </div>
                                </body>
                            </html>
                        """
                    mail.send(msg)

                    # flash('A confirmation email has been sent with an OTP.', 'info')
                    return redirect(url_for('users.verify_otp', user_id=user.id))

            response = generate_response(
                status=HTTPStatus.UNAUTHORIZED,
                message='Login Unsuccessful. Please check email and password.'
            )
            logger.warning(f"Failed login attempt for email {email}.")
            return render_template('login.html', response=response), HTTPStatus.UNAUTHORIZED

        except Exception as e:
            response = generate_response(
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
                message='An error occurred during login.',
                errors=str(e)
            )
            logger.error(f"Exception occurred during login: {str(e)}")
            return render_template('login.html', response=response), HTTPStatus.INTERNAL_SERVER_ERROR

    return render_template('login.html'), HTTPStatus.OK


@users.route('/verify_otp', methods=['POST', 'GET'])
def verify_otp():
    if request.method == 'POST':
        try:
            user_id = request.form.get('user_id')
            otp = request.form.get('otp')

            if not otp:
                response = {
                    'status': 'danger',
                    'message': 'Missing required fields.'
                }
                return render_template('verify_otp.html', response=response, user_id=user_id, username=session.get('username')), HTTPStatus.BAD_REQUEST

            otp_hash = hashlib.sha256(str(otp).encode()).hexdigest()
            otp_entry = OTP.query.filter_by(user_id=user_id).first()

            if otp_entry:
                otp_entry.otp = otp_hash
                otp_entry.created_at = datetime.utcnow()
            else:
                otp_entry = OTP(user_id=user_id, otp=otp_hash, created_at=datetime.utcnow())
                db.session.add(otp_entry)

            db.session.commit()

            if otp_entry and (datetime.utcnow() - otp_entry.created_at) < timedelta(minutes=10):
                user = User.query.get(user_id)
                access_token = create_access_token(
                    identity={'id': user.id, 'email': user.email, 'username': user.username},
                    expires_delta=timedelta(hours=24)
                )
                session['access_token'] = access_token

                flash('Login successful.', 'success')
                return redirect(url_for('users.home'))

            else:
                response = {
                    'status': 'danger',
                    'message': 'Invalid OTP or OTP has expired.'
                }
                return render_template('verify_otp.html', response=response, user_id=user_id, username=session.get('username')), HTTPStatus.UNAUTHORIZED

        except Exception as e:
            response = {
                'status': 'danger',
                'message': 'An error occurred during OTP verification.',
                'errors': str(e)
            }
            return render_template('verify_otp.html', response=response, user_id=user_id, username=session.get('username')), HTTPStatus.INTERNAL_SERVER_ERROR

    user_id = request.args.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            session['user_email'] = user.email
            session['username'] = user.username
            print(f"DEBUG: Retrieved username: {user.username}")  # Debug statement

        else:
            flash('User not found.', 'danger')
            return redirect(url_for('users.login'))

    session['user_id'] = user_id
    username = session.get('username')
    email_id = session.get('user_email')
    return render_template('verify_otp.html', user_id=user_id, username=username, email=email_id), HTTPStatus.OK

nimgs = 15

@users.route('/add', methods=['GET', 'POST'])
def add():
    if request.method == 'POST':
        try:
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            email = request.form.get('email')
            contact_no = request.form.get('contact_no')
            password = request.form.get('password')

            if not first_name or not last_name or not contact_no:
                return render_template(
                    'face_capture.html',
                    response={'status': HTTPStatus.BAD_REQUEST, 'message': 'First name, last name, and contact number are required.'}
                ), HTTPStatus.BAD_REQUEST

            # Generate a random 4-digit number and create the username
            random_digits = str(random.randint(1000, 9999))
            newusername = f"{first_name}_{last_name}_{random_digits}"
            newuserid = contact_no

            userimagefolder = f'static/faces/{newusername}_{newuserid}'
            if not os.path.isdir(userimagefolder):
                os.makedirs(userimagefolder)

            i, j = 0, 0
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                print("Error: Could not open video capture.")
                return render_template(
                    'face_capture.html',
                    response={'status': HTTPStatus.INTERNAL_SERVER_ERROR, 'message': 'Camera initialization failed.'}
                ), HTTPStatus.INTERNAL_SERVER_ERROR

            while True:
                ret, frame = cap.read()
                if not ret or frame is None or frame.size == 0:
                    print("Error: Frame is empty or not captured correctly.")
                    break

                height, width = frame.shape[:2]
                if width <= 0 or height <= 0:
                    print("Error: Frame dimensions are invalid.")
                    break

                faces = extract_faces(frame)
                for (x, y, w, h) in faces:
                    cv2.rectangle(frame, (x, y), (x + w, y + h), (255, 0, 20), 2)
                    cv2.putText(frame, f'Images Captured: {i}/{nimgs}', (30, 30),
                                cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 0, 20), 2, cv2.LINE_AA)
                    if j % 5 == 0:
                        name = f"{newusername}_{i}.jpg"
                        cv2.imwrite(f'{userimagefolder}/{name}', frame[y:y+h, x:x+w])
                        i += 1
                    j += 1
                if j == nimgs * 5:
                    break

                cv2.imshow('Register the user face', frame)
                if cv2.waitKey(1) == 27:  # Exit on 'ESC' key
                    break

            cap.release()
            cv2.destroyAllWindows()

            # Assuming train_model() trains a model and returns it
            model = train_model()

            # Save the model as a .pkl file
            pkl_data = pickle.dumps(model)

            # Save user details to the database, including the .pkl file data
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(
                email=email,
                username=newusername,
                password=hashed_password,
                first_name=first_name,
                last_name=last_name,
                phone_number=contact_no,
                biometric_data=pkl_data
            )
            db.session.add(user)
            db.session.commit()

            # Assume extract_attendance is a function that retrieves attendance information
            first_names, last_names, contact_nos, times, l = extract_biometric_data()

            return render_template('login_with_face.html', names=first_names, rolls=contact_nos, times=times, l=l, totalreg=totalreg(), datetoday2=datetoday2)

        except Exception as e:
            # Log the exception and return an error response
            logger.exception("Exception occurred during user addition.")
            return render_template(
                'face_capture.html',
                response={'status': HTTPStatus.INTERNAL_SERVER_ERROR, 'message': 'An error occurred during user addition.', 'errors': str(e)}
            ), HTTPStatus.INTERNAL_SERVER_ERROR

    return render_template('face_capture.html'), HTTPStatus.OK

@users.route('/start', methods=['GET', 'POST'])
def start():
    if request.method == 'POST':
        # Extract login form data
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Query the database for the user
        user = User.query.filter_by(email=email).first()
        
        # Check if the user exists and if the password is correct
        if user and bcrypt.check_password_hash(user.password, password):
            # Start face recognition
            cap = cv2.VideoCapture(0)
            start_time = time.time()
            recognized = False

            while time.time() - start_time < 20:  # 20-second timeout
                ret, frame = cap.read()
                if not ret:
                    continue
                
                faces = extract_faces(frame)
                if len(faces) > 0:
                    (x, y, w, h) = faces[0]
                    cv2.rectangle(frame, (x, y), (x+w, y+h), (86, 32, 251), 1)
                    cv2.rectangle(frame, (x, y), (x+w, y-40), (86, 32, 251), -1)
                    face = cv2.resize(frame[y:y+h, x:x+w], (50, 50))
                    identified_person = identify_face(face.reshape(1, -1))[0]

                    # Handle multiple underscores in the identified person string
                    parts = identified_person.split('_')
                    if len(parts) > 1:
                        first_name = ' '.join(parts[:-1])  # Join all parts except the last as first name
                        last_name = parts[-1]  # Last part as last name
                    else:
                        first_name = identified_person
                        last_name = ''

                    # Add attendance using first_name and last_name
                    add_biomatric(f'{first_name}_{last_name}', '', '', '')

                    recognized = True
                    break
                
                cv2.imshow('Face verificatuion', frame)
                if cv2.waitKey(1) == 27:  # ESC key pressed
                    break

            cap.release()
            cv2.destroyAllWindows()

            if recognized:
                # Generate JWT token with 24 hours expiration
                access_token = create_access_token(
                    identity={'id': user.id, 'email': user.email},
                    expires_delta=timedelta(hours=24)
                )
                # Store token in session
                session['access_token'] = access_token

                flash('Login successful.', 'success')
                return redirect(url_for('users.home'))
            else:
                flash('Face recognition failed or timed out. Please try again.', 'danger')
                return redirect(url_for('users.start'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')
            return redirect(url_for('users.start'))

    return render_template('login_with_face.html')  #

@users.route('/home')
def home():
    try:
        access_token = session.get('access_token')
        if not access_token:
            response = generate_response(
                status=HTTPStatus.UNAUTHORIZED,
                message='Access token not found in session.'
            )
            return render_template('login.html', response=response), HTTPStatus.UNAUTHORIZED

        try:
            verify_jwt_in_request(optional=True)
            decoded_token = decode_token(access_token)
        except Exception as e:
            response = generate_response(
                status=HTTPStatus.UNAUTHORIZED,
                message='Invalid token or authentication required.'
            )
            return render_template('login.html', response=response), HTTPStatus.UNAUTHORIZED

        current_user = decoded_token['sub']
        logger.error(f"current_user: {current_user}")

        if not current_user:
            response = generate_response(
                status=HTTPStatus.UNAUTHORIZED,
                message='Authentication required.'
            )
            return render_template('login.html', response=response), HTTPStatus.UNAUTHORIZED
        
        user_id = current_user.get('id')
        email_id = session.get("user_email")
        username = session.get('username')
        print(f"home:page {username}")
        return render_template('home.html',username=username,email_id=email_id)

    except Exception as e:
        return render_template('login.html', response=response), HTTPStatus.UNAUTHORIZED
    
#====================================================================================================

@users.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    user_id = session.get('user_id')
    user_email = session.get('user_email')
    username = session.get('username')
    email_id = session.get('user_email')
    recieved_files = EncryptedFile.query.filter_by(email=user_email).all()

    # Print the filenames (for debugging purposes)
    for file in recieved_files:
        print(file.filename)

    # Get files belonging to the user and convert sizes to KB
    files = EncryptedFile.query.filter_by(user_id=user_id).all()
    for file in files:
        size_kb = float(file.file_size)
        file.file_size = size_kb / 1024

    message = None
    status = None

    if request.method == 'POST':
        email = request.form['email']

        if verify_email_in_db(email):
            message = 'Email verified. Please upload your file.'
            status = HTTPStatus.OK
            return render_template('encrypt.html', email_verified=True, email=email, files=files, message=message, status=status)
        else:
            message = 'Email not found in the database.'
            status = HTTPStatus.NOT_FOUND
            return render_template('encrypt.html', email_verified=False, files=files, message=message, status=status)

    return render_template('encrypt.html', email_verified=False, files=files, message=message, status=status,username=username,email_id=email_id)

@users.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        response = {
            'status': HTTPStatus.BAD_REQUEST,
            'message': 'No file part in the request.'
        }
        return render_template('encrypt.html', response=response), HTTPStatus.BAD_REQUEST

    file = request.files['file']
    email = request.form['email']

    if file.filename == '':
        response = {
            'status': HTTPStatus.BAD_REQUEST,
            'message': 'No selected file.'
        }
        return render_template('encrypt.html', response=response), HTTPStatus.BAD_REQUEST

    # Retrieve the user by email
    user = User.query.filter_by(email=email).first()
    if not user:
        response = {
            'status': HTTPStatus.NOT_FOUND,
            'message': 'User not found.'
        }
        return render_template('encrypt.html', response=response), HTTPStatus.NOT_FOUND

    username = user.username
    user_id = session.get('user_id')

    if file:
        # Secure the filename
        filename = secure_filename(file.filename)

        # Specify the directory where files will be saved
        upload_folder = os.path.join('uploads', str(user_id))

        # Create the directory if it doesn't exist
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        # Save the file to the directory
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)

        # Read the file content
        with open(file_path, 'rb') as f:
            file_content = f.read()

        file_size = len(file_content)
        file_type = file.content_type

        # Encrypt the file content
        symmetric_key = generate_symmetric_key()
        encrypted_content = encrypt_file(file_content, symmetric_key)

        # Save the encrypted content back to a file in the directory
        encrypted_file_path = os.path.join(upload_folder, filename + '.enc')
        with open(encrypted_file_path, 'wb') as enc_file:
            enc_file.write(encrypted_content)

        # Store the encrypted file information in the database
        new_file = EncryptedFile(
            email=email,
            user_id=user_id,
            filename=filename,
            file_size=file_size,
            file_type=file_type,
            encrypted_content=encrypted_content,
            symmetric_key=symmetric_key
        )
        db.session.add(new_file)
        db.session.commit()

        # Send the encrypted file via email
        sender_email = os.getenv('EMAIL_USER')
        sender_password = os.getenv('EMAIL_PASS')
        subject = "Encrypted File"
        
        # Update the email body to include the username
        body_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        color: #333;
                        line-height: 1.6;
                    }}
                    .container {{
                        padding: 20px;
                        background-color: #f4f4f4;
                        border-radius: 10px;
                        margin: 0 auto;
                        max-width: 600px;
                    }}
                    h1 {{
                        color: #4CAF50;
                    }}
                    p {{
                        font-size: 16px;
                    }}
                    .message {{
                        padding: 15px;
                        background-color: #e7f3fe;
                        border-left: 6px solid #2196F3;
                        margin-bottom: 20px;
                        border-radius: 5px;
                    }}
                    .key {{
                        background-color: #f8f9fa;
                        padding: 10px;
                        border-radius: 4px;
                        font-family: monospace;
                        font-size: 14px;
                        word-wrap: break-word;
                    }}
                    footer {{
                        margin-top: 30px;
                        font-size: 12px;
                        color: #777;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Hello {username}!</h1>
                    <div class="message">
                        <p>Your file has been successfully encrypted and attached to this email.</p>
                        <p>Here is your symmetric encryption key for decryption:</p>
                        <div class="key">
                            {symmetric_key}
                        </div>
                    </div>
                    <footer>
                        <p>If you have any issues or questions, feel free to reach out to our support team.</p>
                        <p>Thank you for using our secure file encryption service!</p>
                    </footer>
                </div>
            </body>
            </html>
                        """
        send_html_email_with_attachment(sender_email, sender_password, email, subject, body_html, encrypted_content, filename + '.enc')

        response = {
            'status': HTTPStatus.OK,
            'message': 'File uploaded, encrypted, saved, and emailed successfully!'
        }
        return render_template('home.html', response=response), HTTPStatus.OK

    response = {
        'status': HTTPStatus.INTERNAL_SERVER_ERROR,
        'message': 'An error occurred during file processing.'
    }
    return render_template('encrypt.html', response=response), HTTPStatus.INTERNAL_SERVER_ERROR

@users.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    user_id = session.get('user_id')
    username = session.get('username')
    email_id = session.get('user_email')

    # Retrieve the received files for the user
    received_files = EncryptedFile.query.filter_by(email=email_id).all()

    # Check if any files are available for decryption
    if received_files:
        # Decrypt each file and pass them to the template
        for file in received_files:
            try:
                #decrypt_file() # Ensure you're passing the correct file to the decryption function
                pass
            except Exception as e:
                # Log the error or handle it appropriately
                print(f"Error decrypting file {file.filename}: {e}")

        # Pass the list of decrypted files to the template
        return render_template('decrypt.html', email_verified=True, files=received_files,username=username,email_id=email_id)
    else:
        # No files found for the user
        return render_template('decrypt.html', email_verified=False, files=[])
    
@users.route('/process_decryption', methods=['POST'])
def process_decryption():
    symmetric_key = request.form.get('symmetric_key')
    uploaded_file = request.files.get('file')

    if not symmetric_key or not uploaded_file:
        flash("Symmetric key and file are required for decryption.", "error")
        return redirect(url_for('users.decrypt'))

    try:
        # Read the encrypted file content
        encrypted_file_content = uploaded_file.read()

        # Decrypt the file content
        decrypted_file_content = decrypt_files(encrypted_file_content, symmetric_key)

        # Determine the original file extension from the uploaded file name
        original_filename = uploaded_file.filename
        if original_filename.endswith('.enc'):
            # Assume the original extension was stored in the file name before .enc
            base_filename = original_filename[:-4]  # Remove the ".enc" extension
            original_extension = os.path.splitext(base_filename)[1]  # Extract the original extension
        else:
            # If no original extension is found, use a default or handle as needed
            original_extension = ''
        # Save the decrypted file with the original extension
        decrypted_file_path = os.path.join(os.getenv('decrypted_file_path'), f'decrypted_file{original_extension}')
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_file_content)

        # Return the decrypted file as a response
        return send_file(
            decrypted_file_content,
            as_attachment=True,
            download_name=f'decrypted_file{original_extension}'
        )
    except Exception as e:
        flash(f"Error during decryption: {str(e)}", "error")
        return redirect(url_for('users.decrypt'))


#==================================================================================================================
revoked_tokens = set()

@users.route('/logout', methods=['GET'])
def logout():
    try:
        access_token = session.get('access_token')
        if not access_token:
            response = generate_response(
                status=HTTPStatus.UNAUTHORIZED,
                message='You need to login first!'
            )
            return render_template('login.html', response=response), HTTPStatus.UNAUTHORIZED

        # Verify and decode the JWT token
        verify_jwt_in_request(optional=True)
        decoded_token = decode_token(access_token)
        current_user = decoded_token.get('sub')

        if not current_user:
            response = generate_response(
                status=HTTPStatus.UNAUTHORIZED,
                message='Authentication required.'
            )
            return render_template('login.html', response=response), HTTPStatus.UNAUTHORIZED

        # Get the JWT ID (jti) from the current token
        jti = get_jwt().get('jti')
        print(200*"8")

        # Check if the token is already revoked
        if jti in revoked_tokens:
            return render_template('login.html', success=False, status=HTTPStatus.BAD_REQUEST, message='Token has already been revoked.'), HTTPStatus.BAD_REQUEST

        # Add the token to the blacklist
        revoked_tokens.add(jti)
        logger.info(f"Token {jti} successfully added to blacklist.")

        # Clear the session
        session.pop('access_token', None)

        return redirect(url_for('users.login'))

    except Exception as e:
        logger.error(f"Exception occurred during logout: {str(e)}")
        return render_template('login.html', success=False, status=HTTPStatus.INTERNAL_SERVER_ERROR, message='An error occurred while logging out.', errors={'general': str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR
#================================================================================================================================