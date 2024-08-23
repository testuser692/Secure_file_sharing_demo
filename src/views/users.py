import logging as logger
from http import HTTPStatus
from flask import current_app
from datetime import timedelta
from flask_mail import  Message
from config import db, bcrypt, mail
from sqlalchemy.exc import SQLAlchemyError
from src.controller.users_controller import * 
from src.models.users import User,OTP
from itsdangerous import URLSafeTimedSerializer
from flask_jwt_extended import create_access_token ,verify_jwt_in_request,decode_token
from flask import Blueprint, request, render_template, redirect, url_for, session, Response,flash,send_file
import random
import hashlib
import pickle
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

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
            phone_number = request.form.get('phone_number')
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
                msg.body = f"To confirm your email, click the following link: {confirm_url}\n\nIf you did not make this request, simply ignore this email and no changes will be made."

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
                msg.body = f"Dear {user.first_name},\n\nYour account has been successfully activated! Your username is: {user.username}\n\nThank you for registering with us."
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
                msg.body = f"To reset your password, click the following link: {reset_url}\n\nIf you did not make this request, simply ignore this email and no changes will be made."

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

                    msg = Message("Email Confirmation OTP", sender="sheetaljain756@gmail.com", recipients=[email])
                    msg.body = f"Your OTP for email verification is: {otp}\n\nIf you did not make this request, simply ignore this email."
                    mail.send(msg)

                    flash('A confirmation email has been sent with an OTP.', 'info')
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
                return render_template('verify_otp.html', response=response, user_id=user_id), HTTPStatus.BAD_REQUEST

            otp_hash = hashlib.sha256(str(otp).encode()).hexdigest()
            otp_entry = OTP.query.filter_by(user_id=user_id).first()

            if otp_entry:
                # Update the existing OTP entry
                otp_entry.otp = otp_hash
                otp_entry.created_at = datetime.utcnow()
            else:
                # Create a new OTP entry
                otp_entry = OTP(user_id=user_id, otp=otp_hash, created_at=datetime.utcnow())
                db.session.add(otp_entry)

            db.session.commit()

            # Validate OTP
            if otp_entry and (datetime.utcnow() - otp_entry.created_at) < timedelta(minutes=10):
                user = User.query.get(user_id)
                access_token = create_access_token(
                    identity={'id': user.id, 'email': user.email},
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
                return render_template('verify_otp.html', response=response, user_id=user_id), HTTPStatus.UNAUTHORIZED

        except Exception as e:
            response = {
                'status': 'danger',
                'message': 'An error occurred during OTP verification.',
                'errors': str(e)
            }
            return render_template('verify_otp.html', response=response, user_id=user_id), HTTPStatus.INTERNAL_SERVER_ERROR

    user_id = request.args.get('user_id')
    return render_template('verify_otp.html', user_id=user_id), HTTPStatus.OK




# @users.route('/capture_face', methods=['POST'])
# def capture_face():
#     try:
#         user_id = request.form.get('user_id')
#         face_image = request.files.get('face_image')
        
#         # Process the face image and encode it
#         encoded_face = encode_face(face_image)
        
#         # Store the encoded face in the database
#         user = get_user_by_id(user_id)
#         if user:
#             user.face_encoding = encoded_face
#             user.is_active = True
#             db.session.commit()
#             return redirect(url_for('users.login'))
#         else:
#             response = generate_response(
#                 status=HTTPStatus.NOT_FOUND,
#                 message='User does not exist.'
#             )
#             return render_template('face_capture.html', response=response), HTTPStatus.NOT_FOUND
#     except Exception as e:
#         logger.exception("Exception occurred during face capture.")
#         response = generate_response(
#             status=HTTPStatus.INTERNAL_SERVER_ERROR,
#             message='An error occurred during face capture.',
#             errors=str(e)
#         )
#         return render_template('face_capture.html', response=response), HTTPStatus.INTERNAL_SERVER_ERROR


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
            while True:
                _, frame = cap.read()
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
                cv2.imshow('Adding new User', frame)
                if cv2.waitKey(1) == 27:
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
            # db_session = get_db().session
            db.session.add(user)
            # db_session.add(user)
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
                
                cv2.imshow('Attendance', frame)
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

    return render_template('login_with_face.html')  # Assuming there's a login.html for the login form

# @users.route('/start', methods=['GET'])
# def start():
#     first_names, last_names, contact_nos, times, l = extract_attendance()

#     if 'face_recognition_model.pkl' not in os.listdir('static'):
#         return render_template(
#             'home.html', 
#             first_names=first_names, 
#             last_names=last_names, 
#             contact_nos=contact_nos, 
#             times=times, 
#             l=l, 
#             totalreg=totalreg(), 
#             datetoday2=datetoday2, 
#             mess='There is no trained model in the static folder. Please add a new face to continue.'
#         )

#     ret = True
#     cap = cv2.VideoCapture(0)
#     while ret:
#         ret, frame = cap.read()
#         faces = extract_faces(frame)
#         if len(faces) > 0:
#             (x, y, w, h) = faces[0]
#             cv2.rectangle(frame, (x, y), (x+w, y+h), (86, 32, 251), 1)
#             cv2.rectangle(frame, (x, y), (x+w, y-40), (86, 32, 251), -1)
#             face = cv2.resize(frame[y:y+h, x:x+w], (50, 50))
#             identified_person = identify_face(face.reshape(1, -1))[0]

#             # Handle multiple underscores in the identified person string
#             parts = identified_person.split('_')
#             if len(parts) > 1:
#                 first_name = ' '.join(parts[:-1])  # Join all parts except the last as first name
#                 last_name = parts[-1]  # Last part as last name
#             else:
#                 first_name = identified_person
#                 last_name = ''

#             # Add attendance using first_name and last_name
#             add_attendance(f'{first_name}_{last_name}', '', '', '')

#             cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 0, 255), 1)
#             cv2.rectangle(frame, (x, y), (x+w, y+h), (50, 50, 255), 2)
#             cv2.rectangle(frame, (x, y-40), (x+w, y), (50, 50, 255), -1)
#             cv2.putText(frame, f'{identified_person}', (x, y-15), cv2.FONT_HERSHEY_COMPLEX, 1, (255, 255, 255), 1)
#             cv2.rectangle(frame, (x, y), (x+w, y+h), (50, 50, 255), 1)
        
#         imgBackground[162:162 + 480, 55:55 + 640] = frame
#         cv2.imshow('Attendance', imgBackground)
#         if cv2.waitKey(1) == 27:
#             break
#     cap.release()
#     cv2.destroyAllWindows()

#     first_names, last_names, contact_nos, times, l = extract_attendance()
#     return render_template(
#         'home.html', 
#         first_names=first_names, 
#         last_names=last_names, 
#         contact_nos=contact_nos, 
#         times=times, 
#         l=l, 
#         totalreg=totalreg(), 
#         datetoday2=datetoday2
#     )
# @users.route('/login', methods=['POST', 'GET'])
# def login():
#     if request.method == 'POST':
#         logger.info("Entered login POST method")
#         response = generate_response()
#         try:
#             email = request.form.get('email')
#             password = request.form.get('password')
#             logger.info(f"Received email: {email} and password")

#             if not email or not password:
#                 response = generate_response(
#                     status=HTTPStatus.BAD_REQUEST,
#                     message='Missing required fields.'
#                 )
#                 return render_template('login.html', response=response), HTTPStatus.BAD_REQUEST

#             if not validate_email_format(email):
#                 response = generate_response(
#                     status=HTTPStatus.BAD_REQUEST,
#                     message='Invalid email format.'
#                 )
#                 return render_template('login.html', response=response), HTTPStatus.BAD_REQUEST

#             user = User.query.filter_by(email=email).first()
#             if user and bcrypt.check_password_hash(user.password, password):
#                 if user:
#                     otp = random.randint(100000, 999999)
#                     otp_entry = OTP(user_id=user.id, otp=otp, created_at=datetime.utcnow())
#                     db.session.add(otp_entry)
#                     db.session.commit()

#                     msg = Message("Email Confirmation OTP", sender="sheetaljain756@gmail.com", recipients=[email])
#                     msg.body = f"Your OTP for email verification is: {otp}\n\nIf you did not make this request, simply ignore this email."
#                     mail.send(msg)

#                     flash('A confirmation email has been sent with an OTP.', 'info')
#                     return redirect(url_for('users.verify_otp', user_id=user.id))

#                 access_token = create_access_token(
#                     identity={'id': user.id, 'email': user.email},
#                     expires_delta=timedelta(hours=24)  
#                 )
#                 session['access_token'] = access_token
#                 response = generate_response(
#                     success=True,
#                     status=HTTPStatus.OK,
#                     message='Login successful.'
#                 )
#                 logger.info(f"User {user.email} logged in successfully.")
#                 return redirect(url_for('users.verify_otp'))
#             else:
#                 response = generate_response(
#                     status=HTTPStatus.UNAUTHORIZED,
#                     message='Login Unsuccessful. Please check email and password.'
#                 )
#                 logger.warning(f"Failed login attempt for email {email}.")
#                 return render_template('login.html', response=response), HTTPStatus.UNAUTHORIZED
#         except Exception as e:
#             response = generate_response(
#                 status=HTTPStatus.INTERNAL_SERVER_ERROR,
#                 message='An error occurred during login.',
#                 errors=str(e)
#             )
#             logger.error(f"Exception occurred during login: {str(e)}")
#             return render_template('login.html', response=response), HTTPStatus.INTERNAL_SERVER_ERROR

#     return render_template('login.html'), HTTPStatus.OK


# @users.route('/verify_otp', methods=['GET', 'POST'])
# def verify_otp():
#     if request.method == 'POST':
#         otp = request.form.get('otp')
#         user_id = request.form.get('user_id')
        
#         otp_entry = OTP.query.filter_by(user_id=user_id, otp=otp).first()
#         if otp_entry and otp_entry.created_at > datetime.utcnow() - timedelta(minutes=10):
#             user = User.query.get(user_id)
#             user.is_active = True
#             db.session.commit()
#             flash('Your email has been confirmed!', 'success')
#             return redirect(url_for('users.home'))
#         else:
#             flash('Invalid or expired OTP.', 'danger')
#             return render_template('verify_otp.html', user_id=user_id)

#     return render_template('verify_otp.html')



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
        
        role = current_user.get('role')
        user_id = current_user.get('id')
        return render_template('home.html')

    except Exception as e:
        return render_template('login.html', response=response), HTTPStatus.UNAUTHORIZED
    


# UPLOAD_FOLDER = 'uploads'
# ENCRYPTED_FOLDER = 'encrypted_files'

# # Ensure upload and encrypted folders exist
# os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

# current_app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# current_app.config['ENCRYPTED_FOLDER'] = ENCRYPTED_FOLDER
# Mock Database of Emails
# emails_db = ['test@example.com', 'krishna@example.com', 'user@example.com']


# # AES encryption settings
# AES_KEY = os.urandom(32)  # 256-bit key for AES-256
# AES_IV = os.urandom(16)  # 128-bit IV

# def encrypt_file(filepath, filename):
#     # Read the file data
#     with open(filepath, 'rb') as f:
#         file_data = f.read()

#     # Pad the data for AES block size (128 bits)
#     padder = padding.PKCS7(algorithms.AES.block_size).padder()
#     padded_data = padder.update(file_data) + padder.finalize()

#     # Create AES cipher
#     cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=default_backend())
#     encryptor = cipher.encryptor()
    
#     # Encrypt the data
#     encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

#     # Save the encrypted data to a new file
#     encrypted_filename = f'encrypted_{filename}'
#     encrypted_filepath = os.path.join(current_app.config['ENCRYPTED_FOLDER'], encrypted_filename)
    
#     with open(encrypted_filepath, 'wb') as f:
#         f.write(AES_IV + encrypted_data)  # Save IV + encrypted data
    
#     return encrypted_filepath


# def decrypt_file(filepath, filename):
#     try:
#         # Read the encrypted file data
#         with open(filepath, 'rb') as f:
#             file_data = f.read()

#         # Extract the IV and encrypted data
#         iv = file_data[:16]
#         encrypted_data = file_data[16:]

#         # Create AES cipher for decryption
#         cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
#         decryptor = cipher.decryptor()

#         # Decrypt the data
#         decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

#         # Unpad the decrypted data
#         unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
#         decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

#         # Save the decrypted file
#         decrypted_filename = f'decrypted_{filename}'
#         decrypted_filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], decrypted_filename)
        
#         with open(decrypted_filepath, 'wb') as f:
#             f.write(decrypted_data)
        
#         return decrypted_filepath

#     except Exception as e:
#         print(f"Error during decryption: {e}")
#         return None




# @users.route('/', methods=['GET', 'POST'])
# def index():
#     if request.method == 'POST':
#         email = request.form.get('email')
#         if email in emails_db:
#             flash('Email verified ✅', 'success')
#             return render_template('uploadfile.html', email_verified=True)
#         else:
#             flash('Email not found ❌', 'danger')
#     return render_template('uploadfile.html', email_verified=False)

# # @users.route('/upload', methods=['POST'])
# # def upload():
# #     file = request.files['file']
# #     # Logic to encrypt and send the file via email goes here.
# #     flash('File uploaded and sent successfully.', 'success')
# #     return redirect(url_for('users.index'))
# @users.route('/upload', methods=['POST'])
# def upload():
#     file = request.files['file']
#     if file:
#         filename = secure_filename(file.filename)
#         filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
#         file.save(filepath)
        
#         # Encrypt the file
#         encrypted_filepath = encrypt_file(filepath, filename)
        
#         # Check if the encrypted file exists before sending
#         if os.path.exists(encrypted_filepath):
#             flash('File encrypted and uploaded successfully.', 'success')
#             return redirect(url_for('users.index'))
#         else:
#             flash('File not found after encryption.', 'danger')
#             return redirect(url_for('users.index'))



# @users.route('/decrypt', methods=['GET', 'POST'])
# def decrypt():
#     # Debugging - Log request method
#     print(f"Request method: {request.method}")

#     # Handle GET request
#     if request.method == 'GET':
#         return render_template('decrypt.html')  # Return a valid response, e.g., render a template

#     # Handle POST request
#     if request.method == 'POST':
#         # Check if a file was uploaded in the request
#         if 'file' not in request.files:
#             flash('No file part in the request.', 'danger')
#             return redirect(url_for('users.index'))

#         file = request.files['file']

#         if file.filename == '':
#             flash('No selected file.', 'danger')
#             return redirect(url_for('users.index'))

#         if file:
#             # Secure the filename to prevent directory traversal attacks
#             filename = secure_filename(file.filename)

#             # Define the file path to save the encrypted file
#             filepath = os.path.join(current_app.config['ENCRYPTED_FOLDER'], filename)
#             file.save(filepath)

#             # Call the decrypt_file function to handle the file decryption
#             decrypted_filepath = decrypt_file(filepath, filename)

#             if decrypted_filepath:
#                 # File decrypted successfully, send it to the user
#                 flash('File decrypted successfully.', 'success')
#                 return send_file(decrypted_filepath, as_attachment=True)
#             else:
#                 flash('Error during decryption.', 'danger')

#         # Redirect to index if the decryption fails
#         return redirect(url_for('users.index'))

#     # If no valid method is matched, return a default response
#     return redirect(url_for('users.index'))
