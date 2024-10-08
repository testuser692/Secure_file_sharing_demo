import os
import re
import cv2
import csv
import joblib
import base64
import smtplib
import mimetypes
import numpy as np
import pandas as pd
from config import db, bcrypt
from dotenv import load_dotenv
from src.models.users import User
from config.settings import Config
from datetime import datetime, date
from cryptography.fernet import Fernet
from email.message import EmailMessage
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import padding
from sklearn.neighbors import KNeighborsClassifier
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


load_dotenv()

# Configuration for file uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB limit

media_directory = os.getenv('MEDIA_PATH')
media_path = os.path.join(media_directory, 'profile_image','default.png')

def generate_response(success=False, status='', data=None, message='', errors=None):
    """
    Generate a standardized response format.
    """
    response = {
        'success': success,
        'status': status,
        'message': message,
    }

    if data is not None:
        response['data'] = data

    if errors:
        response['errors'] = errors

    return response


def validate_email_format(email):
    """
    Validate the format of an email address using a regular expression.
    """
    email_regex = re.compile(
        r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    )
    return bool(email_regex.match(email))

def validate_password_strength(password):
    """
    Validate password strength requirements.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter."
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit."
    if not re.search(r'[@$!%*?&]', password):
        return False, "Password must contain at least one special character."
    return True, ""


def create_user(email, password, first_name, last_name, phone_number,username, is_active):
    from config import db
    from src.models.users import User  # Assuming the User model is defined in models.py
    
    hashed_password =  bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(
        email=email,
        password=hashed_password,
        first_name=first_name,
        last_name=last_name,
        phone_number=phone_number,
        username = username,
        is_active=is_active,
        created_at=datetime.utcnow(),
        modified_at=datetime.utcnow()
    )
    db.session.add(user)
    return user


def get_user_by_email(email):
    """
    Retrieve a user from the database by email.
    """
    try:
        user = User.query.filter_by(email=email).first()
        return user
    except Exception as e:
        print(f"Error occurred while querying the user: {e}")
        return None

def get_user_by_id(user_id):
    """
    Retrieve a user from the database by ID.
    """
    try:
        user = User.query.get(user_id)
        return user
    except Exception as e:
        print(f"Error occurred while querying the user by ID: {e}")
        return None

def update_user_password(user, new_password):
    """
    Update the password for a user.
    """
    try:
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        return True
    except Exception as e:
        print(f"Error occurred while updating the password: {e}")
        db.session.rollback()
        return False

def save_profile_image(file):
    """
    Save the uploaded profile image file and return the file path.
    """
    # Define the upload folder
    upload_folder = os.path.join(media_directory, 'profile_image')

    # Ensure the directory exists
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)
    
    # Secure the filename and create the file path
    filename = secure_filename(file.filename)
    filepath = os.path.join(upload_folder, filename)
    
    # Save the file
    try:
        file.save(filepath)
        return filepath
    except Exception as e:
        print(f"Failed to save file {filename}: {str(e)}")
        return None

def allowed_file(filename):
    """
    Check if the file extension is allowed.
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def encode_face(image_path):
    # Load the image
    image = cv2.imread(image_path)
    
    # Convert the image to grayscale
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    
    # Load OpenCV's pre-trained face detector
    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
    
    # Detect faces in the image
    faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))
    
    if len(faces) == 0:
        return None  # No face detected
    
    # Extract the face region
    x, y, w, h = faces[0]  # Use the first detected face
    face = gray[y:y+h, x:x+w]
    
    # Flatten the face image to create a 1D array
    face_encoding = face.flatten()
    
    # Encode the face data as a base64 string
    encoded_face = base64.b64encode(face_encoding).decode('utf-8')
    
    return encoded_face

face_detector = cv2.CascadeClassifier('/home/ubuntu/secure_message_file_sharing_app/src/controller/haarcascade_frontalface_default.xml')

datetoday = date.today().strftime("%m_%d_%y")
datetoday2 = date.today().strftime("%d-%B-%Y")

def totalreg():
    return len(os.listdir('static/faces'))

def extract_faces(img):
    try:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        face_points = face_detector.detectMultiScale(gray, 1.2, 5, minSize=(20, 20))
        return face_points
    except Exception as e:
        print(f"Error extracting faces: {e}")
        return []


def identify_face(facearray):
    model = joblib.load('static/face_recognition_model.pkl')
    return model.predict(facearray)


def train_model():
    faces = []
    labels = []
    userlist = os.listdir('static/faces')
    for user in userlist:
        for imgname in os.listdir(f'static/faces/{user}'):
            img = cv2.imread(f'static/faces/{user}/{imgname}')
            resized_face = cv2.resize(img, (50, 50))
            faces.append(resized_face.ravel())
            labels.append(user)
    faces = np.array(faces)
    knn = KNeighborsClassifier(n_neighbors=5)
    knn.fit(faces, labels)
    joblib.dump(knn, 'static/face_recognition_model.pkl')

def extract_biometric_data():
    df = pd.read_csv(f'BiometricData/BiometricData-{datetoday}.csv')
    first_names = df['First Name']
    last_names = df['Last Name']
    contact_nos = df['Contact No']
    times = df['Time']
    l = len(df)
    return first_names, last_names, contact_nos, times, l


def add_biomatric(name, arg2, arg3, arg4):
    username = name.split('_')[0]
    userid = name.split('_')[1]
    current_time = datetime.now().strftime("%H:%M:%S")

    df = pd.read_csv(f'BiometricData/BiometricData-{datetoday}.csv')
    
    # Replace 'userid' with the correct column name, e.g., 'Contact No'
    if int(userid) not in list(df['Contact No']):  # Ensure 'Contact No' is the correct column
        with open(f'BiometricData/BiometricData-{datetoday}.csv', 'a') as f:
            f.write(f'\n{username},{userid},{current_time}')

def getallusers():
    userlist = os.listdir('static/faces')
    first_names = []
    last_names = []
    contact_nos = []
    l = len(userlist)

    for user in userlist:
        first_name, last_name = user.split('_')
        first_names.append(first_name)
        last_names.append(last_name)
        contact_no = user.split('_')[2] if len(user.split('_')) > 2 else ''
        contact_nos.append(contact_no)

    return userlist, first_names, last_names, contact_nos, l


def add_biomatric_information(name, email, contact_no, biometric_data):
    file_path = 'biometric_information.csv'
    
    # Ensure the file exists and has a header
    if not os.path.isfile(file_path):
        with open(file_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Name', 'Email', 'Contact No', 'Biometric Data', 'Date Added'])
    
    # Write the biometric information record
    with open(file_path, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([name, email, contact_no, biometric_data, datetime.now().strftime('%Y-%m-%d %H:%M:%S')])


# Ensure directories exist and initialize the attendance CSV file
if not os.path.isdir('BiometricData'):
    os.makedirs('BiometricData')
if not os.path.isdir('static'):
    os.makedirs('static')
if not os.path.isdir('static/faces'):
    os.makedirs('static/faces')
if f'BiometricData-{datetoday}.csv' not in os.listdir('BiometricData'):
    with open(f'BiometricData/BiometricData-{datetoday}.csv', 'w') as f:
        f.write('First Name,Last Name,Email,Contact No,Password,Time\n')

#===============================================================
SYMMETRIC_KEY_STORE = {}
# Generate a symmetric key for AES encryption
def generate_symmetric_key():
    key = Fernet.generate_key()
    return key

# Encrypt the file content using AES
def encrypt_file(file_content, symmetric_key):
    fernet = Fernet(symmetric_key)
    encrypted_file_content = fernet.encrypt(file_content)
    return encrypted_file_content

# Decrypt the file content using AES
def decrypt_file(encrypted_file_content, symmetric_key):
    fernet = Fernet(symmetric_key)
    decrypted_file_content = fernet.decrypt(encrypted_file_content)
    return decrypted_file_content

# Send the HTML email with an attachment
def send_html_email_with_attachment(sender_email, sender_password, receiver_email, subject, body_html, attachment_content, attachment_name):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg.set_content("This is a plain text fallback.")
    msg.add_alternative(body_html, subtype='html')

    mime_type, _ = mimetypes.guess_type(attachment_name)
    if mime_type is None:
        mime_type, mime_subtype = 'application', 'octet-stream'
    else:
        mime_type, mime_subtype = mime_type.split('/')

    msg.add_attachment(attachment_content, maintype=mime_type, subtype=mime_subtype, filename=attachment_name)
    MAIL_SERVER = os.getenv('MAIL_SERVER')
    with smtplib.SMTP(MAIL_SERVER, 587) as smtp:
        smtp.starttls()
        smtp.login(sender_email, sender_password)
        smtp.send_message(msg)

        
def verify_email_in_db(email):
    user = User.query.filter_by(email=email).first()  # Retrieve the first result if it exists
    if user:
        print(f"Email {email} exists in the database.")
    else:
        print(f"Email {email} does not exist in the database.")
    return user is not None  # Return True if the user exists, otherwise False


# Decrypt the file content using Fernet
def decrypt_files(encrypted_file_content, symmetric_key):
    # Convert symmetric key to bytes
    symmetric_key = symmetric_key.encode()  # Convert to bytes if it's in string format
    
    # Create Fernet instance
    fernet = Fernet(symmetric_key)
    
    # Decrypt the file content
    decrypted_file_content = fernet.decrypt(encrypted_file_content)
    return decrypted_file_content



def encrypt_message(key, plaintext):
    iv = os.urandom(16)  # Initialization Vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding the plaintext to be a multiple of block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_message(key, ciphertext):
    ciphertext = base64.b64decode(ciphertext.encode())
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(actual_ciphertext) + decryptor.finalize()

    # Removing padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data.decode()