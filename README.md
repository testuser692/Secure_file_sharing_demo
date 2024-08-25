# Secure P2P Messaging and File Sharing System

## Project Overview
This project is a secure peer-to-peer (P2P) messaging and file-sharing system with end-to-end encryption, user authentication, access controls, and audit trails. The application is built using Flask (backend), Flask templates (frontend), PostgreSQL (database), and cryptographic libraries like AES and RSA.

## Project Structure
The following is the project structure:
```├── src/
│   ├── controller/
│   │   ├── users_controller.py
│   │   ├── file_controller.py   # Handles file encryption and sharing routes
│   │   └── chat_controller.py   # Handles P2P chat functionalities
│   ├── models/
│   │   ├── users.py
│   │   ├── otp.py
│   │   └── file.py              # Database model for tracking file uploads
│   ├── templates/
│   │   ├── registerasuser.html
│   │   ├── login.html
│   │   ├── confirm_email.html
│   │   ├── forgot_password.html
│   │   ├── reset_password.html
│   │   ├── verify_otp.html
│   │   ├── upload_file.html      # HTML template for file upload
│   │   ├── file_list.html        # Displays list of received files
│   │   └── chat.html             # Chat UI template
├── static/
│   ├── css/
│   │   └── styles.css            
├── config.py
├── app.py
├── README.md
├── requirements.txt
└── .env


```

### Key Files and Directories:
- **app/**: Contains the Flask application files.
  - **models.py**: Defines the database models.
  - **routes.py**: Contains all route handlers (e.g., registration, login, messaging).
  - **utils.py**: Utility functions (e.g., encryption, decryption).
- **config/**: Configuration files (e.g., database, environment configurations).
- **static/**: Static files such as CSS and JavaScript.
- **templates/**: HTML templates for rendering frontend views.
- **.env**: Environment variables for sensitive information.
- **requirements.txt**: Lists Python dependencies.

## Environment Variables
The following environment variables need to be configured in the `.env` file:
```
FLASK_APP=app
FLASK_ENV=development
SECRET_KEY=your_secret_key
DATABASE_URL=postgresql://user@localhost/dbname
FACE_RECOGNITION_MODEL_PATH=path_to_model
ENCRYPTION_KEY=your_encryption_key
JWT_SECRET=your_jwt_secret
SMTP_SERVER=smtp.example.com
EMAIL_USER=email@example.com
EMAIL_PASSWORD=your_email_password
```

### Explanation of Variables:
- **SECRET_KEY**: Used for Flask session encryption.
- **DATABASE_URL**: PostgreSQL connection string.
- **FACE_RECOGNITION_MODEL_PATH**: Path to the face recognition model used in authentication.
- **ENCRYPTION_KEY**: Symmetric key for AES encryption.
- **JWT_SECRET**: Secret key for signing JWT tokens.
- **SMTP_SERVER, EMAIL_USER, EMAIL_PASSWORD**: Email configurations for user notifications.

## Installation

### Prerequisites:
- Python 3.x
- PostgreSQL
- Flask templates
- AWS EC2 Instance (for deployment)

### Steps:
1. Clone the repository:
   ```
   git clone https://github.com/testuser692/Secure_file_sharing_demo.git 
   cd Secure_file_sharing_demo

2. Install Python dependencies:
   ```
    pip install -r requirements.txt

3. Set up PostgreSQL database:
   ```
    Create a PostgreSQL database.
    Configure the DATABASE_URL in the .env file

4. Run the main file
   ```
   python main.py

# Deploy to AWS EC2 instance:
Set up an EC2 instance with necessary security groups.
Install required dependencies on the instance (Python, PostgreSQL, etc.).
Clone the project repository and configure environment variables.
Set up a reverse proxy using Nginx or Apache and run the Flask application using a WSGI server like Gunicorn.

## Usage
```
  ### Key Endpoints:
  /user_registration: Register a new user with biometric face recognition.
  /login: Log in an existing user with face recognition-based authentication.
  /send_message: Send an encrypted message to a user.
  /send_file: Upload and send an encrypted file to another user.
  /decrypt_file: Decrypt a received file for viewing.
  /chat: Start a real-time P2P chat session with another user.
  /decrypt_message: Decrypt chat messages.
  /audit_trail: View audit logs of user actions for monitoring and security anal
```

## Encryption & Decryption:
AES Encryption: Files and messages are encrypted using AES before transmission.
RSA for Key Exchange: RSA encryption is used to securely exchange AES keys between users.
End-to-End Encrypted Chat: All chat messages are encrypted with AES and decrypted on the recipient's end.

## File Sharing:
File Upload and Encryption: When a user uploads a file, it is encrypted with AES before being stored.
File Decryption: The recipient decrypts the file using the AES key provided after secure exchange via RSA.
## P2P Chat:
Real-Time Messaging: Users can send messages to each other via the chat interface, with each message being encrypted.
Message Decryption: Messages are decrypted on the recipient's end to ensure end-to-end security.

## Features
End-to-End Encryption: Secure encryption of messages and files using AES and RSA algorithms.
Biometric Authentication: Face recognition ensures secure login.
Encrypted File Sharing: Enables users to share files securely with AES encryption.
Real-Time Encrypted Chat: Secure real-time messaging between users using AES.
Audit Trails: Tracks user activity for enhanced security.
Email Notifications: Sends OTPs for email verification and password resets.

## Deployment
AWS EC2 Instance: The application is hosted on an EC2 instance for cloud accessibility.
Ensure proper security configurations are set up (e.g., firewalls, SSL).
Use environment variables in the .env file for production settings.

## Contribution Guidelines
Fork the repository.
Create a new branch for your feature or bug fix.
Commit your changes with clear messages.
Push the branch to your forked repository.
Submit a pull request with a description of the changes you made.

This `README.md` includes:
- A clear **project structure**.
- A detailed list of **environment variables** with descriptions.
- **Installation instructions** for setting up the project.
- **Usage instructions** for key endpoints.
- A summary of the **features** included in the system.

