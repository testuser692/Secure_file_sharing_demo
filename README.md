# Secure P2P Messaging and File Sharing System

## Project Overview
This project is a secure peer-to-peer (P2P) messaging and file-sharing system with end-to-end encryption, user authentication, access controls, and audit trails. The application is built using Flask (backend), Flask templates (frontend), PostgreSQL (database), and cryptographic libraries like AES and RSA.

## Project Structure
The following is the project structure:

├── src/
│   ├── controller/
│   │   └── users_controller.py
│   ├── models/
│   │   ├── users.py
│   │   └── otp.py
│   └── templates/
│       ├── registerasuser.html
│       ├── login.html
│       ├── confirm_email.html
│       ├── forgot_password.html
│       ├── reset_password.html
│       └── verify_otp.html
├── config.py
├── app.py
└── README.md



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

FLASK_APP=app
FLASK_ENV=development
SECRET_KEY=your_secret_key
DATABASE_URL=postgresql://user
@localhost/dbname
FACE_RECOGNITION_MODEL_PATH=path_to_model
ENCRYPTION_KEY=your_encryption_key
JWT_SECRET=your_jwt_secret
SMTP_SERVER=smtp.example.com
EMAIL_USER=email@example.com
EMAIL_PASSWORD=your_email_password


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
- Node.js (for React.js frontend)

### Steps:
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo.git
   cd your-repo

Install Python dependencies:
pip install -r requirements.txt
Set up PostgreSQL database and configure the DATABASE_URL in the .env file.

# run the main file
# python main.py


## Usage
/user_registration: Endpoint to register a new user with face recognition.
/login: Endpoint for user login.
Make sure to register users by capturing face images and storing them for biometric authentication.

## Features
End-to-End Encryption: AES encryption for messages and files.
Biometric Authentication: Face recognition for user login.
Audit Trails: Logs of user actions for security purposes.
Contribution Guidelines
Fork the repository.
Create a new branch for your feature.
Submit a pull request.


This `README.md` includes:
- A clear **project structure**.
- A detailed list of **environment variables** with descriptions.
- **Installation instructions** for setting up the project.
- **Usage instructions** for key endpoints.
- A summary of the **features** included in the system.

