# 2FASecureGuard

A secure, robust FastAPI-based two-factor authentication system that provides enhanced security for web applications.

![2FA Security](https://img.shields.io/badge/2FA-Enabled-brightgreen)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Latest-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## 🔐 Overview

2FASecureGuard is a comprehensive authentication system that implements secure two-factor authentication (2FA) using Time-based One-Time Passwords (TOTP). This project provides a complete authentication flow including user registration, login, and 2FA management through a clean RESTful API.

## ✨ Features

- **User Management**
  - Registration with email and password
  - Secure password hashing
  - JWT-based authentication

- **Two-Factor Authentication**
  - TOTP-based 2FA (compatible with Google Authenticator, Authy, etc.)
  - QR code generation for easy 2FA setup
  - 2FA enablement workflow
  - 2FA verification during login
  - Option to disable 2FA

- **Security**
  - Password hashing with bcrypt
  - JWT token-based authentication
  - Protection against brute force attacks
  - TOTP verification with pyotp

## 🛠️ Technologies Used

- **FastAPI**: High-performance web framework
- **SQLite**: Lightweight, file-based database
- **SQLAlchemy**: SQL toolkit and ORM
- **PyOTP**: Python library for generating and verifying one-time passwords
- **JWT**: JSON Web Tokens for secure authentication
- **Pydantic**: Data validation and settings management
- **QRCode**: QR code generation for TOTP setup

## 📋 API Endpoints

### Authentication

- **POST /auth/register** - Register a new user
- **POST /auth/login** - Login (with optional 2FA verification)

### Two-Factor Authentication

- **POST /auth/2fa/setup** - Initialize 2FA setup (generates QR code)
- **POST /auth/2fa/verify** - Verify and enable 2FA
- **POST /auth/2fa/disable** - Disable 2FA for user

## 📥 Installation

1. Clone the repository:
```bash
git clone https://github.com/EmmyAnieDev/2FASecureGuard.git
cd 2FASecureGuard
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install the required dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables (copy from .env.example):
```bash
cp .env.example .env
```

5. Configure your secret key and other settings in the .env file:
```
SECRET_KEY=your_secure_secret_key
ALGORITHM=HS256
```

## 🚀 Usage

1. Start the FastAPI server:
```bash
uvicorn main:app --reload
```

2. Access the API documentation at `http://localhost:8000/docs`

## 📱 2FA Setup Flow

1. User registers with email and password
2. User logs in with credentials
3. User initiates 2FA setup through `/auth/2fa/setup` endpoint
4. User scans the provided QR code with authenticator app
5. User verifies setup by providing a valid TOTP code to `/auth/2fa/verify`
6. 2FA is now enabled for the user account
7. Future login attempts will require both password and TOTP code

## 💡 Example Usage

### Register a new user

```python
import requests

response = requests.post(
    "http://localhost:8000/auth/register",
    json={"email": "user@example.com", "password": "securepassword"}
)
print(response.json())
```

### Login with 2FA

```python
import requests

# First login attempt - will return 2FA requirement
response = requests.post(
    "http://localhost:8000/auth/login",
    json={"email": "user@example.com", "password": "securepassword"}
)

# If 2FA is required, submit with TOTP code
if response.json().get("data", {}).get("requires_2fa"):
    response = requests.post(
        "http://localhost:8000/auth/login",
        json={
            "email": "user@example.com", 
            "password": "securepassword",
            "otp_code": "123456"  # Code from authenticator app
        }
    )

# Get the JWT token
token = response.json().get("data", {}).get("access_token")
```

## 🧪 Testing

Run tests using pytest:

```bash
pytest
```

## 📚 Further Documentation

For more detailed information about the API endpoints, schemas, and usage examples, see the automatically generated Swagger documentation at `/docs` or ReDoc at `/redoc` when running the application.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ✍️ Author

Created by [EmmyAnieDev](https://github.com/EmmyAnieDev)

---

Feel free to open issues or submit pull requests!