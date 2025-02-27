from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import timedelta

import models
import schemas
from database import get_db
from auth import (
    get_password_hash, authenticate_user, create_access_token,
    get_current_user, verify_password
)

from utils.totp import (
    setup_totp_device, get_totp_uri, generate_qr_code,
    confirm_totp_device, requires_totp, validate_login_totp,
    disable_totp
)


auth_router = APIRouter()


@auth_router.post("/register", status_code=201)
def register_user(user_data: schemas.UserCreate, db: Session = Depends(get_db)):
    # Check if user already exists
    db_user = db.query(models.User).filter(models.User.email == user_data.email).first()

    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user_data.password)
    new_user = models.User(email=user_data.email, hashed_password=hashed_password)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "status": True,
        "status_code": 201,
        "message": "User registered successfully",
        "data": {"email": new_user.email}
    }


# Login endpoint with 2FA support
@auth_router.post("/login")
async def login(login_data: schemas.UserLogin, db: Session = Depends(get_db)):
    user = authenticate_user(db, login_data.email, login_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if 2FA is required
    if requires_totp(db, user.id):
        # If 2FA required but no OTP provided
        if not login_data.otp_code:
            return {
                "status": False,
                "status_code": 403,
                "message": "Two-factor authentication required",
                "data": {
                    "requires_2fa": True
                }
            }

        # Validate OTP code
        if not validate_login_totp(db, user.id, login_data.otp_code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication code",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # Create access token
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )

    return {
        "status": True,
        "status_code": 200,
        "message": "Login successful",
        "data": {
            "access_token": access_token,
            "token_type": "bearer"
        }
    }


# Set up 2FA endpoint
@auth_router.post("/2fa/setup")
async def setup_2fa(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    # Initialize TOTP device
    totp_device = setup_totp_device(db, current_user.id)

    # Generate setup info
    otpauth_url = get_totp_uri(totp_device.secret, current_user.email)
    qr_code = generate_qr_code(otpauth_url)

    return {
        "status": True,
        "status_code": 201,
        "message": "2FA setup initiated",
        "data": {
            "secret": totp_device.secret,
            "otpauth_url": otpauth_url,
            "qr_code": qr_code
        }
    }


# Verify and enable 2FA endpoint
@auth_router.post("/2fa/verify")
async def verify_2fa(
        verify_data: schemas.TOTPVerifyRequest,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_user)
):
    if confirm_totp_device(db, current_user.id, verify_data.token):
        return {
            "status": True,
            "status_code": 200,
            "message": "Two-factor authentication enabled successfully"
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid authentication code"
        )


# Disable 2FA endpoint
@auth_router.post("/2fa/disable")
async def disable_2fa_endpoint(
        disable_data: schemas.TOTPDisableRequest,
        db: Session = Depends(get_db),
        current_user: models.User = Depends(get_current_user)
):
    # Verify password
    password_verified = verify_password(disable_data.password, current_user.hashed_password)

    if disable_totp(db, current_user.id, disable_data.token, password_verified):
        return {
            "status": True,
            "status_code": 200,
            "message": "Two-factor authentication disabled successfully"
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password or authentication code"
        )