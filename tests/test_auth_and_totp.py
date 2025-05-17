import pytest
import pyotp
import sys
import os
from unittest.mock import MagicMock, patch
from datetime import datetime
from sqlalchemy.orm import Session
from jose import jwt
from fastapi import HTTPException

# Add the project root directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import models
from utils.totp import (
    generate_totp_secret, get_totp_uri, generate_qr_code, verify_totp,
    setup_totp_device, confirm_totp_device, disable_totp,
    requires_totp, validate_login_totp
)
from app.routes.auth import (
    verify_password, get_password_hash, get_user, authenticate_user,
    create_access_token, get_current_user
)


# Fixtures
@pytest.fixture
def mock_db():
    """Create a mock database session"""
    return MagicMock(spec=Session)


@pytest.fixture
def mock_user():
    """Create a mock user"""
    user = MagicMock(spec=models.User)
    user.id = 1
    user.email = "test@example.com"
    user.hashed_password = get_password_hash("testpassword")
    return user


@pytest.fixture
def mock_totp_device():
    """Create a mock TOTP device"""
    device = MagicMock(spec=models.TOTPDevice)
    device.id = 1
    device.user_id = 1
    device.secret = generate_totp_secret()
    device.confirmed = False
    return device


#   ----------    Tests for TOTP utilities    -----



def test_generate_totp_secret():
    """Test TOTP secret generation"""
    secret = generate_totp_secret()
    assert len(secret) > 0
    assert isinstance(secret, str)


def test_get_totp_uri():
    """Test TOTP URI generation"""
    secret = generate_totp_secret()
    email = "test@example.com"
    issuer = "TestApp"

    uri = get_totp_uri(secret, email, issuer)

    assert "otpauth://totp/" in uri
    # Email might be URL-encoded, so we check for presence of parts of the email
    assert "test" in uri
    assert "example.com" in uri or "example%2Ecom" in uri
    assert issuer in uri
    assert secret in uri


def test_generate_qr_code():
    """Test QR code generation"""
    uri = "otpauth://totp/TestApp:test@example.com?secret=TESTSECRET&issuer=TestApp"
    qr_code = generate_qr_code(uri)

    assert isinstance(qr_code, str)
    assert len(qr_code) > 0
    # Base64 string should start with this prefix
    assert "base64" in qr_code or qr_code[:4].isalnum()


def test_verify_totp_valid():
    """Test TOTP verification with valid token"""
    secret = generate_totp_secret()
    totp = pyotp.TOTP(secret)
    valid_token = totp.now()

    assert verify_totp(secret, valid_token) is True


def test_verify_totp_invalid():
    """Test TOTP verification with invalid token"""
    secret = generate_totp_secret()
    invalid_token = "123456"  # Just a random token, unlikely to match

    assert verify_totp(secret, invalid_token) is False


# Tests for TOTP device management
def test_setup_totp_device_new(mock_db, mock_user):
    """Test setting up a new TOTP device"""
    mock_db.query.return_value.filter.return_value.first.return_value = None

    # Setup the expected behavior for refresh
    mock_db.refresh.side_effect = lambda x: x

    result = setup_totp_device(mock_db, mock_user.id)

    assert mock_db.add.called
    assert mock_db.commit.called
    assert mock_db.refresh.called
    # Check that result is a TOTPDevice object
    assert hasattr(result, 'user_id')
    assert hasattr(result, 'secret')
    assert hasattr(result, 'confirmed')


def test_setup_totp_device_existing_unconfirmed(mock_db, mock_user, mock_totp_device):
    """Test setting up a TOTP device when an unconfirmed one exists"""
    mock_totp_device.confirmed = False
    mock_db.query.return_value.filter.return_value.first.return_value = mock_totp_device

    result = setup_totp_device(mock_db, mock_user.id)

    assert not mock_db.add.called
    assert not mock_db.commit.called
    assert not mock_db.refresh.called
    assert result == mock_totp_device


def test_setup_totp_device_existing_confirmed(mock_db, mock_user, mock_totp_device):
    """Test setting up a TOTP device when a confirmed one exists"""
    mock_totp_device.confirmed = True
    mock_db.query.return_value.filter.return_value.first.return_value = mock_totp_device

    # Setup the expected behavior for refresh
    mock_db.refresh.side_effect = lambda x: x

    result = setup_totp_device(mock_db, mock_user.id)

    assert mock_db.delete.called
    assert mock_db.commit.called
    assert mock_db.add.called
    assert mock_db.refresh.called
    # Check that result is a TOTPDevice object
    assert hasattr(result, 'user_id')
    assert hasattr(result, 'secret')
    assert hasattr(result, 'confirmed')


@patch('utils.totp.verify_totp')
def test_confirm_totp_device_success(mock_verify_totp, mock_db, mock_user, mock_totp_device):
    """Test confirming a TOTP device with valid token"""
    mock_verify_totp.return_value = True
    mock_db.query.return_value.filter.return_value.first.return_value = mock_totp_device

    result = confirm_totp_device(mock_db, mock_user.id, "123456")

    assert result is True
    assert mock_totp_device.confirmed is True
    assert mock_db.commit.called
    mock_verify_totp.assert_called_once_with(mock_totp_device.secret, "123456")


@patch('utils.totp.verify_totp')
def test_confirm_totp_device_failure(mock_verify_totp, mock_db, mock_user, mock_totp_device):
    """Test confirming a TOTP device with invalid token"""
    mock_verify_totp.return_value = False
    mock_db.query.return_value.filter.return_value.first.return_value = mock_totp_device

    result = confirm_totp_device(mock_db, mock_user.id, "123456")

    assert result is False
    assert mock_totp_device.confirmed is False
    assert not mock_db.commit.called


@patch('utils.totp.verify_totp')
def test_disable_totp_success(mock_verify_totp, mock_db, mock_user, mock_totp_device):
    """Test disabling TOTP with valid credentials"""
    mock_verify_totp.return_value = True
    mock_totp_device.confirmed = True
    mock_db.query.return_value.filter.return_value.first.return_value = mock_totp_device

    result = disable_totp(mock_db, mock_user.id, "123456", True)

    assert result is True
    assert mock_db.delete.called
    assert mock_db.commit.called


def test_disable_totp_invalid_password(mock_db, mock_user, mock_totp_device):
    """Test disabling TOTP with invalid password"""
    result = disable_totp(mock_db, mock_user.id, "123456", False)

    assert result is False
    assert not mock_db.delete.called
    assert not mock_db.commit.called


@patch('utils.totp.verify_totp')
def test_disable_totp_invalid_token(mock_verify_totp, mock_db, mock_user, mock_totp_device):
    """Test disabling TOTP with invalid token"""
    mock_verify_totp.return_value = False
    mock_totp_device.confirmed = True
    mock_db.query.return_value.filter.return_value.first.return_value = mock_totp_device

    result = disable_totp(mock_db, mock_user.id, "123456", True)

    assert result is False
    assert not mock_db.delete.called
    assert not mock_db.commit.called


def test_requires_totp_enabled(mock_db, mock_user, mock_totp_device):
    """Test checking if TOTP is required when enabled"""
    mock_totp_device.confirmed = True
    mock_db.query.return_value.filter.return_value.first.return_value = mock_totp_device

    result = requires_totp(mock_db, mock_user.id)

    assert result is True


def test_requires_totp_disabled(mock_db, mock_user):
    """Test checking if TOTP is required when disabled"""
    mock_db.query.return_value.filter.return_value.first.return_value = None

    result = requires_totp(mock_db, mock_user.id)

    assert result is False


@patch('utils.totp.verify_totp')
def test_validate_login_totp_valid(mock_verify_totp, mock_db, mock_user, mock_totp_device):
    """Test validating TOTP during login with valid token"""
    mock_verify_totp.return_value = True
    mock_totp_device.confirmed = True
    mock_db.query.return_value.filter.return_value.first.return_value = mock_totp_device

    result = validate_login_totp(mock_db, mock_user.id, "123456")

    assert result is True
    mock_verify_totp.assert_called_once_with(mock_totp_device.secret, "123456")


@patch('utils.totp.verify_totp')
def test_validate_login_totp_invalid(mock_verify_totp, mock_db, mock_user, mock_totp_device):
    """Test validating TOTP during login with invalid token"""
    mock_verify_totp.return_value = False
    mock_totp_device.confirmed = True
    mock_db.query.return_value.filter.return_value.first.return_value = mock_totp_device

    result = validate_login_totp(mock_db, mock_user.id, "123456")

    assert result is False


def test_validate_login_totp_not_required(mock_db, mock_user):
    """Test validating TOTP during login when not required"""
    mock_db.query.return_value.filter.return_value.first.return_value = None

    result = validate_login_totp(mock_db, mock_user.id, "123456")

    assert result is True


#   -----------     Tests for authentication utilities     -------------


def test_verify_password_valid():
    """Test password verification with valid password"""
    password = "testpassword"
    hashed = get_password_hash(password)

    assert verify_password(password, hashed) is True


def test_verify_password_invalid():
    """Test password verification with invalid password"""
    password = "testpassword"
    wrong_password = "wrongpassword"
    hashed = get_password_hash(password)

    assert verify_password(wrong_password, hashed) is False


def test_get_password_hash():
    """Test password hashing"""
    password = "testpassword"
    hashed = get_password_hash(password)

    assert password != hashed
    assert len(hashed) > 0


def test_get_user(mock_db, mock_user):
    """Test getting a user by email"""
    mock_db.query.return_value.filter.return_value.first.return_value = mock_user

    result = get_user(mock_db, mock_user.email)

    assert result == mock_user
    mock_db.query.assert_called_once_with(models.User)


@patch('app.routes.auth.verify_password')
def test_authenticate_user_valid(mock_verify_password, mock_db, mock_user):
    """Test user authentication with valid credentials"""
    mock_verify_password.return_value = True
    mock_db.query.return_value.filter.return_value.first.return_value = mock_user

    result = authenticate_user(mock_db, mock_user.email, "testpassword")

    assert result == mock_user


@patch('app.routes.auth.verify_password')
def test_authenticate_user_invalid_password(mock_verify_password, mock_db, mock_user):
    """Test user authentication with invalid password"""
    mock_verify_password.return_value = False
    mock_db.query.return_value.filter.return_value.first.return_value = mock_user

    result = authenticate_user(mock_db, mock_user.email, "wrongpassword")

    assert result is False


def test_authenticate_user_nonexistent(mock_db):
    """Test user authentication with nonexistent user"""
    mock_db.query.return_value.filter.return_value.first.return_value = None

    result = authenticate_user(mock_db, "nonexistent@example.com", "testpassword")

    assert result is False


@patch('app.routes.auth.jwt.encode')
@patch('app.routes.auth.datetime')
def test_create_access_token(mock_datetime, mock_jwt_encode):
    """Test access token creation"""
    # Setup
    mock_datetime.utcnow.return_value = datetime(2023, 1, 1, 12, 0)
    mock_jwt_encode.return_value = "test.jwt.token"

    # Execute
    data = {"sub": "test@example.com"}
    token = create_access_token(data)

    # Assert
    assert token == "test.jwt.token"
    assert mock_jwt_encode.called


@patch('app.routes.auth.jwt.decode')
def test_get_current_user_valid(mock_jwt_decode, mock_db, mock_user):
    """Test getting current user with valid token"""
    # Setup
    mock_jwt_decode.return_value = {"sub": mock_user.email}
    mock_db.query.return_value.filter.return_value.first.return_value = mock_user

    # Execute
    result = get_current_user(mock_db, "valid.jwt.token")

    # Assert
    assert result == mock_user
    assert mock_jwt_decode.called


@patch('app.routes.auth.jwt.decode')
def test_get_current_user_invalid_token(mock_jwt_decode, mock_db):
    """Test getting current user with invalid token"""
    # Setup
    mock_jwt_decode.side_effect = jwt.JWTError("Invalid token")

    # Execute and Assert
    with pytest.raises(HTTPException) as exc_info:
        get_current_user(mock_db, "invalid.jwt.token")

    assert exc_info.value.status_code == 401
    assert "Could not validate credentials" in exc_info.value.detail


@patch('app.routes.auth.jwt.decode')
def test_get_current_user_missing_email(mock_jwt_decode, mock_db):
    """Test getting current user with token missing email"""
    # Setup
    mock_jwt_decode.return_value = {}  # No 'sub' key

    # Execute and Assert
    with pytest.raises(HTTPException) as exc_info:
        get_current_user(mock_db, "missing_sub.jwt.token")

    assert exc_info.value.status_code == 401
    assert "Could not validate credentials" in exc_info.value.detail


@patch('app.routes.auth.jwt.decode')
def test_get_current_user_user_not_found(mock_jwt_decode, mock_db):
    """Test getting current user when user not found in database"""
    # Setup
    mock_jwt_decode.return_value = {"sub": "nonexistent@example.com"}
    mock_db.query.return_value.filter.return_value.first.return_value = None

    # Execute and Assert
    with pytest.raises(HTTPException) as exc_info:
        get_current_user(mock_db, "valid.jwt.token")

    assert exc_info.value.status_code == 401
    assert "Could not validate credentials" in exc_info.value.detail