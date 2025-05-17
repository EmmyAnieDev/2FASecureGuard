import pyotp
import qrcode
import io
import base64
from sqlalchemy.orm import Session
from app import models


def generate_totp_secret():
    """Generate a new TOTP secret"""
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str, issuer_name: str = "AppName"):
    """Generate the otpauth URI for QR code generation"""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer_name)


def generate_qr_code(uri: str) -> str:
    """Generate a QR code for the TOTP URI and return as a base64 encoded string"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buffered = io.BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return img_str


def verify_totp(secret: str, token: str) -> bool:
    """Verify a TOTP token against the secret"""
    totp = pyotp.TOTP(secret)
    return totp.verify(token)


def setup_totp_device(db: Session, user_id: int):
    """Initialize TOTP setup for a user"""
    # Check if user already has a TOTP device
    existing_device = db.query(models.TOTPDevice).filter(models.TOTPDevice.user_id == user_id).first()

    # If device exists but is not confirmed, return it
    if existing_device and not existing_device.confirmed:
        return existing_device

    # If device exists and is confirmed, delete it
    if existing_device:
        db.delete(existing_device)
        db.commit()

    # Generate new secret
    secret = generate_totp_secret()

    # Create new TOTP device
    totp_device = models.TOTPDevice(user_id=user_id, secret=secret, confirmed=False)
    db.add(totp_device)
    db.commit()
    db.refresh(totp_device)

    return totp_device


def confirm_totp_device(db: Session, user_id: int, token: str) -> bool:
    """Confirm and enable TOTP for a user"""
    totp_device = db.query(models.TOTPDevice).filter(models.TOTPDevice.user_id == user_id).first()

    if not totp_device:
        return False

    if verify_totp(totp_device.secret, token):
        totp_device.confirmed = True
        db.commit()
        return True

    return False


def disable_totp(db: Session, user_id: int, token: str, password_verified: bool) -> bool:
    """Disable TOTP for a user"""
    if not password_verified:
        return False

    totp_device = db.query(models.TOTPDevice).filter(models.TOTPDevice.user_id == user_id).first()

    if not totp_device or not totp_device.confirmed:
        return False

    if verify_totp(totp_device.secret, token):
        db.delete(totp_device)
        db.commit()
        return True

    return False


def requires_totp(db: Session, user_id: int) -> bool:
    """Check if a user has TOTP enabled"""
    totp_device = db.query(models.TOTPDevice).filter(
        models.TOTPDevice.user_id == user_id,
        models.TOTPDevice.confirmed == True
    ).first()

    return totp_device is not None


def validate_login_totp(db: Session, user_id: int, token: str) -> bool:
    """Validate a TOTP token during login"""
    totp_device = db.query(models.TOTPDevice).filter(
        models.TOTPDevice.user_id == user_id,
        models.TOTPDevice.confirmed == True
    ).first()

    if not totp_device:
        return True  # No TOTP required

    return verify_totp(totp_device.secret, token)