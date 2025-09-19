from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.models.user import User, get_db, OTP
from app.schemas.user import RegisterSchema, LoginSchema
from app.utils.security import create_access_token, get_current_user_email, blacklist_token, send_email
from app.config import get_settings
from app.utils.email_templates import welcome_email, password_reset_code, password_reset_success
from datetime import datetime, timedelta
import random
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

router = APIRouter()
bearer = HTTPBearer(auto_error=False)

@router.post("/register")
def register(user: RegisterSchema, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    new_user = User(
        first_name=user.firstName,
        last_name=user.lastName,
        email=user.email,
        phone=user.phone,
        password=user.password  # hash in real app
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    settings = get_settings()
    if getattr(settings, 'ENABLE_EMAIL_NOTIFICATIONS', True):
        try:
            tpl = welcome_email(new_user.first_name)
            send_email(new_user.email, tpl['subject'], tpl['body'])
        except Exception:
            pass
    return {"message": "User registered successfully"}

@router.post("/login")
def simple_login(credentials: LoginSchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == credentials.email).first()
    if not user or user.password != credentials.password:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token(subject=user.email)
    return {"access_token": token, "token_type": "bearer", "expires_in_minutes": 60 * 24 * 7}


@router.post("/password/forgot")
def forgot_password(payload: dict, db: Session = Depends(get_db)):
    """Generate a 6-digit code, store in OTP table (invalidate previous), email to user.
    Payload: { "email": "..." }
    Always return success message to avoid leaking user existence.
    """
    email = (payload.get("email") or "").strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="Email required")
    user = db.query(User).filter(User.email == email).first()
    code = f"{random.randint(0, 999999):06d}"
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    if user:
        # Invalidate previous OTPs
        db.query(OTP).filter(OTP.email == email, OTP.used == False).update({OTP.used: True})  # type: ignore
        db.add(OTP(email=email, code=code, expires_at=expires_at))
        db.commit()
        # Send email
        try:
            settings = get_settings()
            if getattr(settings, 'ENABLE_EMAIL_NOTIFICATIONS', True):
                tpl = password_reset_code(code)
                send_email(email, tpl['subject'], tpl['body'])
        except Exception:
            pass
    return {"message": "If that email exists, a reset code was sent"}


@router.post("/password/reset")
def reset_password(payload: dict, db: Session = Depends(get_db)):
    """Reset password using code.
    Payload: { email, code, newPassword }
    """
    email = (payload.get("email") or "").strip().lower()
    code = (payload.get("code") or "").strip()
    new_password = payload.get("newPassword")
    if not all([email, code, new_password]):
        raise HTTPException(status_code=400, detail="Missing fields")
    if len(new_password) < 6:
        raise HTTPException(status_code=400, detail="Password too short")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid code or email")
    otp = db.query(OTP).filter(OTP.email == email, OTP.code == code, OTP.used == False).first()  # type: ignore
    if not otp or not otp.expires_at or otp.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Invalid or expired code")
    # Mark OTP used and update password
    otp.used = True
    user.password = new_password  # NOTE: hash in production
    db.commit()
    # Send confirmation
    try:
        settings = get_settings()
        if getattr(settings, 'ENABLE_EMAIL_NOTIFICATIONS', True):
            tpl = password_reset_success()
            send_email(email, tpl['subject'], tpl['body'])
    except Exception:
        pass
    return {"message": "Password reset successful"}


@router.post("/logout")
def logout(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    if not creds or not creds.credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    from jose import jwt
    from app.config import get_settings
    settings = get_settings()
    try:
        payload = jwt.decode(creds.credentials, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        jti = payload.get("jti")
        if jti:
            blacklist_token(jti)
        return {"message": "Logged out"}
    except Exception:
        # Even if token invalid, respond 200 to avoid token probing
        return {"message": "Logged out"}
