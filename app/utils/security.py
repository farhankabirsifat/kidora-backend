from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
import smtplib
from email.mime.text import MIMEText
import logging
import uuid

from jose import jwt, JWTError

logger = logging.getLogger(__name__)
try:
    from app.config import get_settings
    settings = get_settings()
    ADMIN_EMAIL = settings.ADMIN_EMAIL
    ADMIN_EMAIL_PASSWORD = settings.ADMIN_EMAIL_PASSWORD
    SMTP_SERVER = settings.SMTP_SERVER
    SMTP_PORT = settings.SMTP_PORT
    EMAIL_BACKEND = getattr(settings, "EMAIL_BACKEND", "console")
    SECRET_KEY = settings.SECRET_KEY
    ALGORITHM = settings.ALGORITHM
    ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES
except Exception:
    # WARNING: Fallback minimal defaults if config import fails early.
    # These defaults are insecure and should NEVER be used in production!
    # JWT settings removed in basic auth mode
    ADMIN_EMAIL = "admin@example.com"
    import os
    ADMIN_EMAIL_PASSWORD = os.environ.get("ADMIN_EMAIL_PASSWORD", "")
    SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
    EMAIL_BACKEND = os.environ.get("EMAIL_BACKEND", "console")
    EMAIL_BACKEND = "console"
    SECRET_KEY = os.environ.get("SECRET_KEY", "change_me_secret")
    ALGORITHM = os.environ.get("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", str(7 * 24 * 60)))

http_basic = HTTPBasic()
http_bearer = HTTPBearer(auto_error=False)

def get_current_user(credentials: HTTPBasicCredentials = Depends(http_basic)):
    from app.models.user import SessionLocal, User
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == credentials.username).first()
        if not user or user.password != credentials.password:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return user.email
    finally:
        db.close()


# ===== JWT helpers =====
def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    jti = uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {"sub": subject, "exp": expire, "iat": now, "nbf": now, "jti": jti}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token


def is_token_blacklisted(jti: str) -> bool:
    from app.models.user import SessionLocal, TokenBlacklist
    db = SessionLocal()
    try:
        return db.query(TokenBlacklist).filter(TokenBlacklist.jti == jti).first() is not None
    finally:
        db.close()


def blacklist_token(jti: str) -> None:
    from app.models.user import SessionLocal, TokenBlacklist
    db = SessionLocal()
    try:
        if not db.query(TokenBlacklist).filter(TokenBlacklist.jti == jti).first():
            db.add(TokenBlacklist(jti=jti))
            db.commit()
    finally:
        db.close()


def get_current_user_email(token: HTTPAuthorizationCredentials = Depends(http_bearer)) -> str:
    if not token or not token.credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti")
        if not jti or is_token_blacklisted(jti):
            raise HTTPException(status_code=401, detail="Token revoked")
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def _send_email_console(to_email: str, subject: str, body: str):
    # Development helper: logs the email content instead of sending
    logger.info("[EMAIL:console] To=%s Subject=%s Body=%s", to_email, subject, body)


def send_email(to_email: str, subject: str, body: str):
    """Send an email using configured backend.

    In development (EMAIL_BACKEND=console), the email is logged instead of sent.
    In SMTP mode, errors are logged and won't raise to callers to avoid 500s.
    """
    backend = (EMAIL_BACKEND or "console").lower()

    # Console backend or missing credentials: log and return
    if backend != "smtp" or not ADMIN_EMAIL or not ADMIN_EMAIL_PASSWORD:
        if backend == "smtp" and (not ADMIN_EMAIL or not ADMIN_EMAIL_PASSWORD):
            logger.warning(
                "EMAIL_BACKEND=smtp but credentials missing (ADMIN_EMAIL set=%s, password length=%s). Falling back to console.",
                bool(ADMIN_EMAIL), len(ADMIN_EMAIL_PASSWORD or "")
            )
        logger.debug("Email backend in use: console (to=%s subject=%s)", to_email, subject)
        _send_email_console(to_email, subject, body)
        return True

    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = ADMIN_EMAIL
        msg["To"] = to_email

        logger.debug("Attempting SMTP connection to %s:%s backend=%s", SMTP_SERVER, SMTP_PORT, backend)
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20) as server:
            server.starttls()
            server.login(ADMIN_EMAIL, ADMIN_EMAIL_PASSWORD)
            server.send_message(msg)
        logger.info("Email sent via SMTP to %s", to_email)
        return True
    except Exception as e:
        # Do not break API flow on email failure
        logger.error("Failed to send email via SMTP: %s", e, exc_info=True)
        _send_email_console(to_email, subject, body)
        return False


def is_admin_email(email: str) -> bool:
    if not email:
        return False
    if email == ADMIN_EMAIL or email.endswith("@admin") or email == "admin@example.com":
        return True
    return False
