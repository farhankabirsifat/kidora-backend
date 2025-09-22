import os
from functools import lru_cache

# Prefer loading environment variables from a .env file if python-dotenv is available
try:
    from dotenv import load_dotenv, find_dotenv
    _env_path = find_dotenv(usecwd=True)
    if _env_path:
        load_dotenv(_env_path, override=True)
except Exception:
    # If python-dotenv is not installed, skip silently
    pass


class Settings:
    SECRET_KEY: str = os.getenv("SECRET_KEY")
    ALGORITHM: str = os.getenv("ALGORITHM")
    # Default to 7 days so users stay logged in for a week
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
    DATABASE_URL: str = os.getenv("DATABASE_URL")
    # Primary legacy single admin email (kept for backward compatibility)
    ADMIN_EMAIL: str = os.getenv("ADMIN_EMAIL")
    # Optional comma separated list of additional admin emails (including primary if desired)
    ADMIN_EMAILS: str = os.getenv("ADMIN_EMAILS")
    ADMIN_EMAIL_PASSWORD: str = os.getenv("ADMIN_EMAIL_PASSWORD")
    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    EMAIL_BACKEND: str = os.getenv("EMAIL_BACKEND", "console").lower()
    # Feature flag for sending notification emails
    ENABLE_EMAIL_NOTIFICATIONS: bool = bool(int(os.getenv("ENABLE_EMAIL_NOTIFICATIONS", "1")))


@lru_cache
def get_settings():
    return Settings()
