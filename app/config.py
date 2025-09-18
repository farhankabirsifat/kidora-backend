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
    SECRET_KEY: str = os.getenv("SECRET_KEY", "change_me_secret")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    # Default to 7 days so users stay logged in for a week
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", str(7 * 24 * 60)))
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql+psycopg://postgres:1234@localhost:5432/kidora")
    ADMIN_EMAIL: str = os.getenv("ADMIN_EMAIL", "admin@example.com")
    ADMIN_EMAIL_PASSWORD: str = os.getenv("ADMIN_EMAIL_PASSWORD", "")
    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    EMAIL_BACKEND: str = os.getenv("EMAIL_BACKEND", "console").lower()


@lru_cache
def get_settings():
    return Settings()
