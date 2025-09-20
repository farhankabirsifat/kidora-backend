# passenger_wsgi.py
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Optional: load .env early (safe – silently skips if python-dotenv not installed)
try:
    from dotenv import load_dotenv, find_dotenv  # type: ignore
    _env = find_dotenv(usecwd=True)
    if _env:
        load_dotenv(_env, override=False)
except Exception:
    pass

# Import FastAPI app
from app.main import app as fastapi_app  # noqa: E402

# Try to wrap ASGI -> WSGI for Passenger
try:
    from asgiref.wsgi import AsgiToWsgi  # type: ignore
    application = AsgiToWsgi(fastapi_app)
except ImportError:
    application = fastapi_app
    print("[passenger] WARNING: 'asgiref' not installed; install it for proper WSGI adaptation.")

def application_health_check(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"OK"]
