from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.models.user import User, get_db
from app.schemas.user import RegisterSchema, LoginSchema
from app.utils.security import create_access_token, get_current_user_email, blacklist_token
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
    return {"message": "User registered successfully"}

@router.post("/login")
def simple_login(credentials: LoginSchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == credentials.email).first()
    if not user or user.password != credentials.password:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token(subject=user.email)
    return {"access_token": token, "token_type": "bearer", "expires_in_minutes": 60 * 24 * 7}


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
