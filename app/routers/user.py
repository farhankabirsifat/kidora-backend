from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.models.user import User, get_db
from app.schemas.user import ProfileUpdate, ProfileOut, PasswordChange
from app.utils.security import get_current_user


router = APIRouter()


@router.get("/me", response_model=ProfileOut)
def get_profile(current_user_email: str = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return ProfileOut(
        firstName=user.first_name,
        lastName=user.last_name,
        email=user.email,
        phone=user.phone,
    )


@router.put("/me", response_model=ProfileOut)
def update_profile(payload: ProfileUpdate, current_user_email: str = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Apply updates if provided
    if payload.firstName is not None:
        user.first_name = payload.firstName
    if payload.lastName is not None:
        user.last_name = payload.lastName
    if payload.email is not None:
        # Optional: enforce unique email here
        user.email = payload.email
    if payload.phone is not None:
        user.phone = payload.phone

    db.commit()
    db.refresh(user)
    return ProfileOut(
        firstName=user.first_name,
        lastName=user.last_name,
        email=user.email,
        phone=user.phone,
    )


@router.put("/me/password")
def change_password(payload: PasswordChange, current_user_email: str = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.password != payload.currentPassword:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if not payload.newPassword or len(payload.newPassword) < 6:
        raise HTTPException(status_code=400, detail="New password too short")
    user.password = payload.newPassword  # NOTE: hash in real app
    db.commit()
    return {"message": "Password updated"}
