from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from app.models.user import User, get_db
from app.utils.security import get_current_user, is_admin_email


router = APIRouter()


def _is_admin(email: str) -> bool:
    return is_admin_email(email)


@router.get("/", response_model=List[dict])
def get_all_users(db: Session = Depends(get_db), current_user_email: str = Depends(get_current_user)):
    if not _is_admin(current_user_email):
        raise HTTPException(status_code=403, detail="Admin access required")
    users = db.query(User).order_by(User.id.asc()).all()
    return [
        {
            "id": u.id,
            "firstName": u.first_name,
            "lastName": u.last_name,
            "email": u.email,
            "phone": u.phone,
            "role": u.role,
        }
        for u in users
    ]


@router.put("/{id}/role")
def change_user_role(id: int, payload: dict, db: Session = Depends(get_db), current_user_email: str = Depends(get_current_user)):
    if not _is_admin(current_user_email):
        raise HTTPException(status_code=403, detail="Admin access required")
    user = db.query(User).filter(User.id == id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    role = payload.get("role")
    if role not in {"USER", "SUB_ADMIN", "ADMIN"}:
        raise HTTPException(status_code=400, detail="Invalid role")
    user.role = role
    db.commit()
    db.refresh(user)
    return {"message": "Role updated", "id": user.id, "role": user.role}
