from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.models.user import get_db
from app.models.return_request import ReturnRequest
from app.utils.security import get_current_user, ADMIN_EMAIL


router = APIRouter()


def _is_admin_or_sub(email: str) -> bool:
    return email == ADMIN_EMAIL or email.endswith("@admin") or email == "admin@example.com"


# 43. Get Return Requests (Admin)
@router.get("/")
def get_return_requests(db: Session = Depends(get_db), current_user_email: str = Depends(get_current_user)):
    if not _is_admin_or_sub(current_user_email):
        raise HTTPException(status_code=403, detail="Admin access required")
    reqs = db.query(ReturnRequest).order_by(ReturnRequest.created_at.desc()).all()
    return [
        {
            "id": r.id,
            "orderId": r.order_id,
            "userId": r.user_id,
            "reason": r.reason,
            "status": r.status,
            "createdAt": r.created_at.isoformat() if r.created_at else None,
        }
        for r in reqs
    ]


# 44. Update Return Status (Admin)
@router.put("/{id}/status")
def update_return_status(id: int, payload: dict, db: Session = Depends(get_db), current_user_email: str = Depends(get_current_user)):
    if not _is_admin_or_sub(current_user_email):
        raise HTTPException(status_code=403, detail="Admin access required")
    req = db.query(ReturnRequest).filter(ReturnRequest.id == id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Return request not found")
    status = payload.get("status")
    if status not in {"PENDING", "APPROVED", "REJECTED", "COMPLETED"}:
        raise HTTPException(status_code=400, detail="Invalid status")
    req.status = status
    db.commit()
    return {"message": "Return status updated", "id": req.id, "status": req.status}
