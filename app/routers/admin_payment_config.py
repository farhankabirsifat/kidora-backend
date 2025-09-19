from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.models.user import get_db
from app.models.payment_config import PaymentConfig, get_or_create_payment_config
from app.utils.security import get_current_user, is_admin_email

router = APIRouter()


@router.get("/payments/config")
def public_payment_config(db: Session = Depends(get_db)):
    cfg = db.query(PaymentConfig).first()
    # Default masked placeholders if not yet configured
    default_mask = "017xxxxxxxx"
    if not cfg:
        return {"bkashNumber": default_mask, "nagadNumber": default_mask, "rocketNumber": default_mask}
    return {
        "bkashNumber": (cfg.bkash_number or default_mask) or default_mask,
        "nagadNumber": (cfg.nagad_number or default_mask) or default_mask,
        "rocketNumber": (cfg.rocket_number or default_mask) or default_mask
    }


@router.get("/admin/payments/config")
def admin_get_payment_config(db: Session = Depends(get_db), current_user_email: str = Depends(get_current_user)):
    if not is_admin_email(current_user_email):
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Admin access required")
    cfg = get_or_create_payment_config(db)
    return {
        "id": cfg.id,
        "bkashNumber": cfg.bkash_number or "",
        "nagadNumber": cfg.nagad_number or "",
        "rocketNumber": cfg.rocket_number or "",
        "updatedAt": cfg.updated_at
    }


@router.put("/admin/payments/config")
def admin_update_payment_config(payload: dict, db: Session = Depends(get_db), current_user_email: str = Depends(get_current_user)):
    if not is_admin_email(current_user_email):
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Admin access required")
    allowed = {"bkashNumber", "nagadNumber", "rocketNumber"}
    if not any(k in payload for k in allowed):
        raise HTTPException(status_code=400, detail="No valid fields provided")
    cfg = get_or_create_payment_config(db)
    if "bkashNumber" in payload:
        cfg.bkash_number = (payload.get("bkashNumber") or "").strip()
    if "nagadNumber" in payload:
        cfg.nagad_number = (payload.get("nagadNumber") or "").strip()
    if "rocketNumber" in payload:
        cfg.rocket_number = (payload.get("rocketNumber") or "").strip()
    db.commit()
    db.refresh(cfg)
    return {
        "message": "Payment config updated",
        "bkashNumber": cfg.bkash_number or "",
        "nagadNumber": cfg.nagad_number or "",
        "rocketNumber": cfg.rocket_number or "",
        "updatedAt": cfg.updated_at
    }
