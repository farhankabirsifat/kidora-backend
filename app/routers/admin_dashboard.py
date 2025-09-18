from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.models.user import get_db, User
from app.models.product import Product
from app.models.order import Order
from app.utils.security import get_current_user, ADMIN_EMAIL


router = APIRouter()


def _is_admin_or_sub(email: str) -> bool:
    # Accept ADMIN_EMAIL, admin@example.com, or emails ending with @admin as admins
    return email == ADMIN_EMAIL or email.endswith("@admin") or email == "admin@example.com"


# 40. Get Dashboard Overview
@router.get("/dashboard/overview")
def get_dashboard_overview(db: Session = Depends(get_db), current_user_email: str = Depends(get_current_user)):
    if not _is_admin_or_sub(current_user_email):
        raise HTTPException(status_code=403, detail="Admin access required")
    users = db.query(User).count()
    products = db.query(Product).count()
    orders = db.query(Order).count()
    revenue_rows = db.query(Order.total_amount).all()
    revenue = float(sum((row[0] or 0.0) for row in revenue_rows))
    return {"users": users, "products": products, "orders": orders, "revenue": revenue}


# 41. Update Admin Order Status
@router.put("/orders/{id}/status")
def update_admin_order_status(id: int, payload: dict, db: Session = Depends(get_db), current_user_email: str = Depends(get_current_user)):
    if not _is_admin_or_sub(current_user_email):
        raise HTTPException(status_code=403, detail="Admin access required")
    order = db.query(Order).filter(Order.id == id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    status = payload.get("status")
    if status not in {"PENDING", "CONFIRMED", "SHIPPED", "DELIVERED", "CANCELLED"}:
        raise HTTPException(status_code=400, detail="Invalid status")
    order.status = status
    db.commit()
    return {"message": "Order status updated", "id": order.id, "status": order.status}


# 42. Update Admin Payment Status
@router.put("/orders/{id}/payment-status")
def update_admin_payment_status(id: int, payload: dict, db: Session = Depends(get_db), current_user_email: str = Depends(get_current_user)):
    if not _is_admin_or_sub(current_user_email):
        raise HTTPException(status_code=403, detail="Admin access required")
    order = db.query(Order).filter(Order.id == id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    payment_status = payload.get("paymentStatus")
    if payment_status not in {"PENDING", "PAID", "REFUNDED"}:
        raise HTTPException(status_code=400, detail="Invalid payment status")
    order.payment_status = payment_status
    db.commit()
    return {"message": "Payment status updated", "id": order.id, "paymentStatus": order.payment_status}
