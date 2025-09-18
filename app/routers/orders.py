from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime
from sqlalchemy.exc import ProgrammingError, IntegrityError
from sqlalchemy import text

from app.models.user import User, get_db
from app.models.order import Order, OrderItem
from app.models.product import Product
from app.schemas.order import (
    OrderCreate,
    OrderOut,
    OrderItemOut,
    OrderStatusUpdate,
    OrderPaymentStatusUpdate,
)
from app.utils.security import get_current_user
from app.models.user import engine


router = APIRouter()
admin_router = APIRouter()


def map_order_to_out(order: Order) -> OrderOut:
    shipping = {
        "name": getattr(order, "shipping_name", None),
        "phone": getattr(order, "shipping_phone", None),
        "street": order.shipping_street,
        "city": order.shipping_city,
        "state": order.shipping_state,
        "zipCode": order.shipping_zip_code,
        "country": order.shipping_country,
    }
    items = [
        OrderItemOut(
            id=i.id,
            productId=i.product_id,
            quantity=i.quantity,
            selectedSize=i.selected_size,
            price=i.price,
        )
        for i in order.items
    ]
    return OrderOut(
        id=order.id,
        items=items,
        shippingAddress=shipping,  # type: ignore
        paymentMethod=order.payment_method,
        paymentProvider=order.payment_provider,
        senderNumber=order.payment_sender_number,
        transactionId=order.payment_transaction_id,
        totalAmount=order.total_amount,
        status=order.status,  # type: ignore
        paymentStatus=order.payment_status,  # type: ignore
        createdAt=order.created_at.isoformat(),
        updatedAt=order.updated_at.isoformat(),
    )


# 14. Create Order
@router.post("/", response_model=OrderOut)
def create_order(
    payload: OrderCreate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")

    if not payload.items:
        raise HTTPException(status_code=400, detail="Order must contain at least one item")

    # Validate products/stock and compute total using server-side discounted price
    computed_total = 0.0
    discounted_unit_prices = {}
    for item in payload.items:
        product = db.query(Product).filter(Product.id == item.productId).first()
        if not product:
            raise HTTPException(status_code=404, detail=f"Product {item.productId} not found")
        # Validate total stock
        if product.stock is not None and product.stock < item.quantity:
            raise HTTPException(status_code=400, detail=f"Insufficient stock for product {product.id}")
        # Validate per-size stock if configured
        sel_size = getattr(item, 'selectedSize', None) or None
        if product.sizes_stock and sel_size:
            size_qty = int(product.sizes_stock.get(sel_size, 0) or 0)
            if size_qty < item.quantity:
                raise HTTPException(status_code=400, detail=f"Insufficient stock for size {sel_size} of product {product.id}")
        base_price = float(product.price or 0)
        discount_pct = int(getattr(product, 'discount', 0) or 0)
        unit_price = round(base_price * (1 - discount_pct / 100), 2) if discount_pct else round(base_price, 2)
        discounted_unit_prices[item.productId] = unit_price
        computed_total += unit_price * item.quantity

    # Trust client total if matches computed (within cents) else use computed
    total = round(computed_total, 2)

    order = Order(
        user_id=user.id,
        shipping_name=getattr(payload.shippingAddress, 'name', None),
        shipping_phone=getattr(payload.shippingAddress, 'phone', None),
        shipping_street=payload.shippingAddress.street,
        shipping_city=payload.shippingAddress.city,
        shipping_state=payload.shippingAddress.state,
        shipping_zip_code=payload.shippingAddress.zipCode,
        shipping_country=payload.shippingAddress.country,
        payment_method=payload.paymentMethod,
        payment_provider=payload.paymentProvider,
        payment_sender_number=payload.senderNumber,
        payment_transaction_id=payload.transactionId,
        total_amount=total,
        status="PENDING",
    )
    db.add(order)
    try:
        db.flush()  # get order.id
    except ProgrammingError as e:
        # Handle missing columns on legacy DBs: add columns then retry once
        db.rollback()
        try:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE IF EXISTS orders ADD COLUMN IF NOT EXISTS payment_provider VARCHAR(50)"))
                conn.execute(text("ALTER TABLE IF EXISTS orders ADD COLUMN IF NOT EXISTS payment_sender_number VARCHAR(50)"))
                conn.execute(text("ALTER TABLE IF EXISTS orders ADD COLUMN IF NOT EXISTS payment_transaction_id VARCHAR(100)"))
                conn.execute(text("ALTER TABLE IF EXISTS orders ADD COLUMN IF NOT EXISTS shipping_name VARCHAR(255)"))
                conn.execute(text("ALTER TABLE IF EXISTS orders ADD COLUMN IF NOT EXISTS shipping_phone VARCHAR(50)"))
        except Exception:
            pass
        # Re-add and flush again
        db.add(order)
        db.flush()

    for item in payload.items:
        unit_price = discounted_unit_prices.get(item.productId, float(item.price) if item.price is not None else 0.0)
        db.add(
            OrderItem(
                order_id=order.id,
                product_id=item.productId,
                quantity=item.quantity,
                selected_size=item.selectedSize,
                price=unit_price,
            )
        )

    # Reduce stock (per-size then total recomputed)
    for item in payload.items:
        product = db.query(Product).filter(Product.id == item.productId).first()
        if not product:
            continue

        # Decrement per-size stock if configured and size provided
        sel_size = getattr(item, 'selectedSize', None) or None
        if product.sizes_stock and sel_size:
            try:
                current = int((product.sizes_stock or {}).get(sel_size, 0) or 0)
                new_qty = max(0, current - item.quantity)
                # Reassign JSONB dict to ensure SQLAlchemy change tracking
                sizes_copy = dict(product.sizes_stock or {})
                sizes_copy[sel_size] = new_qty
                product.sizes_stock = sizes_copy
            except Exception:
                pass

        # Recompute total stock from sizes_stock when available; otherwise decrement fallback
        try:
            if product.sizes_stock:
                total_from_sizes = sum(int(v or 0) for v in product.sizes_stock.values())
                product.stock = max(0, int(total_from_sizes))
            else:
                if product.stock is not None:
                    product.stock = max(0, int(product.stock) - int(item.quantity))
        except Exception:
            # Fallback: ensure non-negative
            try:
                if product.stock is not None:
                    product.stock = max(0, int(product.stock))
            except Exception:
                pass

    db.commit()
    db.refresh(order)
    return map_order_to_out(order)


# 15. Get User Orders
@router.get("/", response_model=List[OrderOut])
def get_user_orders(
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")
    orders = db.query(Order).filter(Order.user_id == user.id).order_by(Order.created_at.desc()).all()
    return [map_order_to_out(o) for o in orders]


# 16. Get Order by ID
@router.get("/{id}", response_model=OrderOut)
def get_order_by_id(
    id: int,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")
    order = db.query(Order).filter(Order.id == id, Order.user_id == user.id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return map_order_to_out(order)


# 17. Update Order Status (user's own order)
@router.put("/{id}/status", response_model=OrderOut)
def update_order_status(
    id: int,
    payload: OrderStatusUpdate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")
    order = db.query(Order).filter(Order.id == id, Order.user_id == user.id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    # Users can set only certain transitions; for simplicity allow any from enum
    # Normalize to uppercase to satisfy DB constraint even if client sends lowercase
    order.status = str(payload.status).upper()
    order.updated_at = datetime.utcnow()
    try:
        db.commit()
    except IntegrityError:
        # Likely due to legacy CHECK constraint not allowing our canonical statuses
        db.rollback()
        try:
            with engine.begin() as conn:
                # Normalize existing values to uppercase
                conn.execute(text("UPDATE orders SET status = UPPER(status) WHERE status IS NOT NULL"))
                # Drop old constraints with common names
                conn.execute(text("ALTER TABLE IF EXISTS orders DROP CONSTRAINT IF EXISTS orders_status_check"))
                conn.execute(text("ALTER TABLE IF EXISTS orders DROP CONSTRAINT IF EXISTS order_status_check"))
                # Recreate compatible constraint
                conn.execute(text(
                    "ALTER TABLE IF EXISTS orders "
                    "ADD CONSTRAINT orders_status_check CHECK (UPPER(status) IN ('PENDING','CONFIRMED','PACKED','OUT_FOR_DELIVERY','SHIPPED','DELIVERED','CANCELLED'))"
                ))
        except Exception:
            pass
        db.commit()
    db.refresh(order)
    return map_order_to_out(order)


# 18. Cancel Order
@router.post("/{id}/cancel", response_model=OrderOut)
def cancel_order(
    id: int,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")
    order = db.query(Order).filter(Order.id == id, Order.user_id == user.id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    if order.status in ("CANCELLED", "DELIVERED"):
        raise HTTPException(status_code=400, detail="Order cannot be cancelled")
    order.status = "CANCELLED"
    order.updated_at = datetime.utcnow()

    # Optional: restore stock on cancel
    for item in order.items:
        product = db.query(Product).filter(Product.id == item.product_id).first()
        if product and product.stock is not None:
            product.stock = product.stock + item.quantity

    db.commit()
    db.refresh(order)
    return map_order_to_out(order)


# 19. Get Admin Orders (Admin/Sub-Admin)
@admin_router.get("/", response_model=List[OrderOut])
def get_admin_orders(
    page: int = Query(0, ge=0),
    size: int = Query(20, ge=1),
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    # Simple rule: treat the first registered user as admin, or match specific email
    is_admin = current_user_email.endswith("@admin") or current_user_email == "admin@example.com"
    if not is_admin:
        # Fallback: allow ADMIN_EMAIL from settings to act as admin as well
        from app.utils.security import ADMIN_EMAIL

        if current_user_email != ADMIN_EMAIL:
            raise HTTPException(status_code=403, detail="Admin access required")

    query = db.query(Order).order_by(Order.created_at.desc())
    orders = query.offset(page * size).limit(size).all()
    return [map_order_to_out(o) for o in orders]


# 20. Admin: Update Order Status
@admin_router.put("/{id}/status", response_model=OrderOut)
def admin_update_order_status(
    id: int,
    payload: OrderStatusUpdate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    is_admin = current_user_email.endswith("@admin") or current_user_email == "admin@example.com"
    if not is_admin:
        from app.utils.security import ADMIN_EMAIL

        if current_user_email != ADMIN_EMAIL:
            raise HTTPException(status_code=403, detail="Admin access required")

    order = db.query(Order).filter(Order.id == id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    order.status = str(payload.status).upper()
    order.updated_at = datetime.utcnow()
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        try:
            with engine.begin() as conn:
                conn.execute(text("UPDATE orders SET status = UPPER(status) WHERE status IS NOT NULL"))
                conn.execute(text("ALTER TABLE IF EXISTS orders DROP CONSTRAINT IF EXISTS orders_status_check"))
                conn.execute(text("ALTER TABLE IF EXISTS orders DROP CONSTRAINT IF EXISTS order_status_check"))
                conn.execute(text(
                    "ALTER TABLE IF EXISTS orders "
                    "ADD CONSTRAINT orders_status_check CHECK (UPPER(status) IN ('PENDING','CONFIRMED','PACKED','OUT_FOR_DELIVERY','SHIPPED','DELIVERED','CANCELLED'))"
                ))
        except Exception:
            pass
        db.commit()
    db.refresh(order)
    return map_order_to_out(order)


# 21. Admin: Update Payment Status
@admin_router.put("/{id}/payment-status", response_model=OrderOut)
def admin_update_payment_status(
    id: int,
    payload: OrderPaymentStatusUpdate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    is_admin = current_user_email.endswith("@admin") or current_user_email == "admin@example.com"
    if not is_admin:
        from app.utils.security import ADMIN_EMAIL

        if current_user_email != ADMIN_EMAIL:
            raise HTTPException(status_code=403, detail="Admin access required")

    order = db.query(Order).filter(Order.id == id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    order.payment_status = str(payload.paymentStatus).upper()
    order.updated_at = datetime.utcnow()
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        try:
            with engine.begin() as conn:
                conn.execute(text("UPDATE orders SET payment_status = UPPER(payment_status) WHERE payment_status IS NOT NULL"))
                conn.execute(text("ALTER TABLE IF EXISTS orders DROP CONSTRAINT IF EXISTS orders_payment_status_check"))
                conn.execute(text("ALTER TABLE IF EXISTS orders DROP CONSTRAINT IF EXISTS order_payment_status_check"))
                conn.execute(text(
                    "ALTER TABLE IF EXISTS orders "
                    "ADD CONSTRAINT orders_payment_status_check CHECK (UPPER(payment_status) IN ('PENDING','PAID','REFUNDED'))"
                ))
        except Exception:
            pass
        db.commit()
    db.refresh(order)
    return map_order_to_out(order)
