from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from datetime import datetime
from typing import List, Optional

from app.models.user import User, get_db
from app.models.cart import Cart, CartItem
from app.models.product import Product
from app.schemas.cart import CartItemIn, CartOut, CartItemOut
from app.utils.security import get_current_user


router = APIRouter()


def _get_or_create_cart(db: Session, user_id: int) -> Cart:
    cart = db.query(Cart).filter(Cart.user_id == user_id).first()
    if not cart:
        cart = Cart(user_id=user_id)
        db.add(cart)
        db.flush()
    return cart


def _serialize_cart(cart: Cart) -> CartOut:
    items = [
        CartItemOut(productId=i.product_id, quantity=i.quantity, selectedSize=i.selected_size)
        for i in cart.items
    ]
    return CartOut(items=items)


# 20. Get Cart
@router.get("/", response_model=CartOut)
def get_cart(db: Session = Depends(get_db), current_user_email: str = Depends(get_current_user)):
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")
    cart = _get_or_create_cart(db, user.id)
    db.commit()  # ensure cart persisted if created
    db.refresh(cart)
    return _serialize_cart(cart)


# 21. Add/Update Cart Item
@router.post("/", response_model=CartOut)
def add_or_update_cart_item(
    payload: CartItemIn,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")

    # Validate product exists
    product = db.query(Product).filter(Product.id == payload.productId).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    cart = _get_or_create_cart(db, user.id)

    # Normalize size key for consistent matching (uppercase, trimmed)
    size_key = None
    if payload.selectedSize is not None:
        s = str(payload.selectedSize).strip()
        size_key = s.upper() if s else None

    existing = (
        db.query(CartItem)
        .filter(
            CartItem.cart_id == cart.id,
            CartItem.product_id == payload.productId,
            CartItem.selected_size == size_key,
        )
        .first()
    )

    # Determine target quantity (increment if exists)
    new_qty = payload.quantity if not existing else (existing.quantity + payload.quantity)

    # Validate against available stock (per-size when provided, else total)
    if size_key and product.sizes_stock:
        available = int((product.sizes_stock or {}).get(size_key, 0) or 0)
        if new_qty > available:
            raise HTTPException(status_code=400, detail=f"Not enough stock for size {size_key}. Available: {available}")
    else:
        # Fall back to total stock check if no size or no per-size config
        available_total = int(product.stock or 0)
        if new_qty > available_total:
            raise HTTPException(status_code=400, detail=f"Not enough stock. Available: {available_total}")

    try:
        if existing:
            existing.quantity = new_qty
            existing.updated_at = datetime.utcnow()
        else:
            db.add(
                CartItem(
                    cart_id=cart.id,
                    product_id=payload.productId,
                    selected_size=size_key,
                    quantity=new_qty,
                )
            )
        db.commit()
    except IntegrityError:
        # In case of a race, merge by incrementing
        db.rollback()
        existing = (
            db.query(CartItem)
            .filter(
                CartItem.cart_id == cart.id,
                CartItem.product_id == payload.productId,
                CartItem.selected_size == size_key,
            )
            .first()
        )
        if existing:
            # Recompute and validate again just in case
            merged_qty = existing.quantity + payload.quantity
            if size_key and product.sizes_stock:
                available = int((product.sizes_stock or {}).get(size_key, 0) or 0)
                if merged_qty > available:
                    raise HTTPException(status_code=400, detail=f"Not enough stock for size {size_key}. Available: {available}")
            else:
                available_total = int(product.stock or 0)
                if merged_qty > available_total:
                    raise HTTPException(status_code=400, detail=f"Not enough stock. Available: {available_total}")
            existing.quantity = merged_qty
            existing.updated_at = datetime.utcnow()
            db.commit()
        else:
            # Try fresh insert one more time
            db.add(
                CartItem(
                    cart_id=cart.id,
                    product_id=payload.productId,
                    selected_size=size_key,
                    quantity=payload.quantity,
                )
            )
            db.commit()

    db.refresh(cart)
    return _serialize_cart(cart)


# 22. Remove Cart Item
@router.delete("/", response_model=CartOut)
def remove_cart_item(
    productId: int = Query(...),
    selectedSize: str = Query(...),
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")
    cart = _get_or_create_cart(db, user.id)

    item = (
        db.query(CartItem)
        .filter(
            CartItem.cart_id == cart.id,
            CartItem.product_id == productId,
            CartItem.selected_size == selectedSize,
        )
        .first()
    )
    if not item:
        raise HTTPException(status_code=404, detail="Cart item not found")

    db.delete(item)
    db.commit()
    db.refresh(cart)
    return _serialize_cart(cart)


# 23. Clear Cart
@router.delete("/clear", response_model=CartOut)
def clear_cart(db: Session = Depends(get_db), current_user_email: str = Depends(get_current_user)):
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")
    cart = _get_or_create_cart(db, user.id)

    for item in list(cart.items):
        db.delete(item)
    db.commit()
    db.refresh(cart)
    return _serialize_cart(cart)
