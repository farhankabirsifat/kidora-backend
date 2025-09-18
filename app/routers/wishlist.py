from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

from app.models.user import User, get_db
from app.models.wishlist import Wishlist, WishlistItem
from app.models.product import Product
from app.schemas.wishlist import WishlistOut, WishlistItemOut
from app.utils.security import get_current_user


router = APIRouter()


def _get_or_create_wishlist(db: Session, user_id: int) -> Wishlist:
    wl = db.query(Wishlist).filter(Wishlist.user_id == user_id).first()
    if not wl:
        wl = Wishlist(user_id=user_id)
        db.add(wl)
        db.flush()
    return wl


def _serialize_wishlist(wl: Wishlist) -> WishlistOut:
    items = [WishlistItemOut(productId=i.product_id) for i in wl.items]
    return WishlistOut(items=items)


# 24. Get Wishlist
@router.get("/", response_model=WishlistOut)
def get_wishlist(db: Session = Depends(get_db), current_user_email: str = Depends(get_current_user)):
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")
    wl = _get_or_create_wishlist(db, user.id)
    db.commit()
    db.refresh(wl)
    return _serialize_wishlist(wl)


# 25. Toggle Wishlist Item
@router.post("/toggle", response_model=WishlistOut)
def toggle_wishlist_item(
    productId: int = Query(...),
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")

    product = db.query(Product).filter(Product.id == productId).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    wl = _get_or_create_wishlist(db, user.id)

    item = (
        db.query(WishlistItem)
        .filter(
            WishlistItem.product_id == productId,
            or_(WishlistItem.wishlist_id == wl.id, WishlistItem.user_id == user.id)
        )
        .first()
    )
    if item:
        db.delete(item)
    else:
        try:
            db.add(WishlistItem(wishlist_id=wl.id, product_id=productId, user_id=user.id))
            db.commit()
        except IntegrityError:
            # Legacy unique constraint (user_id, product_id) already exists; treat as already in wishlist
            db.rollback()
            existing = (
                db.query(WishlistItem)
                .filter(
                    WishlistItem.product_id == productId,
                    or_(WishlistItem.wishlist_id == wl.id, WishlistItem.user_id == user.id)
                )
                .first()
            )
            if not existing:
                # As a fallback, try to set user_id on any row with same (wishlist_id, product_id)
                try:
                    db.add(WishlistItem(wishlist_id=wl.id, product_id=productId, user_id=user.id))
                    db.commit()
                except Exception:
                    db.rollback()
            # proceed to return current state
        else:
            # ensure session refreshed
            db.refresh(wl)
            return _serialize_wishlist(wl)

    db.commit()
    db.refresh(wl)
    return _serialize_wishlist(wl)


# 26. Remove Wishlist Item
@router.delete("/", response_model=WishlistOut)
def remove_wishlist_item(
    productId: int = Query(...),
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user),
):
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")
    wl = _get_or_create_wishlist(db, user.id)

    item = (
        db.query(WishlistItem)
        .filter(
            WishlistItem.product_id == productId,
            or_(WishlistItem.wishlist_id == wl.id, WishlistItem.user_id == user.id)
        )
        .first()
    )
    if not item:
        raise HTTPException(status_code=404, detail="Item not in wishlist")

    db.delete(item)
    db.commit()
    db.refresh(wl)
    return _serialize_wishlist(wl)
