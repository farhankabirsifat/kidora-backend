from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from app.models.user import User, get_db
from app.models.address import Address
from app.schemas.address import AddressOut, AddressCreate, AddressUpdate
from app.utils.security import get_current_user


router = APIRouter()


def _to_out(a: Address) -> AddressOut:
    return AddressOut(
        id=a.id,
        street=a.street,
        city=a.city,
        state=a.state,
        zipCode=a.zip_code,
        country=a.country,
        isDefault=a.is_default,
    )


def _maybe_clear_default(db: Session, user_id: int):
    db.query(Address).filter(Address.user_id == user_id, Address.is_default == True).update({Address.is_default: False})


# 27. Get User Addresses
@router.get("/", response_model=List[AddressOut])
def get_user_addresses(db: Session = Depends(get_db), current_user_email: str = Depends(get_current_user)):
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")
    addresses = db.query(Address).filter(Address.user_id == user.id).order_by(Address.is_default.desc(), Address.created_at.desc()).all()
    return [_to_out(a) for a in addresses]


# 28. Create Address
@router.post("/", response_model=AddressOut)
def create_address(payload: AddressCreate, db: Session = Depends(get_db), current_user_email: str = Depends(get_current_user)):
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")

    if payload.isDefault:
        _maybe_clear_default(db, user.id)

    address = Address(
        user_id=user.id,
        street=payload.street,
        city=payload.city,
        state=payload.state,
        zip_code=payload.zipCode,
        country=payload.country,
        is_default=payload.isDefault,
    )
    db.add(address)
    db.commit()
    db.refresh(address)
    return _to_out(address)


# 29. Update Address
@router.put("/{id}", response_model=AddressOut)
def update_address(id: int, payload: AddressUpdate, db: Session = Depends(get_db), current_user_email: str = Depends(get_current_user)):
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")
    address = db.query(Address).filter(Address.id == id, Address.user_id == user.id).first()
    if not address:
        raise HTTPException(status_code=404, detail="Address not found")

    if payload.isDefault:
        _maybe_clear_default(db, user.id)

    address.street = payload.street
    address.city = payload.city
    address.state = payload.state
    address.zip_code = payload.zipCode
    address.country = payload.country
    address.is_default = payload.isDefault
    db.commit()
    db.refresh(address)
    return _to_out(address)


# 30. Delete Address
@router.delete("/{id}")
def delete_address(id: int, db: Session = Depends(get_db), current_user_email: str = Depends(get_current_user)):
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")
    address = db.query(Address).filter(Address.id == id, Address.user_id == user.id).first()
    if not address:
        raise HTTPException(status_code=404, detail="Address not found")

    db.delete(address)
    db.commit()
    return {"message": "Address deleted"}
