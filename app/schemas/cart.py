from pydantic import BaseModel, Field
from typing import List, Optional


class CartItemIn(BaseModel):
    productId: int
    quantity: int = Field(gt=0)
    selectedSize: Optional[str] = None


class CartItemOut(BaseModel):
    productId: int
    quantity: int
    selectedSize: Optional[str] = None


class CartOut(BaseModel):
    items: List[CartItemOut]
