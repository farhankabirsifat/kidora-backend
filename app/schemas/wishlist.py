from pydantic import BaseModel
from typing import List


class WishlistItemOut(BaseModel):
    productId: int


class WishlistOut(BaseModel):
    items: List[WishlistItemOut]
