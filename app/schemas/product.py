from pydantic import BaseModel, ConfigDict
from typing import List, Optional

class ProductBase(BaseModel):
    title: str
    description: Optional[str] = None
    price: float
    category: str
    stock: int
    rating: Optional[float] = 0.0
    discount: Optional[int] = 0
    sizes_stock: Optional[dict] = None

class ProductCreate(ProductBase):
    pass

class ProductUpdate(ProductBase):
    pass

class ProductOut(ProductBase):
    id: int
    main_image: Optional[str] = None
    images: Optional[List[str]] = None

    # Pydantic v2 config
    model_config = ConfigDict(from_attributes=True)
