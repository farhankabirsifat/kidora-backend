from pydantic import BaseModel
from typing import Optional


class HeroBannerOut(BaseModel):
    id: int
    title: Optional[str] = None
    subtitle: Optional[str] = None
    imageUrl: Optional[str] = None
    linkUrl: Optional[str] = None
