from sqlalchemy import Column, Integer, String, Float, Numeric, Boolean
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from app.models.user import Base

class Product(Base):
    __tablename__ = "products"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(String(1000))
    price = Column(Numeric(10, 2), nullable=False)
    category = Column(String(100), index=True)
    stock = Column(Integer, default=0)
    rating = Column(Float, default=0.0)
    discount = Column(Integer, default=0)
    main_image = Column(String(255))
    # Optional embedded video URL (e.g., YouTube embed)
    video_url = Column(String(500))
    images = Column(JSONB)  # List of URLs or paths
    sizes_stock = Column(JSONB)  # Optional per-size inventory, e.g., {"XS": 3, "S": 5, ...}
    free_shipping = Column(Boolean, default=False)

