from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from app.models.user import Base


class HeroBanner(Base):
    __tablename__ = "hero_banners"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=True)
    subtitle = Column(String(500), nullable=True)
    image_url = Column(String(255), nullable=True)
    link_url = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
