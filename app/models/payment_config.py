from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from sqlalchemy.orm import Session

from app.models.user import Base, get_db  # Reuse existing Base/Session


class PaymentConfig(Base):
    __tablename__ = "payment_config"
    id = Column(Integer, primary_key=True, index=True)
    bkash_number = Column(String(30))
    nagad_number = Column(String(30))
    rocket_number = Column(String(30))
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


def get_or_create_payment_config(db: Session) -> PaymentConfig:
    cfg = db.query(PaymentConfig).first()
    if not cfg:
        cfg = PaymentConfig(
            bkash_number="017xxxxxxxx",
            nagad_number="018xxxxxxxx",
            rocket_number="019xxxxxxxx",
        )
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg
