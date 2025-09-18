from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from app.models.user import Base


class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    # shipping address fields
    shipping_name = Column(String(255))
    shipping_phone = Column(String(50))
    shipping_street = Column(String(255))
    shipping_city = Column(String(100))
    shipping_state = Column(String(100))
    shipping_zip_code = Column(String(20))
    shipping_country = Column(String(100))

    payment_method = Column(String(50))
    payment_provider = Column(String(50))  # e.g., bkash, nagad, rocket
    payment_sender_number = Column(String(50))
    payment_transaction_id = Column(String(100))
    total_amount = Column(Float, default=0.0)
    status = Column(String(20), default="PENDING")  # PENDING, CONFIRMED, SHIPPED, DELIVERED, CANCELLED
    payment_status = Column(String(20), default="PENDING")  # PENDING, PAID, REFUNDED

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    items = relationship("OrderItem", back_populates="order", cascade="all, delete-orphan")


class OrderItem(Base):
    __tablename__ = "order_items"

    id = Column(Integer, primary_key=True, index=True)
    order_id = Column(Integer, ForeignKey("orders.id"), nullable=False, index=True)
    product_id = Column(Integer, ForeignKey("products.id"), nullable=False)
    quantity = Column(Integer, nullable=False)
    selected_size = Column(String(50))
    price = Column(Float, nullable=False)  # unit price at time of order

    order = relationship("Order", back_populates="items")
