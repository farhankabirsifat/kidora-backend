from pydantic import BaseModel, Field
from typing import List, Optional, Literal


class OrderItemIn(BaseModel):
    productId: int
    quantity: int = Field(gt=0)
    selectedSize: Optional[str] = None
    price: float = Field(ge=0)


class ShippingAddress(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    street: str
    city: str
    state: str
    zipCode: str
    country: str


class OrderCreate(BaseModel):
    items: List[OrderItemIn]
    shippingAddress: ShippingAddress
    paymentMethod: str
    totalAmount: float = Field(ge=0)
    paymentProvider: Optional[str] = None
    senderNumber: Optional[str] = None
    transactionId: Optional[str] = None


OrderStatus = Literal["PENDING", "CONFIRMED", "PACKED","OUT_FOR_DELIVERY", "SHIPPED", "DELIVERED", "CANCELLED"]
PaymentStatus = Literal["PENDING", "PAID", "REFUNDED"]


class OrderStatusUpdate(BaseModel):
    status: OrderStatus


class OrderPaymentStatusUpdate(BaseModel):
    paymentStatus: PaymentStatus


class OrderItemOut(BaseModel):
    id: int
    productId: int
    quantity: int
    selectedSize: Optional[str] = None
    price: float


class OrderOut(BaseModel):
    id: int
    items: List[OrderItemOut]
    shippingAddress: ShippingAddress
    paymentMethod: str
    paymentProvider: Optional[str] = None
    senderNumber: Optional[str] = None
    transactionId: Optional[str] = None
    totalAmount: float
    status: OrderStatus
    paymentStatus: PaymentStatus
    createdAt: str
    updatedAt: str
