from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class OrderItem(BaseModel):
    product_id: str
    name: str
    quantity: int
    unit_price: float


class Order(BaseModel):
    id: str
    user_id: str
    tenant_id: str
    items: List[OrderItem]
    total_amount: float
    currency: str = "USD"
    status: str = "COMPLETED"  # PENDING, PROCESSING, COMPLETED, CANCELLED
    shipping_address: str
    created_at: str


class OrderCreateRequest(BaseModel):
    items: List[OrderItem]
    shipping_address: str


class User(BaseModel):
    id: str
    tenant_id: str
    username: str
    email: str
    full_name: str
    role: str = "customer"  # customer, admin, merchant
    is_active: bool = True
    created_at: str


class Transaction(BaseModel):
    id: str
    user_id: str
    order_id: str
    amount: float
    currency: str = "USD"
    status: str = "SUCCESS"  # SUCCESS, FAILED, PENDING
    payment_method: str = "CREDIT_CARD"
    timestamp: str


class HealthResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    version: str = "1.0.0"


class StandardResponse(BaseModel):
    success: bool
    data: Optional[Any] = None
    message: Optional[str] = None
    gateway_context: Optional[Dict[str, Any]] = None

