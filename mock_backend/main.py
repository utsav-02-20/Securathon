import sys
from pathlib import Path

# Ensure project root is in sys.path when executed directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import uvicorn
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings
from core.logger import setup_logger
from mock_backend.models import (
    Order,
    OrderItem,
    OrderCreateRequest,
    User,
    Transaction,
    HealthResponse,
    StandardResponse
)
from mock_backend.seed_data import USERS_DB, ORDERS_DB, TRANSACTIONS_DB

logger = setup_logger("mock_backend")

app = FastAPI(
    title="Securathon Downstream Mock Microservice",
    description="Simulates downstream enterprise APIs protected by the Intelligent API Security Gateway.",
    version="1.0.0"
)

# Enable CORS for local dashboards and testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def extract_gateway_context(request: Request) -> Dict[str, Any]:
    """
    Extracts security context headers injected by the upstream Security Gateway.
    """
    return {
        "x_user_id": request.headers.get("x-user-id"),
        "x_user_role": request.headers.get("x-user-role"),
        "x_tenant_id": request.headers.get("x-tenant-id"),
        "x_request_id": request.headers.get("x-request-id"),
        "x_gateway_risk_score": request.headers.get("x-gateway-risk-score"),
        "x_forwarded_for": request.headers.get("x-forwarded-for"),
    }


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """
    Health check endpoint for container probes and gateway readiness checks.
    """
    return HealthResponse(
        status="healthy",
        service="mock-microservice",
        timestamp=datetime.now(timezone.utc).isoformat(),
        version="1.0.0"
    )


@app.get("/api/v1/orders", response_model=StandardResponse, tags=["Orders"])
async def list_orders(request: Request, user_id: Optional[str] = None):
    """
    Lists orders. Optional filter by user_id.
    """
    context = extract_gateway_context(request)
    orders = list(ORDERS_DB.values())
    
    if user_id:
        orders = [o for o in orders if o.user_id == user_id]
        
    return StandardResponse(
        success=True,
        data=orders,
        message=f"Retrieved {len(orders)} orders successfully.",
        gateway_context=context
    )


@app.get("/api/v1/orders/{order_id}", response_model=StandardResponse, tags=["Orders"])
async def get_order_by_id(order_id: str, request: Request):
    """
    Vulnerable Endpoint (BOLA/IDOR Target):
    Returns order details by ID without local authorization checks.
    Relies on the upstream API Gateway to enforce identity and detect sequential scraping.
    """
    context = extract_gateway_context(request)
    
    order = ORDERS_DB.get(order_id)
    if not order:
        logger.warning(f"Order not found: {order_id} | Context: {context}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Order '{order_id}' was not found in the database."
        )

    logger.info(f"Serving order {order_id} (Owner: {order.user_id}) | Gateway User: {context.get('x_user_id')}")
    return StandardResponse(
        success=True,
        data=order,
        message="Order retrieved successfully.",
        gateway_context=context
    )


@app.post("/api/v1/orders", response_model=StandardResponse, status_code=status.HTTP_201_CREATED, tags=["Orders"])
async def create_order(payload: OrderCreateRequest, request: Request):
    """
    Creates a new order for the currently identified user.
    """
    context = extract_gateway_context(request)
    user_id = context.get("x_user_id") or "user_101"
    
    user = USERS_DB.get(user_id)
    tenant_id = user.tenant_id if user else "tenant_alpha"

    new_order_id = str(len(ORDERS_DB) + 1001)
    total = sum(item.quantity * item.unit_price for item in payload.items)

    new_order = Order(
        id=new_order_id,
        user_id=user_id,
        tenant_id=tenant_id,
        items=payload.items,
        total_amount=round(total, 2),
        currency="USD",
        status="PENDING",
        shipping_address=payload.shipping_address,
        created_at=datetime.now(timezone.utc).isoformat()
    )
    ORDERS_DB[new_order_id] = new_order

    logger.info(f"Created order {new_order_id} for user {user_id}")
    return StandardResponse(
        success=True,
        data=new_order,
        message="Order created successfully.",
        gateway_context=context
    )


@app.get("/api/v1/users/{user_id}", response_model=StandardResponse, tags=["Users"])
async def get_user_profile(user_id: str, request: Request):
    """
    Retrieves user profile information by ID.
    """
    context = extract_gateway_context(request)
    user = USERS_DB.get(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{user_id}' not found."
        )

    return StandardResponse(
        success=True,
        data=user,
        message="User profile retrieved.",
        gateway_context=context
    )


@app.get("/api/v1/transactions", response_model=StandardResponse, tags=["Transactions"])
async def list_transactions(request: Request):
    """
    Lists financial transactions.
    """
    context = extract_gateway_context(request)
    transactions = list(TRANSACTIONS_DB.values())
    return StandardResponse(
        success=True,
        data=transactions,
        message=f"Retrieved {len(transactions)} transactions.",
        gateway_context=context
    )


@app.get("/api/v1/debug/headers", tags=["Debug"])
async def debug_headers(request: Request):
    """
    Echoes back all received request headers.
    Essential for inspecting gateway proxy forwarding and injected security headers.
    """
    return {
        "headers": dict(request.headers),
        "client": request.client.host if request.client else "unknown",
        "url": str(request.url),
        "gateway_context": extract_gateway_context(request)
    }


def start():
    """Entry point to launch the mock backend with uvicorn."""
    logger.info(f"Starting Securathon Mock Backend on {settings.backend_host}:{settings.backend_port}")
    uvicorn.run(
        "mock_backend.main:app",
        host=settings.backend_host,
        port=settings.backend_port,
        reload=False,
        log_level=settings.log_level.lower()
    )


if __name__ == "__main__":
    start()

