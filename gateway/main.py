import uuid
import time
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional
from datetime import timedelta

import uvicorn
from fastapi import FastAPI, Request, Response, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from core.config import settings
from core.logger import setup_logger
from core.redis_client import get_redis_client, close_redis_client, blacklist_token
from core.security import create_access_token, verify_jwt_token, revoke_token_by_payload
from core.rate_limiter import rate_limiter, RateLimitResult
from gateway.dependencies import get_authenticated_claims, enforce_sliding_window_rate_limit
from gateway.proxy import get_proxy_client, close_proxy_client, forward_request

logger = setup_logger("gateway.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Gateway lifecycle manager.
    Initializes Redis state connection and high-concurrency HTTP proxy client on startup,
    and cleanly tears them down on shutdown.
    """
    logger.info("Initializing Intelligent Security Gateway...")
    try:
        await get_redis_client()
        get_proxy_client()
        logger.info("Gateway services initialized successfully.")
    except Exception as e:
        logger.error(f"Error initializing gateway dependencies: {e}")
    yield
    logger.info("Shutting down Security Gateway...")
    await close_proxy_client()
    await close_redis_client()
    logger.info("Security Gateway shutdown complete.")


app = FastAPI(
    title="Securathon Intelligent API Security Gateway",
    description="High-performance Guard + Detective Reverse Proxy protecting APIs from BOLA/IDOR, volumetric attacks, and token tampering.",
    version="1.0.0",
    lifespan=lifespan
)

# Cross-Origin Resource Sharing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------------------------------------------------------------
# Auth & System Schemas
# ------------------------------------------------------------------------------
class TokenRequest(BaseModel):
    user_id: str = Field(default="user_101", description="Subject / User identifier")
    role: str = Field(default="customer", description="Role (customer, admin, merchant)")
    tenant_id: str = Field(default="tenant_alpha", description="Tenant / Organization ID")
    expires_in_minutes: int = Field(default=60, description="Token validity duration")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    user_id: str
    role: str
    tenant_id: str
    jti: str


class RevokeRequest(BaseModel):
    token: Optional[str] = Field(default=None, description="Full JWT to revoke")
    jti: Optional[str] = Field(default=None, description="Direct JWT ID (jti) to blacklist")
    ttl_seconds: Optional[int] = Field(default=3600, description="Time to keep in blacklist")


# ------------------------------------------------------------------------------
# Public System & Auth Endpoints
# ------------------------------------------------------------------------------
@app.get("/health", tags=["System"])
async def gateway_health():
    """
    Readiness & liveness check for the Security Gateway.
    """
    return {
        "status": "healthy",
        "service": "api-security-gateway",
        "port": settings.gateway_port,
        "backend_target": settings.backend_service_url,
        "guard_status": "active",
        "rate_limiter_status": "active (sliding-window)",
        "rate_limit_window": f"{settings.rate_limit_window_seconds}s"
    }


@app.post("/auth/token", response_model=TokenResponse, tags=["Authentication"])
async def issue_token(payload: TokenRequest):
    """
    Issues a cryptographically signed JWT token for a given user identity.
    Includes JTI for O(1) revocation capability.
    """
    jti = str(uuid.uuid4())
    token_data = {
        "sub": payload.user_id,
        "role": payload.role,
        "tenant_id": payload.tenant_id,
        "jti": jti
    }
    expires_delta = timedelta(minutes=payload.expires_in_minutes)
    token = create_access_token(token_data, expires_delta=expires_delta)

    return TokenResponse(
        access_token=token,
        token_type="Bearer",
        expires_in=payload.expires_in_minutes * 60,
        user_id=payload.user_id,
        role=payload.role,
        tenant_id=payload.tenant_id,
        jti=jti
    )


@app.post("/auth/revoke", tags=["Authentication"])
async def revoke_token(payload: RevokeRequest):
    """
    Instantly blacklists a token in Redis by JTI.
    Revoked tokens are rejected within <0.2ms by the Gateway Guard.
    """
    if payload.jti:
        success = await blacklist_token(payload.jti, ttl_seconds=payload.ttl_seconds or 3600)
        return {
            "success": success,
            "message": f"Token JTI '{payload.jti}' has been revoked and blacklisted in Redis."
        }
    elif payload.token:
        try:
            claims = await verify_jwt_token(payload.token)
            success = await revoke_token_by_payload(claims)
            return {
                "success": success,
                "jti": claims.get("jti"),
                "message": "Token successfully revoked."
            }
        except Exception as err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unable to decode token for revocation: {err}"
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must provide either 'token' or 'jti' to revoke."
        )


@app.get("/auth/demo-tokens", tags=["Authentication"])
async def get_demo_tokens():
    """
    Utility endpoint for live demonstrations & tests.
    Returns pre-generated valid tokens for all persona profiles.
    """
    personas = [
        {"user_id": "user_101", "role": "customer", "tenant_id": "tenant_alpha", "name": "Alice (Alpha Corp)"},
        {"user_id": "user_102", "role": "customer", "tenant_id": "tenant_beta", "name": "Bob (Beta Logistics)"},
        {"user_id": "user_104", "role": "customer", "tenant_id": "tenant_gamma", "name": "Eve (Attacker)"},
        {"user_id": "user_999", "role": "admin", "tenant_id": "system", "name": "System Admin"},
    ]
    tokens = {}
    for p in personas:
        jti = str(uuid.uuid4())
        token = create_access_token({
            "sub": p["user_id"],
            "role": p["role"],
            "tenant_id": p["tenant_id"],
            "jti": jti
        })
        tokens[p["user_id"]] = {
            "name": p["name"],
            "token": token,
            "jti": jti
        }
    return tokens


@app.get("/auth/rate-limit-status", tags=["Rate Limiting"])
async def get_current_rate_limit(
    request: Request,
    claims: Dict[str, Any] = Depends(get_authenticated_claims)
):
    """
    Inspects current sliding window rate limit status for the authenticated user without consuming quota.
    """
    user_id = claims["sub"]
    role = claims.get("role", "customer").lower()
    limit = settings.rate_limit_admin if role == "admin" else (settings.rate_limit_merchant if role == "merchant" else settings.rate_limit_customer)
    
    # Query without adding a new point (using 0 limit mock check or inspect)
    r = await get_redis_client()
    key = f"ratelimit:user:{user_id}"
    now = time.time()
    pipe = r.pipeline(transaction=True)
    pipe.zremrangebyscore(key, "-inf", now - settings.rate_limit_window_seconds)
    pipe.zcard(key)
    results = await pipe.execute()
    current_count = int(results[1])
    remaining = max(0, limit - current_count)

    return {
        "user_id": user_id,
        "role": role,
        "limit": limit,
        "current_count": current_count,
        "remaining": remaining,
        "window_seconds": settings.rate_limit_window_seconds
    }


# ------------------------------------------------------------------------------
# Core Reverse Proxy Route with Guard + Rate Limiting Pipeline
# ------------------------------------------------------------------------------
@app.api_route(
    "/api/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    tags=["Reverse Proxy"]
)
async def proxy_protected_api(
    path: str,
    request: Request,
    claims: Dict[str, Any] = Depends(enforce_sliding_window_rate_limit)
):
    """
    STEP 1, 2 & 3 of Gateway Request Lifecycle:
    1. Intercepts incoming client request.
    2. Validates cryptographic JWT identity (The Guard).
    3. Evaluates atomic Redis sliding-window rate limit (Drops bursts in <1ms with 429).
    4. Injects enriched identity context headers:
       - X-User-ID: Authenticated subject
       - X-User-Role: RBAC role
       - X-Tenant-ID: Organization / Tenant
       - X-Request-ID: Unique tracing UUID
       - X-Forwarded-For: Client IP
       - X-Gateway-Guard: Status flag ('passed')
    5. Forwards seamlessly to downstream microservice (:8001).
    6. Appends RFC Rate-Limiting response headers (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset).
    """
    request_id = str(uuid.uuid4())
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Enriched context headers for downstream service consumption
    injected_headers = {
        "X-User-ID": str(claims.get("sub", "")),
        "X-User-Role": str(claims.get("role", "customer")),
        "X-Tenant-ID": str(claims.get("tenant_id", "default")),
        "X-Request-ID": request_id,
        "X-Forwarded-For": client_ip,
        "X-Gateway-Guard": "passed"
    }

    downstream_url = f"{settings.backend_service_url}/api/{path}"
    logger.info(
        f"Proxying [{request.method}] /api/{path} -> {downstream_url} | "
        f"User: {claims.get('sub')} | ReqID: {request_id}"
    )

    downstream_response = await forward_request(request, downstream_url, injected_headers)

    # Attach RFC rate-limit headers from Step 3 to downstream response
    rate_limit_result: Optional[RateLimitResult] = getattr(request.state, "rate_limit_result", None)
    if rate_limit_result:
        for header_name, header_value in rate_limit_result.headers.items():
            downstream_response.headers[header_name] = header_value

    return downstream_response


def start():
    """Starts the Security Gateway service on configured host:port."""
    logger.info(f"Starting Intelligent API Security Gateway on {settings.gateway_host}:{settings.gateway_port}")
    uvicorn.run(
        "gateway.main:app",
        host=settings.gateway_host,
        port=settings.gateway_port,
        reload=False,
        log_level=settings.log_level.lower()
    )


if __name__ == "__main__":
    start()
