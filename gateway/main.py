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
from ml.detector import anomaly_detector, AnomalyDetectionResult
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
        "guard_status": "active (JWT HS256/RS256 + Redis JTI Blacklist)",
        "rate_limiter_status": "active (atomic sliding-window)",
        "ai_engine_status": "active (Isolation Forest sub-ms scoring)",
        "anomaly_threshold": settings.anomaly_score_threshold
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
# Core Reverse Proxy Route with 4-Step Pipeline: Guard + Rate Limiter + AI Detective
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
    REQUEST LIFECYCLE:
    Step 1: Intercept incoming client request.
    Step 2: Cryptographic Identity Guard (enforces valid JWT, drops alg:none, checks JTI blacklist).
    Step 3: Atomic Sliding Window Rate Limiter (drops volumetric floods with 429).
    Step 4: Behavioral Telemetry Extraction & AI Scoring (Isolation Forest evaluates sequential BOLA patterns in <1ms).
    Step 5 (Forwarding): Enriches request with X-User-ID, X-Role, and X-Gateway-Risk-Score, and proxies to :8001.
    """
    user_id = str(claims.get("sub", "unknown_user"))
    request_id = str(uuid.uuid4())
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Step 4: AI Detective Anomaly Scoring
    raw_body = await request.body()
    body_text = raw_body.decode("utf-8", errors="ignore") if raw_body else ""
    
    eval_result: AnomalyDetectionResult = await anomaly_detector.evaluate_request(
        user_id=user_id,
        path=f"/api/{path}",
        query_string=str(request.query_params),
        body_text=body_text
    )

    # Enriched context headers for downstream service consumption
    injected_headers = {
        "X-User-ID": user_id,
        "X-User-Role": str(claims.get("role", "customer")),
        "X-Tenant-ID": str(claims.get("tenant_id", "default")),
        "X-Request-ID": request_id,
        "X-Forwarded-For": client_ip,
        "X-Gateway-Guard": "passed",
        "X-Gateway-Risk-Score": str(eval_result.risk_score),
        "X-Gateway-Anomaly": str(eval_result.is_anomaly).lower()
    }

    downstream_url = f"{settings.backend_service_url}/api/{path}"
    logger.info(
        f"Proxying [{request.method}] /api/{path} -> {downstream_url} | "
        f"User: {user_id} | Risk Score: {eval_result.risk_score} | "
        f"Anomaly: {eval_result.is_anomaly} | AI Latency: {eval_result.inference_latency_ms}ms"
    )

    downstream_response = await forward_request(request, downstream_url, injected_headers)

    # Attach Step 3 Rate-Limit headers
    rate_limit_result: Optional[RateLimitResult] = getattr(request.state, "rate_limit_result", None)
    if rate_limit_result:
        for header_name, header_value in rate_limit_result.headers.items():
            downstream_response.headers[header_name] = header_value

    # Attach Step 4 AI Telemetry headers
    downstream_response.headers["X-Gateway-Risk-Score"] = str(eval_result.risk_score)
    downstream_response.headers["X-Gateway-Anomaly"] = str(eval_result.is_anomaly).lower()
    downstream_response.headers["X-Gateway-AI-Latency-Ms"] = str(eval_result.inference_latency_ms)

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
