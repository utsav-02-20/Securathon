import os
import uuid
import time
import asyncio
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional, List
from datetime import timedelta

import uvicorn
from fastapi import FastAPI, Request, Response, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from core.config import settings
from core.logger import setup_logger
from core.redis_client import get_redis_client, close_redis_client, blacklist_token
from core.security import create_access_token, verify_jwt_token, revoke_token_by_payload
from core.rate_limiter import rate_limiter, RateLimitResult
from core.event_stream import event_broadcaster, ThreatEvent
from ml.detector import anomaly_detector, AnomalyDetectionResult
from gateway.mitigation import mitigation_engine, MitigationDecision
from db.session import init_db, close_db
from db.audit_logger import audit_logger
from gateway.dependencies import get_authenticated_claims, enforce_sliding_window_rate_limit
from gateway.proxy import get_proxy_client, close_proxy_client, forward_request

logger = setup_logger("gateway.main")

DASHBOARD_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard", "index.html")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Gateway lifecycle manager.
    Initializes Redis, DB engine, audit logging worker, and proxy client on startup,
    and cleanly tears them down on shutdown.
    """
    logger.info("Initializing Intelligent Security Gateway...")
    try:
        await get_redis_client()
        await init_db()
        audit_logger.start()
        get_proxy_client()
        logger.info("All gateway security layers initialized successfully.")
    except Exception as e:
        logger.error(f"Error initializing gateway dependencies: {e}")
    yield
    logger.info("Shutting down Security Gateway...")
    await close_proxy_client()
    await audit_logger.stop()
    await close_db()
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
# Public System, Dashboard & Auth Endpoints
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
        "mitigation_pipeline": "active (Allow / Tarpit / Block / Auto-Revoke)",
        "audit_store": "active (PostgreSQL / asyncpg non-blocking)",
        "soc_dashboard": "active (/dashboard, /ws/security-stream)",
        "anomaly_threshold": settings.anomaly_score_threshold
    }


@app.get("/", include_in_schema=False)
async def root_redirect():
    """Redirect root path to interactive SOC Dashboard."""
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/dashboard", response_class=HTMLResponse, tags=["Observability"])
async def get_dashboard():
    """
    Serves the interactive real-time SOC Observability Dashboard.
    """
    if os.path.exists(DASHBOARD_FILE):
        with open(DASHBOARD_FILE, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>SOC Dashboard file not found</h1>", status_code=404)


@app.websocket("/ws/security-stream")
async def websocket_security_stream(websocket: WebSocket):
    """
    WebSocket endpoint streaming live security incidents and telemetry
    to connected SOC dashboards.
    """
    await event_broadcaster.connect(websocket)
    try:
        while True:
            # Keep connection alive & receive heartbeat pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        event_broadcaster.disconnect(websocket)
    except Exception as e:
        logger.warning(f"WebSocket client error: {e}")
        event_broadcaster.disconnect(websocket)


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
# Forensic Audit & Incident Inspection Endpoints
# ------------------------------------------------------------------------------
@app.get("/audit/incidents", tags=["Audit & Forensics"])
async def list_security_incidents(limit: int = 50):
    """
    Retrieves recent forensic security incident records stored in the database.
    """
    incidents = await audit_logger.get_recent_incidents(limit=limit)
    return {
        "count": len(incidents),
        "incidents": incidents
    }


@app.get("/audit/summary", tags=["Audit & Forensics"])
async def get_security_summary():
    """
    Retrieves aggregate incident summary by threat classification.
    """
    return await audit_logger.get_incident_summary()


# ------------------------------------------------------------------------------
# Complete Request Lifecycle: Steps 1 through 5 with Live Event Broadcasting
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
    COMPLETE 5-STEP REQUEST PIPELINE WITH LIVE EVENT STREAMING:
    Step 1: Ingestion by reverse proxy.
    Step 2: Cryptographic Identity & RBAC Check (The Guard) -> Drop 401/403.
    Step 3: Atomic Sliding Window Rate Limiter -> Drop 429 (<1ms).
    Step 4: Behavioral Telemetry Extraction & AI Scoring (Isolation Forest) -> Risk Score (0.0 to 1.0).
    Step 5: Threat Mitigation, Forensic Persistence & Live SOC Event Streaming:
            - Block (403): Malicious BOLA/IDOR attacks stopped, JTI auto-revoked, streamed to SOC.
            - Tarpit: Artificial delay injected to exhaust attacker sockets.
            - Allow: Context injected, proxied to :8001, telemetry broadcasted to SOC.
    """
    t_start = time.perf_counter()
    user_id = str(claims.get("sub", "unknown_user"))
    jti = str(claims.get("jti", ""))
    request_id = str(uuid.uuid4())
    client_ip = request.client.host if request.client else "127.0.0.1"
    endpoint_path = f"/api/{path}"

    # Extract Payload for Telemetry
    raw_body = await request.body()
    body_text = raw_body.decode("utf-8", errors="ignore") if raw_body else ""

    # Step 4: AI Detective Evaluation
    eval_result: AnomalyDetectionResult = await anomaly_detector.evaluate_request(
        user_id=user_id,
        path=endpoint_path,
        query_string=str(request.query_params),
        body_text=body_text
    )

    # Step 5: Mitigation Policy Decision
    decision: MitigationDecision = mitigation_engine.decide(eval_result)
    total_latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

    # Check 1: Action is BLOCK (HTTP 403)
    if decision.action == "BLOCK":
        # 1. Log incident asynchronously in PostgreSQL
        audit_logger.log_incident_async(
            request_id=request_id,
            user_id=user_id,
            client_ip=client_ip,
            endpoint=endpoint_path,
            http_method=request.method,
            risk_score=decision.risk_score,
            threat_type=decision.threat_type,
            threat_indicators=decision.threat_indicators,
            action_taken="BLOCKED",
            features_snapshot=eval_result.features
        )

        # 2. Auto-Revocation: Blacklist the attacking token JTI in Redis
        if decision.should_revoke_token and jti:
            await blacklist_token(jti, ttl_seconds=3600)
            logger.critical(f"AUTO-REVOCATION TRIGGERED: Blacklisted JTI '{jti}' for attacker '{user_id}'")

        # 3. Broadcast Live Attack Alert to SOC WebSockets
        threat_event = event_broadcaster.create_event(
            event_type=decision.threat_type,
            user_id=user_id,
            client_ip=client_ip,
            endpoint=endpoint_path,
            http_method=request.method,
            risk_score=decision.risk_score,
            action="BLOCKED",
            threat_indicators=decision.threat_indicators,
            latency_ms=total_latency_ms
        )
        await event_broadcaster.broadcast(threat_event)

        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "ANOMALY_BLOCKED",
                "message": decision.reason,
                "threat_type": decision.threat_type,
                "risk_score": decision.risk_score,
                "threat_indicators": decision.threat_indicators,
                "action_taken": "BLOCKED",
                "request_id": request_id
            },
            headers={
                "X-Gateway-Risk-Score": str(decision.risk_score),
                "X-Gateway-Threat-Type": decision.threat_type,
                "X-Gateway-Action": "BLOCKED",
                "X-Gateway-Request-ID": request_id
            }
        )

    # Check 2: Action is TARPIT (Artificial Latency Injection)
    if decision.action == "TARPIT" and decision.delay_seconds > 0:
        logger.warning(f"Injecting tarpit delay of {decision.delay_seconds}s for user {user_id}")
        await asyncio.sleep(decision.delay_seconds)

    # Check 3: Action is ALLOW / PROXY
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
    proxy_overhead_ms = round((time.perf_counter() - t_start) * 1000, 2)
    downstream_response = await forward_request(request, downstream_url, injected_headers)

    total_latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

    # Log telemetry event asynchronously
    audit_logger.log_telemetry_async(
        user_id=user_id,
        endpoint=endpoint_path,
        risk_score=eval_result.risk_score,
        latency_ms=proxy_overhead_ms,
        status_code=downstream_response.status_code
    )

    # Broadcast Normal Request to SOC Dashboard
    allow_event = event_broadcaster.create_event(
        event_type="REQUEST_ALLOWED",
        user_id=user_id,
        client_ip=client_ip,
        endpoint=endpoint_path,
        http_method=request.method,
        risk_score=eval_result.risk_score,
        action="ALLOW",
        latency_ms=proxy_overhead_ms
    )
    asyncio.create_task(event_broadcaster.broadcast(allow_event))

    # Attach Rate Limit & AI Headers to Client Response
    rate_limit_result: Optional[RateLimitResult] = getattr(request.state, "rate_limit_result", None)
    if rate_limit_result:
        for header_name, header_value in rate_limit_result.headers.items():
            downstream_response.headers[header_name] = header_value

    downstream_response.headers["X-Gateway-Risk-Score"] = str(eval_result.risk_score)
    downstream_response.headers["X-Gateway-Anomaly"] = str(eval_result.is_anomaly).lower()
    downstream_response.headers["X-Gateway-Action"] = decision.action
    downstream_response.headers["X-Gateway-Latency-Ms"] = str(proxy_overhead_ms)
    downstream_response.headers["X-Gateway-Total-Latency-Ms"] = str(total_latency_ms)
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
