from typing import Dict, Any, Optional
from fastapi import Request, HTTPException, status
from core.config import settings
from core.security import (
    verify_jwt_token,
    AlgNoneExploitException,
    TokenExpiredException,
    TokenRevokedException,
    InvalidTokenException,
    MissingTokenException
)
from core.rate_limiter import rate_limiter, RateLimitResult
from core.event_stream import event_broadcaster
from core.logger import setup_logger

logger = setup_logger("gateway.dependencies")


async def get_authenticated_claims(request: Request) -> Dict[str, Any]:
    """
    STEP 2: Deterministic Cryptographic Identity Guard.
    Extracts Bearer token, validates signature, ensures algorithm integrity,
    checks Redis blacklist, and returns claims.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        if not settings.require_auth:
            anon_id = f"ip_{client_ip.replace('.', '_').replace(':', '_')}"
            return {
                "sub": anon_id,
                "role": "unauthenticated",
                "tenant_id": "public",
                "jti": f"anon_{anon_id}",
                "is_unauthenticated": True
            }
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "MISSING_TOKEN",
                "message": "Authorization Bearer token is required."
            },
            headers={"WWW-Authenticate": "Bearer"}
        )


    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "INVALID_HEADER_FORMAT",
                "message": "Authorization header must be formatted as: 'Bearer <token>'"
            },
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = parts[1]

    try:
        claims = await verify_jwt_token(token)
        return claims
    except AlgNoneExploitException as exc:
        # Broadcast live exploit event to SOC dashboard
        event = event_broadcaster.create_event(
            event_type="ALG_NONE_EXPLOIT",
            user_id="anonymous_attacker",
            client_ip=client_ip,
            endpoint=request.url.path,
            http_method=request.method,
            risk_score=1.0,
            action="BLOCKED",
            threat_indicators=["SIGNATURE_EVASION_ATTACK"]
        )
        await event_broadcaster.broadcast(event)

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": exc.error_code,
                "message": exc.message,
                "threat_type": "SIGNATURE_EVASION_ATTACK"
            }
        )
    except TokenExpiredException as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": exc.error_code,
                "message": exc.message
            },
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\", error_description=\"The token has expired\""}
        )
    except TokenRevokedException as exc:
        # Broadcast revoked token usage event to SOC dashboard
        event = event_broadcaster.create_event(
            event_type="TOKEN_REVOKED",
            user_id="revoked_identity",
            client_ip=client_ip,
            endpoint=request.url.path,
            http_method=request.method,
            risk_score=0.95,
            action="BLOCKED",
            threat_indicators=["BLACK_LISTED_JTI_REJECTION"]
        )
        await event_broadcaster.broadcast(event)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": exc.error_code,
                "message": exc.message
            },
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\", error_description=\"The token has been revoked\""}
        )
    except InvalidTokenException as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": exc.error_code,
                "message": exc.message
            },
            headers={"WWW-Authenticate": "Bearer error=\"invalid_token\", error_description=\"Cryptographic signature mismatch\""}
        )
    except Exception as exc:
        logger.error(f"Unexpected authorization error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "AUTH_ERROR",
                "message": "Failed to authenticate request."
            }
        )


async def enforce_sliding_window_rate_limit(
    request: Request
) -> Dict[str, Any]:
    """
    STEP 2 & STEP 3 Combined Pipeline:
    1. Authenticates identity claims (Step 2).
    2. Evaluates atomic Redis sliding-window limit for the authenticated user (Step 3).
    3. Rejects volumetric bursts / flood attacks in <1ms with HTTP 429 and RFC headers.
    4. Attaches rate limit telemetry to request.state for downstream proxy header injection.
    """
    claims = await get_authenticated_claims(request)
    user_id = str(claims.get("sub", "unknown_user"))
    role = str(claims.get("role", "customer")).lower()
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Determine quota and scope
    if claims.get("is_unauthenticated"):
        limit = settings.rate_limit_unauth_ip
        scope = "ip"
        identifier = client_ip
    elif role == "admin":
        limit = settings.rate_limit_admin
        scope = "user"
        identifier = user_id
    elif role == "merchant":
        limit = settings.rate_limit_merchant
        scope = "user"
        identifier = user_id
    else:
        limit = settings.rate_limit_customer
        scope = "user"
        identifier = user_id

    # Check sliding window rate limit atomically in Redis
    result: RateLimitResult = await rate_limiter.is_allowed(
        identifier=identifier,
        limit=limit,
        window_seconds=settings.rate_limit_window_seconds,
        scope=scope
    )


    request.state.rate_limit_result = result

    if not result.allowed:
        logger.warning(f"Volumetric spike blocked: User '{user_id}' exceeded limit of {limit} req/{settings.rate_limit_window_seconds}s")
        
        # Broadcast Rate Limit Drop event to SOC dashboard
        event = event_broadcaster.create_event(
            event_type="RATE_LIMIT_DROP",
            user_id=user_id,
            client_ip=client_ip,
            endpoint=request.url.path,
            http_method=request.method,
            risk_score=0.85,
            action="BLOCKED",
            threat_indicators=["VOLUMETRIC_SPIKE_EXCEEDED"]
        )
        await event_broadcaster.broadcast(event)

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "RATE_LIMIT_EXCEEDED",
                "message": f"Too many requests. Limit of {limit} requests per {settings.rate_limit_window_seconds}s exceeded.",
                "limit": limit,
                "window_seconds": settings.rate_limit_window_seconds,
                "retry_after": result.retry_after
            },
            headers=result.headers
        )

    return claims
