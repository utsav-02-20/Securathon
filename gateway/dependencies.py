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
from core.logger import setup_logger

logger = setup_logger("gateway.dependencies")


async def get_authenticated_claims(request: Request) -> Dict[str, Any]:
    """
    STEP 2: Deterministic Cryptographic Identity Guard.
    Extracts Bearer token, validates signature, ensures algorithm integrity,
    checks Redis blacklist, and returns claims.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header:
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

    # Determine role-based quota
    if role == "admin":
        limit = settings.rate_limit_admin
    elif role == "merchant":
        limit = settings.rate_limit_merchant
    else:
        limit = settings.rate_limit_customer

    # Check sliding window rate limit atomically in Redis
    result: RateLimitResult = await rate_limiter.is_allowed(
        identifier=user_id,
        limit=limit,
        window_seconds=settings.rate_limit_window_seconds,
        scope="user"
    )

    # Attach to request state for response header enrichment
    request.state.rate_limit_result = result

    if not result.allowed:
        logger.warning(f"Volumetric spike blocked: User '{user_id}' exceeded limit of {limit} req/{settings.rate_limit_window_seconds}s")
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
