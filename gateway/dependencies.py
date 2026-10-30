from typing import Dict, Any, Optional
from fastapi import Request, HTTPException, status
from core.security import (
    verify_jwt_token,
    AlgNoneExploitException,
    TokenExpiredException,
    TokenRevokedException,
    InvalidTokenException,
    MissingTokenException
)
from core.logger import setup_logger

logger = setup_logger("gateway.auth")


async def get_authenticated_claims(request: Request) -> Dict[str, Any]:
    """
    FastAPI dependency: Deterministic Cryptographic Identity Guard.
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

