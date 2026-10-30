import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError, DecodeError

from core.config import settings
from core.logger import setup_logger
from core.redis_client import is_token_blacklisted, blacklist_token

logger = setup_logger("core.security")


class SecurityException(Exception):
    """Base exception for security gateway rejections."""
    def __init__(self, message: str, status_code: int = 401, error_code: str = "UNAUTHORIZED"):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code


class AlgNoneExploitException(SecurityException):
    """Raised when an attacker attempts an unsigned 'alg: none' JWT bypass."""
    def __init__(self, message: str = "Malicious Exploit Detected: 'alg: none' is strictly forbidden."):
        super().__init__(message=message, status_code=403, error_code="EXPLOIT_ALG_NONE")


class TokenExpiredException(SecurityException):
    """Raised when a JWT has expired."""
    def __init__(self, message: str = "Token signature has expired."):
        super().__init__(message=message, status_code=401, error_code="TOKEN_EXPIRED")


class TokenRevokedException(SecurityException):
    """Raised when a token's JTI is found in the Redis blacklist."""
    def __init__(self, message: str = "Token has been revoked and blacklisted."):
        super().__init__(message=message, status_code=401, error_code="TOKEN_REVOKED")


class InvalidTokenException(SecurityException):
    """Raised when token signature, structure, or claims are invalid."""
    def __init__(self, message: str = "Invalid token or signature verification failed."):
        super().__init__(message=message, status_code=401, error_code="INVALID_TOKEN")


class MissingTokenException(SecurityException):
    """Raised when required Authorization header is absent."""
    def __init__(self, message: str = "Missing Authorization Bearer token."):
        super().__init__(message=message, status_code=401, error_code="MISSING_TOKEN")


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Creates a signed cryptographically secure JWT token with standard claims:
    - sub (Subject / User ID)
    - role (RBAC role)
    - tenant_id (Multi-tenancy identifier)
    - jti (Unique Token ID for O(1) revocation)
    - iat & exp (Issued at and Expiration timestamps)
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.jwt_expiration_minutes)

    # Ensure required claims are present
    if "jti" not in to_encode:
        to_encode["jti"] = str(uuid.uuid4())
    to_encode["iat"] = int(now.timestamp())
    to_encode["exp"] = int(expire.timestamp())

    token = jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm
    )
    return token


async def verify_jwt_token(token: str) -> Dict[str, Any]:
    """
    Deterministically verifies an incoming JWT token:
    1. Header inspection: Immediately traps and flags 'alg: none' exploits.
    2. Cryptographic signature check: Validates signature using configured secret & algorithm.
    3. Expiration verification: Ensures token has not expired.
    4. Redis JTI Blacklist check: Performs O(1) revocation lookup.
    """
    if not token or not isinstance(token, str):
        raise InvalidTokenException("Token must be a non-empty string.")

    # 1. Header Inspection (Detect alg:none before signature verification)
    try:
        unverified_header = jwt.get_unverified_header(token)
    except Exception as e:
        logger.warning(f"Failed to parse unverified JWT header: {e}")
        raise InvalidTokenException("Malformed JWT header structure.")

    alg = unverified_header.get("alg", "")
    if str(alg).lower() == "none":
        logger.critical("SECURITY ALERT: 'alg: none' exploit attempt detected and blocked!")
        raise AlgNoneExploitException()

    if alg != settings.jwt_algorithm:
        logger.warning(f"Rejected token with unauthorized algorithm: {alg}")
        raise InvalidTokenException(f"Algorithm '{alg}' is not permitted.")

    # 2. Cryptographic Verification
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            options={
                "verify_signature": True,
                "require": ["exp", "sub"]
            }
        )
    except ExpiredSignatureError:
        logger.info("Rejected expired JWT token.")
        raise TokenExpiredException()
    except (InvalidTokenError, DecodeError) as err:
        logger.warning(f"JWT signature verification failed: {err}")
        raise InvalidTokenException("Cryptographic verification failed: tampered signature or invalid claims.")

    # 3. Redis Blacklist / JTI Revocation Check
    jti = payload.get("jti")
    if jti:
        if await is_token_blacklisted(jti):
            logger.warning(f"Rejected blacklisted token jti={jti}")
            raise TokenRevokedException()

    return payload


async def revoke_token_by_payload(payload: Dict[str, Any]) -> bool:
    """
    Revokes a token by calculating remaining TTL and adding jti to Redis blacklist.
    """
    jti = payload.get("jti")
    if not jti:
        return False
        
    exp = payload.get("exp", 0)
    now = int(time.time())
    remaining_ttl = max(exp - now, 60)  # Minimum 60 seconds TTL

    return await blacklist_token(jti, ttl_seconds=remaining_ttl)

