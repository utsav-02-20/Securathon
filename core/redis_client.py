import socket
import logging
from typing import Optional
import redis.asyncio as aioredis
from core.config import settings
from core.logger import setup_logger

logger = setup_logger("core.redis")

_redis_instance: Optional[aioredis.Redis] = None


def is_redis_port_open(host: str, port: int, timeout: float = 0.2) -> bool:
    """Quick non-blocking probe to verify if Redis port is listening."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


async def get_redis_client() -> aioredis.Redis:
    """
    Returns an active async Redis client instance.
    If real Redis is unreachable and USE_FAKE_REDIS_FALLBACK is True,
    gracefully initializes an in-memory fakeredis instance in milliseconds.
    """
    global _redis_instance

    if _redis_instance is not None:
        return _redis_instance

    # Fast probe before connecting to avoid long OS TCP timeouts
    redis_available = is_redis_port_open(settings.redis_host, settings.redis_port, timeout=0.15)

    if redis_available:
        try:
            real_client = aioredis.Redis(
                host=settings.redis_host,
                port=settings.redis_port,
                db=settings.redis_db,
                password=settings.redis_password or None,
                decode_responses=False,
                socket_timeout=1.0,
                socket_connect_timeout=1.0
            )
            await real_client.ping()
            logger.info(f"Connected to Redis server at {settings.redis_host}:{settings.redis_port}")
            _redis_instance = real_client
            return _redis_instance
        except Exception as exc:
            logger.warning(f"Ping failed on Redis port: {exc}")

    if settings.use_fake_redis_fallback:
        logger.info("Using high-performance async in-memory FakeRedis (fallback mode active).")
        import fakeredis.aioredis
        _redis_instance = fakeredis.aioredis.FakeRedis(decode_responses=False)
        return _redis_instance
    else:
        raise ConnectionError(f"Redis unavailable at {settings.redis_host}:{settings.redis_port}")


async def close_redis_client():
    """Closes the Redis connection pool cleanly."""
    global _redis_instance
    if _redis_instance is not None:
        if hasattr(_redis_instance, "aclose"):
            await _redis_instance.aclose()
        else:
            await _redis_instance.close()
        _redis_instance = None
        logger.info("Closed Redis connection pool.")


async def is_token_blacklisted(jti: str) -> bool:
    """
    Checks if a JWT token ID (jti) exists in the Redis blacklist.
    Sub-millisecond O(1) lookup.
    """
    if not jti:
        return False
    try:
        r = await get_redis_client()
        key = f"blacklist:{jti}"
        return bool(await r.exists(key))
    except Exception as e:
        logger.error(f"Error checking token blacklist for jti {jti}: {e}")
        return False


async def blacklist_token(jti: str, ttl_seconds: int = 3600) -> bool:
    """
    Adds a JWT token ID (jti) to the Redis blacklist with a TTL.
    TTL should match the remaining expiration of the token.
    """
    if not jti:
        return False
    try:
        r = await get_redis_client()
        key = f"blacklist:{jti}"
        await r.set(key, "revoked", ex=max(ttl_seconds, 1))
        logger.info(f"Blacklisted token jti={jti} with TTL={ttl_seconds}s")
        return True
    except Exception as e:
        logger.error(f"Error blacklisting token jti {jti}: {e}")
        return False
