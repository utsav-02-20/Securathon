from typing import Optional, Dict, Any
import httpx
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from core.config import settings
from core.logger import setup_logger

logger = setup_logger("gateway.proxy")

# Global persistent AsyncClient with high-concurrency connection pooling
_proxy_client: Optional[httpx.AsyncClient] = None

# Hop-by-hop headers to filter out during proxying (RFC 2616 / RFC 7230)
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length"
}


def get_proxy_client() -> httpx.AsyncClient:
    """
    Returns the persistent global httpx.AsyncClient for reverse proxying.
    Configured for high throughput and sub-15ms low-latency reuse.
    """
    global _proxy_client
    if _proxy_client is None or _proxy_client.is_closed:
        _proxy_client = httpx.AsyncClient(
            limits=httpx.Limits(
                max_keepalive_connections=100,
                max_connections=500,
                keepalive_expiry=30.0
            ),
            timeout=httpx.Timeout(
                connect=2.0,
                read=10.0,
                write=5.0,
                pool=2.0
            ),
            follow_redirects=False
        )
    return _proxy_client


async def close_proxy_client():
    """Cleanly closes the proxy connection pool."""
    global _proxy_client
    if _proxy_client and not _proxy_client.is_closed:
        await _proxy_client.aclose()
        _proxy_client = None
        logger.info("Closed reverse proxy connection pool.")


async def forward_request(
    request: Request,
    target_url: str,
    injected_headers: Optional[Dict[str, str]] = None
) -> Response:
    """
    Forwards an incoming client HTTP request to the downstream target microservice.
    Filters out hop-by-hop headers and injects gateway context headers.
    """
    client = get_proxy_client()

    # 1. Prepare Forwarding Headers
    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    }

    # Inject Gateway context headers (X-User-ID, X-Role, X-Request-ID, etc.)
    if injected_headers:
        forward_headers.update(injected_headers)

    # 2. Extract Body and Query Parameters
    body = await request.body()
    query_params = dict(request.query_params)

    # 3. Dispatch to Downstream Microservice
    try:
        downstream_resp = await client.request(
            method=request.method,
            url=target_url,
            params=query_params,
            headers=forward_headers,
            content=body
        )
    except httpx.ConnectError as err:
        logger.error(f"Downstream service unreachable at {target_url}: {err}")
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={
                "error": "BAD_GATEWAY",
                "message": "Downstream microservice is unavailable or not running.",
                "target_url": target_url
            }
        )
    except httpx.TimeoutException as err:
        logger.error(f"Gateway timeout contacting {target_url}: {err}")
        return JSONResponse(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            content={
                "error": "GATEWAY_TIMEOUT",
                "message": "Downstream microservice timed out.",
                "target_url": target_url
            }
        )
    except Exception as err:
        logger.error(f"Unexpected error proxying request to {target_url}: {err}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "PROXY_ERROR",
                "message": f"Reverse proxy failure: {str(err)}"
            }
        )

    # 4. Clean and return downstream response
    response_headers = {
        k: v for k, v in downstream_resp.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    }

    return Response(
        content=downstream_resp.content,
        status_code=downstream_resp.status_code,
        headers=response_headers,
        media_type=downstream_resp.headers.get("content-type")
    )

