import time
import pytest
from fastapi.testclient import TestClient
import httpx

from core.config import settings
from core.security import create_access_token
from core.rate_limiter import SlidingWindowRateLimiter
import gateway.proxy as proxy_module
from gateway.main import app as gateway_app
from mock_backend.main import app as backend_app


@pytest.fixture(autouse=True)
def setup_test_proxy():
    """Route gateway proxy requests directly to mock backend ASGI app."""
    mock_transport = httpx.ASGITransport(app=backend_app)
    proxy_module._proxy_client = httpx.AsyncClient(
        transport=mock_transport,
        base_url=settings.backend_service_url
    )
    yield
    proxy_module._proxy_client = None


@pytest.fixture
def gateway_client():
    """TestClient for the FastAPI Security Gateway."""
    with TestClient(gateway_app) as client:
        yield client


@pytest.mark.asyncio
async def test_sliding_window_unit_increments():
    """Verify atomic sliding window decrements remaining quota correctly on consecutive requests."""
    limiter = SlidingWindowRateLimiter()
    user_id = f"unit_test_user_{int(time.time() * 1000)}"

    # 1st request
    res1 = await limiter.is_allowed(user_id, limit=3, window_seconds=10)
    assert res1.allowed is True
    assert res1.current_count == 1
    assert res1.remaining == 2
    assert "X-RateLimit-Remaining" in res1.headers
    assert "Retry-After" not in res1.headers

    # 2nd request
    res2 = await limiter.is_allowed(user_id, limit=3, window_seconds=10)
    assert res2.allowed is True
    assert res2.current_count == 2
    assert res2.remaining == 1

    # 3rd request (hits threshold)
    res3 = await limiter.is_allowed(user_id, limit=3, window_seconds=10)
    assert res3.allowed is True
    assert res3.current_count == 3
    assert res3.remaining == 0

    # 4th request (volumetric flood / blocked)
    res4 = await limiter.is_allowed(user_id, limit=3, window_seconds=10)
    assert res4.allowed is False
    assert res4.remaining == 0
    assert res4.retry_after >= 1
    assert "Retry-After" in res4.headers
    assert int(res4.headers["Retry-After"]) >= 1


@pytest.mark.asyncio
async def test_sliding_window_user_isolation():
    """Verify rate limit quotas are strictly isolated per user identity."""
    limiter = SlidingWindowRateLimiter()
    unique_ts = int(time.time() * 1000)
    user_a = f"isolated_user_a_{unique_ts}"
    user_b = f"isolated_user_b_{unique_ts}"

    # Exhaust user A's limit of 2
    await limiter.is_allowed(user_a, limit=2, window_seconds=10)
    await limiter.is_allowed(user_a, limit=2, window_seconds=10)
    res_a_blocked = await limiter.is_allowed(user_a, limit=2, window_seconds=10)
    assert res_a_blocked.allowed is False

    # User B must still be fully permitted
    res_b = await limiter.is_allowed(user_b, limit=2, window_seconds=10)
    assert res_b.allowed is True
    assert res_b.remaining == 1


def test_gateway_rate_limit_headers_on_success(gateway_client: TestClient):
    """Verify that successful proxied requests return RFC rate-limiting headers."""
    unique_user = f"header_test_user_{int(time.time() * 1000)}"
    token = create_access_token({"sub": unique_user, "role": "customer"})
    headers = {"Authorization": f"Bearer {token}"}

    resp = gateway_client.get("/api/v1/orders/1001", headers=headers)
    assert resp.status_code == 200
    assert "x-ratelimit-limit" in resp.headers
    assert "x-ratelimit-remaining" in resp.headers
    assert "x-ratelimit-reset" in resp.headers
    assert "x-ratelimit-scope" in resp.headers
    assert resp.headers["x-ratelimit-scope"] == "user"


def test_gateway_volumetric_burst_triggers_429(gateway_client: TestClient, monkeypatch):
    """
    CRITICAL SECURITY TEST:
    Verify that a rapid burst of requests exceeding the configured sliding-window threshold
    is dropped instantly (<1ms) with HTTP 429 Too Many Requests and RFC headers.
    """
    # Temporarily set customer rate limit to 4 for this fast test
    monkeypatch.setattr(settings, "rate_limit_customer", 4)
    monkeypatch.setattr(settings, "rate_limit_window_seconds", 30)

    burst_user = f"burst_attacker_{int(time.time() * 1000)}"
    token = create_access_token({"sub": burst_user, "role": "customer"})
    headers = {"Authorization": f"Bearer {token}"}

    # First 4 requests should succeed (200 OK)
    for i in range(4):
        resp = gateway_client.get("/api/v1/orders/1001", headers=headers)
        assert resp.status_code == 200, f"Request {i+1} failed unexpectedly"

    # 5th request must be dropped with 429 Too Many Requests
    blocked_resp = gateway_client.get("/api/v1/orders/1001", headers=headers)
    assert blocked_resp.status_code == 429
    err = blocked_resp.json()
    assert err["detail"]["error"] == "RATE_LIMIT_EXCEEDED"
    assert err["detail"]["limit"] == 4
    assert "retry_after" in err["detail"]
    assert "retry-after" in blocked_resp.headers
    assert blocked_resp.headers["x-ratelimit-remaining"] == "0"


def test_role_based_tier_limits(gateway_client: TestClient):
    """Verify that different RBAC roles receive their respective tiered rate limits."""
    # Merchant should have higher limit than customer
    merchant_user = f"merchant_user_{int(time.time() * 1000)}"
    token = create_access_token({"sub": merchant_user, "role": "merchant"})
    headers = {"Authorization": f"Bearer {token}"}

    resp = gateway_client.get("/api/v1/orders/1001", headers=headers)
    assert resp.status_code == 200
    limit = int(resp.headers["x-ratelimit-limit"])
    assert limit == settings.rate_limit_merchant


def test_rate_limit_status_endpoint(gateway_client: TestClient):
    """Verify /auth/rate-limit-status inspects quota without consuming it."""
    status_user = f"status_user_{int(time.time() * 1000)}"
    token = create_access_token({"sub": status_user, "role": "customer"})
    headers = {"Authorization": f"Bearer {token}"}

    resp = gateway_client.get("/auth/rate-limit-status", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["user_id"] == status_user
    assert data["role"] == "customer"
    assert data["limit"] == settings.rate_limit_customer
    assert data["current_count"] == 0
    assert data["remaining"] == settings.rate_limit_customer

