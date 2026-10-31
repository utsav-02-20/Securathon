import uuid
from datetime import timedelta
import pytest
import jwt
from fastapi.testclient import TestClient
import httpx

from core.config import settings
from core.security import create_access_token
import gateway.proxy as proxy_module
from gateway.main import app as gateway_app
from mock_backend.main import app as backend_app


@pytest.fixture(autouse=True)
def setup_test_proxy():
    """
    Configures the gateway's proxy client to route directly to the mock backend ASGI app.
    Enables true in-process end-to-end integration testing.
    """
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


def test_gateway_health(gateway_client: TestClient):
    """Verify Gateway health endpoint returns 200 and active status."""
    resp = gateway_client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["service"] == "api-security-gateway"
    assert "active" in data["guard_status"]


def test_issue_token(gateway_client: TestClient):
    """Verify /auth/token endpoint issues signed tokens with JTI and standard claims."""
    payload = {
        "user_id": "user_101",
        "role": "customer",
        "tenant_id": "tenant_alpha",
        "expires_in_minutes": 30
    }
    resp = gateway_client.post("/auth/token", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["user_id"] == "user_101"
    assert data["role"] == "customer"
    assert data["tenant_id"] == "tenant_alpha"
    assert "jti" in data
    assert data["expires_in"] == 1800


def test_multi_role_tokens_issuance(gateway_client: TestClient):
    """Verify /auth/token endpoint issues valid tokens for different roles dynamically."""
    roles = ["customer", "merchant", "admin"]
    for role in roles:
        resp = gateway_client.post("/auth/token", json={"user_id": f"test_{role}", "role": role})
        assert resp.status_code == 200
        data = resp.json()
        assert data["role"] == role
        assert "access_token" in data
        assert "jti" in data


def test_missing_token_blocked_401(gateway_client: TestClient):
    """Verify requests to protected endpoints without Authorization header are dropped with 401."""
    resp = gateway_client.get("/api/v1/orders/1001")
    assert resp.status_code == 401
    err = resp.json()
    assert err["detail"]["error"] == "MISSING_TOKEN"


def test_invalid_header_format_blocked_401(gateway_client: TestClient):
    """Verify malformed Authorization headers (e.g. Basic instead of Bearer) are dropped with 401."""
    headers = {"Authorization": "Basic invalid_credentials_string"}
    resp = gateway_client.get("/api/v1/orders/1001", headers=headers)
    assert resp.status_code == 401
    err = resp.json()
    assert err["detail"]["error"] == "INVALID_HEADER_FORMAT"


def test_tampered_signature_blocked_401(gateway_client: TestClient):
    """Verify tampered JWT signature is rejected deterministically with 401."""
    # Generate legitimate token
    valid_token = create_access_token({"sub": "user_101", "role": "customer", "tenant_id": "tenant_alpha"})
    
    # Tamper with the last 5 characters of the cryptographic signature
    tampered_token = valid_token[:-5] + "XXXXX"
    headers = {"Authorization": f"Bearer {tampered_token}"}
    
    resp = gateway_client.get("/api/v1/orders/1001", headers=headers)
    assert resp.status_code == 401
    err = resp.json()
    assert err["detail"]["error"] == "INVALID_TOKEN"


def test_expired_token_blocked_401(gateway_client: TestClient):
    """Verify expired token is rejected with 401 TOKEN_EXPIRED."""
    # Generate token that expired 10 minutes ago
    expired_token = create_access_token(
        {"sub": "user_101", "role": "customer", "tenant_id": "tenant_alpha"},
        expires_delta=timedelta(minutes=-10)
    )
    headers = {"Authorization": f"Bearer {expired_token}"}
    
    resp = gateway_client.get("/api/v1/orders/1001", headers=headers)
    assert resp.status_code == 401
    err = resp.json()
    assert err["detail"]["error"] == "TOKEN_EXPIRED"


def test_alg_none_exploit_blocked_403(gateway_client: TestClient):
    """
    CRITICAL SECURITY TEST:
    Verify that an attacker attempting an 'alg: none' signature evasion exploit
    is immediately detected, flagged, and dropped with 403 Forbidden.
    """
    # Forge token with alg: none
    exploit_payload = {
        "sub": "user_104_attacker",
        "role": "admin",
        "tenant_id": "tenant_alpha"
    }
    # pyjwt allows algorithm="none" when secret is empty string
    none_token = jwt.encode(exploit_payload, key="", algorithm="none")
    headers = {"Authorization": f"Bearer {none_token}"}

    resp = gateway_client.get("/api/v1/orders/1001", headers=headers)
    assert resp.status_code == 403
    err = resp.json()
    assert err["detail"]["error"] == "EXPLOIT_ALG_NONE"
    assert err["detail"]["threat_type"] == "SIGNATURE_EVASION_ATTACK"


def test_valid_jwt_proxies_to_backend_successfully(gateway_client: TestClient):
    """Verify a valid token successfully proxies through the gateway to the downstream service."""
    token = create_access_token({"sub": "user_101", "role": "customer", "tenant_id": "tenant_alpha"})
    headers = {"Authorization": f"Bearer {token}"}

    resp = gateway_client.get("/api/v1/orders/1001", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["data"]["id"] == "1001"
    assert data["data"]["user_id"] == "user_101"


def test_gateway_context_header_injection_end_to_end(gateway_client: TestClient):
    """
    Verify the gateway injects enriched context headers (X-User-ID, X-User-Role, X-Tenant-ID, X-Gateway-Guard)
    into the proxied request, and downstream receives them.
    """
    token = create_access_token({
        "sub": "user_103",
        "role": "merchant",
        "tenant_id": "tenant_alpha"
    })
    headers = {"Authorization": f"Bearer {token}"}

    resp = gateway_client.get("/api/v1/debug/headers", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    context = data["gateway_context"]
    assert context["x_user_id"] == "user_103"
    assert context["x_user_role"] == "merchant"
    assert context["x_tenant_id"] == "tenant_alpha"
    assert "x_request_id" in context
    assert data["headers"]["x-gateway-guard"] == "passed"


def test_token_revocation_blacklist_lifecycle(gateway_client: TestClient):
    """
    Verify complete revocation lifecycle:
    1. Issue token and ensure it works.
    2. Revoke token via /auth/revoke.
    3. Ensure subsequent request with same token is dropped with 401 TOKEN_REVOKED.
    """
    token_resp = gateway_client.post("/auth/token", json={"user_id": "user_101", "role": "customer"})
    token = token_resp.json()["access_token"]
    jti = token_resp.json()["jti"]
    headers = {"Authorization": f"Bearer {token}"}

    # Step 1: Works initially
    resp_init = gateway_client.get("/api/v1/orders/1001", headers=headers)
    assert resp_init.status_code == 200

    # Step 2: Revoke token via JTI
    revoke_resp = gateway_client.post("/auth/revoke", json={"jti": jti})
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["success"] is True

    # Step 3: Immediate rejection by Gateway Guard (<0.2ms O(1) Redis check)
    resp_after = gateway_client.get("/api/v1/orders/1001", headers=headers)
    assert resp_after.status_code == 401
    err = resp_after.json()
    assert err["detail"]["error"] == "TOKEN_REVOKED"

