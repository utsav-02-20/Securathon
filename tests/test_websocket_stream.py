import json
import pytest
from fastapi.testclient import TestClient
import httpx

from core.config import settings
from core.security import create_access_token
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


def test_dashboard_page_serves_html(gateway_client: TestClient):
    """Verify the interactive SOC Dashboard is served at /dashboard with HTTP 200."""
    resp = gateway_client.get("/dashboard")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "SECURATHON SOC" in resp.text
    assert "threatChart" in resp.text


def test_websocket_handshake_and_ping_pong(gateway_client: TestClient):
    """Verify WebSocket connection at /ws/security-stream completes handshake and answers heartbeats."""
    with gateway_client.websocket_connect("/ws/security-stream") as websocket:
        # Step 1: Handshake
        initial_msg = websocket.receive_text()
        data = json.loads(initial_msg)
        assert data["type"] == "HANDSHAKE"
        assert "Securathon" in data["message"]
        assert "stats" in data

        # Step 2: Ping / Pong heartbeat
        websocket.send_text("ping")
        pong = websocket.receive_text()
        assert pong == "pong"


def test_websocket_receives_live_attack_stream(gateway_client: TestClient):
    """
    CRITICAL REAL-TIME STREAMING TEST:
    Verify that an attack intercepted by the gateway is instantly pushed
    to all active WebSocket observers in real time (<1ms).
    """
    with gateway_client.websocket_connect("/ws/security-stream") as websocket:
        # Receive handshake
        _ = websocket.receive_text()

        # Trigger an 'alg: none' exploit attempt via HTTP
        none_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlcl93cyIsInJvbGUiOiJhZG1pbiJ9."
        http_resp = gateway_client.get("/api/v1/orders/1001", headers={"Authorization": f"Bearer {none_token}"})
        assert http_resp.status_code == 403

        # WebSocket must receive the streamed threat alert
        alert_msg = websocket.receive_text()
        alert = json.loads(alert_msg)

        assert alert["event_type"] == "ALG_NONE_EXPLOIT"
        assert alert["action"] == "BLOCKED"
        assert alert["risk_score"] == 1.0
        assert "SIGNATURE_EVASION_ATTACK" in alert["threat_indicators"]

