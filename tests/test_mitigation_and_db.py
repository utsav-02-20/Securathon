import time
import asyncio
import pytest
from fastapi.testclient import TestClient
import httpx

from core.config import settings
from core.security import create_access_token
from ml.detector import AnomalyDetectionResult
from gateway.mitigation import MitigationEngine
from db.models import SecurityIncident
from db.session import init_db, get_async_session
from db.audit_logger import audit_logger
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


def test_mitigation_engine_policy_decisions():
    """Verify mitigation engine accurately decides ALLOW, TARPIT, or BLOCK based on risk scores."""
    engine = MitigationEngine(block_threshold=0.75, tarpit_threshold=0.65, tarpit_delay=1.5)

    # 1. Low risk -> ALLOW
    res_low = AnomalyDetectionResult(
        risk_score=0.25,
        is_anomaly=False,
        threshold=0.75,
        features={},
        threat_indicators=[],
        inference_latency_ms=1.2
    )
    dec_low = engine.decide(res_low)
    assert dec_low.action == "ALLOW"
    assert dec_low.should_revoke_token is False
    assert dec_low.delay_seconds == 0.0

    # 2. Moderate risk -> TARPIT
    res_mod = AnomalyDetectionResult(
        risk_score=0.70,
        is_anomaly=False,
        threshold=0.75,
        features={},
        threat_indicators=["ELEVATED_VELOCITY"],
        inference_latency_ms=1.5
    )
    dec_mod = engine.decide(res_mod)
    assert dec_mod.action == "TARPIT"
    assert dec_mod.delay_seconds == 1.5
    assert dec_mod.should_revoke_token is False

    # 3. High risk BOLA -> BLOCK with auto-revocation flag
    res_high = AnomalyDetectionResult(
        risk_score=0.88,
        is_anomaly=True,
        threshold=0.75,
        features={},
        threat_indicators=["SEQUENTIAL_ID_ENUMERATION"],
        inference_latency_ms=2.1
    )
    dec_high = engine.decide(res_high)
    assert dec_high.action == "BLOCK"
    assert dec_high.threat_type == "BOLA_IDOR_ATTACK"
    assert dec_high.should_revoke_token is True


@pytest.mark.asyncio
async def test_db_persistence_and_query():
    """Verify SQLAlchemy models and async session persist security incidents to database."""
    await init_db()
    req_id = f"test_req_{int(time.time() * 1000)}"

    incident = SecurityIncident(
        request_id=req_id,
        user_id="attacker_99",
        client_ip="192.168.1.100",
        endpoint="/api/v1/orders/1005",
        http_method="GET",
        risk_score=0.92,
        threat_type="BOLA_IDOR_ATTACK",
        threat_indicators=["SEQUENTIAL_ID_ENUMERATION"],
        action_taken="BLOCKED",
        features_snapshot={"velocity": 3.5, "delta": 1.0}
    )

    async with get_async_session() as session:
        session.add(incident)

    # Query back
    incidents = await audit_logger.get_recent_incidents(limit=10)
    matching = [i for i in incidents if i["request_id"] == req_id]
    assert len(matching) == 1
    assert matching[0]["threat_type"] == "BOLA_IDOR_ATTACK"
    assert matching[0]["risk_score"] == 0.92


@pytest.mark.asyncio
async def test_audit_logger_async_queue_persistence():
    """Verify non-blocking async queue worker drains and persists incidents."""
    audit_logger.start()
    unique_user = f"queue_test_user_{int(time.time() * 1000)}"

    audit_logger.log_incident_async(
        request_id=f"req_{unique_user}",
        user_id=unique_user,
        client_ip="10.0.0.1",
        endpoint="/api/v1/orders/1009",
        http_method="GET",
        risk_score=0.85,
        threat_type="BOLA_IDOR_ATTACK",
        threat_indicators=["SEQUENTIAL_ID_ENUMERATION"],
        action_taken="BLOCKED",
        features_snapshot={"unique_ratio": 1.0}
    )

    # Wait brief moment for worker to persist
    await asyncio.sleep(0.3)

    incidents = await audit_logger.get_recent_incidents(limit=20)
    matching = [i for i in incidents if i["user_id"] == unique_user]
    assert len(matching) >= 1
    assert matching[0]["action_taken"] == "BLOCKED"


def test_gateway_blocks_bola_attack_and_auto_revokes(gateway_client: TestClient):
    """
    CRITICAL END-TO-END SECURITY INTEGRATION TEST:
    1. Attacker loops sequential IDs: 1001 -> 1002 -> 1003 -> 1004.
    2. Step 4 AI flags anomaly, Step 5 Mitigation Engine blocks with HTTP 403 Forbidden.
    3. Attacker token is automatically blacklisted in Redis.
    4. Subsequent request with the same token is dropped with HTTP 401 TOKEN_REVOKED!
    """
    attacker_id = f"e2e_attacker_{int(time.time() * 1000)}"
    token_resp = gateway_client.post("/auth/token", json={"user_id": attacker_id, "role": "customer"})
    token = token_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Step 1: Initial requests
    r1 = gateway_client.get("/api/v1/orders/1001", headers=headers)
    assert r1.status_code == 200

    r2 = gateway_client.get("/api/v1/orders/1002", headers=headers)
    assert r2.status_code == 200

    # Step 2: 3rd sequential request establishes sequential pattern and trips BOLA detection
    r3 = gateway_client.get("/api/v1/orders/1003", headers=headers)
    assert r3.status_code == 403
    err_body = r3.json()
    assert err_body["error"] == "ANOMALY_BLOCKED"
    assert err_body["threat_type"] == "BOLA_IDOR_ATTACK"
    assert "SEQUENTIAL_ID_ENUMERATION" in err_body["threat_indicators"]
    assert err_body["action_taken"] == "BLOCKED"

    # Step 3: Auto-revocation check — token is now blacklisted in Redis!
    r4 = gateway_client.get("/api/v1/orders/1001", headers=headers)
    assert r4.status_code == 401
    revoked_err = r4.json()
    assert revoked_err["detail"]["error"] == "TOKEN_REVOKED"


def test_audit_endpoints(gateway_client: TestClient):
    """Verify forensic audit incident listing and summary endpoints."""
    resp = gateway_client.get("/audit/incidents?limit=10")
    assert resp.status_code == 200
    data = resp.json()
    assert "count" in data
    assert "incidents" in data

    resp_summary = gateway_client.get("/audit/summary")
    assert resp_summary.status_code == 200
    summary_data = resp_summary.json()
    assert "total_incidents" in summary_data
    assert "by_threat_type" in summary_data
