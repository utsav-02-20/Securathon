import time
import pytest
from fastapi.testclient import TestClient
import httpx

from core.config import settings
from core.security import create_access_token
from ml.features import (
    calculate_shannon_entropy,
    extract_resource_identifier,
    compute_features_from_history
)
from ml.detector import anomaly_detector
from ml.evaluate import evaluate_model
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


def test_shannon_entropy_calculation():
    """Verify Shannon entropy accurately distinguishes structured data from randomized fuzzing payloads."""
    assert calculate_shannon_entropy("") == 0.0
    
    # Normal structured URL parameter
    normal_str = "/api/v1/orders/1001?status=completed&format=json"
    entropy_normal = calculate_shannon_entropy(normal_str)
    assert 2.0 <= entropy_normal <= 4.5

    # High entropy payload (e.g. randomized hex / base64 exploit string)
    random_str = "aZ9#kL2$vM8*qP4!xR7^yB1~wT6@uC3%sD5&jN0="
    entropy_random = calculate_shannon_entropy(random_str)
    assert entropy_random > 4.7
    assert entropy_random > entropy_normal


def test_resource_identifier_extraction():
    """Verify regex correctly parses resource entities from standard API paths."""
    assert extract_resource_identifier("/api/v1/orders/1001") == "1001"
    assert extract_resource_identifier("/api/v1/users/user_102") == "user_102"
    assert extract_resource_identifier("/api/v1/transactions/txn_5001") == "txn_5001"
    assert extract_resource_identifier("/health") is None


def test_sequential_idor_feature_variance():
    """
    Verify feature computation detects sequential step patterns:
    Accessing 1001 -> 1002 -> 1003 results in delta=1.0 and high sequentiality.
    """
    now = time.time()
    timestamps = [now - 3.0, now - 2.0, now - 1.0]
    ids = ["1001", "1002", "1003"]
    
    features = compute_features_from_history(
        current_time=now,
        current_id="1004",
        path="/api/v1/orders/1004",
        query_string="",
        body_text="",
        history_timestamps=timestamps,
        history_ids=ids
    )

    assert features.id_jump_delta == 1.0
    assert features.id_jump_variance == 0.0
    assert features.sequentiality > 0.90
    assert features.unique_id_ratio == 1.0


@pytest.mark.asyncio
async def test_ai_detector_normal_user_behavior():
    """Verify normal sporadic user browsing generates low anomaly risk score."""
    normal_user = f"normal_shopper_{int(time.time() * 1000)}"
    
    # User views order 1001, then views it again (refresh / viewing details)
    await anomaly_detector.evaluate_request(normal_user, "/api/v1/orders/1001")
    result = await anomaly_detector.evaluate_request(normal_user, "/api/v1/orders/1001")

    assert result.is_anomaly is False
    assert result.risk_score < 0.60
    assert result.inference_latency_ms < 15.0  # Must meet strict sub-15ms SLA


@pytest.mark.asyncio
async def test_ai_detector_catches_bola_attack():
    """
    CRITICAL AI SECURITY TEST:
    Verify that an authenticated attacker iterating through sequential IDs
    (OWASP API Top 10 #1 BOLA / IDOR) is detected by the Isolation Forest engine
    and assigned a high anomaly score (>= 0.75).
    """
    attacker = f"stealth_bola_bot_{int(time.time() * 1000)}"
    
    # Attacker traverses sequential order IDs: 1001 -> 1002 -> 1003 -> 1004
    await anomaly_detector.evaluate_request(attacker, "/api/v1/orders/1001")
    await anomaly_detector.evaluate_request(attacker, "/api/v1/orders/1002")
    await anomaly_detector.evaluate_request(attacker, "/api/v1/orders/1003")
    final_result = await anomaly_detector.evaluate_request(attacker, "/api/v1/orders/1004")

    assert final_result.is_anomaly is True
    assert final_result.risk_score >= 0.75
    assert "SEQUENTIAL_ID_ENUMERATION" in final_result.threat_indicators
    assert final_result.inference_latency_ms < 15.0


def test_gateway_injects_ai_risk_score_headers(gateway_client: TestClient):
    """
    Verify that the Gateway attaches the computed AI anomaly risk score
    and inference latency to downstream headers and client response headers.
    """
    unique_user = f"ai_header_user_{int(time.time() * 1000)}"
    token = create_access_token({"sub": unique_user, "role": "customer"})
    headers = {"Authorization": f"Bearer {token}"}

    resp = gateway_client.get("/api/v1/orders/1001", headers=headers)
    assert resp.status_code == 200
    
    assert "x-gateway-risk-score" in resp.headers
    assert "x-gateway-anomaly" in resp.headers
    assert "x-gateway-ai-latency-ms" in resp.headers
    
    risk_score = float(resp.headers["x-gateway-risk-score"])
    assert 0.0 <= risk_score <= 1.0
    latency = float(resp.headers["x-gateway-ai-latency-ms"])
    assert latency < 15.0  # Confirms sub-15ms AI scoring SLA!


def test_model_evaluation_metrics_and_benchmark():
    """
    Verify that the model meets strict accuracy (>95% ROC-AUC)
    and sub-15ms latency SLA benchmark.
    """
    metrics = evaluate_model()
    assert metrics["roc_auc_score"] >= 0.95
    assert metrics["attack_breakdown"]["bola_idor_detection_rate"] >= 0.95
    assert metrics["latency_benchmark"]["sla_met"] is True
    assert metrics["latency_benchmark"]["p99_latency_ms"] < 15.0
