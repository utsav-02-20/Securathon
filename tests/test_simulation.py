import pytest
import httpx
import gateway.proxy as proxy_module
from gateway.main import app as gateway_app
from mock_backend.main import app as backend_app
from core.config import settings

from simulate_attacks import (
    run_scenario_1_normal_user,
    run_scenario_2_alg_none,
    run_scenario_3_rate_limit,
    run_scenario_4_bola_attack,
    run_scenario_5_param_fuzzing,
    run_scenario_6_expired_token,
    run_scenario_7_missing_token,
)
from benchmark import run_benchmark


@pytest.fixture(autouse=True)
def setup_test_proxy():
    """
    Configures in-process ASGI mock backend proxy routing for simulations and benchmarks.
    """
    mock_transport = httpx.ASGITransport(app=backend_app)
    proxy_module._proxy_client = httpx.AsyncClient(
        transport=mock_transport,
        base_url=settings.backend_service_url
    )
    yield
    proxy_module._proxy_client = None


def get_sim_client() -> httpx.AsyncClient:
    """Returns an AsyncClient wired directly to the Gateway ASGI app."""
    transport = httpx.ASGITransport(app=gateway_app)
    return httpx.AsyncClient(transport=transport, base_url="http://gateway.local", timeout=10.0)


@pytest.mark.asyncio
async def test_simulation_scenario_1_normal_user():
    """Scenario 1: Normal human user browsing orders is permitted (HTTP 200)."""
    async with get_sim_client() as client:
        passed = await run_scenario_1_normal_user(client)
        assert passed is True


@pytest.mark.asyncio
async def test_simulation_scenario_2_alg_none():
    """Scenario 2: Cryptographic 'alg: none' tampering is blocked (HTTP 403)."""
    async with get_sim_client() as client:
        passed = await run_scenario_2_alg_none(client)
        assert passed is True


@pytest.mark.asyncio
async def test_simulation_scenario_3_rate_limit():
    """Scenario 3: Volumetric flood triggers sliding-window rate limit (HTTP 429)."""
    async with get_sim_client() as client:
        passed = await run_scenario_3_rate_limit(client)
        assert passed is True


@pytest.mark.asyncio
async def test_simulation_scenario_4_bola_attack():
    """Scenario 4: Sequential BOLA IDOR attack is detected (403) and token auto-revoked (401)."""
    async with get_sim_client() as client:
        passed = await run_scenario_4_bola_attack(client)
        assert passed is True


@pytest.mark.asyncio
async def test_simulation_scenario_5_param_fuzzing():
    """Scenario 5: High-entropy SQLi / parameter fuzzing payload is blocked (HTTP 403)."""
    async with get_sim_client() as client:
        passed = await run_scenario_5_param_fuzzing(client)
        assert passed is True


@pytest.mark.asyncio
async def test_simulation_scenario_6_expired_token():
    """Scenario 6: Expired JWT replay attempt is trapped by cryptographic guard (HTTP 401)."""
    async with get_sim_client() as client:
        passed = await run_scenario_6_expired_token(client)
        assert passed is True


@pytest.mark.asyncio
async def test_simulation_scenario_7_missing_token():
    """Scenario 7: Zero-trust perimeter drops unauthenticated request (HTTP 401)."""
    async with get_sim_client() as client:
        passed = await run_scenario_7_missing_token(client)
        assert passed is True


@pytest.mark.asyncio
async def test_benchmark_execution_and_sla():
    """Benchmark: 30 requests verify throughput, latency calculation, and sub-15ms SLA target."""
    import asyncio
    await asyncio.sleep(0.5)
    report = await run_benchmark(n_requests=30, concurrency=1, force_in_process=True)
    assert report["successful_requests"] == 30
    assert report["throughput_rps"] > 0
    assert "p95" in report["latency_percentiles_ms"]
    assert report["sla"]["sla_target_overhead_ms"] == 15.0
    assert report["sla"]["sla_met"] is True
