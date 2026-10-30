import sys
import asyncio
import time
import json
import socket
import numpy as np
from typing import Tuple, List, Dict, Any
import httpx

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from core.config import settings
from core.security import create_access_token
import gateway.proxy as proxy_module
from gateway.main import app as gateway_app
from mock_backend.main import app as backend_app

REPORT_PATH = "benchmark_report.json"


def is_port_open(host: str, port: int, timeout: float = 0.2) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


async def get_test_client() -> Tuple[httpx.AsyncClient, str]:
    gateway_running = is_port_open(settings.gateway_host if settings.gateway_host != "0.0.0.0" else "127.0.0.1", settings.gateway_port)
    if gateway_running:
        base_url = f"http://127.0.0.1:{settings.gateway_port}"
        client = httpx.AsyncClient(base_url=base_url, timeout=10.0)
        mode = f"Live HTTP Server ({base_url})"
    else:
        proxy_module._proxy_client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=backend_app),
            base_url=settings.backend_service_url
        )
        transport = httpx.ASGITransport(app=gateway_app)
        client = httpx.AsyncClient(transport=transport, base_url="http://gateway.local", timeout=10.0)
        mode = "In-Process High-Speed ASGI Pipeline"
    return client, mode


async def run_benchmark(n_requests: int = 150, concurrency: int = 1) -> Dict[str, Any]:
    """
    Executes a high-precision throughput and latency benchmark against the Gateway pipeline.
    Validates the strict sub-15ms proxy latency SLA.
    """
    print(f"\n[*] Starting Gateway Latency & Throughput Benchmark ({n_requests} requests, concurrency={concurrency})...")
    client, mode = await get_test_client()
    print(f"Target Mode: {mode}")

    # Use Admin token to avoid hitting standard user rate limits during high-volume benchmarking
    token = create_access_token({"sub": "bench_admin", "role": "admin"})
    headers = {"Authorization": f"Bearer {token}"}

    # Warm-up phase: 5 requests to prime JIT caches, async connections, and model inference
    for _ in range(5):
        await client.get("/api/v1/orders/1001", headers=headers)

    latencies: List[float] = []
    semaphore = asyncio.Semaphore(concurrency)

    async def send_worker(req_id: int):
        async with semaphore:
            t0 = time.perf_counter()
            resp = await client.get("/api/v1/orders/1001", headers=headers)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            if resp.status_code == 200:
                latencies.append(elapsed_ms)

    t_wall_start = time.perf_counter()
    tasks = [send_worker(i) for i in range(n_requests)]
    await asyncio.gather(*tasks)
    t_wall_total = time.perf_counter() - t_wall_start

    await client.aclose()

    # Calculate percentiles
    success_count = len(latencies)
    throughput_rps = round(success_count / max(0.001, t_wall_total), 2)
    mean_lat = round(float(np.mean(latencies)), 2)
    p50_lat = round(float(np.percentile(latencies, 50)), 2)
    p90_lat = round(float(np.percentile(latencies, 90)), 2)
    p95_lat = round(float(np.percentile(latencies, 95)), 2)
    p99_lat = round(float(np.percentile(latencies, 99)), 2)
    max_lat = round(float(np.max(latencies)), 2)
    sla_target = 15.0
    sla_met = bool(p95_lat < sla_target)

    report = {
        "total_requests": n_requests,
        "successful_requests": success_count,
        "concurrency": concurrency,
        "total_time_seconds": round(t_wall_total, 3),
        "throughput_rps": throughput_rps,
        "latency_percentiles_ms": {
            "mean": mean_lat,
            "p50_median": p50_lat,
            "p90": p90_lat,
            "p95": p95_lat,
            "p99": p99_lat,
            "max": max_lat
        },
        "sla": {
            "sla_target_overhead_ms": sla_target,
            "p95_actual_ms": p95_lat,
            "sla_met": sla_met
        }
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("=" * 60)
    print("[*] GATEWAY BENCHMARK & SLA PERFORMANCE REPORT [*]")
    print("=" * 60)
    print(f"Total Requests Processed: {success_count}/{n_requests}")
    print(f"Total Wall-Clock Time   : {t_wall_total:.2f}s")
    print(f"Throughput              : {throughput_rps} Requests/sec")
    print(f"Mean Latency            : {mean_lat}ms")
    print(f"P50 (Median) Latency    : {p50_lat}ms")
    print(f"P90 Latency             : {p90_lat}ms")
    print(f"P95 Latency             : {p95_lat}ms")
    print(f"P99 Latency             : {p99_lat}ms")
    print("-" * 60)
    print(f"SLA Target (< 15ms)     : {'[PASSED] (Within SLA Budget)' if sla_met else '[FAILED]'}")
    print(f"Report saved to         : {REPORT_PATH}")
    print("=" * 60)

    return report


if __name__ == "__main__":
    asyncio.run(run_benchmark(n_requests=150, concurrency=1))
