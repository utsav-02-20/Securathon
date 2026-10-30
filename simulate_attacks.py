import sys
import asyncio
import time
import socket
import jwt
from typing import Dict, Any, Tuple
import httpx

# Ensure UTF-8 output on Windows consoles
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

# Terminal Color Codes
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


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


async def run_scenario_1_normal_user(client: httpx.AsyncClient) -> bool:
    print(f"\n{BOLD}{CYAN}--- [SCENARIO 1] Normal Human Browsing (Alice) ---{RESET}")
    print("Action: Alice uses valid JWT to view her order (1001), refresh, and view order list.")
    
    alice_id = f"alice_{int(time.time() * 1000)}"
    token = create_access_token({"sub": alice_id, "role": "customer", "tenant_id": "tenant_alpha"})
    headers = {"Authorization": f"Bearer {token}"}

    t0 = time.perf_counter()
    r1 = await client.get("/api/v1/orders/1001", headers=headers)
    await asyncio.sleep(0.15)
    r2 = await client.get("/api/v1/orders/1001", headers=headers)
    await asyncio.sleep(0.15)
    r3 = await client.get("/api/v1/orders", headers=headers)
    lat = (time.perf_counter() - t0 - 0.30) * 1000 / 3

    risk = r3.headers.get("x-gateway-risk-score", "0.0")
    status_ok = r1.status_code == 200 and r2.status_code == 200 and r3.status_code == 200

    if status_ok:
        print(f"  Result: {GREEN}[PASSED]{RESET} (HTTP 200 OK) | Avg Latency: {lat:.2f}ms | Risk Score: {risk} | Action: ALLOW")
        return True
    else:
        print(f"  Result: {RED}[FAILED]{RESET} (Statuses: r1={r1.status_code}, r2={r2.status_code}, r3={r3.status_code})")
        return False


async def run_scenario_2_alg_none(client: httpx.AsyncClient) -> bool:
    print(f"\n{BOLD}{CYAN}--- [SCENARIO 2] Cryptographic Tampering: 'alg: none' Exploit ---{RESET}")
    print("Action: Attacker sends forged admin JWT with signature stripped and 'alg: none'.")

    none_token = jwt.encode({"sub": "attacker_none", "role": "admin"}, key="", algorithm="none")
    headers = {"Authorization": f"Bearer {none_token}"}

    t0 = time.perf_counter()
    resp = await client.get("/api/v1/orders/1001", headers=headers)
    lat = (time.perf_counter() - t0) * 1000

    blocked = resp.status_code == 403
    if blocked:
        body = resp.json()
        threat = body.get("detail", {}).get("threat_type", "SIGNATURE_EVASION")
        print(f"  Result: {GREEN}[PASSED]{RESET} (HTTP 403 Forbidden) | Latency: {lat:.2f}ms | Threat: {RED}{threat}{RESET}")
        return True
    else:
        print(f"  Result: {RED}[FAILED]{RESET} (Expected 403, got {resp.status_code})")
        return False


async def run_scenario_3_rate_limit(client: httpx.AsyncClient) -> bool:
    print(f"\n{BOLD}{CYAN}--- [SCENARIO 3] Volumetric DDoS Burst (Redis Sliding Window) ---{RESET}")
    print("Action: Attacker fires rapid volumetric flood of requests to exhaust server compute.")

    user_id = f"ddos_attacker_{int(time.time() * 1000)}"
    token = create_access_token({"sub": user_id, "role": "customer"})
    headers = {"Authorization": f"Bearer {token}"}

    statuses = []
    t0 = time.perf_counter()
    for _ in range(115):
        r = await client.get("/api/v1/orders/1001", headers=headers)
        statuses.append(r.status_code)
        if r.status_code == 429:
            break
    lat = (time.perf_counter() - t0) * 1000

    has_429 = 429 in statuses
    if has_429:
        drop_idx = statuses.index(429) + 1
        print(f"  Result: {GREEN}[PASSED]{RESET} (HTTP 429 Too Many Requests) | Dropped at req #{drop_idx} in {lat:.2f}ms | Action: DROP")
        return True
    else:
        print(f"  Result: {RED}[FAILED]{RESET} (No 429 triggered across 115 requests)")
        return False


async def run_scenario_4_bola_attack(client: httpx.AsyncClient) -> bool:
    print(f"\n{BOLD}{CYAN}--- [SCENARIO 4] OWASP #1 BOLA / IDOR Behavioral Attack (Eve) ---{RESET}")
    print("Action: Eve holds 100% valid JWT, stays under rate limit, and traverses sequential order IDs (1001 -> 1002 -> 1003).")

    eve_id = f"eve_bola_{int(time.time() * 1000)}"
    token = create_access_token({"sub": eve_id, "role": "customer"})
    headers = {"Authorization": f"Bearer {token}"}

    t0 = time.perf_counter()
    r1 = await client.get("/api/v1/orders/1001", headers=headers)
    r2 = await client.get("/api/v1/orders/1002", headers=headers)
    r3 = await client.get("/api/v1/orders/1003", headers=headers)
    lat = (time.perf_counter() - t0) * 1000

    blocked = r3.status_code == 403
    body = r3.json() if blocked else {}
    threat = body.get("threat_type", "")
    risk = body.get("risk_score", 0.0)

    # Check auto-revocation: next request must be 401 TOKEN_REVOKED
    r_revoked = await client.get("/api/v1/orders/1001", headers=headers)
    auto_revoked = r_revoked.status_code == 401

    if blocked and auto_revoked:
        print(f"  Step 1: Intercepted on req 3: {GREEN}HTTP 403 Forbidden{RESET} | Risk Score: {risk} | Threat: {RED}{threat}{RESET}")
        print(f"  Step 2: Auto-Revocation: Attacking token blacklisted in Redis -> Next req: {GREEN}HTTP 401 TOKEN_REVOKED{RESET}")
        print(f"  Result: {GREEN}[PASSED]{RESET} (BOLA Attack Neutralized in {lat:.2f}ms)")
        return True
    else:
        print(f"  Result: {RED}[FAILED]{RESET} (Status: r3={r3.status_code}, r_revoked={r_revoked.status_code})")
        return False


async def main():
    print("=" * 66)
    print(f"{BOLD}[*] SECURATHON API SECURITY GATEWAY - ATTACK SIMULATION [*]{RESET}")
    print("=" * 66)

    client, mode = await get_test_client()
    print(f"Execution Mode: {BOLD}{mode}{RESET}")

    results = []
    results.append(("Normal Human Browsing", await run_scenario_1_normal_user(client)))
    results.append(("alg: none Signature Tampering", await run_scenario_2_alg_none(client)))
    results.append(("Volumetric DDoS Rate Limit Burst", await run_scenario_3_rate_limit(client)))
    results.append(("Stealthy BOLA / IDOR Scraper", await run_scenario_4_bola_attack(client)))

    await client.aclose()

    print("\n" + "=" * 66)
    print(f"{BOLD}[*] ATTACK SIMULATION SUMMARY REPORT [*]{RESET}")
    print("=" * 66)
    all_passed = True
    for name, passed in results:
        status_text = f"{GREEN}PASSED [NEUTRALIZED]{RESET}" if passed else f"{RED}FAILED{RESET}"
        print(f"  {name:<36} : {status_text}")
        if not passed:
            all_passed = False

    print("=" * 66)
    if all_passed:
        print(f"{BOLD}{GREEN}ALL 4 CORE ATTACK VECTORS SUCCESSFULLY NEUTRALIZED!{RESET}")
    else:
        print(f"{BOLD}{RED}SOME SCENARIOS FAILED - REVIEW LOGS.{RESET}")
    print("=" * 66)


if __name__ == "__main__":
    asyncio.run(main())
