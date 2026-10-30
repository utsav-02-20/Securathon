# 🛡️ Securathon: Intelligent API Security Gateway

> **An Enterprise-Grade Hybrid "Guard + Detective" API Reverse Proxy designed to detect and neutralize OWASP API Top 10 threats—specifically BOLA / IDOR (#1), cryptographic token tampering (`alg: none`), and volumetric floods—with strict sub-15ms proxy latency overhead.**

---

## 📌 Architecture Overview

```
                                  [ Incoming Client Request ]
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│  STEP 1: High-Performance FastAPI Reverse Proxy Gateway (:8000)                             │
│  - Async non-blocking connection pool (httpx.AsyncClient)                                   │
│  - Gateway Context Injection (X-User-ID, X-User-Role, X-Tenant-ID, X-Request-ID)            │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│  STEP 2: Cryptographic Identity Engine (The Guard)                                          │
│  - Strict HS256/RS256 signature verification and required claim validation                  │
│  - Zero-Tolerance Hard Block: 'alg: none' signature evasion attempts (HTTP 403)            │
│  - O(1) Instant Redis Token Blacklist / JTI Revocation verification (<0.2ms)                │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │ Valid Non-Revoked Token
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│  STEP 3: Atomic Sliding-Window Rate Limiter                                                 │
│  - Redis Sorted Sets (ZSET) transaction pipeline for atomic rolling 60s windows             │
│  - Tiered quotas: Customer (100 req/60s), Merchant (500 req/60s), Admin (2000 req/60s)      │
│  - Drops volumetric spikes and DDoS attempts with HTTP 429 & RFC 'Retry-After' in <1ms      │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │ Within Rate Limit Quota
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│  STEP 4: Behavioral Telemetry & AI Detective Engine                                         │
│  - Rolling history tracking: velocity, unique resource ratio, sequentiality                 │
│  - Shannon Entropy: H(X) = -Σ p log2(p) to detect payload injection / parameter fuzzing      │
│  - Lightweight Tree Model: Isolation Forest (<1ms inference) -> Risk Score (0.00 to 1.00)  │
│  - 0.9975 ROC-AUC, 100% BOLA recall on enterprise telemetry dataset                         │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│  STEP 5: Multi-Tier Risk Mitigation Pipeline & Forensic Audit Store                         │
│  ├── LOW RISK (Score < 0.70)   : ALLOW -> Inject headers & proxy to downstream backend      │
│  ├── MEDIUM RISK (0.70 - 0.75) : TARPIT -> Dynamically inject 2.0s delay to disrupt scrapers │
│  └── HIGH RISK (Score >= 0.75) : BLOCK (403) -> Auto-Revoke JTI in Redis (next req = 401)   │
│  - Non-blocking async queue worker writes incidents to PostgreSQL / SQLite forensics store   │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │
                        ┌──────────────────────┴──────────────────────┐
                        ▼                                             ▼
┌──────────────────────────────────────────────┐ ┌──────────────────────────────────────────┐
│  STEP 6: Real-time Threat Streaming & SOC    │ │  Protected Downstream Microservice (:8001│
│  - Dual-dispatch: WebSocket + Redis Pub/Sub  │ │  - Multi-tenant Orders, Users, & Accounts │
│  - Dark-mode SOC Observability Dashboard     │ │  - Completely shielded from BOLA & floods│
│  - Live incident feed, gauge, & charts       │ └──────────────────────────────────────────┘
└──────────────────────────────────────────────┘
```

---

## 🗂️ Project Directory Structure

```
Securathon/
├── core/
│   ├── config.py             # Pydantic Settings & environment variable validation
│   ├── event_stream.py       # Dual-dispatch threat streaming (WebSocket + Redis Pub/Sub)
│   ├── logger.py             # Structured logging configuration
│   ├── rate_limiter.py       # Atomic Redis sliding-window rolling rate limiter
│   ├── redis_client.py       # Fast async Redis client with in-memory FakeRedis fallback
│   └── security.py           # JWT cryptographic engine, signature verify, & 'alg: none' block
├── mock_backend/
│   ├── main.py               # Downstream microservice on port 8001
│   ├── models.py             # Pydantic domain models (Orders, Users, Transactions)
│   └── seed_data.py          # Realistic multi-tenant mock database (orders 1001-1010)
├── ml/
│   ├── detector.py           # Real-time behavioral anomaly detector (<1ms inference)
│   ├── evaluate.py           # Quantitative validation (ROC-AUC, Precision, Recall, Latency)
│   ├── features.py           # Feature extraction (velocity, sequentiality, Shannon entropy)
│   ├── metrics_report.json   # Serialized ML performance benchmark report
│   └── train.py              # Model trainer generating models/isolation_forest.joblib
├── data/
│   ├── generate_dataset.py   # Telemetry dataset generator (2,650 labeled samples)
│   └── telemetry_dataset.csv # Training and evaluation dataset
├── db/
│   ├── audit_logger.py       # Non-blocking async background queue persistence worker
│   ├── models.py             # SQLAlchemy 2.0 models (incidents, blocked entities, logs)
│   └── session.py            # Async engine with PostgreSQL & SQLite fallback
├── gateway/
│   ├── dependencies.py       # FastAPI dependency chain (Auth Guard + Rate Limiter)
│   ├── main.py               # Gateway entrypoint on port 8000, routes, & WebSocket
│   ├── mitigation.py         # Multi-tier mitigation decision engine
│   └── proxy.py              # High-concurrency httpx reverse proxy
├── dashboard/
│   ├── index.html            # Cyber dark-mode SOC Security Dashboard UI
│   └── styles.css            # SOC styles, radar animations, and glowing indicators
├── tests/                    # 46 automated unit and integration tests (100% passing)
│   ├── test_ai_engine.py
│   ├── test_gateway_jwt.py
│   ├── test_mitigation_and_db.py
│   ├── test_mock_backend.py
│   ├── test_rate_limiter.py
│   ├── test_simulation.py
│   └── test_websocket_stream.py
├── benchmark.py              # Automated latency percentile (P50, P90, P95, P99) benchmark
├── simulate_attacks.py       # End-to-end multi-vector attack simulation suite
├── docker-compose.yml        # Redis and PostgreSQL container orchestration
├── pytest.ini                # Pytest configuration and warning filters
└── requirements.txt          # Python dependencies
```

---

## 🎯 7-Phase Implementation Roadmap & Status

| Phase | Milestone | Status | Key Deliverables & Achievements |
|---|---|---|---|
| **Phase 1** | Project Architecture & Mock Backend | ✅ Complete | Modular architecture, `docker-compose.yml`, mock downstream microservice (:8001) with seed data and gateway context header reflection. |
| **Phase 2** | FastAPI Gateway & Cryptographic Guard | ✅ Complete | Async reverse proxy (:8000), strict signature verification, hard rejection of `alg: none` (403), O(1) Redis JTI token revocation (<0.2ms). |
| **Phase 3** | Atomic Sliding-Window Rate Limiter | ✅ Complete | Atomic Redis Sorted Sets (ZSET) transaction pipeline, tiered quotas, sub-millisecond flood drop (HTTP 429) with RFC `Retry-After`. |
| **Phase 4** | Behavioral Telemetry & Isolation Forest | ✅ Complete | Feature engineering (Shannon entropy, sequentiality), 2,650 sample dataset, 0.9975 ROC-AUC, 100% BOLA recall, <1ms inference. |
| **Phase 5** | Risk Mitigation Pipeline & Audit Store | ✅ Complete | Policy engine (Allow, Tarpit delay, Block 403, Redis Auto-Revoke JTI -> 401), non-blocking async queue worker, PostgreSQL / SQLite forensics. |
| **Phase 6** | Real-time Streaming & SOC Dashboard | ✅ Complete | Dual-dispatch WebSocket `/ws/security-stream` + Redis Pub/Sub, responsive cyber dark-mode SOC UI at `/dashboard`. |
| **Phase 7** | Attack Simulation Suite & Benchmarking | ✅ Complete | Multi-vector simulation (`simulate_attacks.py`), latency percentiles (`benchmark.py`), proven sub-15ms SLA (P95: 9.5ms), 46/46 pytest tests. |

---

## 🛡️ Neutralized Threat Vectors

Securathon actively demonstrates protection against 4 primary attack vectors:

### 1. Normal Human Browsing (Benign Baseline)
* **Behavior**: Sporadic human clicks, order inspection, and list navigation with valid JWT credentials.
* **Gateway Action**: `ALLOW` (HTTP 200 OK).
* **Telemetry**: Risk Score < 0.45, zero anomaly indicators, forwarded seamlessly to downstream backend.

### 2. Cryptographic Tampering (`alg: none` Exploit)
* **Attack**: Attacker attempts signature evasion by modifying JWT header to `{"alg": "none"}` and stripping the cryptographic signature.
* **Gateway Action**: `BLOCK` (HTTP 403 Forbidden).
* **Threat Flag**: `SIGNATURE_EVASION_ATTACK`. Processed deterministically in <1.1ms before hitting downstream services.

### 3. Volumetric DDoS & Brute-Force Burst
* **Attack**: Attacker sends a rapid flood (>100 requests in rolling 60s) to exhaust backend compute resources.
* **Gateway Action**: `DROP` (HTTP 429 Too Many Requests).
* **Protection**: Atomic Redis sliding window drops the burst with RFC standard `Retry-After: 60` headers in <1ms.

### 4. OWASP #1 BOLA / IDOR Sequential Enum (Stealthy Scraper)
* **Attack**: Attacker holds a 100% valid JWT, stays under the volumetric rate limit, but traverses sequential object IDs (`/orders/1001` → `/orders/1002` → `/orders/1003`).
* **Gateway Action**: `BLOCK` (HTTP 403 Forbidden on req 3) + **AUTO-REVOCATION**.
* **Auto-Revocation**: The gateway's mitigation engine automatically extracts the attacker's token JTI and commits it to the Redis token blacklist with a 3600s TTL. Any subsequent request with that token is immediately dropped with **HTTP 401 TOKEN_REVOKED**.

---

## 📊 Latency SLA & Performance Benchmarks

The gateway was benchmarked under strict end-to-end SLA requirements (Overhead Target: `< 15.0ms`).

### Benchmark Results (`benchmark_report.json`):
* **Total Requests**: 150 requests
* **Throughput**: **129.97 Requests/sec**
* **Mean Latency**: **7.67ms**
* **P50 (Median) Latency**: **7.24ms**
* **P90 Latency**: **8.49ms**
* **P95 Latency**: **9.50ms**  *(SLA Target: < 15.0ms — **PASSED**)*
* **P99 Latency**: **18.38ms**
* **Inference Latency**: **~0.8ms - 1.2ms** (Isolation Forest)

```
============================================================
[*] GATEWAY BENCHMARK & SLA PERFORMANCE REPORT [*]
============================================================
Total Requests Processed: 150/150
Total Wall-Clock Time   : 1.15s
Throughput              : 129.97 Requests/sec
Mean Latency            : 7.67ms
P50 (Median) Latency    : 7.24ms
P90 Latency             : 8.49ms
P95 Latency             : 9.5ms
P99 Latency             : 18.38ms
------------------------------------------------------------
SLA Target (< 15ms)     : [PASSED] (Within SLA Budget)
Report saved to         : benchmark_report.json
============================================================
```

---

## 💻 Quickstart & Verification Commands

### 1. Run the Full Automated Test Suite (46 Tests)
```bash
python -m pytest tests/ -v
```
*Expected: 46 passed across all modules (0 failures, 0 errors).*

### 2. Run the Multi-Vector Attack Simulation
```bash
python simulate_attacks.py
```
*Executes all 4 attack scenarios in real-time, displaying live latency and mitigation actions.*

### 3. Run the Gateway Latency Benchmark
```bash
python benchmark.py
```
*Calculates P50, P90, P95, and P99 percentiles and outputs `benchmark_report.json`.*

### 4. Launch the Live Gateway & Microservices
In Terminal 1 (Mock Backend):
```bash
python -m mock_backend.main
```

In Terminal 2 (Security Gateway):
```bash
python -m gateway.main
```

In your browser, visit:
* **Interactive SOC Observability Dashboard**: `http://127.0.0.1:8000/dashboard`
* **Gateway Interactive Swagger Docs**: `http://127.0.0.1:8000/docs`
* **Downstream Microservice Docs**: `http://127.0.0.1:8001/docs`

---

## 🔒 Standalone Zero-Crash Fallbacks

To ensure seamless local evaluation without requiring live Docker containers:
* **Redis**: Automatically detects if local Redis is running; instantly falls back to high-performance async in-memory `fakeredis.aioredis` if unavailable.
* **PostgreSQL**: Automatically detects if PostgreSQL is reachable; seamlessly falls back to local async `sqlite+aiosqlite:///./securathon_audit.db` if unavailable.
* **Zero Configuration Needed**: Run `python simulate_attacks.py` or `pytest` immediately out-of-the-box!
