# 🛡️ Securathon: Intelligent API Security Gateway

> **A Hybrid "Guard + Detective" API Reverse Proxy designed to defeat OWASP API Top 10 threats—specifically BOLA / IDOR, credential stuffing, and volumetric floods—with sub-15ms proxy latency.**

---

## 📌 Architecture Overview

```
[ Incoming Client Request ]
           │
           ▼
┌──────────────────────────────────────────────────────────────────┐
│  STEP 1: FastAPI Gateway (:8000)                                 │
│  High-concurrency async reverse proxy (httpx)                    │
└──────────────────────────────┬───────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│  STEP 2: Cryptographic Identity Engine (The Guard)               │
│  - Strict HS256/RS256 signature verification                     │
│  - Hard rejection of `alg: none` & tampered claims               │
│  - Instant Redis JTI Blacklist verification (<0.2ms)             │
└──────────────────────────────┬───────────────────────────────────┘
                               │ Valid Non-Revoked Token
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│  STEP 3: Atomic Sliding-Window Rate Limiter                      │
│  - Redis Sorted Sets (ZSET) / Lua atomics                        │
│  - Volumetric DDoS & brute-force drop (HTTP 429 in <1ms)          │
└──────────────────────────────┬───────────────────────────────────┘
                               │ Normal Traffic Velocity
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│  STEP 4: Behavioral Telemetry & Anomaly Engine (The Detective)   │
│  - Feature Extraction: Request Velocity, Entropy, ID Jump Delta  │
│  - Lightweight Tree Model: Isolation Forest (<1ms inference)      │
│  - Generates Risk Score (0.0 to 1.0)                             │
└──────────────────────────────┬───────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│  STEP 5: Mitigation Pipeline & Observability                     │
│  ├── Low Risk (Score < 0.75): Inject Context & Proxy to Backend  │
│  ├── High Risk (Score >= 0.75): Drop (403) or Tarpit Delay       │
│  ├── Forensic Persistence: Non-blocking asyncpg into PostgreSQL   │
│  └── Live SOC Feed: Redis Pub/Sub -> WebSocket Dashboard         │
└──────────────────────────────┬───────────────────────────────────┘
                               │
                               ▼
               [ Downstream Microservice (:8001) ]
```

---

## 🗂️ Project Directory Structure

```
Securathon/
├── .env                    # Local environment configuration
├── .env.example            # Template for environment variables
├── .gitignore              # Git ignore configuration
├── README.md               # Project documentation
├── docker-compose.yml      # Redis & PostgreSQL container orchestration
├── requirements.txt        # Python package dependencies
├── core/                   # Shared configurations, logging, and helpers
│   ├── __init__.py
│   ├── config.py           # Pydantic Settings management
│   └── logger.py           # High-performance structured logging
├── mock_backend/           # Vulnerable downstream enterprise microservice
│   ├── __init__.py
│   ├── main.py             # FastAPI backend running on port 8001
│   ├── models.py           # Schemas for Orders, Users, Transactions
│   └── seed_data.py        # Realistic multi-tenant data for BOLA simulation
├── gateway/                # Phase 2: Reverse Proxy & Cryptographic Engine
│   └── __init__.py
├── ml/                     # Phase 4: Telemetry extraction & Isolation Forest
│   └── __init__.py
├── db/                     # Phase 5: PostgreSQL async forensic store
│   └── __init__.py
├── dashboard/              # Phase 6: SOC WebSocket Live Observability UI
│   └── __init__.py
└── tests/                  # Automated pytest testing suite
    ├── __init__.py
    ├── conftest.py         # Pytest fixtures and test client
    └── test_mock_backend.py# Unit tests for mock backend
```

---

## 🚀 Phase Status & Deliverables

| Phase | Milestone | Status | Key Deliverables |
|---|---|---|---|
| **Phase 1** | Project Architecture, Infrastructure & Mock Backend | ✅ Complete | Directory structure, `docker-compose.yml` (Redis + Postgres), `.env`, `mock_backend/` (:8001), 9 unit tests passing. |
| **Phase 2** | FastAPI Reverse Proxy & Cryptographic JWT Engine | ✅ Complete | High-concurrency `httpx` proxy (:8000), deterministic JWT Guard (HS256), `alg: none` exploit hard-block (403), Redis JTI Blacklist revocation ($O(1) <0.2\text{ms}$), 11 unit tests passing. |
| **Phase 3** | Atomic Redis Sliding-Window Rate Limiter | ✅ Complete | Rolling 60s sliding window via Redis Sorted Sets (ZSET) transaction pipeline, role-based tiers (Customer/Merchant/Admin), sub-millisecond flood drop (HTTP 429), standard RFC headers (`Retry-After`, `X-RateLimit-*`), 6 unit tests passing. |
| **Phase 4** | Telemetry Extraction & Isolation Forest AI Engine | ✅ Complete | Behavioral telemetry extraction (velocity, Shannon entropy, sequential ID jump variance), persistent dataset (`data/telemetry_dataset.csv`, 2650 samples), lightweight `IsolationForest` ($<1\text{ms}$ inference), quantitative benchmark (ROC-AUC 0.9975, 100% BOLA recall), 7 unit tests passing. |
| **Phase 5** | Risk Mitigation Pipeline & PostgreSQL Audit Store | ✅ Complete | Policy engine (Allow, Tarpit latency injection, Block 403, Auto-JTI revocation in Redis), non-blocking async audit logger (`db/`), tables (`security_incidents`, `blocked_entities`, `telemetry_logs`), audit query endpoints, 5 unit tests passing (38/38 total). |
| **Phase 6** | Real-time Event Streaming & Security SOC Dashboard | ⏳ Next | Redis Pub/Sub broadcast, WebSocket threat stream, live interactive SOC Dashboard UI. |
| **Phase 7** | Attack Simulation Suite & Performance Benchmarking | ⏳ Pending | Automated attack runner (`simulate_attacks.py`), Locust/k6 latency validation (<15ms). |

---

## ⚡ Quickstart

### 1. Start Infrastructure (Optional / When Docker is Available)
```bash
docker compose up -d
```
* Redis will be available on `localhost:6379`.
* PostgreSQL will be available on `localhost:5432`.

### 2. Run the Mock Microservice
```bash
python -m mock_backend.main
```
The mock microservice will start at `http://127.0.0.1:8001`.
* Swagger API Documentation: `http://127.0.0.1:8001/docs`
* Health Check: `http://127.0.0.1:8001/health`
* Vulnerable Order Endpoint: `http://127.0.0.1:8001/api/v1/orders/1001`

### 3. Run the Automated Tests
```bash
python -m pytest tests/test_mock_backend.py -v
```

---

## ⏭️ Next Step: Phase 2
**Phase 2: FastAPI Reverse Proxy & Cryptographic JWT Engine**
* Implement `gateway/proxy.py` using `httpx.AsyncClient` listening on port `8000`.
* Implement cryptographic JWT validation middleware with strict signature checking.
* Reject `alg: "none"` signature evasion exploits, forged keys, and expired tokens.
* Implement O(1) Redis Token Blacklist check for instant token revocation.

