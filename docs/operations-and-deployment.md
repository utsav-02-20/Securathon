# 🚀 Operations, Deployment & Run Guide

Step-by-step guide to installing, configuring, operating, and testing the **Securathon Intelligent API Security Gateway**.

---

## 📋 Prerequisites

- **Python**: Version 3.10, 3.11, 3.12, 3.13, or 3.14.
- **Node.js** (Optional): Only if rebuilding or developing the frontend with Vite.
- **Docker & Docker Compose** (Optional): If running Redis and PostgreSQL containers.

> [!NOTE]
> Securathon contains built-in zero-dependency fallbacks:
> - If Redis is unavailable, it automatically starts an in-memory **`FakeRedis`** instance.
> - If PostgreSQL is unavailable, it automatically uses local **SQLite** (`securathon_audit.db`).
>
> You can run the complete project with zero external database servers!

---

## ⚙️ Environment Configuration

Create or modify your `.env` file based on `.env.example`:

```env
# Gateway Ingress Configuration
GATEWAY_HOST=0.0.0.0
GATEWAY_PORT=8000
SOURCE_URL=http://0.0.0.0:8000
LOG_LEVEL=INFO

# Downstream Microservice (Destination Target)
BACKEND_HOST=127.0.0.1
BACKEND_PORT=8001
BACKEND_SERVICE_URL=http://127.0.0.1:8001
DESTINATION_URL=http://127.0.0.1:8001

# Cryptographic Identity & Access Control
REQUIRE_AUTH=true
JWT_SECRET_KEY=super-secret-production-grade-encryption-key-32chars
JWT_ALGORITHM=HS256
JWT_EXPIRATION_MINUTES=60

# Redis State & Token Revocation Store
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
USE_FAKE_REDIS_FALLBACK=true

# Database Persistence (SQLite or PostgreSQL)
DB_TYPE=sqlite
DATABASE_URL=sqlite+aiosqlite:///securathon_audit.db

# Sliding-Window Rate Limiting Quotas (per 60-second window)
RATE_LIMIT_REQUESTS_PER_WINDOW=100
RATE_LIMIT_WINDOW_SECONDS=60
RATE_LIMIT_CUSTOMER=100
RATE_LIMIT_MERCHANT=250
RATE_LIMIT_ADMIN=1000
RATE_LIMIT_UNAUTH_IP=30

# Behavioral ML & Telemetry
ANOMALY_SCORE_THRESHOLD=0.75
TARPIT_DELAY_SECONDS=2.0
```

---

## 🏃 Local Execution Walkthrough

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Launch the Downstream Mock Microservice (Terminal 1)
```bash
python3 -m mock_backend.main
# Or directly:
python3 mock_backend/main.py
```
- Listens on `http://127.0.0.1:8001`
- Verifies endpoints: `curl http://127.0.0.1:8001/health`

### 3. Launch the Intelligent Security Gateway (Terminal 2)
```bash
python3 -m gateway.main
# Or directly:
python3 gateway/main.py
```
- Listens on `http://0.0.0.0:8000`
- Verifies health: `curl http://127.0.0.1:8000/health`
- Serves SOC Dashboard at: `http://127.0.0.1:8000/dashboard`

---

## 🧪 Comprehensive Verification & Testing

### 1. Run Complete Pytest Suite
Executes 49 automated unit and integration tests across all gateway components:
```bash
pytest -v
```
*(All 49 tests should pass in under 10 seconds)*

### 2. Run Attack Simulation Suite
Fires all 7 multi-layer attack scenarios against the gateway to verify active mitigation:
```bash
python3 simulate_attacks.py
```
Expected output:
```
ALL 7 MULTI-LAYER ATTACK VECTORS SUCCESSFULLY NEUTRALIZED!
```

### 3. Run Latency SLA & Throughput Benchmark
Measures sub-15ms proxy latency compliance and throughput:
```bash
python3 benchmark.py
```
Expected output:
```
SLA Target (< 15ms)     : [PASSED] (Within SLA Budget)
Report saved to         : benchmark_report.json
```

### 4. Run ML Model Evaluation & Latency Profiler
Verifies ROC-AUC and sub-millisecond inference speed:
```bash
python3 ml/evaluate.py
```

---

## 🐳 Docker Deployment (Optional Infrastructure)

To run dedicated Redis and PostgreSQL instances using Docker Compose:

```bash
docker compose up -d
```

This starts:
- `securathon-redis` on port `6379`.
- `securathon-postgres` on port `5432`.

To point Securathon to PostgreSQL, update `.env`:
```env
DB_TYPE=postgres
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/securathon_audit
USE_FAKE_REDIS_FALLBACK=false
```

---

## 🛠️ Troubleshooting & FAQs

### Port Conflict on 8000 or 8001
- Check which process is occupying the port:
  ```bash
  ss -tulpn | grep -E "8000|8001"
  ```
- Terminate or change `GATEWAY_PORT` or `BACKEND_PORT` in `.env`.

### `FakeRedis` vs Production Redis
- By default, `USE_FAKE_REDIS_FALLBACK=true` allows Securathon to run out-of-the-box without requiring a running Redis daemon.
- In production, install Redis and set `USE_FAKE_REDIS_FALLBACK=false`.

### WebSocket Connection Issues
- Ensure `http://127.0.0.1:8000` is used rather than `0.0.0.0` when opening the browser dashboard.
- Verify the WebSocket endpoint `ws://127.0.0.1:8000/ws/security-stream` is reachable.
