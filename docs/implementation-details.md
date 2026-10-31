# 🛠️ Implementation Details & Codebase Deep Dive

This document provides a technical walkthrough of every module, component, database schema, and architectural pattern implemented across the **Securathon** codebase.

---

## 📂 Source Code Directory Structure

```
Securathon/
├── core/                   # Shared foundational services & infrastructure
│   ├── config.py           # Pydantic Settings, environment validation, URL normalization
│   ├── event_stream.py     # Dual-dispatch threat streaming (WebSocket + Redis Pub/Sub)
│   ├── logger.py           # Structured logging configuration
│   ├── rate_limiter.py     # Atomic Redis sliding-window rate limiter (ZSET pipeline)
│   ├── redis_client.py     # Async Redis client with transparent FakeRedis fallback
│   └── security.py         # JWT cryptographic engine, signature checks & blacklist
├── gateway/                # Reverse proxy gateway implementation (:8000)
│   ├── dependencies.py     # FastAPI dependency chain (Auth Guard + Rate Limiter)
│   ├── main.py             # Gateway entrypoint, routes, lifespan, dashboard mount
│   ├── mitigation.py       # Multi-tier decision engine (Allow / Tarpit / Block)
│   └── proxy.py            # High-concurrency httpx reverse proxy client
├── ml/                     # Machine learning & behavioral detection engine
│   ├── detector.py         # Real-time behavioral anomaly detector (<1ms inference)
│   ├── evaluate.py         # Quantitative model evaluation (ROC-AUC, Precision, Latency)
│   ├── features.py         # Telemetry feature engineering & Shannon entropy
│   ├── metrics_report.json # Serialized evaluation and benchmark report
│   ├── models/             # Serialized model artifacts (isolation_forest.joblib)
│   └── train.py            # Model training script for Isolation Forest
├── db/                     # Forensic audit persistence layer
│   ├── audit_logger.py     # Non-blocking async queue background worker
│   ├── models.py           # SQLAlchemy 2.0 ORM models (Incidents, Entities, Logs)
│   └── session.py          # Async engine with PostgreSQL & SQLite fallback
├── mock_backend/           # Downstream protected microservice (:8001)
│   ├── main.py             # Microservice FastAPI entrypoint and CRUD endpoints
│   ├── models.py           # Pydantic schemas (Order, User, Transaction)
│   └── seed_data.py        # In-memory database store
├── ui/                     # Decoupled modern SOC Observability Frontend
│   ├── package.json        # Frontend configuration and npm scripts
│   ├── public/             # Static assets (Favicons, SVGs)
│   └── src/                # Modular frontend assets (HTML, CSS, JS)
│       ├── css/dashboard.css
│       ├── js/api.js
│       ├── js/app.js
│       ├── js/charts.js
│       └── index.html
├── benchmark.py            # High-precision gateway latency & SLA benchmarking
├── simulate_attacks.py     # Multi-scenario automated attack simulation suite
└── tests/                  # Pytest automated test suite (49 comprehensive tests)
```

---

## 📦 Module Breakdown

### 1. `core/` (Foundational Infrastructure)

#### `core/config.py`
- Inherits from `pydantic_settings.BaseSettings` with `.env` loading.
- Features `model_post_init` hook that harmonizes:
  - `SOURCE_URL` $\leftrightarrow$ `GATEWAY_HOST` & `GATEWAY_PORT`.
  - `DESTINATION_URL` / `TARGET_URL` $\leftrightarrow$ `BACKEND_SERVICE_URL`.
- Enforces typed fallback configurations for Redis, PostgreSQL, SQLite, and rate limiting thresholds.

#### `core/security.py`
- Implements `create_access_token(sub, role, tenant_id, expires_delta)` with UUID4 `jti` generation.
- Implements `verify_jwt_token(token)`:
  - First parses unverified headers using `jwt.get_unverified_header`.
  - Rejects tokens with `alg == "none"` with **HTTP 403 Forbidden**.
  - Verifies signature using `jwt.decode(..., algorithms=[settings.jwt_algorithm])`.
  - Checks if `jti` is present in Redis blacklist; if present, raises **HTTP 401 Unauthorized**.
- Implements `revoke_token_by_payload(payload)`: Extracts `jti` and sets key `blacklist:jti:{jti}` in Redis with TTL.

#### `core/rate_limiter.py`
- Implements `SlidingWindowRateLimiter`.
- Uses Redis Sorted Set (ZSET) transaction pipeline:
  ```python
  pipe = redis.pipeline(transaction=True)
  pipe.zremrangebyscore(key, "-inf", clear_before)
  pipe.zcard(key)
  pipe.zadd(key, {request_id: now})
  pipe.expire(key, window_seconds + 5)
  results = await pipe.execute()
  ```
- Evaluates role tier quotas:
  - Customer: 100 req / 60s
  - Merchant: 250 req / 60s
  - Admin: 1,000 req / 60s
  - Unauthenticated IP: 30 req / 60s

#### `core/redis_client.py`
- Singleton connection pool manager via `get_redis_client()`.
- Supports production Redis servers (`redis.asyncio`).
- **Transparent Fallback**: If Redis is unreachable, seamlessly initializes `fakeredis.aioredis.FakeRedis()`, ensuring tests and local development function with zero external infrastructure dependencies.

#### `core/event_stream.py`
- `EventBroadcaster`: Manages active WebSocket connections (`Set[WebSocket]`).
- Dispatches `ThreatEvent` objects to:
  1. Connected browser clients via WebSocket JSON push.
  2. Distributed subscribers via Redis Pub/Sub channel `security:threat-stream`.

---

### 2. `gateway/` (Reverse Proxy & Ingress)

#### `gateway/main.py`
- Serves as the primary HTTP & WebSocket server on port 8000.
- Implements FastAPI lifespan manager (`@asynccontextmanager`) initializing Redis, DB, proxy client, and audit queue.
- Hosts SOC dashboard at `/dashboard` and `/`.
- Mounts `/ui` static assets directory (`StaticFiles(directory=UI_SRC_DIR)`).
- Endpoints:
  - `POST /api/auth/token`: Issues test JWT tokens for development and testing.
  - `POST /api/auth/revoke`: Explicit token revocation endpoint.
  - `GET /health`: Comprehensive gateway readiness and layer status probe.
  - `GET /api/rate-limit/status`: Exposes current user quota usage.
  - `GET /api/audit/incidents`: Queries historical incidents from forensic DB.
  - `GET /api/audit/blocked`: Queries currently blacklisted tokens and IPs.
  - `WebSocket /ws/security-stream`: Real-time bidirectional threat observability stream.
  - `ALL /api/{path:path}`: Proxies requests to downstream backend with `/api/` prefix.
  - `ALL /raw/{path:path}`: Direct passthrough proxying without path modification.

#### `gateway/dependencies.py`
- `get_authenticated_claims`: Validates Authorization Bearer token or rejects unauthenticated requests with **HTTP 401 Unauthorized** and `WWW-Authenticate: Bearer` challenge.
- `enforce_sliding_window_rate_limit`: Extracts identity/IP, calculates remaining quota, sets rate limit headers on response, and raises **HTTP 429** when quota is exhausted.

#### `gateway/mitigation.py`
- `MitigationDecisionEngine`:
  - Receives `AnomalyDetectionResult` from ML detector.
  - Categorizes into `ALLOW`, `TARPIT`, or `BLOCK`.
  - If `BLOCK`: invokes `revoke_token_by_payload` to instantly blacklist the attacker's `jti` in Redis.

#### `gateway/proxy.py`
- Maintains singleton `httpx.AsyncClient` with non-blocking connection pooling.
- Strips hop-by-hop headers (`connection`, `keep-alive`, `transfer-encoding`).
- Injects `X-User-ID`, `X-User-Role`, `X-Tenant-ID`, `X-Request-ID`, and `X-Gateway-Risk-Score`.
- Forwards method, path, query parameters, request headers, and request body.

---

### 3. `ml/` (Behavioral Intelligence & AI Detective)

#### `ml/features.py`
- `extract_resource_identifier(path)`: Uses regex `r"/(?:orders|users|transactions|accounts)/([a-zA-Z0-9_\-]+)"` to extract object IDs.
- `calculate_shannon_entropy(text)`:
  ```python
  probabilities = [count / length for count in collections.Counter(text).values()]
  return -sum(p * math.log2(p) for p in probabilities)
  ```
- `compute_features_from_history(...)`: Aggregates:
  1. `request_velocity`: Requests per second over observed window.
  2. `sequentiality`: Ratio of sequential integer ID increments.
  3. `id_jump_delta`: Normalized difference between consecutive IDs.
  4. `payload_entropy`: Maximum Shannon entropy across query parameters and body.
  5. `unique_id_ratio`: Ratio of distinct resource IDs accessed to total requests.

#### `ml/detector.py`
- `BehavioralAnomalyDetector`:
  - Retrieves rolling history from Redis key `telemetry:history:{user_id}`.
  - Invokes `features.compute_features_from_history`.
  - Runs inference on `IsolationForest` model.
  - Transforms raw decision function score into a normalized `risk_score` in $[0.0, 1.0]$.
  - Identifies human-readable threat indicators (e.g. `BOLA_IDOR_ATTACK`, `PARAM_FUZZING_ATTACK`).

#### `ml/train.py` & `ml/evaluate.py`
- Train an `IsolationForest(n_estimators=100, contamination=0.10, random_state=42)` model.
- Model serialized using `joblib` to [`ml/models/isolation_forest.joblib`](file:///home/dev/Desktop/Securathon/ml/models/isolation_forest.joblib).
- Evaluation verifies 0.9975 ROC-AUC, 100% BOLA recall, and $<1.0\text{ms}$ average inference latency.

---

### 4. `db/` (Forensic Audit Store)

#### `db/models.py` (SQLAlchemy 2.0)
1. **`SecurityIncident` (`security_incidents`)**:
   - `id`: Integer primary key.
   - `incident_id`: UUID unique string.
   - `timestamp`: UTC datetime.
   - `user_id`, `client_ip`, `user_role`, `endpoint`, `http_method`.
   - `risk_score`: Float.
   - `mitigation_action`: String (`ALLOW`, `TARPIT`, `BLOCK`).
   - `threat_indicators`: JSON / String list of threat tags.
   - `request_id`: Tracing UUID.
2. **`BlockedEntity` (`blocked_entities`)**:
   - `entity_type`: String (`JTI` or `IP`).
   - `entity_value`: String identifier.
   - `reason`: String explanation.
   - `created_at`, `expires_at`: UTC datetime.
3. **`TelemetryLog` (`telemetry_logs`)**:
   - High-volume behavioral telemetry stream for training and offline analytics.

#### `db/audit_logger.py`
- Asynchronous producer-consumer queue pattern.
- In-memory `asyncio.Queue` buffers incoming events from gateway request threads.
- Background worker `_worker()` consumes batches and commits transactions to SQLAlchemy async session.
- **Zero Latency Impact**: Prevents database write latency from impacting the proxy response time.

---

### 5. `mock_backend/` (Protected Microservice)

- Independent FastAPI application running on port 8001.
- Implements enterprise REST endpoints:
  - `GET /health`: Microservice readiness.
  - `GET /api/orders`: List orders.
  - `GET /api/orders/{order_id}`: Retrieve order details.
  - `POST /api/orders`: Create new order.
  - `GET /api/users/{user_id}`: Retrieve profile.
  - `GET /api/transactions`: View transactions.
  - `GET /debug/headers`: Echoes received headers, verifying gateway context injection.
- Zero mock data hardcoded in static storage; uses clean in-memory structures initialized on demand.

---

### 6. `ui/` (SOC Observability Dashboard)

- Pure HTML5, modern CSS3, and Vanilla JavaScript.
- Connects automatically to `ws://127.0.0.1:8000/ws/security-stream`.
- **Key Visual Components**:
  - Live Threat Feed table with real-time row insertion and status badges.
  - Real-time gauge for Anomaly Risk Score.
  - Multi-tier metric counters: Total Requests, Threat Blocks, BOLA Detections, Tarpitted Requests.
  - Interactive attack simulator trigger buttons for testing scenarios directly from the browser.
