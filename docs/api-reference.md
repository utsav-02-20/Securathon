# 📡 API Reference & Endpoint Specification

Complete specification of all endpoints exposed by the **Securathon Security Gateway (:8000)** and the **Protected Downstream Microservice (:8001)**.

---

## 🚪 Security Gateway Endpoints (:8000)

### 1. Health & Status Probes

#### `GET /health`
Returns the operational status of all gateway security layers.

- **Authentication**: None required.
- **Response**: `200 OK`
  ```json
  {
    "status": "healthy",
    "service": "api-security-gateway",
    "source_url": "http://0.0.0.0:8000",
    "destination_url": "http://127.0.0.1:8001",
    "port": 8000,
    "backend_target": "http://127.0.0.1:8001",
    "db_type": "sqlite",
    "require_auth": true,
    "guard_status": "active (JWT HS256/RS256 + Redis JTI Blacklist)",
    "rate_limiter_status": "active (atomic sliding-window)",
    "ai_engine_status": "active (Isolation Forest sub-ms scoring)",
    "mitigation_pipeline": "active (Allow / Tarpit / Block / Auto-Revoke)",
    "audit_store": "active (SQLite non-blocking)",
    "soc_dashboard": "active (/dashboard, /ws/security-stream)",
    "anomaly_threshold": 0.75
  }
  ```

---

### 2. Authentication & Token Management

#### `POST /api/auth/token`
Generates a signed test JWT for developing and testing API calls.

- **Request Body**:
  ```json
  {
    "user_id": "user_alice",
    "role": "customer",
    "tenant_id": "tenant_default",
    "expires_minutes": 60
  }
  ```
  *(Supported roles: `customer`, `merchant`, `admin`)*
- **Response**: `200 OK`
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "role": "customer",
    "user_id": "user_alice",
    "jti": "d3b07384-d113-4e4b-9ecb-365cf71587a3"
  }
  ```

#### `POST /api/auth/revoke`
Explicitly revokes an active JWT, adding its `jti` to the Redis blacklist.

- **Headers**: `Authorization: Bearer <token>`
- **Response**: `200 OK`
  ```json
  {
    "status": "revoked",
    "jti": "d3b07384-d113-4e4b-9ecb-365cf71587a3",
    "message": "Token has been added to the blacklist."
  }
  ```

---

### 3. Rate Limit & Telemetry

#### `GET /api/rate-limit/status`
Returns the current rate limit usage for the requesting user or IP.

- **Headers**: Optional `Authorization: Bearer <token>`
- **Response**: `200 OK`
  ```json
  {
    "identity": "user_alice",
    "role": "customer",
    "limit": 100,
    "remaining": 94,
    "window_seconds": 60,
    "reset_in_ms": 42150
  }
  ```

---

### 4. Forensic Audit & Blacklist

#### `GET /api/audit/incidents`
Queries recent forensic security incidents from the database.

- **Parameters**: `limit` (int, default 50)
- **Response**: `200 OK`
  ```json
  [
    {
      "incident_id": "4a7f0e34-58a2-4752-9cc1-df289efb387a",
      "timestamp": "2026-10-31T15:24:00.123456Z",
      "user_id": "attacker_eve",
      "client_ip": "127.0.0.1",
      "user_role": "customer",
      "endpoint": "/api/orders/1003",
      "http_method": "GET",
      "risk_score": 0.99,
      "mitigation_action": "BLOCK",
      "threat_indicators": ["BOLA_IDOR_ATTACK", "HIGH_SEQUENTIALITY_TRAVERSAL"]
    }
  ]
  ```

#### `GET /api/audit/blocked`
Returns entities currently blacklisted by automated auto-revocation or IP blocks.

- **Response**: `200 OK`
  ```json
  [
    {
      "entity_type": "JTI",
      "entity_value": "9f3c15be-630d-405a-a3df-7b94adbc9c21",
      "reason": "Automated auto-revocation triggered by BOLA_IDOR_ATTACK",
      "created_at": "2026-10-31T15:24:00.125000Z",
      "expires_at": "2026-10-31T16:24:00.125000Z"
    }
  ]
  ```

---

### 5. Threat Observability WebSocket

#### `WebSocket /ws/security-stream`
Bidirectional real-time stream of all evaluated API requests and threats.

- **Client $\to$ Gateway**: Optional ping `{"type": "ping"}`
- **Gateway $\to$ Client**: Event payload for each evaluated request:
  ```json
  {
    "event_id": "3c8808d9-28c0-4351-a204-749e49cfa34b",
    "timestamp": "2026-10-31T15:24:00.120000Z",
    "request_id": "bfd91242-70b1-4042-882d-8b010c253ff6",
    "user_id": "attacker_eve",
    "client_ip": "127.0.0.1",
    "user_role": "customer",
    "endpoint": "/api/orders/1003",
    "http_method": "GET",
    "risk_score": 0.99,
    "action": "BLOCK",
    "is_anomaly": true,
    "threat_indicators": ["BOLA_IDOR_ATTACK"],
    "inference_latency_ms": 0.85,
    "proxy_latency_ms": 1.2
  }
  ```

---

### 6. Reverse Proxy Routes

#### `ALL /api/{path:path}`
Standard proxied route. Validates auth, evaluates AI behavioral risk, enforces rate limits, and forwards the request to `http://<destination>/api/{path}`.

#### `ALL /raw/{path:path}`
Raw passthrough route without `/api/` prefixing. Proxies directly to `http://<destination>/{path}`.

---

## 🔒 Protected Downstream Microservice Endpoints (:8001)

### 1. `GET /health`
Microservice readiness check.

### 2. `GET /api/orders`
Lists all active orders.
- **Injected Context Required**: Injected automatically by the Gateway (`X-User-ID`, `X-Tenant-ID`).
- **Response**: `200 OK`
  ```json
  [
    {
      "id": "1001",
      "user_id": "user_101",
      "tenant_id": "tenant_1",
      "total_amount": 149.99,
      "status": "completed",
      "items": [
        {"item_id": "prod_1", "name": "Secure YubiKey 5C", "quantity": 1, "price": 55.0}
      ]
    }
  ]
  ```

### 3. `GET /api/orders/{order_id}`
Returns details for a specific order.

### 4. `POST /api/orders`
Creates a new customer order.
- **Request Body**:
  ```json
  {
    "items": [
      {"item_id": "prod_3", "name": "Hardware Security Module", "quantity": 1, "price": 450.0}
    ]
  }
  ```

### 5. `GET /api/users/{user_id}`
Retrieves user profile and account status.

### 6. `GET /api/transactions`
Retrieves enterprise financial transaction ledger.

### 7. `GET /debug/headers`
Echoes back all received request headers. Useful for validating that the gateway successfully injected security context:
- `x-user-id`
- `x-user-role`
- `x-tenant-id`
- `x-request-id`
- `x-gateway-risk-score`
- `x-forwarded-for`

---

## ⚠️ Standard Error Responses

### `401 Unauthorized`
Returned when credentials are missing, signature is invalid, or the token has been revoked:
```json
{
  "detail": "Token has been revoked"
}
```
*Header: `WWW-Authenticate: Bearer error="invalid_token"`*

### `403 Forbidden`
Returned when cryptographic evasion (`alg: none`) or high-risk attacks (BOLA / fuzzing) are detected:
```json
{
  "detail": "High-risk API exploit detected: ['BOLA_IDOR_ATTACK']. Request terminated and token auto-revoked."
}
```

### `429 Too Many Requests`
Returned when sliding-window volumetric limit is exceeded:
```json
{
  "detail": "Rate limit quota exceeded. Try again in 45 seconds."
}
```
*Headers: `Retry-After: 45`, `X-RateLimit-Limit: 100`, `X-RateLimit-Remaining: 0`*
