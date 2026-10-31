# ⚔️ Attack Scenarios & Automated Mitigations

This document provides a detailed breakdown of all 7 multi-layer attack scenarios simulated and neutralized by the **Securathon Intelligent API Security Gateway**.

---

## 📊 Summary of Attack Vectors

| Scenario | Attack Type | Target Vulnerability | Gateway Defense Layer | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Scenario 1** | Normal Browsing | None (Benign User) | Baseline Telemetry Profiling | `ALLOW (HTTP 200)` |
| **Scenario 2** | Cryptographic Evasion | JWT Signature Bypass (`alg: none`) | Cryptographic Identity Guard | `BLOCK (HTTP 403)` |
| **Scenario 3** | Volumetric DDoS | Resource Exhaustion Flood | Atomic Sliding-Window Limiter | `DROP (HTTP 429)` |
| **Scenario 4** | OWASP #1 BOLA / IDOR | Horizontal Privilege Escalation | AI Detective (Sequentiality Tree) | `BLOCK (HTTP 403) + Auto-Revoke` |
| **Scenario 5** | Parameter Fuzzing / SQLi | Obfuscated Code Injection | Shannon Entropy $H(X)$ Analyzer | `BLOCK (HTTP 403)` |
| **Scenario 6** | Token Replay Attack | Stale / Expired Session Capture | Expiration & Claim Validator | `BLOCK (HTTP 401)` |
| **Scenario 7** | Zero-Trust Probe | Unauthenticated Reconnaissance | Zero-Trust Perimeter Guard | `BLOCK (HTTP 401)` |

---

## 🔍 Detailed Scenario Walkthroughs

### Scenario 1: Normal Human Browsing (Benign Baseline)

- **Actor**: Alice (`user_alice`, role: `customer`).
- **Behavior**:
  - Authenticates with valid JWT.
  - Views her own order (`GET /api/orders/1001`).
  - Refreshes her profile or orders list.
  - Request velocity is human-paced (1–3 req/sec).
- **Gateway Evaluation**:
  - Cryptographic signature: Valid.
  - Sliding-window quota: Well below 100 req/60s.
  - AI Detective Features: $S=0$, $\Delta_{ID}=0$, Entropy $H(X) \approx 3.0$, Unique ID ratio $\le 0.2$.
  - Calculated Risk Score: **0.37** (Safe baseline).
- **Action**: `ALLOW` $\to$ Gateway injects `X-User-ID: user_alice` and proxies to backend.
- **Result**: `HTTP 200 OK` (Average proxy latency $<5\text{ms}$).

---

### Scenario 2: Cryptographic Tampering: 'alg: none' Exploit

- **Actor**: External Attacker.
- **Vector**:
  - The attacker crafts a JWT payload asserting `"role": "admin"` and `"sub": "admin_root"`.
  - The signature component is removed.
  - The JWT header is explicitly set to:
    ```json
    {
      "alg": "none",
      "typ": "JWT"
    }
    ```
- **Gateway Evaluation**:
  - In [`core/security.py`](file:///home/dev/Desktop/Securathon/core/security.py), `verify_jwt_token()` inspects the raw unverified header prior to decoding.
  - The gateway detects `"alg": "none"` and refuses to parse claims without verification.
- **Action**: Immediate hard block.
- **Response**: `HTTP 403 Forbidden`
  ```json
  {
    "detail": "Cryptographic signature evasion ('alg: none') detected and blocked."
  }
  ```
- **Threat Tag**: `SIGNATURE_EVASION_ATTACK`.

---

### Scenario 3: Volumetric DDoS Burst (Redis Sliding Window)

- **Actor**: Botnet or DDoS Script.
- **Vector**:
  - Fires rapid burst of 150+ requests within 3 seconds to overwhelm compute resources.
- **Gateway Evaluation**:
  - In [`core/rate_limiter.py`](file:///home/dev/Desktop/Securathon/core/rate_limiter.py), the atomic Redis transaction pipeline executes `ZREMRANGEBYSCORE` and `ZCARD`.
  - At request #101 (for customer tier), count exceeds 100 in the rolling 60s window.
- **Action**: Request dropped before touching backend services or ML models.
- **Response**: `HTTP 429 Too Many Requests`
  ```json
  {
    "detail": "Rate limit quota exceeded. Try again in 58 seconds."
  }
  ```
- **Headers Returned**:
  - `Retry-After: 58`
  - `X-RateLimit-Limit: 100`
  - `X-RateLimit-Remaining: 0`
  - `X-RateLimit-Reset: 58000`

---

### Scenario 4: OWASP #1 BOLA / IDOR Behavioral Attack

- **Actor**: Eve (`attacker_eve`, role: `customer`).
- **Vector**:
  - Eve possesses a completely valid, signed token.
  - Stays strictly under volumetric rate limits (5–10 req/minute).
  - Traverses sequential order IDs:
    `GET /api/orders/1001` $\to$ `GET /api/orders/1002` $\to$ `GET /api/orders/1003`...
  - Attempts unauthorized data access on other tenants' data.
- **Gateway Evaluation**:
  - The token is valid, so Stage 2 passes.
  - The request count is low, so Stage 3 passes.
  - In Stage 4, `BehavioralAnomalyDetector` retrieves Eve's rolling history from Redis:
    - Sequentiality score reaches $S = 1.0$.
    - ID jump delta averages $\Delta_{ID} = 1.0$.
    - Unique ID ratio reaches $1.0$.
  - The Isolation Forest model outputs raw anomaly score $< -0.15$, calibrated to a **Risk Score of 0.99**.
- **Action (Two-Step Neutralization)**:
  1. **Immediate Block**: Request 3 is terminated with `HTTP 403 Forbidden`:
     ```json
     {
       "detail": "High-risk API exploit detected: ['BOLA_IDOR_ATTACK']. Request terminated and token auto-revoked."
     }
     ```
  2. **Automated Auto-Revocation**: Eve's active `jti` is immediately written to the Redis blacklist.
  3. **Re-attempt Prevention**: When Eve attempts request 4, the Guard at Stage 2 immediately rejects it with `HTTP 401 Unauthorized` (`Token has been revoked`), completely neutralizing the session.

---

### Scenario 5: High-Entropy Parameter Fuzzing & SQL Injection

- **Actor**: Automated Web Vulnerability Scanner / Attacker.
- **Vector**:
  - Attacker probes query parameters with obfuscated SQLi and fuzzing strings:
    ```
    /api/orders?search=%27%20UNION%20SELECT%20schema_name,2,3%20FROM%20information_schema.schemata%20WHERE%201=1--%20a9f8e7d6c5b4
    ```
- **Gateway Evaluation**:
  - `features.calculate_shannon_entropy()` evaluates the character distribution:
    $$H(X) = - \sum p \log_2(p) \ge 4.8$$
  - High entropy flag triggers alongside payload anomaly detection in the Isolation Forest model.
  - Combined Risk Score: **0.85**.
- **Action**: Request blocked with `HTTP 403 Forbidden`.
- **Threat Tag**: `PARAM_FUZZING_ATTACK`.

---

### Scenario 6: Stale Session & Expired Token Replay Attack

- **Actor**: Attacker who intercepted an expired token from logs or network capture.
- **Vector**:
  - Replays expired JWT against protected endpoints (`GET /api/orders`).
- **Gateway Evaluation**:
  - `verify_jwt_token()` detects `jwt.ExpiredSignatureError`.
- **Action**: Immediate edge rejection.
- **Response**: `HTTP 401 Unauthorized` with standard RFC challenge header:
  `WWW-Authenticate: Bearer error="invalid_token", error_description="The token has expired"`

---

### Scenario 7: Zero-Trust Perimeter Unauthenticated Probe

- **Actor**: Internet Web Crawler / Unauthorized Bot.
- **Vector**:
  - Unauthenticated GET probe to internal protected routes:
    `GET /api/orders/1001` with no `Authorization` header.
- **Gateway Evaluation**:
  - `get_authenticated_claims` dependency intercepts request.
- **Action**: Edge rejection.
- **Response**: `HTTP 401 Unauthorized` with `detail="Missing or malformed Authorization header"`.
