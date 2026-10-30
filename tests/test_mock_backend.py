from fastapi.testclient import TestClient


def test_health_check(client: TestClient):
    """Verify mock microservice health endpoint returns 200 and healthy status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "mock-microservice"
    assert "timestamp" in data


def test_list_orders(client: TestClient):
    """Verify listing seed orders returns successful response with items."""
    response = client.get("/api/v1/orders")
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert len(payload["data"]) >= 5
    
    # Filter by user_id
    response_filtered = client.get("/api/v1/orders?user_id=user_101")
    assert response_filtered.status_code == 200
    filtered_payload = response_filtered.json()
    assert all(o["user_id"] == "user_101" for o in filtered_payload["data"])


def test_get_order_by_id_success(client: TestClient):
    """Verify retrieving existing order by ID."""
    response = client.get("/api/v1/orders/1001")
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    order = payload["data"]
    assert order["id"] == "1001"
    assert order["user_id"] == "user_101"
    assert order["total_amount"] == 1310.00
    assert len(order["items"]) == 2


def test_get_order_by_id_not_found(client: TestClient):
    """Verify 404 when querying an order that does not exist."""
    response = client.get("/api/v1/orders/999999")
    assert response.status_code == 404
    payload = response.json()
    assert "detail" in payload
    assert "999999" in payload["detail"]


def test_create_order(client: TestClient):
    """Verify creating a new order returns 201 Created."""
    order_data = {
        "items": [
            {
                "product_id": "prod_100",
                "name": "YubiKey 5C NFC",
                "quantity": 2,
                "unit_price": 55.00
            }
        ],
        "shipping_address": "123 Cyber Sec Way, Tech City"
    }
    headers = {"X-User-ID": "user_102"}
    response = client.post("/api/v1/orders", json=order_data, headers=headers)
    assert response.status_code == 201
    payload = response.json()
    assert payload["success"] is True
    created = payload["data"]
    assert created["user_id"] == "user_102"
    assert created["total_amount"] == 110.00
    assert created["status"] == "PENDING"


def test_get_user_profile(client: TestClient):
    """Verify retrieving user profile."""
    response = client.get("/api/v1/users/user_101")
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    user = payload["data"]
    assert user["username"] == "alice"
    assert user["email"] == "alice@alpha-corp.com"
    assert user["tenant_id"] == "tenant_alpha"


def test_get_user_not_found(client: TestClient):
    """Verify 404 when querying an invalid user."""
    response = client.get("/api/v1/users/user_unknown_999")
    assert response.status_code == 404


def test_list_transactions(client: TestClient):
    """Verify retrieving financial transactions."""
    response = client.get("/api/v1/transactions")
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert len(payload["data"]) > 0


def test_debug_headers_gateway_context(client: TestClient):
    """Verify mock microservice captures injected context headers from the gateway."""
    custom_headers = {
        "X-User-ID": "user_101",
        "X-User-Role": "admin",
        "X-Tenant-ID": "tenant_alpha",
        "X-Request-ID": "req-uuid-test-12345",
        "X-Gateway-Risk-Score": "0.12"
    }
    response = client.get("/api/v1/debug/headers", headers=custom_headers)
    assert response.status_code == 200
    payload = response.json()
    context = payload["gateway_context"]
    assert context["x_user_id"] == "user_101"
    assert context["x_user_role"] == "admin"
    assert context["x_tenant_id"] == "tenant_alpha"
    assert context["x_request_id"] == "req-uuid-test-12345"
    assert context["x_gateway_risk_score"] == "0.12"
