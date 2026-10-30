from typing import Dict, List
from mock_backend.models import Order, OrderItem, User, Transaction

# Pre-populated in-memory database of multi-tenant enterprise data

USERS_DB: Dict[str, User] = {
    "user_101": User(
        id="user_101",
        tenant_id="tenant_alpha",
        username="alice",
        email="alice@alpha-corp.com",
        full_name="Alice Smith",
        role="customer",
        is_active=True,
        created_at="2026-01-15T09:00:00Z"
    ),
    "user_102": User(
        id="user_102",
        tenant_id="tenant_beta",
        username="bob",
        email="bob@beta-logistics.com",
        full_name="Bob Jones",
        role="customer",
        is_active=True,
        created_at="2026-02-10T11:30:00Z"
    ),
    "user_103": User(
        id="user_103",
        tenant_id="tenant_alpha",
        username="charlie",
        email="charlie@alpha-corp.com",
        full_name="Charlie Brown",
        role="merchant",
        is_active=True,
        created_at="2026-02-20T14:15:00Z"
    ),
    "user_104": User(
        id="user_104",
        tenant_id="tenant_gamma",
        username="eve_attacker",
        email="eve@attacker-domain.org",
        full_name="Eve Mallory",
        role="customer",
        is_active=True,
        created_at="2026-03-01T08:00:00Z"
    ),
    "user_999": User(
        id="user_999",
        tenant_id="system",
        username="sys_admin",
        email="admin@securathon-internal.io",
        full_name="System Administrator",
        role="admin",
        is_active=True,
        created_at="2025-12-01T00:00:00Z"
    )
}

ORDERS_DB: Dict[str, Order] = {
    "1001": Order(
        id="1001",
        user_id="user_101",
        tenant_id="tenant_alpha",
        items=[
            OrderItem(product_id="prod_901", name="Enterprise Firewall Appliance", quantity=1, unit_price=1250.00),
            OrderItem(product_id="prod_902", name="Cat6e Patch Cable 10m", quantity=4, unit_price=15.00)
        ],
        total_amount=1310.00,
        currency="USD",
        status="COMPLETED",
        shipping_address="100 Technology Way, Silicon Valley, CA",
        created_at="2026-03-01T10:00:00Z"
    ),
    "1002": Order(
        id="1002",
        user_id="user_101",
        tenant_id="tenant_alpha",
        items=[
            OrderItem(product_id="prod_903", name="Hardware Security Key (FIDO2)", quantity=5, unit_price=45.00)
        ],
        total_amount=225.00,
        currency="USD",
        status="COMPLETED",
        shipping_address="100 Technology Way, Silicon Valley, CA",
        created_at="2026-03-02T11:20:00Z"
    ),
    "1003": Order(
        id="1003",
        user_id="user_102",
        tenant_id="tenant_beta",
        items=[
            OrderItem(product_id="prod_888", name="Fleet GPS Tracking Module", quantity=10, unit_price=120.00)
        ],
        total_amount=1200.00,
        currency="USD",
        status="PROCESSING",
        shipping_address="45 Industrial Blvd, Austin, TX",
        created_at="2026-03-03T14:40:00Z"
    ),
    "1004": Order(
        id="1004",
        user_id="user_103",
        tenant_id="tenant_alpha",
        items=[
            OrderItem(product_id="prod_777", name="Point-of-Sale Terminal", quantity=2, unit_price=350.00)
        ],
        total_amount=700.00,
        currency="USD",
        status="COMPLETED",
        shipping_address="77 Market Plaza, Seattle, WA",
        created_at="2026-03-04T09:15:00Z"
    ),
    "1005": Order(
        id="1005",
        user_id="user_102",
        tenant_id="tenant_beta",
        items=[
            OrderItem(product_id="prod_889", name="Rugged Barcode Scanner", quantity=3, unit_price=220.00)
        ],
        total_amount=660.00,
        currency="USD",
        status="SHIPPED",
        shipping_address="45 Industrial Blvd, Austin, TX",
        created_at="2026-03-05T16:00:00Z"
    ),
    "1006": Order(
        id="1006",
        user_id="user_101",
        tenant_id="tenant_alpha",
        items=[
            OrderItem(product_id="prod_904", name="27-inch 4K Developer Monitor", quantity=2, unit_price=450.00)
        ],
        total_amount=900.00,
        currency="USD",
        status="COMPLETED",
        shipping_address="100 Technology Way, Silicon Valley, CA",
        created_at="2026-03-06T12:00:00Z"
    ),
    "1007": Order(
        id="1007",
        user_id="user_104",
        tenant_id="tenant_gamma",
        items=[
            OrderItem(product_id="prod_111", name="Basic USB Drive 32GB", quantity=1, unit_price=12.00)
        ],
        total_amount=12.00,
        currency="USD",
        status="COMPLETED",
        shipping_address="99 Shadow Way, Reno, NV",
        created_at="2026-03-07T18:00:00Z"
    ),
    "1008": Order(
        id="1008",
        user_id="user_102",
        tenant_id="tenant_beta",
        items=[
            OrderItem(product_id="prod_890", name="Thermal Shipping Label Roll", quantity=20, unit_price=8.50)
        ],
        total_amount=170.00,
        currency="USD",
        status="DELIVERED",
        shipping_address="45 Industrial Blvd, Austin, TX",
        created_at="2026-03-08T08:30:00Z"
    ),
    "1009": Order(
        id="1009",
        user_id="user_103",
        tenant_id="tenant_alpha",
        items=[
            OrderItem(product_id="prod_778", name="Receipt Paper 50-Pack", quantity=5, unit_price=24.00)
        ],
        total_amount=120.00,
        currency="USD",
        status="COMPLETED",
        shipping_address="77 Market Plaza, Seattle, WA",
        created_at="2026-03-09T13:45:00Z"
    ),
    "1010": Order(
        id="1010",
        user_id="user_101",
        tenant_id="tenant_alpha",
        items=[
            OrderItem(product_id="prod_905", name="Server Rack Rail Kit 2U", quantity=2, unit_price=75.00)
        ],
        total_amount=150.00,
        currency="USD",
        status="COMPLETED",
        shipping_address="100 Technology Way, Silicon Valley, CA",
        created_at="2026-03-10T15:20:00Z"
    )
}

TRANSACTIONS_DB: Dict[str, Transaction] = {
    "txn_5001": Transaction(
        id="txn_5001",
        user_id="user_101",
        order_id="1001",
        amount=1310.00,
        currency="USD",
        status="SUCCESS",
        payment_method="CORPORATE_CARD",
        timestamp="2026-03-01T10:01:00Z"
    ),
    "txn_5002": Transaction(
        id="txn_5002",
        user_id="user_101",
        order_id="1002",
        amount=225.00,
        currency="USD",
        status="SUCCESS",
        payment_method="CORPORATE_CARD",
        timestamp="2026-03-02T11:21:00Z"
    ),
    "txn_5003": Transaction(
        id="txn_5003",
        user_id="user_102",
        order_id="1003",
        amount=1200.00,
        currency="USD",
        status="SUCCESS",
        payment_method="ACH_TRANSFER",
        timestamp="2026-03-03T14:41:00Z"
    ),
    "txn_5004": Transaction(
        id="txn_5004",
        user_id="user_103",
        order_id="1004",
        amount=700.00,
        currency="USD",
        status="SUCCESS",
        payment_method="CREDIT_CARD",
        timestamp="2026-03-04T09:16:00Z"
    ),
    "txn_5005": Transaction(
        id="txn_5005",
        user_id="user_104",
        order_id="1007",
        amount=12.00,
        currency="USD",
        status="SUCCESS",
        payment_method="DEBIT_CARD",
        timestamp="2026-03-07T18:01:00Z"
    )
}

