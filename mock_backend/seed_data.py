from typing import Dict
from mock_backend.models import Order, User, Transaction

# Clean in-memory stores initialized empty - no pre-seeded or mock data
USERS_DB: Dict[str, User] = {}
ORDERS_DB: Dict[str, Order] = {}
TRANSACTIONS_DB: Dict[str, Transaction] = {}


def clear_stores():
    """Clears all in-memory database stores."""
    USERS_DB.clear()
    ORDERS_DB.clear()
    TRANSACTIONS_DB.clear()
