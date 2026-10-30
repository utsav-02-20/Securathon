import pytest
from fastapi.testclient import TestClient
from mock_backend.main import app


@pytest.fixture
def client():
    """
    Standard test client for the mock backend API.
    """
    with TestClient(app) as test_client:
        yield test_client
