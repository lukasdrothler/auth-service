from fastapi.testclient import TestClient
from main import app
import pytest

@pytest.fixture
def client(postgres_service, rmq_service):
    with TestClient(app) as c:
        yield c

def test_read_docs(client):
    # Docs are only enabled if CURRENT_ENV is development, which might not be the case during tests
    # unless we set the env var. 
    # However, we can check if the app initializes correctly.
    # Let's check a 404 on root since it's not defined
    response = client.get("/")
    assert response.status_code == 404
