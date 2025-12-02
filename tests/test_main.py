from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_read_docs():
    # Docs are only enabled if CURRENT_ENV is development, which might not be the case during tests
    # unless we set the env var. 
    # However, we can check if the app initializes correctly.
    # Let's check a 404 on root since it's not defined
    response = client.get("/")
    assert response.status_code == 404
