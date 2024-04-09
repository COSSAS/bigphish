from fastapi.testclient import TestClient
from utils import is_url

from .main import app

client = TestClient(app)


def test_is_url():
    assert is_url("https://tno.nl")
    assert is_url("hxxsp://tno.nl")
    assert is_url("https://tno.nl/path/to/folder.js")
    assert is_url("http://tno.nl/difficult.php?query=parameter")
    assert is_url("tno.hfghghghdghdgh") is False


def test_route_home():
    response = client.get("/api/v1/status")
    assert "BigPhish API" in response.json()

    response = client.post("/api/v1/status")
    assert response.status_code == 405

    response = client.post("/api/v1/")
    assert response.status_code == 404


def test_route_active_domains_urls():
    response = client.post("/api/v1/active_domains_urls")
    assert response.status_code != 200

    response = client.get(
        "/api/v1/active_domains_urls", headers={"X-API-KEY": "thisisthewrongkey"}
    )
    assert response.status_code == 401
