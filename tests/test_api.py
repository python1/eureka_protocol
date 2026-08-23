import pytest
from fastapi.testclient import TestClient

from eureka_protocol.src.eureka_daemon.api import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_manifest_shape(client):
    r = client.get("/v1/manifest")
    assert r.status_code == 200
    body = r.json()
    assert body["node_id"]
    assert isinstance(body["capabilities"], list)
    assert body["runtime"]


def test_peers_returns_list(client):
    r = client.get("/v1/peers")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_logs_reachable(client):
    r = client.get("/v1/logs")
    assert r.status_code == 200


def test_unknown_route_404(client):
    assert client.get("/v1/nope").status_code == 404
