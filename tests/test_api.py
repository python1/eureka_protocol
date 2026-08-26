import pytest
from fastapi.testclient import TestClient

from eureka_protocol.src.eureka_daemon.api import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_manifest_shape(client):
    """
    The open manifest carries identity and nothing else.

    It stays open because first contact needs it -- a caller reads node_id
    here to address its handshake offer. What changed is that the capability
    list is no longer in it: that said what this node can be asked to do, and
    told it to anyone who could reach the port.
    """
    r = client.get("/v1/manifest")
    assert r.status_code == 200
    body = r.json()
    assert body["node_id"]
    assert body["runtime"]
    assert "capabilities" not in body


def test_peers_rejects_unauthenticated_get(client):
    """
    Reading the peer table is a POST carrying a signature. A GET is refused by
    the router, before any handler consults anything.
    """
    assert client.get("/v1/peers").status_code == 405


def test_logs_rejects_unauthenticated_get(client):
    assert client.get("/v1/logs").status_code == 405


def test_unknown_route_404(client):
    assert client.get("/v1/nope").status_code == 404
