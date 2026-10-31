"""
Browser access is an exact-origin allowlist, off by default, and grants nothing.
"""
import pytest
from fastapi.testclient import TestClient

from eureka_protocol.src.eureka_daemon import cors
from eureka_protocol.src.eureka_daemon.api import create_app
from eureka_protocol.src.eureka_daemon.crypto import EurekaCrypto
from eureka_protocol.src.eureka_daemon.node import EurekaNode
from eureka_protocol.src.eureka_daemon.server import parse_arguments
from eureka_protocol.src.eureka_daemon.trust import TrustList

ROOM = "https://knights-circle.vercel.app"


def app_with(origins):
    crypto = EurekaCrypto()
    node = EurekaNode(crypto.derive_node_id(), crypto, trust_list=TrustList(), capabilities=[])
    app = create_app(node)
    cors.install(app, origins)
    return TestClient(app)


def preflight(client, origin):
    return client.options("/v1/handshake/offer", headers={
        "Origin": origin, "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type"})


def test_without_origins_no_page_may_read_replies():
    client = app_with([])
    response = client.get("/v1/manifest", headers={"Origin": ROOM})
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_a_listed_origin_may_read_replies_and_preflight_succeeds():
    client = app_with([ROOM])
    assert client.get("/v1/manifest", headers={"Origin": ROOM}).headers["access-control-allow-origin"] == ROOM
    response = preflight(client, ROOM)
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == ROOM
    assert "POST" in response.headers["access-control-allow-methods"]
    assert "access-control-allow-credentials" not in response.headers


def test_any_other_origin_gets_nothing():
    client = app_with([ROOM])
    for origin in ("https://evil.example", "https://knights-circle.vercel.app.evil.example",
                   "http://knights-circle.vercel.app", "https://preview-knights-circle.vercel.app"):
        assert "access-control-allow-origin" not in client.get("/v1/manifest", headers={"Origin": origin}).headers
        assert "access-control-allow-origin" not in preflight(client, origin).headers


def test_cors_grants_nothing_a_listed_page_is_still_refused_without_a_handshake():
    client = app_with([ROOM])
    response = client.post("/v1/peers", headers={"Origin": ROOM}, json={"query": {}})
    assert response.headers["access-control-allow-origin"] == ROOM
    assert response.json()["event"] == "read_rejected"


def test_origins_must_be_exact():
    assert cors.normalise_origin("https://Knights-Circle.vercel.app/") == ROOM
    assert cors.normalise_origin("https://example.com:443") == "https://example.com"
    assert cors.normalise_origin("http://127.0.0.1:4173") == "http://127.0.0.1:4173"
    assert cors.normalise_origin("http://localhost:4173") == "http://localhost:4173"
    for bad in ("*", "https://*.vercel.app", "https://example.com/path", "example.com",
                "http://example.com", "http://192.168.1.5:4173", "ftp://example.com", "",
                "https://user@example.com", "https://example.com/?q=1"):
        with pytest.raises(ValueError):
            cors.normalise_origin(bad)


def test_origins_come_from_the_command_line_and_the_environment():
    assert cors.origins_from([ROOM], {cors.ORIGINS_ENV: "http://127.0.0.1:4173, " + ROOM}) == (
        ROOM, "http://127.0.0.1:4173")
    assert parse_arguments([]).cors_origins == ()
    assert parse_arguments(["--cors-origin", ROOM]).cors_origins == (ROOM,)
    with pytest.raises(SystemExit):
        parse_arguments(["--cors-origin", "https://*.vercel.app"])
