"""
The mutual handshake over HTTP.

Over a socket there is no EurekaNode on the other end -- only JSON in and JSON
out. These tests drive the real ASGI app: the three messages cross the
transport, the bodies are untrusted, and every signature must still verify on
the far side of a JSON round trip.
"""
import asyncio
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from eureka_protocol.src.eureka_daemon import api
from eureka_protocol.src.eureka_daemon.api import MAX_REQUEST_BODY_BYTES, app
from eureka_protocol.src.eureka_daemon.client import (
    CONFIRM_PATH,
    OFFER_PATH,
    fetch_peer_id,
    handshake_over_http,
)
from eureka_protocol.src.eureka_daemon.crypto import (
    EurekaCrypto,
    canonical_json_bytes,
)
from eureka_protocol.src.eureka_daemon.node import (
    EurekaNode,
    REASON_BAD_SIGNATURE,
    REASON_MALFORMED,
    REASON_REPLAYED_NONCE,
    REASON_STALE,
    REASON_UNKNOWN_NONCE,
    REASON_UNTRUSTED_KEY,
    REASON_WRONG_PEER,
)
from eureka_protocol.src.eureka_daemon.trust import TrustList

STATE_TABLES = ("peers", "pending_challenges", "seen_nonces", "pending_peers")


@pytest.fixture
def daemon():
    """
    The module-level node behind the app, with its state isolated per test.

    api.node_engine is a singleton created at import, so each test clears its
    tables and allowlist on the way in and restores them on the way out.
    """
    node = api.node_engine
    saved = {name: dict(getattr(node, name)) for name in STATE_TABLES}
    saved_trust = node.trust_list

    for name in STATE_TABLES:
        getattr(node, name).clear()
    node.trust_list = TrustList()

    yield node

    for name, contents in saved.items():
        table = getattr(node, name)
        table.clear()
        table.update(contents)
    node.trust_list = saved_trust


@pytest.fixture
def client():
    # No context manager: the startup hook is irrelevant to these routes, and
    # this keeps the deprecated on_event path out of the way entirely.
    return TestClient(app)


def make_node(node_id):
    return EurekaNode(
        node_id=node_id,
        crypto_engine=EurekaCrypto(),
        capabilities=["code-exec"],
    )


def link(initiator, daemon_node):
    """Mutual trust between a local initiator and the daemon's node."""
    daemon_node.trust_list.add(initiator.node_id, initiator.public_key_hex)
    initiator.trust_list.add(daemon_node.node_id, daemon_node.public_key_hex)
    return initiator


@pytest.fixture
def initiator(daemon):
    return link(make_node("node_http_initiator"), daemon)


def authenticated_peers(node):
    return {
        pid for pid, info in node.peers.items()
        if info.get("status") == "authenticated"
    }


def post_offer(client, offer):
    return client.post(OFFER_PATH, json=offer)


def post_confirm(client, confirmation):
    return client.post(CONFIRM_PATH, json=confirmation)


def drive_http(client, initiator, daemon):
    """Run the three messages across the transport, returning everything."""
    offer = initiator.create_handshake_offer(daemon.node_id)
    reply = post_offer(client, offer)
    message_two = reply.json()
    if message_two.get("authenticated") is False:
        return offer, message_two, None, message_two, message_two
    mine = asyncio.run(initiator.complete_handshake(message_two))
    confirmation = initiator.confirm_handshake(message_two)
    theirs = post_confirm(client, confirmation).json()
    return offer, message_two, confirmation, mine, theirs


# ---------------------------------------------------------------------------
# Full round trip
# ---------------------------------------------------------------------------

def test_full_handshake_over_http_authenticates_both_sides(client, initiator, daemon):
    offer, message_two, confirmation, mine, theirs = drive_http(
        client, initiator, daemon
    )

    assert mine["authenticated"] is True
    assert theirs["authenticated"] is True

    # Both directions recorded, across the socket.
    assert daemon.node_id in authenticated_peers(initiator)
    assert initiator.node_id in authenticated_peers(daemon)

    assert initiator.peers[daemon.node_id]["public_key"] == daemon.public_key_hex
    assert daemon.peers[initiator.node_id]["public_key"] == initiator.public_key_hex


def test_endpoints_return_200_for_a_completed_exchange(client, initiator, daemon):
    offer = initiator.create_handshake_offer(daemon.node_id)
    reply = post_offer(client, offer)
    assert reply.status_code == 200

    message_two = reply.json()
    asyncio.run(initiator.complete_handshake(message_two))
    confirm = post_confirm(client, initiator.confirm_handshake(message_two))
    assert confirm.status_code == 200


def test_authentication_failure_is_still_200(client, daemon):
    """A rejection is a completed exchange, not a transport error."""
    stranger = make_node("node_stranger")  # daemon trusts nobody

    reply = post_offer(client, stranger.create_handshake_offer(daemon.node_id))

    assert reply.status_code == 200
    assert reply.json()["reason"] == REASON_UNTRUSTED_KEY
    assert daemon.peers == {}


def test_client_function_drives_all_three_messages(daemon):
    """The client returns the same shape as the in-process driver."""
    initiator = link(make_node("node_client_initiator"), daemon)

    async def go():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport,
                                     base_url="http://daemon") as http:
            return await handshake_over_http(initiator, http=http)

    result = asyncio.run(go())

    assert result["authenticated"] is True
    assert result["mutual"] is True
    assert result["event"] == "handshake_established"
    assert daemon.node_id in authenticated_peers(initiator)
    assert initiator.node_id in authenticated_peers(daemon)


def test_client_discovers_peer_id_from_the_manifest(daemon):
    initiator = link(make_node("node_manifest_initiator"), daemon)

    async def go():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport,
                                     base_url="http://daemon") as http:
            discovered = await fetch_peer_id(http)
            result = await handshake_over_http(initiator, http=http)
            return discovered, result

    discovered, result = asyncio.run(go())

    assert discovered == daemon.node_id
    assert result["authenticated"] is True


def test_client_reports_an_untrusted_rejection(daemon):
    """No trust either way: the client surfaces the peer's reason."""
    initiator = make_node("node_untrusted_initiator")

    async def go():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport,
                                     base_url="http://daemon") as http:
            return await handshake_over_http(initiator, peer_id=daemon.node_id,
                                             http=http)

    result = asyncio.run(go())

    assert result["authenticated"] is False
    assert result["reason"] == REASON_UNTRUSTED_KEY
    assert initiator.peers == {}
    assert daemon.peers == {}


# ---------------------------------------------------------------------------
# Requirement (f): the bytes must survive the transport
# ---------------------------------------------------------------------------

def test_signed_payload_is_byte_identical_after_an_http_round_trip(
    client, initiator, daemon
):
    """
    If JSON round-tripping changed the bytes, every signature would break.
    Compare the canonical encoding on both sides of the socket.
    """
    offer = initiator.create_handshake_offer(daemon.node_id)
    before = canonical_json_bytes(offer["challenge"])

    message_two = post_offer(client, offer).json()
    after = canonical_json_bytes(message_two["challenge"])

    assert after == before
    assert message_two["challenge"] == offer["challenge"]


def test_in_process_signature_verifies_after_an_http_round_trip(
    client, initiator, daemon
):
    offer = initiator.create_handshake_offer(daemon.node_id)
    message_two = post_offer(client, offer).json()

    # The initiator's message-1 signature, made locally, still verifies against
    # the challenge as it came back over the wire.
    assert EurekaCrypto.verify_handshake_offer(
        offer["public_key"], offer["signature"], message_two["challenge"]
    ) is True

    # And the daemon's message-2 signature, made on the far side, verifies here.
    assert EurekaCrypto.verify_handshake(
        message_two["public_key"], message_two["signature"],
        message_two["challenge"],
    ) is True

    # The counter-challenge survives too -- message 3 is signed over it.
    counter = message_two["counter_challenge"]
    assert canonical_json_bytes(counter) == canonical_json_bytes(
        json.loads(json.dumps(counter))
    )


def test_confirm_signature_made_locally_verifies_on_the_daemon(
    client, initiator, daemon
):
    offer = initiator.create_handshake_offer(daemon.node_id)
    message_two = post_offer(client, offer).json()
    asyncio.run(initiator.complete_handshake(message_two))

    confirmation = initiator.confirm_handshake(message_two)
    # Signed in-process, verified on the far side of the transport.
    assert post_confirm(client, confirmation).json()["authenticated"] is True


# ---------------------------------------------------------------------------
# Untrusted bodies: never a 500, never a traceback
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [OFFER_PATH, CONFIRM_PATH])
@pytest.mark.parametrize("body", [
    b"{ this is not json",
    b"",
    b"\xff\xfe\x00broken",
    b"{'single': 'quotes'}",
    b"{\"unterminated\": ",
])
def test_malformed_json_returns_400_not_500(client, daemon, path, body):
    response = client.post(path, content=body)

    assert response.status_code == 400
    assert response.json()["reason"] == REASON_MALFORMED
    assert response.json()["authenticated"] is False
    # No traceback leaked to the caller.
    assert "Traceback" not in response.text


@pytest.mark.parametrize("path", [OFFER_PATH, CONFIRM_PATH])
@pytest.mark.parametrize("document", [
    [],
    "a string",
    42,
    {"event": "handshake_offer"},                       # missing everything
    {"challenge": "not a mapping"},
    {"challenge": {"nonce": 1234}},                     # wrong types
    {"challenge": None, "signature": None, "public_key": None},
    {"challenge": {}, "signature": [], "public_key": {}},
])
def test_wrong_shape_returns_a_reason_not_500(client, daemon, path, document):
    response = client.post(path, json=document)

    assert response.status_code == 200
    body = response.json()
    assert body["authenticated"] is False
    assert body["reason"] in {
        REASON_MALFORMED, REASON_UNKNOWN_NONCE, REASON_UNTRUSTED_KEY,
    }
    assert "Traceback" not in response.text


def test_an_unexpected_protocol_error_is_not_a_500(client, daemon, monkeypatch):
    """
    The last-resort guard. No real input reaches it, so it is forced here:
    a crash inside the protocol must still leave the endpoint returning a
    structured rejection with no traceback in the body.
    """
    def boom(_document):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(daemon, "answer_handshake_offer", boom)

    response = client.post(OFFER_PATH, json={"anything": True})

    assert response.status_code == 200
    assert response.json()["authenticated"] is False
    assert response.json()["reason"] == REASON_MALFORMED
    assert "secret internal detail" not in response.text
    assert "Traceback" not in response.text


def test_an_unexpected_confirm_error_is_not_a_500(client, daemon, monkeypatch):
    async def boom(_document):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(daemon, "complete_mutual_handshake", boom)

    response = client.post(CONFIRM_PATH, json={"anything": True})

    assert response.status_code == 200
    assert response.json()["authenticated"] is False
    assert "secret internal detail" not in response.text


@pytest.mark.parametrize("path", [OFFER_PATH, CONFIRM_PATH])
def test_json_null_body_is_a_reason_not_500(client, daemon, path):
    """
    Literal JSON null: well-formed JSON, but not a message.

    Sent as raw content because httpx reads json=None as "send no body at
    all", which is the empty-body case covered above instead.
    """
    response = client.post(path, content=b"null")

    assert response.status_code == 200
    assert response.json()["reason"] == REASON_MALFORMED


@pytest.mark.parametrize("path", [OFFER_PATH, CONFIRM_PATH])
def test_oversized_body_is_refused(client, daemon, path):
    payload = json.dumps({"pad": "x" * (MAX_REQUEST_BODY_BYTES + 1024)})
    assert len(payload) > MAX_REQUEST_BODY_BYTES

    response = client.post(path, content=payload)

    assert response.status_code == 413
    assert response.json()["reason"] == REASON_MALFORMED


def test_oversized_body_is_refused_before_parsing(client, daemon):
    """
    The body is both oversized and invalid JSON. Parsing first would report
    400; the 413 shows the size cap ran before anything tried to parse.
    """
    body = b"{ not valid json " + b"x" * (MAX_REQUEST_BODY_BYTES + 1024)

    response = client.post(OFFER_PATH, content=body)

    assert response.status_code == 413
    assert response.json()["reason"] == REASON_MALFORMED


@pytest.mark.parametrize("path", [OFFER_PATH, CONFIRM_PATH])
def test_oversized_chunked_body_is_refused(client, daemon, path):
    """
    A streamed body declares no Content-Length, so the header check cannot
    see it coming. The cap has to hold while the stream is being read, or a
    peer could sidestep it just by using chunked transfer-encoding.
    """
    def chunks():
        for _ in range((MAX_REQUEST_BODY_BYTES // 1024) + 8):
            yield b"x" * 1024

    response = client.post(path, content=chunks())

    assert response.status_code == 413
    assert response.json()["reason"] == REASON_MALFORMED


def test_small_chunked_body_is_still_processed(client, daemon):
    """The streaming path is not simply refusing everything."""
    response = client.post(OFFER_PATH, content=iter([b'{"event": "x"}']))

    assert response.status_code == 200
    assert response.json()["reason"] == REASON_MALFORMED


def test_a_body_at_the_limit_is_still_processed(client, daemon):
    """The cap refuses oversize, not everything large."""
    padding = "x" * (MAX_REQUEST_BODY_BYTES // 2)
    response = client.post(OFFER_PATH, json={"pad": padding})

    assert response.status_code == 200
    assert response.json()["reason"] == REASON_MALFORMED


def test_lying_content_length_is_refused(client, daemon):
    response = client.post(
        OFFER_PATH,
        content=b"{}",
        headers={"content-length": str(MAX_REQUEST_BODY_BYTES + 1)},
    )

    assert response.status_code in {400, 413}
    assert response.json()["authenticated"] is False


def test_unparseable_content_length_is_refused(client, daemon):
    response = client.post(
        OFFER_PATH, content=b"{}", headers={"content-length": "not-a-number"}
    )

    assert response.status_code in {400, 413}


# ---------------------------------------------------------------------------
# The in-process rejection scenarios, now over HTTP
# ---------------------------------------------------------------------------

def test_http_rejects_an_untrusted_initiator(client, daemon):
    stranger = make_node("node_stranger")
    stranger.trust_list.add(daemon.node_id, daemon.public_key_hex)

    body = post_offer(client, stranger.create_handshake_offer(daemon.node_id)).json()

    assert body["authenticated"] is False
    assert body["reason"] == REASON_UNTRUSTED_KEY
    assert "counter_challenge" not in body
    assert daemon.pending_peers == {}


def test_http_rejects_a_tampered_offer(client, initiator, daemon):
    offer = initiator.create_handshake_offer(daemon.node_id)
    offer["challenge"]["initiator_id"] = "node_attacker"

    body = post_offer(client, offer).json()

    assert body["reason"] == REASON_BAD_SIGNATURE


def test_http_rejects_a_replayed_offer(client, initiator, daemon):
    offer = initiator.create_handshake_offer(daemon.node_id)

    assert post_offer(client, offer).json()["event"] == "handshake_response"
    replayed = post_offer(client, offer).json()

    assert replayed["reason"] == REASON_REPLAYED_NONCE


def test_http_rejects_a_stale_offer(client, initiator, daemon):
    from datetime import datetime, timedelta, timezone

    challenge = initiator.create_challenge(daemon.node_id)
    challenge["timestamp"] = (
        datetime.now(timezone.utc) - timedelta(seconds=300)
    ).isoformat()
    offer = {
        "event": "handshake_offer",
        "initiator_id": initiator.node_id,
        "challenge": challenge,
        "public_key": initiator.public_key_hex,
        "signature": initiator.crypto.sign_handshake_offer(challenge),
    }

    assert post_offer(client, offer).json()["reason"] == REASON_STALE


def test_http_rejects_a_mismatched_initiator_id(client, initiator, daemon):
    offer = initiator.create_handshake_offer(daemon.node_id)
    offer["initiator_id"] = "node_somebody_else"

    assert post_offer(client, offer).json()["reason"] == REASON_WRONG_PEER


@pytest.mark.parametrize("bad_signature", ["!!!!", "abc", "", "@@@@"])
def test_http_rejects_malformed_signatures(client, initiator, daemon, bad_signature):
    offer = initiator.create_handshake_offer(daemon.node_id)
    offer["signature"] = bad_signature

    assert post_offer(client, offer).json()["reason"] == REASON_BAD_SIGNATURE


def test_http_rejects_an_unknown_confirmation(client, initiator, daemon):
    """A confirmation for a challenge the daemon never issued."""
    rogue = make_node("node_rogue")
    counter = rogue.create_challenge(initiator.node_id)
    confirmation = initiator.confirm_handshake({"counter_challenge": counter})

    assert post_confirm(client, confirmation).json()["reason"] == REASON_UNKNOWN_NONCE


def test_http_rejects_a_replayed_confirmation(client, initiator, daemon):
    offer = initiator.create_handshake_offer(daemon.node_id)
    message_two = post_offer(client, offer).json()
    asyncio.run(initiator.complete_handshake(message_two))
    confirmation = initiator.confirm_handshake(message_two)

    assert post_confirm(client, confirmation).json()["authenticated"] is True
    replayed = post_confirm(client, confirmation).json()

    assert replayed["reason"] == REASON_REPLAYED_NONCE


def test_http_rejects_a_tampered_confirmation(client, initiator, daemon):
    offer = initiator.create_handshake_offer(daemon.node_id)
    message_two = post_offer(client, offer).json()
    confirmation = initiator.confirm_handshake(message_two)
    confirmation["challenge"]["initiator_id"] = "node_attacker"

    body = post_confirm(client, confirmation).json()

    assert body["reason"] == REASON_BAD_SIGNATURE
    assert daemon.peers == {}


def test_http_abandoning_after_message_two_leaves_no_authenticated_peer(
    client, initiator, daemon
):
    offer = initiator.create_handshake_offer(daemon.node_id)
    message_two = post_offer(client, offer).json()
    mine = asyncio.run(initiator.complete_handshake(message_two))

    assert mine["authenticated"] is True
    assert daemon.peers == {}
    assert len(daemon.pending_peers) == 1


# ---------------------------------------------------------------------------
# Two initiators at once
# ---------------------------------------------------------------------------

def test_interleaved_handshakes_do_not_interfere(client, daemon):
    """Two initiators, messages interleaved against one daemon."""
    alice = link(make_node("node_alice"), daemon)
    bob = link(make_node("node_bob"), daemon)

    offer_a = alice.create_handshake_offer(daemon.node_id)
    offer_b = bob.create_handshake_offer(daemon.node_id)

    two_a = post_offer(client, offer_a).json()
    two_b = post_offer(client, offer_b).json()

    # Each got its own counter-challenge.
    assert two_a["counter_challenge"]["nonce"] != two_b["counter_challenge"]["nonce"]

    assert asyncio.run(alice.complete_handshake(two_a))["authenticated"] is True
    assert asyncio.run(bob.complete_handshake(two_b))["authenticated"] is True

    # Confirm out of order.
    confirm_b = post_confirm(client, bob.confirm_handshake(two_b)).json()
    confirm_a = post_confirm(client, alice.confirm_handshake(two_a)).json()

    assert confirm_a["authenticated"] is True
    assert confirm_b["authenticated"] is True
    assert confirm_a["peer_id"] == alice.node_id
    assert confirm_b["peer_id"] == bob.node_id

    assert authenticated_peers(daemon) == {alice.node_id, bob.node_id}


def test_one_initiator_cannot_answer_anothers_challenge(client, daemon):
    """Bob must not be able to complete the exchange Alice started."""
    alice = link(make_node("node_alice"), daemon)
    bob = link(make_node("node_bob"), daemon)

    two_a = post_offer(client, alice.create_handshake_offer(daemon.node_id)).json()

    # Bob signs Alice's counter-challenge with his own (trusted) key.
    stolen = bob.confirm_handshake(two_a)
    stolen["initiator_id"] = alice.node_id

    body = post_confirm(client, stolen).json()

    assert body["authenticated"] is False
    assert alice.node_id not in daemon.peers
    assert bob.node_id not in daemon.peers


def test_concurrent_clients_do_not_interfere(daemon):
    """Two client drivers running concurrently against the same daemon."""
    alice = link(make_node("node_conc_alice"), daemon)
    bob = link(make_node("node_conc_bob"), daemon)

    async def go():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport,
                                     base_url="http://daemon") as http:
            return await asyncio.gather(
                handshake_over_http(alice, peer_id=daemon.node_id, http=http),
                handshake_over_http(bob, peer_id=daemon.node_id, http=http),
            )

    result_a, result_b = asyncio.run(go())

    assert result_a["authenticated"] is True
    assert result_b["authenticated"] is True
    assert authenticated_peers(daemon) == {alice.node_id, bob.node_id}
    assert authenticated_peers(alice) == {daemon.node_id}
    assert authenticated_peers(bob) == {daemon.node_id}


# ---------------------------------------------------------------------------
# The existing routes are untouched
# ---------------------------------------------------------------------------

def test_existing_routes_still_work(client, daemon):
    assert client.get("/v1/manifest").status_code == 200
    assert client.get("/v1/peers").status_code == 200
    assert client.get("/v1/logs").status_code == 200
    assert client.get("/v1/nope").status_code == 404


def test_handshake_routes_reject_get(client, daemon):
    assert client.get(OFFER_PATH).status_code == 405
    assert client.get(CONFIRM_PATH).status_code == 405
