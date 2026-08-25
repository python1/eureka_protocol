"""
Peer discovery over a private mesh.

Addresses were configured by hand and went stale. These tests cover learning
them by gossip instead, and -- mostly -- cover the ways that must not go wrong:
an address is never a trust decision, it is advice until a handshake proves it,
gossip is served only to authenticated peers and only about keys the caller
already knows, the table is bounded, and nothing outside the configured mesh is
ever contacted.

The nodes here are real: real ASGI apps, real JSON over the transport, real
signatures. Discovery only means anything with several nodes talking to each
other, so mocking the peers would test the wrong thing.
"""
import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from eureka_protocol.src.eureka_daemon.address_book import (
    MAX_ADDRESSES_PER_KEY,
    AddressBook,
)
from eureka_protocol.src.eureka_daemon.api import create_app
from eureka_protocol.src.eureka_daemon.crypto import EurekaCrypto
from eureka_protocol.src.eureka_daemon.discovery import (
    ANSWER_EVENT,
    DISCOVERY_PATH,
    MAX_QUERY_KEYS,
    QUERY_EVENT,
    REASON_NOT_AUTHENTICATED,
    REJECTED_EVENT,
    addresses_to_disclose,
    answer_query,
    build_query,
    confirm_address,
    discover,
    learn_addresses,
    query_peer,
)
from eureka_protocol.src.eureka_daemon.node import (
    EurekaNode,
    REASON_BAD_SIGNATURE,
    REASON_MALFORMED,
    REASON_REVOKED_KEY,
    REASON_STALE,
    REASON_UNTRUSTED_KEY,
)
from eureka_protocol.src.eureka_daemon.trust import TrustList


def run(coro):
    return asyncio.run(coro)


def some_key():
    return EurekaCrypto().get_public_key_hex()


class Mesh:
    """
    A private mesh of in-process nodes, addressed by URL.

    Doubles as the proof for "no public network is contacted": every dial goes
    through here, so a test can simply assert which addresses were reached --
    and that an address nobody configured was never reached at all.
    """

    def __init__(self):
        self.apps = {}
        self.nodes = {}
        self.dialled = []

    def add(self, name, address, capabilities=("code-exec",)):
        node = EurekaNode(node_id=name, crypto_engine=EurekaCrypto(),
                          capabilities=list(capabilities),
                          trust_list=TrustList())
        self.nodes[name] = node
        self.apps[address] = create_app(node)
        node.address = address
        return node

    def client_factory(self, address, timeout):
        self.dialled.append(address)
        app = self.apps.get(address)
        if app is None:
            # Nothing is listening there. A real client would fail to connect;
            # this fails the same way, without leaving the process.
            raise httpx.ConnectError(f"nothing listening at {address}")
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=address, timeout=timeout,
        )


def trust(a, b):
    """One direction: a trusts b's key."""
    a.trust_list.add(b.node_id, b.public_key_hex)


def mutually_trust(a, b):
    trust(a, b)
    trust(b, a)


@pytest.fixture
def mesh():
    return Mesh()


# ---------------------------------------------------------------------------
# The headline: C learns B's address from A, and reaches B with it
# ---------------------------------------------------------------------------

def test_a_node_learns_a_peer_address_by_gossip_and_reaches_it(mesh):
    a = mesh.add("node_a", "http://a.mesh")
    b = mesh.add("node_b", "http://b.mesh")
    c = mesh.add("node_c", "http://c.mesh")

    # Everyone trusts everyone; only A knows where B is.
    mutually_trust(a, b)
    mutually_trust(a, c)
    mutually_trust(b, c)
    a.address_book.add(b.public_key_hex, "http://b.mesh")
    a.address_book.confirm(b.public_key_hex, "http://b.mesh")

    # C starts knowing only A.
    summary = run(discover(c, bootstrap=["http://a.mesh"],
                           client_factory=mesh.client_factory))

    assert "http://b.mesh" in c.address_book.addresses(b.public_key_hex)
    assert summary["learned"] >= 1
    # And the address was not merely stored -- a handshake reached B with it.
    assert c.address_book.is_confirmed(b.public_key_hex, "http://b.mesh")
    assert c.peers[b.node_id]["status"] == "authenticated"


def test_discovery_confirms_the_bootstrap_address_too(mesh):
    a = mesh.add("node_a", "http://a.mesh")
    c = mesh.add("node_c", "http://c.mesh")
    mutually_trust(a, c)

    run(discover(c, bootstrap=["http://a.mesh"],
                 client_factory=mesh.client_factory))

    assert c.address_book.is_confirmed(a.public_key_hex, "http://a.mesh")


# ---------------------------------------------------------------------------
# Learning an address is never a trust decision
# ---------------------------------------------------------------------------

def test_a_gossiped_address_for_an_untrusted_key_is_discarded(mesh):
    c = mesh.add("node_c", "http://c.mesh")
    stranger = some_key()

    accepted = learn_addresses(c, {"addresses": {stranger: ["http://evil.mesh"]}})

    assert accepted == 0
    assert c.address_book.addresses(stranger) == []
    assert stranger not in c.address_book.keys()
    # And nothing about the trust list moved.
    assert not c.trust_list.trusts(stranger)


def test_a_gossiped_address_for_a_revoked_key_is_discarded(mesh):
    c = mesh.add("node_c", "http://c.mesh")
    retired = some_key()
    c.trust_list.add("old-peer", retired)
    c.trust_list.revoke(retired, reason="compromised")

    accepted = learn_addresses(c, {"addresses": {retired: ["http://old.mesh"]}})

    assert accepted == 0
    assert c.address_book.addresses(retired) == []


def test_learning_an_address_grants_no_capabilities(mesh):
    """An address says where, never what a peer may do."""
    c = mesh.add("node_c", "http://c.mesh")
    b = mesh.add("node_b", "http://b.mesh")
    trust(c, b)

    learn_addresses(c, {"addresses": {b.public_key_hex: ["http://b.mesh"]}})

    assert c.granted_capabilities(b.node_id) == set()
    assert c.is_permitted(b.node_id, "code-exec") is False


@pytest.mark.parametrize("addresses", [
    "http://not-a-list.mesh", 42, None, {"nested": "object"},
])
def test_malformed_answers_teach_nothing(mesh, addresses):
    c = mesh.add("node_c", "http://c.mesh")
    b = mesh.add("node_b", "http://b.mesh")
    trust(c, b)

    assert learn_addresses(c, {"addresses": {b.public_key_hex: addresses}}) == 0
    assert learn_addresses(c, addresses) == 0


@pytest.mark.parametrize("address", [
    "file:///etc/passwd", "unix:///var/run/x.sock", "ftp://x.mesh",
    "", "   ", "x" * 300, 42, None,
])
def test_undialable_addresses_are_refused(mesh, address):
    """
    A gossiped address gets handed to an HTTP client later. Only http(s) is
    stored, so a peer cannot talk this node into dialling a local socket.
    """
    c = mesh.add("node_c", "http://c.mesh")
    b = mesh.add("node_b", "http://b.mesh")
    trust(c, b)

    assert c.address_book.add(b.public_key_hex, address) is False
    assert c.address_book.addresses(b.public_key_hex) == []


# ---------------------------------------------------------------------------
# An address is advice until a handshake proves it
# ---------------------------------------------------------------------------

def test_a_wrong_address_fails_the_handshake_and_poisons_nothing(mesh):
    """
    A gossips C a *wrong* address for B: the one where some other trusted peer
    lives. The handshake there succeeds -- that peer is genuinely trusted -- and
    the address is still not confirmed for B, because B is not who answered.
    """
    b = mesh.add("node_b", "http://b.mesh")
    d = mesh.add("node_d", "http://d.mesh")
    c = mesh.add("node_c", "http://c.mesh")
    mutually_trust(c, b)
    mutually_trust(c, d)

    c.address_book.add(b.public_key_hex, "http://d.mesh", source="liar")
    confirmed = run(confirm_address(c, b.public_key_hex, "http://d.mesh",
                                    client_factory=mesh.client_factory))

    assert confirmed is False
    assert not c.address_book.is_confirmed(b.public_key_hex, "http://d.mesh")
    # The trust decision is untouched: B is still B, D is still D.
    assert c.trust_list.name_for(b.public_key_hex) == b.node_id
    assert c.trust_list.name_for(d.public_key_hex) == d.node_id
    assert not c.trust_list.is_revoked(b.public_key_hex)


def test_an_address_that_leads_nowhere_is_simply_not_confirmed(mesh):
    b = mesh.add("node_b", "http://b.mesh")
    c = mesh.add("node_c", "http://c.mesh")
    mutually_trust(c, b)
    c.address_book.add(b.public_key_hex, "http://nowhere.mesh")

    confirmed = run(confirm_address(c, b.public_key_hex, "http://nowhere.mesh",
                                    client_factory=mesh.client_factory))

    assert confirmed is False
    assert c.address_book.addresses(b.public_key_hex) == ["http://nowhere.mesh"]
    assert not c.address_book.is_confirmed(b.public_key_hex, "http://nowhere.mesh")


def test_an_impostor_at_a_gossiped_address_confirms_nothing(mesh):
    """
    The nastiest shape of a wrong address. C already knows B. A node calling
    itself node_b, holding a different key, sits at the gossiped address and
    answers the handshake. C's own verification rejects it -- the key is not
    trusted -- but the rejection still names node_b, and C already has a
    node_b on file. Confirming on the strength of that name would file an
    impostor's address under the real B's key.
    """
    b = mesh.add("node_b", "http://b.mesh")
    c = mesh.add("node_c", "http://c.mesh")
    mutually_trust(c, b)
    run(c.handshake(b))
    assert c.peers[b.node_id]["status"] == "authenticated"

    impostor = mesh.add("node_b", "http://impostor.mesh")   # same id, new key
    impostor.trust_list.add("node_c", c.public_key_hex)     # so it replies

    c.address_book.add(b.public_key_hex, "http://impostor.mesh", source="liar")
    confirmed = run(confirm_address(c, b.public_key_hex, "http://impostor.mesh",
                                    client_factory=mesh.client_factory))

    assert confirmed is False
    assert not c.address_book.is_confirmed(b.public_key_hex,
                                           "http://impostor.mesh")
    # The real B is untouched, and the impostor's key gained nothing.
    assert c.peers[b.node_id]["public_key"] == b.public_key_hex
    assert not c.trust_list.trusts(impostor.public_key_hex)


def test_a_correct_address_is_confirmed(mesh):
    b = mesh.add("node_b", "http://b.mesh")
    c = mesh.add("node_c", "http://c.mesh")
    mutually_trust(c, b)
    c.address_book.add(b.public_key_hex, "http://b.mesh")

    assert run(confirm_address(c, b.public_key_hex, "http://b.mesh",
                               client_factory=mesh.client_factory)) is True
    assert c.address_book.is_confirmed(b.public_key_hex, "http://b.mesh")


def test_a_learned_address_starts_unconfirmed(mesh):
    c = mesh.add("node_c", "http://c.mesh")
    b = mesh.add("node_b", "http://b.mesh")
    trust(c, b)

    learn_addresses(c, {"addresses": {b.public_key_hex: ["http://b.mesh"]}})

    assert c.address_book.addresses(b.public_key_hex) == ["http://b.mesh"]
    assert not c.address_book.is_confirmed(b.public_key_hex, "http://b.mesh")


# ---------------------------------------------------------------------------
# Gossip is served only to authenticated peers
# ---------------------------------------------------------------------------

def test_gossip_to_an_unauthenticated_caller_returns_nothing(mesh):
    """Trusted is not enough. A peer must have completed a handshake."""
    a = mesh.add("node_a", "http://a.mesh")
    b = mesh.add("node_b", "http://b.mesh")
    c = mesh.add("node_c", "http://c.mesh")
    mutually_trust(a, c)
    trust(a, b)
    a.address_book.add(b.public_key_hex, "http://b.mesh")

    # C is trusted by A but has never handshaked with it.
    answer = answer_query(a, build_query(c))

    assert answer["event"] == REJECTED_EVENT
    assert answer["reason"] == REASON_NOT_AUTHENTICATED
    assert answer["addresses"] == {}


def test_gossip_to_a_stranger_returns_nothing(mesh):
    a = mesh.add("node_a", "http://a.mesh")
    stranger = mesh.add("node_stranger", "http://s.mesh")

    answer = answer_query(a, build_query(stranger))

    assert answer["event"] == REJECTED_EVENT
    assert answer["reason"] == REASON_UNTRUSTED_KEY
    assert answer["addresses"] == {}


def test_gossip_to_a_revoked_peer_returns_nothing(mesh):
    a = mesh.add("node_a", "http://a.mesh")
    c = mesh.add("node_c", "http://c.mesh")
    mutually_trust(a, c)
    run(c.handshake(a))
    a.trust_list.revoke(c.public_key_hex, reason="compromised")

    answer = answer_query(a, build_query(c))

    assert answer["event"] == REJECTED_EVENT
    assert answer["reason"] == REASON_REVOKED_KEY
    assert answer["addresses"] == {}


def test_a_forged_signature_gets_nothing(mesh):
    a = mesh.add("node_a", "http://a.mesh")
    c = mesh.add("node_c", "http://c.mesh")
    mutually_trust(a, c)
    run(c.handshake(a))

    query = build_query(c)
    query["query"]["keys"] = [some_key()]      # tampered after signing

    answer = answer_query(a, query)

    assert answer["reason"] == REASON_BAD_SIGNATURE
    assert answer["addresses"] == {}


def test_a_query_claiming_someone_elses_key_gets_nothing(mesh):
    """The signature is real, but it is not the key it claims to be."""
    a = mesh.add("node_a", "http://a.mesh")
    c = mesh.add("node_c", "http://c.mesh")
    other = mesh.add("node_other", "http://o.mesh")
    mutually_trust(a, c)
    mutually_trust(a, other)
    run(c.handshake(a))

    query = build_query(c)
    query["public_key"] = other.public_key_hex

    answer = answer_query(a, query)

    assert answer["reason"] == REASON_BAD_SIGNATURE


def test_a_stale_query_gets_nothing(mesh):
    a = mesh.add("node_a", "http://a.mesh")
    c = mesh.add("node_c", "http://c.mesh")
    mutually_trust(a, c)
    run(c.handshake(a))

    old = datetime.now(timezone.utc) - timedelta(seconds=600)
    answer = answer_query(a, build_query(c, now=old))

    assert answer["reason"] == REASON_STALE


@pytest.mark.parametrize("document", [
    None, 42, "a string", {}, {"query": {}},
    {"query": {"protocol": "eureka/1.0"}, "public_key": "x", "signature": "y"},
])
def test_malformed_queries_get_nothing(mesh, document):
    a = mesh.add("node_a", "http://a.mesh")
    answer = answer_query(a, document)
    assert answer["addresses"] == {}
    assert answer["event"] == REJECTED_EVENT


def signed_query(node, keys, now=None):
    """
    A properly signed query naming exactly `keys`.

    build_query caps what it will ask for, so an oversized query has to be
    built by hand -- and it has to be *signed*, or the length check would never
    be the thing that rejected it.
    """
    query = {
        "protocol": "eureka/1.0",
        "event": QUERY_EVENT,
        "requester_id": node.node_id,
        "timestamp": (now or datetime.now(timezone.utc)).isoformat(),
        "keys": list(keys),
    }
    return {
        "event": QUERY_EVENT,
        "requester_id": node.node_id,
        "public_key": node.public_key_hex,
        "query": query,
        "signature": node.crypto.sign_discovery_query(query),
    }


def test_an_oversized_query_is_refused_not_truncated(mesh):
    """
    Truncating would answer a different question than the one asked.

    The query names a key that WOULD be disclosed, padded past the cap, so
    refusing and answering look different. Padding with keys nobody trusts
    would make this pass whether the cap worked or not.
    """
    a = mesh.add("node_a", "http://a.mesh")
    b = mesh.add("node_b", "http://b.mesh")
    c = mesh.add("node_c", "http://c.mesh")
    mutually_trust(a, c)
    trust(a, b)
    a.address_book.add(b.public_key_hex, "http://b.mesh")
    run(c.handshake(a))

    # Sanity: this exact key is disclosed when the query is a legal size.
    assert answer_query(a, signed_query(c, [b.public_key_hex]))["addresses"]

    oversized = signed_query(
        c, [b.public_key_hex] + [some_key() for _ in range(MAX_QUERY_KEYS)])

    answer = answer_query(a, oversized)

    assert answer["event"] == REJECTED_EVENT
    assert answer["addresses"] == {}


def test_the_envelope_must_agree_with_the_signed_body(mesh):
    """
    The signature covers the inner query, so a mismatched envelope is a request
    that says two different things about who is asking. Refuse rather than pick
    one.
    """
    a = mesh.add("node_a", "http://a.mesh")
    c = mesh.add("node_c", "http://c.mesh")
    mutually_trust(a, c)
    run(c.handshake(a))

    query = build_query(c)
    query["requester_id"] = "node_someone_else"     # envelope only; body intact

    answer = answer_query(a, query)

    assert answer["event"] == REJECTED_EVENT
    assert answer["reason"] == REASON_MALFORMED
    assert answer["addresses"] == {}


# ---------------------------------------------------------------------------
# A peer is not told about keys it does not trust
# ---------------------------------------------------------------------------

def test_a_peer_is_not_told_about_keys_it_does_not_trust(mesh):
    """
    A knows where B and E are. C trusts B but has never heard of E. C's query
    names only B, so A's answer mentions B and says nothing at all about E --
    C cannot even learn that E exists.
    """
    a = mesh.add("node_a", "http://a.mesh")
    b = mesh.add("node_b", "http://b.mesh")
    e = mesh.add("node_e", "http://e.mesh")
    c = mesh.add("node_c", "http://c.mesh")
    mutually_trust(a, c)
    trust(a, b)
    trust(a, e)
    trust(c, b)                       # C trusts B, and has never heard of E
    a.address_book.add(b.public_key_hex, "http://b.mesh")
    a.address_book.add(e.public_key_hex, "http://e.mesh")
    run(c.handshake(a))

    answer = answer_query(a, build_query(c))

    assert answer["event"] == ANSWER_EVENT
    assert set(answer["addresses"]) == {b.public_key_hex}
    assert e.public_key_hex not in answer["addresses"]
    assert "http://e.mesh" not in str(answer)


def test_a_key_the_responder_does_not_trust_is_not_disclosed(mesh):
    """The caller asks about a key A has an address for but no longer trusts."""
    a = mesh.add("node_a", "http://a.mesh")
    b = mesh.add("node_b", "http://b.mesh")
    c = mesh.add("node_c", "http://c.mesh")
    mutually_trust(a, c)
    trust(a, b)
    trust(c, b)
    a.address_book.add(b.public_key_hex, "http://b.mesh")
    run(c.handshake(a))
    a.trust_list.revoke(b.public_key_hex, reason="compromised")

    answer = answer_query(a, build_query(c))

    assert answer["addresses"] == {}


def test_disclosure_is_limited_to_the_keys_named(mesh):
    a = mesh.add("node_a", "http://a.mesh")
    b = mesh.add("node_b", "http://b.mesh")
    e = mesh.add("node_e", "http://e.mesh")
    trust(a, b)
    trust(a, e)
    a.address_book.add(b.public_key_hex, "http://b.mesh")
    a.address_book.add(e.public_key_hex, "http://e.mesh")

    disclosed = addresses_to_disclose(a, [b.public_key_hex])

    assert set(disclosed) == {b.public_key_hex}


def test_a_query_only_names_keys_the_caller_trusts(mesh):
    """
    The caller-driven design's other half: we ask only about keys we already
    trust, so a query never leaks curiosity about anything else.
    """
    c = mesh.add("node_c", "http://c.mesh")
    b = mesh.add("node_b", "http://b.mesh")
    trust(c, b)
    revoked = some_key()
    c.trust_list.add("gone", revoked)
    c.trust_list.revoke(revoked)

    query = build_query(c)

    assert query["query"]["keys"] == [b.public_key_hex]
    assert revoked not in query["query"]["keys"]


# ---------------------------------------------------------------------------
# Bounded
# ---------------------------------------------------------------------------

def test_the_address_table_is_bounded_under_flooding(mesh):
    """
    A trusted peer floods thousands of addresses for a key. The table holds the
    cap and no more; the key count is bounded by the trust list, because
    nothing untrusted can be stored at all.
    """
    c = mesh.add("node_c", "http://c.mesh")
    b = mesh.add("node_b", "http://b.mesh")
    trust(c, b)

    for index in range(5000):
        learn_addresses(c, {"addresses": {
            b.public_key_hex: [f"http://flood-{index}.mesh"],
            some_key(): [f"http://untrusted-{index}.mesh"],
        }})

    assert len(c.address_book.addresses(b.public_key_hex)) == MAX_ADDRESSES_PER_KEY
    assert len(c.address_book) == 1                # only the one trusted key
    assert c.address_book.total_addresses() <= MAX_ADDRESSES_PER_KEY


def test_the_key_count_is_capped_independently():
    book = AddressBook(max_keys=3)

    for _ in range(50):
        book.add(some_key(), "http://x.mesh")

    assert len(book) == 3


def test_confirmed_addresses_are_not_evicted_by_flooding():
    """Hearsay must not push out an address a handshake actually reached."""
    book = AddressBook()
    key = some_key()
    book.add(key, "http://real.mesh")
    book.confirm(key, "http://real.mesh")

    for index in range(100):
        book.add(key, f"http://flood-{index}.mesh")

    assert "http://real.mesh" in book.addresses(key)
    assert book.is_confirmed(key, "http://real.mesh")


def test_a_peer_that_moves_can_still_be_relearned():
    """
    Every slot confirmed must not lock a peer's address in forever, or a node
    that legitimately moves could never be found again.
    """
    book = AddressBook(max_addresses_per_key=2)
    key = some_key()
    for name in ("http://old-1.mesh", "http://old-2.mesh"):
        book.add(key, name)
        book.confirm(key, name)

    assert book.add(key, "http://new.mesh") is True
    assert "http://new.mesh" in book.addresses(key)


def test_confirmed_addresses_are_offered_first():
    book = AddressBook()
    key = some_key()
    book.add(key, "http://hearsay.mesh")
    book.add(key, "http://known-good.mesh")
    book.confirm(key, "http://known-good.mesh")

    assert book.addresses(key)[0] == "http://known-good.mesh"


def test_a_repeated_address_is_stored_once():
    book = AddressBook()
    key = some_key()
    for _ in range(10):
        book.add(key, "http://b.mesh")

    assert book.addresses(key) == ["http://b.mesh"]


def test_re_offering_an_address_does_not_confirm_it():
    book = AddressBook()
    key = some_key()
    book.add(key, "http://b.mesh")
    book.add(key, "http://b.mesh")

    assert not book.is_confirmed(key, "http://b.mesh")


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------

def test_unconfirmed_addresses_expire():
    book = AddressBook(unconfirmed_ttl_seconds=60)
    key = some_key()
    book.add(key, "http://hearsay.mesh")

    later = datetime.now(timezone.utc) + timedelta(seconds=61)
    dropped = book.prune(now=later)

    assert dropped == 1
    assert book.addresses(key) == []
    assert key not in book.keys()


def test_confirmed_addresses_survive_expiry():
    book = AddressBook(unconfirmed_ttl_seconds=60)
    key = some_key()
    book.add(key, "http://real.mesh")
    book.confirm(key, "http://real.mesh")

    book.prune(now=datetime.now(timezone.utc) + timedelta(days=30))

    assert book.addresses(key) == ["http://real.mesh"]


def test_an_unexpired_address_is_kept():
    book = AddressBook(unconfirmed_ttl_seconds=600)
    key = some_key()
    book.add(key, "http://hearsay.mesh")

    assert book.prune(now=datetime.now(timezone.utc) + timedelta(seconds=60)) == 0
    assert book.addresses(key) == ["http://hearsay.mesh"]


def test_the_expiry_window_is_configurable():
    key = some_key()
    strict, lax = AddressBook(unconfirmed_ttl_seconds=1), AddressBook(
        unconfirmed_ttl_seconds=10_000)
    strict.add(key, "http://x.mesh")
    lax.add(key, "http://x.mesh")

    moment = datetime.now(timezone.utc) + timedelta(seconds=100)

    assert strict.prune(now=moment) == 1
    assert lax.prune(now=moment) == 0


def test_forgetting_a_key_drops_its_addresses():
    book = AddressBook()
    key = some_key()
    book.add(key, "http://x.mesh")

    assert book.forget(key) is True
    assert book.addresses(key) == []


# ---------------------------------------------------------------------------
# Nothing outside the configured mesh is contacted
# ---------------------------------------------------------------------------

def test_an_empty_bootstrap_list_contacts_nothing(mesh):
    c = mesh.add("node_c", "http://c.mesh")

    summary = run(discover(c, bootstrap=[], client_factory=mesh.client_factory))

    assert mesh.dialled == []
    assert summary == {"contacted": [], "learned": 0, "confirmed": [],
                       "failed": []}
    assert len(c.address_book) == 0


def test_discovery_only_dials_configured_and_learned_addresses(mesh):
    a = mesh.add("node_a", "http://a.mesh")
    b = mesh.add("node_b", "http://b.mesh")
    c = mesh.add("node_c", "http://c.mesh")
    mutually_trust(a, c)
    mutually_trust(a, b)
    mutually_trust(b, c)
    a.address_book.add(b.public_key_hex, "http://b.mesh")

    run(discover(c, bootstrap=["http://a.mesh"],
                 client_factory=mesh.client_factory))

    assert set(mesh.dialled) <= {"http://a.mesh", "http://b.mesh"}


def test_gossip_about_an_untrusted_key_is_never_dialled(mesh):
    """
    A gossips an address for a key C does not trust. C cannot store it, so C
    never dials it -- the storage gate is also the dialling gate.
    """
    a = mesh.add("node_a", "http://a.mesh")
    c = mesh.add("node_c", "http://c.mesh")
    outsider = mesh.add("node_outsider", "http://outsider.mesh")
    mutually_trust(a, c)
    trust(a, outsider)
    a.address_book.add(outsider.public_key_hex, "http://outsider.mesh")

    run(discover(c, bootstrap=["http://a.mesh"],
                 client_factory=mesh.client_factory))

    assert "http://outsider.mesh" not in mesh.dialled
    assert c.address_book.addresses(outsider.public_key_hex) == []


def test_a_bootstrap_address_that_is_down_is_reported_not_raised(mesh):
    c = mesh.add("node_c", "http://c.mesh")

    summary = run(discover(c, bootstrap=["http://down.mesh"],
                           client_factory=mesh.client_factory))

    assert summary["failed"] == ["http://down.mesh"]
    assert summary["learned"] == 0


def test_a_bootstrap_peer_that_does_not_trust_us_teaches_nothing(mesh):
    a = mesh.add("node_a", "http://a.mesh")
    c = mesh.add("node_c", "http://c.mesh")
    trust(c, a)                       # one-way: A does not trust C

    summary = run(discover(c, bootstrap=["http://a.mesh"],
                           client_factory=mesh.client_factory))

    assert summary["learned"] == 0
    assert summary["failed"] == ["http://a.mesh"]


# ---------------------------------------------------------------------------
# Over the wire
# ---------------------------------------------------------------------------

def test_the_endpoint_answers_an_authenticated_peer(mesh):
    a = mesh.add("node_a", "http://a.mesh")
    b = mesh.add("node_b", "http://b.mesh")
    c = mesh.add("node_c", "http://c.mesh")
    mutually_trust(a, c)
    trust(a, b)
    trust(c, b)
    a.address_book.add(b.public_key_hex, "http://b.mesh")

    async def exchange():
        from eureka_protocol.src.eureka_daemon.client import handshake_over_http
        http = mesh.client_factory("http://a.mesh", 10)
        async with http:
            assert (await handshake_over_http(c, http=http))["authenticated"]
        return await query_peer(c, "http://a.mesh",
                                client_factory=mesh.client_factory)

    answer = run(exchange())

    assert answer["event"] == ANSWER_EVENT
    assert answer["addresses"][b.public_key_hex] == ["http://b.mesh"]


def test_the_endpoint_refuses_an_unauthenticated_peer_over_the_wire(mesh):
    a = mesh.add("node_a", "http://a.mesh")
    c = mesh.add("node_c", "http://c.mesh")
    mutually_trust(a, c)

    answer = run(query_peer(c, "http://a.mesh",
                            client_factory=mesh.client_factory))

    assert answer["event"] == REJECTED_EVENT
    assert answer["addresses"] == {}


def test_a_garbage_body_gets_a_rejection_not_a_crash(mesh):
    a = mesh.add("node_a", "http://a.mesh")

    async def post():
        async with mesh.client_factory("http://a.mesh", 10) as http:
            return await http.post(DISCOVERY_PATH, json=["not", "an", "object"])

    response = run(post())

    assert response.status_code == 200
    assert response.json()["addresses"] == {}


def test_the_query_is_domain_separated(mesh):
    """
    A handshake signature must not be usable as a discovery query. The tag is
    part of the signed bytes, so the same payload signs to something different
    in each context.
    """
    c = mesh.add("node_c", "http://c.mesh")
    query = build_query(c)["query"]

    handshake_signature = c.crypto.sign_handshake(query)
    discovery_signature = c.crypto.sign_discovery_query(query)

    assert handshake_signature != discovery_signature
    assert EurekaCrypto.verify_discovery_query(
        c.public_key_hex, handshake_signature, query) is False
    assert EurekaCrypto.verify_discovery_query(
        c.public_key_hex, discovery_signature, query) is True
