"""
The executor: the handler registry, and web-retrieval end to end.

`assign()` used to sleep half a second and return a canned string. These tests
cover what replaced it -- a registry that a node validates its advertised
capabilities against at construction, and one real capability behind it.

Most of the web-retrieval tests run against a real HTTP server on a real
socket. That is deliberate and it costs something: the fetch policy refuses
loopback, so the origin fixture has to be reached through a policy built with
`allow_loopback=True`. The alternative was a mock transport everywhere, which
would have tested the code's opinion of httpx rather than httpx -- and the
things most worth testing here (a body that streams past the cap, a server
that never answers, a connection that lands somewhere other than where DNS
said it would) only exist once there is a socket. The default policy, the one
the daemon runs, is tested separately and refuses that same server.
"""
import asyncio
import socket
import threading
import time

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Response
from fastapi.responses import PlainTextResponse, RedirectResponse, StreamingResponse

from eureka_protocol.src.eureka_daemon.crypto import EurekaCrypto
from eureka_protocol.src.eureka_daemon.handlers import (
    AddressPolicy,
    HandlerContext,
    HandlerError,
    HandlerRegistry,
    REASON_ADDRESS_NOT_ALLOWED,
    REASON_BODY_TOO_LARGE,
    REASON_CONNECTION_FAILED,
    REASON_DNS_FAILED,
    REASON_HANDLER_ERROR,
    REASON_INVALID_PAYLOAD,
    REASON_NOT_IMPLEMENTED,
    REASON_OK,
    REASON_SCHEME_NOT_ALLOWED,
    REASON_TIMEOUT,
    REASON_TOO_MANY_REDIRECTS,
    STATUS_COMPLETED,
    STATUS_FAILED,
    WebRetrieval,
    completed,
    default_registry,
)
from eureka_protocol.src.eureka_daemon.node import EurekaNode
from eureka_protocol.src.eureka_daemon.trust import TrustList


def run(coro):
    return asyncio.run(coro)


def context(capability="web-retrieval", task="t", peer=None):
    return HandlerContext(node_id="node_test", capability=capability,
                          task_name=task, peer=peer)


# ---------------------------------------------------------------------------
# A real origin server to fetch from
# ---------------------------------------------------------------------------

def free_port():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def build_origin():
    app = FastAPI()

    @app.get("/hello")
    async def hello():
        return PlainTextResponse("hello from the origin",
                                 media_type="text/plain; charset=utf-8")

    @app.get("/boom")
    async def boom():
        return PlainTextResponse("upstream is having a day", status_code=500)

    @app.get("/declared-large")
    async def declared_large():
        # A normal response, so uvicorn declares content-length. The fetch
        # refuses it on that declaration without downloading it.
        return PlainTextResponse("x" * (256 * 1024))

    @app.get("/streamed-large")
    async def streamed_large():
        # Chunked: no content-length to refuse on, so the only thing that can
        # stop it is the reader counting bytes.
        async def chunks():
            for _ in range(64):
                yield b"y" * 4096
        return StreamingResponse(chunks(), media_type="text/plain")

    @app.get("/slow")
    async def slow():
        await asyncio.sleep(3)
        return PlainTextResponse("eventually")

    @app.get("/delay")
    async def delay(ms: int = 500):
        # A target that is slow but does answer, for showing that a fetch in
        # flight does not hold up anything else on the daemon.
        await asyncio.sleep(ms / 1000)
        return PlainTextResponse("worth the wait")

    @app.get("/redirect-to-hello")
    async def redirect_to_hello():
        return RedirectResponse("/hello", status_code=302)

    @app.get("/redirect-to-private")
    async def redirect_to_private():
        return RedirectResponse("http://10.1.2.3/secrets", status_code=302)

    @app.get("/redirect-loop")
    async def redirect_loop():
        return RedirectResponse("/redirect-loop", status_code=302)

    @app.get("/no-location")
    async def no_location():
        return Response(status_code=302)

    return app


@pytest.fixture(scope="module")
def origin():
    """A real HTTP server on loopback, for the fetch path to fetch."""
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(
        build_origin(), host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 20
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        pytest.fail("origin server did not start")

    yield f"http://127.0.0.1:{port}"

    server.should_exit = True
    thread.join(timeout=10)


def opener(**kwargs):
    """A fetcher allowed to reach the loopback origin, and nothing more."""
    kwargs.setdefault("policy", AddressPolicy(allow_loopback=True))
    return WebRetrieval(**kwargs)


def fixed_resolver(*addresses):
    """A resolver that answers every name with the same addresses."""
    async def resolve(host, port):
        return list(addresses)
    return resolve


# ---------------------------------------------------------------------------
# The registry, and what a node may advertise
# ---------------------------------------------------------------------------

def test_advertising_a_capability_with_no_handler_fails_at_startup():
    """
    The whole point of the registry. A node that claims code-exec and has
    nothing to run it would tell a granted peer yes at every gate and then
    hand it nothing -- so it does not get to start.
    """
    with pytest.raises(HandlerError, match="code-exec"):
        EurekaNode(node_id="node_liar", crypto_engine=EurekaCrypto(),
                   capabilities=["web-retrieval", "code-exec"],
                   trust_list=TrustList(), handlers=default_registry())


def test_the_daemon_entry_point_validates_too(tmp_path):
    """with_persistent_identity is what api.py calls; the check is there too."""
    with pytest.raises(HandlerError, match="data-analysis"):
        EurekaNode.with_persistent_identity(
            capabilities=["data-analysis"],
            identity_path=str(tmp_path / "identity.key"),
            handlers=default_registry(),
        )


def test_a_node_given_a_registry_and_no_list_advertises_what_it_can_run():
    node = EurekaNode(node_id="node_derived", crypto_engine=EurekaCrypto(),
                      trust_list=TrustList(), handlers=default_registry())
    assert node.capabilities == ["web-retrieval"]


def test_the_deployed_registry_holds_web_retrieval_and_nothing_else():
    """code-exec has a gate and no sandbox. It must not have a handler."""
    assert default_registry().names() == frozenset({"web-retrieval"})


def test_a_registered_handler_need_not_be_advertised():
    """The asymmetry is on purpose: holding code is not offering it."""
    registry = default_registry()
    registry.validate_advertised([])
    registry.validate_advertised(["web-retrieval"])


def test_registering_the_same_capability_twice_is_refused():
    registry = default_registry()
    with pytest.raises(HandlerError, match="already registered"):
        registry.register("web-retrieval", lambda payload, ctx: None)


def test_a_registry_refuses_nonsense_registrations():
    registry = HandlerRegistry()
    with pytest.raises(HandlerError):
        registry.register("", lambda payload, ctx: None)
    with pytest.raises(HandlerError):
        registry.register("thing", "not callable")


def test_an_unregistered_capability_is_a_distinct_outcome():
    result = run(default_registry().run("code-exec", {}, context("code-exec")))
    assert result.status == STATUS_FAILED
    assert result.reason == REASON_NOT_IMPLEMENTED


def test_a_node_with_no_executor_runs_nothing():
    """Every client node in this codebase. It advertises; it cannot execute."""
    node = EurekaNode(node_id="node_client", crypto_engine=EurekaCrypto(),
                      capabilities=["web-retrieval"], trust_list=TrustList())
    result = run(node.assign({"task_name": "t", "payload": {}},
                             capability="web-retrieval"))
    assert result["status"] == STATUS_FAILED
    assert result["reason"] == REASON_NOT_IMPLEMENTED


def test_a_node_needs_either_a_list_or_a_registry():
    with pytest.raises(ValueError, match="capability list or a handler"):
        EurekaNode(node_id="node_nothing", crypto_engine=EurekaCrypto(),
                   trust_list=TrustList())


# ---------------------------------------------------------------------------
# A handler that misbehaves is an outcome, not a crash
# ---------------------------------------------------------------------------

def test_a_handler_that_raises_returns_a_reason_and_no_traceback():
    async def explode(payload, ctx):
        raise RuntimeError("secret internal detail")

    registry = HandlerRegistry().register("boom", explode)
    result = run(registry.run("boom", {}, context("boom")))

    assert result.status == STATUS_FAILED
    assert result.reason == REASON_HANDLER_ERROR
    assert "secret internal detail" not in str(result)
    assert "RuntimeError" not in str(result)


def test_a_handler_that_hangs_hits_the_registry_deadline():
    async def forever(payload, ctx):
        await asyncio.sleep(60)

    registry = HandlerRegistry(deadline_seconds=0.2).register("slow", forever)
    result = run(registry.run("slow", {}, context("slow")))

    assert result.status == STATUS_FAILED
    assert result.reason == REASON_TIMEOUT


def test_the_registry_runs_handlers_concurrently_under_its_cap():
    """
    The cap bounds sockets, not throughput: work that could overlap does.

    Four handlers that each sleep 0.2s finish in well under the 0.8s they
    would take in sequence, which is the property that keeps a slow fetch from
    serialising every other request behind it.
    """
    async def nap(payload, ctx):
        await asyncio.sleep(0.2)
        return completed("napped")

    registry = HandlerRegistry(max_concurrent=4).register("nap", nap)

    async def go():
        started = time.monotonic()
        results = await asyncio.gather(*[
            registry.run("nap", {}, context("nap")) for _ in range(4)
        ])
        return results, time.monotonic() - started

    results, elapsed = run(go())
    assert [r.reason for r in results] == [REASON_OK] * 4
    assert elapsed < 0.6


def test_the_concurrency_cap_survives_a_second_event_loop():
    """
    A Semaphore binds to the loop it first waits on. The cap has to be
    contended to bind it, and contended again on another loop to catch it --
    an uncontended registry moves between loops without complaint, so a test
    that only ran one handler at a time would prove nothing and the failure
    would wait for production load to show up.
    """
    async def nap(payload, ctx):
        await asyncio.sleep(0.05)
        return completed("napped")

    registry = HandlerRegistry(max_concurrent=1).register("nap", nap)

    async def contend():
        results = await asyncio.gather(*[
            registry.run("nap", {}, context("nap")) for _ in range(3)
        ])
        return [r.reason for r in results]

    assert run(contend()) == [REASON_OK] * 3
    assert run(contend()) == [REASON_OK] * 3


# ---------------------------------------------------------------------------
# The address policy: what this node will and will not be pointed at
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("address", [
    "127.0.0.1", "127.1.2.3", "::1",
    "10.0.0.7", "172.16.4.1", "192.168.1.180",
    "169.254.169.254",                     # cloud metadata, the classic target
    "100.64.0.1",                          # carrier-grade NAT
    "0.0.0.0", "::",
    "224.0.0.1", "ff02::1",                # multicast
    "240.0.0.1",                           # reserved
    "fc00::1", "fe80::1",
    "::ffff:127.0.0.1",                    # loopback wearing an IPv6 hat
    "::ffff:10.0.0.1",
    "not-an-address",
])
def test_the_default_policy_refuses_everything_off_the_public_internet(address):
    assert AddressPolicy().refusal(address) == REASON_ADDRESS_NOT_ALLOWED


@pytest.mark.parametrize("address", [
    "93.184.216.34", "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111",
])
def test_the_default_policy_allows_public_unicast(address):
    assert AddressPolicy().refusal(address) is None


def test_the_test_only_flags_open_exactly_one_door_each():
    loopback_only = AddressPolicy(allow_loopback=True)
    assert loopback_only.refusal("127.0.0.1") is None
    assert loopback_only.refusal("10.0.0.7") == REASON_ADDRESS_NOT_ALLOWED

    private_only = AddressPolicy(allow_private=True)
    assert private_only.refusal("10.0.0.7") is None
    assert private_only.refusal("127.0.0.1") == REASON_ADDRESS_NOT_ALLOWED


# ---------------------------------------------------------------------------
# SSRF: literals, names, redirects, and a name that changes its mind
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://127.0.0.1:8443/v1/manifest",
    "http://[::1]/", "http://10.0.0.7/", "http://192.168.1.180:8443/v1/peers",
    "http://169.254.169.254/latest/meta-data/",
    "https://172.16.0.1/", "http://[::ffff:127.0.0.1]/",
])
def test_literal_blocked_addresses_are_refused(url):
    result = run(WebRetrieval()(({"url": url}), context()))
    assert result.status == STATUS_FAILED
    assert result.reason == REASON_ADDRESS_NOT_ALLOWED


def test_a_hostname_that_resolves_into_loopback_is_refused():
    """
    `localhost` is the honest version of this test: a real name, resolved by
    the real resolver, landing on 127.0.0.1 and ::1. No mock is involved in
    the part that matters -- the policy sees addresses, never the name.
    """
    result = run(WebRetrieval()({"url": "http://localhost:8443/v1/manifest"},
                                context()))
    assert result.reason == REASON_ADDRESS_NOT_ALLOWED


@pytest.mark.parametrize("addresses", [
    ("127.0.0.1",),
    ("10.9.9.9",),
    ("169.254.169.254",),
    ("93.184.216.34", "127.0.0.1"),   # one good answer does not excuse the bad one
])
def test_a_name_resolving_into_a_blocked_range_is_refused(addresses):
    fetch = WebRetrieval(resolver=fixed_resolver(*addresses))
    result = run(fetch({"url": "http://harmless.example/"}, context()))
    assert result.reason == REASON_ADDRESS_NOT_ALLOWED


def test_a_name_that_resolves_public_and_connects_private_is_caught(origin):
    """
    DNS rebinding, simulated end to end against a live server.

    The resolver lies -- it answers with a public address -- so the pre-flight
    check passes and the fetch goes ahead under the DEFAULT policy, which
    refuses loopback. httpx then connects for real, to the origin on 127.0.0.1.
    The peer address is read off the open socket and refused there, which is
    the only check left standing once resolution has been subverted.

    It must fail for that reason and not another: a closed port would refuse
    the connection first and the test would pass without the check ever
    running.
    """
    fetch = WebRetrieval(resolver=fixed_resolver("93.184.216.34"))
    result = run(fetch({"url": f"{origin}/hello"}, context()))
    assert result.reason == REASON_ADDRESS_NOT_ALLOWED


def test_the_connected_peer_check_sees_a_real_socket(origin):
    """
    The counterpart: the same lying resolver, but a policy that permits
    loopback, so the post-connect check has to be what decides. It permits it,
    which proves the check ran on a real address rather than failing open.
    """
    fetch = opener(resolver=fixed_resolver("93.184.216.34"))
    result = run(fetch({"url": f"{origin}/hello"}, context()))
    assert result.status == STATUS_COMPLETED
    assert result.output["body"] == "hello from the origin"


def test_a_redirect_into_a_blocked_range_is_refused(origin):
    """
    The hop is where a URL that passed the check becomes one that did not.
    Redirects are followed by hand for exactly this: the origin is reachable
    (loopback is permitted for this fetcher) and it points at 10.1.2.3, which
    is not.
    """
    result = run(opener()({"url": f"{origin}/redirect-to-private"}, context()))
    assert result.status == STATUS_FAILED
    assert result.reason == REASON_ADDRESS_NOT_ALLOWED


def test_a_redirect_within_policy_is_followed(origin):
    result = run(opener()({"url": f"{origin}/redirect-to-hello"}, context()))
    assert result.status == STATUS_COMPLETED
    assert result.output["body"] == "hello from the origin"
    assert result.output["redirects"] == 1
    assert result.output["final_url"].endswith("/hello")


def test_the_redirect_cap_is_enforced(origin):
    result = run(opener(max_redirects=2)({"url": f"{origin}/redirect-loop"},
                                         context()))
    assert result.reason == REASON_TOO_MANY_REDIRECTS


def test_a_redirect_with_no_location_is_not_followed(origin):
    result = run(opener()({"url": f"{origin}/no-location"}, context()))
    assert result.reason == REASON_INVALID_PAYLOAD


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "file:///var/lib/eureka/identity.key",
    "ftp://example.com/x",
    "gopher://example.com:70/_x",
    "data:text/plain,hello",
    "//example.com/no-scheme",
])
def test_non_http_schemes_are_refused(url):
    result = run(WebRetrieval()({"url": url}, context()))
    assert result.status == STATUS_FAILED
    assert result.reason == REASON_SCHEME_NOT_ALLOWED


@pytest.mark.parametrize("payload", [
    {}, {"url": ""}, {"url": "   "}, {"url": 42}, {"url": None},
    {"url": "http:///nohost"},
])
def test_a_payload_without_a_usable_url_is_refused(payload):
    result = run(WebRetrieval()(payload, context()))
    assert result.status == STATUS_FAILED
    assert result.reason == REASON_INVALID_PAYLOAD


def test_a_name_that_does_not_resolve_says_so():
    async def nxdomain(host, port):
        raise socket.gaierror("Name or service not known")

    result = run(WebRetrieval(resolver=nxdomain)(
        {"url": "http://nothing.invalid/"}, context()))
    assert result.reason == REASON_DNS_FAILED


def test_a_name_that_resolves_to_nothing_says_so():
    result = run(WebRetrieval(resolver=fixed_resolver())(
        {"url": "http://empty.example/"}, context()))
    assert result.reason == REASON_DNS_FAILED


# ---------------------------------------------------------------------------
# The fetch itself, against a real server
# ---------------------------------------------------------------------------

def test_a_permitted_fetch_returns_status_type_and_body(origin):
    result = run(opener()({"url": f"{origin}/hello"}, context()))

    assert result.status == STATUS_COMPLETED
    assert result.reason == REASON_OK
    assert result.output["http_status"] == 200
    assert result.output["content_type"].startswith("text/plain")
    assert result.output["body"] == "hello from the origin"
    assert result.output["bytes"] == len("hello from the origin")
    assert result.output["truncated"] is False
    assert result.output["redirects"] == 0


def test_an_upstream_500_is_a_successful_fetch_of_a_failing_page(origin):
    """
    The target's status is not this node's outcome. "We could not fetch" and
    "we fetched, and it said 500" are different facts and the caller needs
    both -- so the fetch completes and carries the 500.
    """
    result = run(opener()({"url": f"{origin}/boom"}, context()))

    assert result.status == STATUS_COMPLETED
    assert result.reason == REASON_OK
    assert result.output["http_status"] == 500
    assert "having a day" in result.output["body"]


def test_a_declared_oversized_body_is_refused_before_it_is_downloaded(origin):
    result = run(opener(max_body_bytes=1024)(
        {"url": f"{origin}/declared-large"}, context()))

    assert result.status == STATUS_FAILED
    assert result.reason == REASON_BODY_TOO_LARGE
    assert result.output is None


def test_a_streamed_oversized_body_is_truncated_and_says_so(origin):
    """
    Chunked, so there is no content-length to refuse on. The reader counts,
    stops at the cap, and flags it -- a peer must be able to tell a short page
    from a long one that was cut.
    """
    result = run(opener(max_body_bytes=4096)(
        {"url": f"{origin}/streamed-large"}, context()))

    assert result.status == STATUS_COMPLETED
    assert result.output["truncated"] is True
    assert result.output["bytes"] == 4096
    assert len(result.output["body"]) == 4096


def test_a_body_exactly_at_the_cap_is_not_called_truncated(origin):
    result = run(opener(max_body_bytes=len("hello from the origin"))(
        {"url": f"{origin}/hello"}, context()))
    assert result.output["truncated"] is False
    assert result.output["body"] == "hello from the origin"


def test_a_slow_target_times_out_with_a_distinct_reason(origin):
    result = run(opener(timeout_seconds=0.3)({"url": f"{origin}/slow"},
                                             context()))
    assert result.status == STATUS_FAILED
    assert result.reason == REASON_TIMEOUT
    assert result.output is None


def test_a_refused_connection_is_a_distinct_reason():
    port = free_port()   # bound, then released: nothing is listening
    result = run(opener()({"url": f"http://127.0.0.1:{port}/"}, context()))
    assert result.status == STATUS_FAILED
    assert result.reason == REASON_CONNECTION_FAILED


def test_no_failure_leaks_a_traceback_or_a_local_path(origin):
    """Every refusal is one word from a fixed vocabulary."""
    outcomes = [
        run(opener(timeout_seconds=0.3)({"url": f"{origin}/slow"}, context())),
        run(WebRetrieval()({"url": "http://127.0.0.1/"}, context())),
        run(WebRetrieval()({"url": "file:///etc/passwd"}, context())),
    ]
    for result in outcomes:
        text = str(result)
        assert "Traceback" not in text
        assert "/root" not in text
        assert "eureka_protocol" not in text


def test_the_fetch_does_not_block_the_event_loop(origin):
    """
    A slow fetch must not stop anything else running. The fetch is awaited
    while a counter ticks on the same loop; if the handler blocked, the
    counter would not move.
    """
    async def go():
        ticks = 0

        async def tick():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.01)
                ticks += 1

        ticker = asyncio.create_task(tick())
        result = await opener(timeout_seconds=1.0)(
            {"url": f"{origin}/slow"}, context())
        ticker.cancel()
        return result, ticks

    result, ticks = run(go())
    assert result.reason == REASON_TIMEOUT
    assert ticks > 10


def test_concurrent_fetches_do_not_interfere(origin):
    """Four at once, each getting its own answer rather than someone else's."""
    async def go():
        fetch = opener()
        return await asyncio.gather(
            fetch({"url": f"{origin}/hello"}, context()),
            fetch({"url": f"{origin}/boom"}, context()),
            fetch({"url": f"{origin}/redirect-to-hello"}, context()),
            fetch({"url": f"{origin}/hello"}, context()),
        )

    hello, boom, redirected, hello_again = run(go())
    assert hello.output["http_status"] == 200
    assert boom.output["http_status"] == 500
    assert redirected.output["redirects"] == 1
    assert hello_again.output["body"] == hello.output["body"]


def test_a_transport_without_a_socket_still_fetches(origin):
    """
    The post-connect check needs a real socket. A transport that exposes none
    -- a mock here, a future httpx that drops the extension -- leaves the
    pre-flight check standing alone rather than failing open or crashing.
    """
    def mock_client():
        def respond(request):
            return httpx.Response(200, text="mocked",
                                  headers={"content-type": "text/plain"})
        return httpx.AsyncClient(transport=httpx.MockTransport(respond),
                                 follow_redirects=False)

    fetch = WebRetrieval(resolver=fixed_resolver("93.184.216.34"),
                         client_factory=mock_client)
    result = run(fetch({"url": "http://public.example/"}, context()))

    assert result.status == STATUS_COMPLETED
    assert result.output["body"] == "mocked"
