"""
What this node can actually be asked to do, and the code that does it.

Until now `assign()` was a stub: it slept half a second and returned a canned
string. The gate in front of it was real -- signed request, authenticated peer,
capability grant, single-use nonce -- so the protocol could carry work, but
nothing did any. This module is the executor that gate was built for.

Two ideas, and the first one is the load-bearing one:

**A capability is a claim, and a claim needs an implementation behind it.**
`node.capabilities` is what this node advertises: it is intersected with a
peer's grants to decide what that peer may run, and it is what the trust file
is validated against. Advertising `code-exec` with nothing registered to run
it meant the node was claiming something it could not do, and the discovery of
that came at request time, to a peer that had been told yes by every gate. So
a node built with a registry validates its advertised list against it at
construction: an advertised capability with no handler is a startup error, and
`with_persistent_identity` -- the entry point a daemon uses -- always builds
with one. The daemon cannot start while it is lying about itself.

A node built with no registry at all (`handlers=None`) is the other case, and
it is not a loophole: it is every node in this codebase that is a *client*.
Such a node executes nothing, and any assign that reaches it is refused with
`capability_not_implemented` before dispatch. It cannot be a daemon, because
the daemon path supplies a registry.

**A handler failure is an outcome, not an exception.** Anything a handler can
do -- time out, be refused, hit a 500, raise something nobody predicted -- comes
back as a HandlerResult with a distinct reason. Nothing propagates out of
`run()`. A network daemon that turns an upstream timeout into a traceback has
converted somebody else's bad day into its own, and the traceback is an
information leak on top of it.

----------------------------------------------------------------------------
web-retrieval, and the SSRF problem
----------------------------------------------------------------------------

`web-retrieval` fetches a URL a peer names. That makes this node an HTTP client
pointed by somebody else, which is the classic server-side request forgery
shape: the peer cannot reach the private network this daemon sits in, but the
daemon can, so a granted peer that names `http://127.0.0.1:8443/` or
`http://192.168.1.174:8000/` is asking this node to be its proxy into a network
it was never given.

**The policy: only globally routable unicast addresses.** Loopback, private
ranges (10/8, 172.16/12, 192.168/16), link-local including 169.254.169.254,
carrier-grade NAT space, multicast, reserved and unspecified addresses are all
refused, in IPv4 and in IPv6, including IPv4-mapped IPv6 forms. `is_global` is
the single predicate; the named ranges are what it excludes. The daemon's own
API needs no special case: CT 101 answers on 192.168.1.180, which is private,
and on loopback, which is refused for the same reason.

**Enforced after resolution, not on the string.** `evil.example` resolving to
127.0.0.1 is the entire attack, so the check runs on addresses, never on the
hostname: every address `getaddrinfo` returns must pass, not merely the first.
Then it runs *again* on the address actually connected to, read back from the
socket, because a name resolved twice can resolve differently the second time
-- and httpx does its own resolution when it connects. The gap between our
lookup and its lookup is the DNS-rebinding window; checking the peer address
of the open connection before a single byte of body is read is what closes it.

**And again on every redirect.** Redirects are followed by hand, with
`follow_redirects=False`, because httpx following them internally would take
the hops without asking: a URL that passes the check and then 302s to
`http://169.254.169.254/latest/meta-data/` is the same attack with one more
step. Each hop is a fresh scheme check, a fresh resolution, and a fresh policy
decision, and there are at most `max_redirects` of them.

The rest of the limits are because this runs on a daemon and the peer chooses
the URL: a body cap (a peer must not be able to point this node at an endless
stream and make it allocate), a wall-clock timeout, and http/https only --
`file://` would read the disk, and everything else is somebody's gadget.
"""
import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

import httpx

# ---------------------------------------------------------------------------
# Outcomes
#
# One vocabulary for everything a handler can do. These are what the audit log
# records and what the caller reads; each names a decision and none of them
# carries a detail from the failure, because a detail from a failure on this
# side of the fence is this node describing its own network to a stranger.
# ---------------------------------------------------------------------------
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"

REASON_OK = "ok"
# No handler is registered for the capability. On a daemon this is unreachable
# -- startup validation refuses to advertise what it cannot run -- so seeing it
# means a node was built without an executor, and the gate let a grant through
# to nothing.
REASON_NOT_IMPLEMENTED = "capability_not_implemented"
REASON_INVALID_PAYLOAD = "invalid_payload"
REASON_SCHEME_NOT_ALLOWED = "scheme_not_allowed"
REASON_ADDRESS_NOT_ALLOWED = "address_not_allowed"
REASON_DNS_FAILED = "dns_resolution_failed"
REASON_TIMEOUT = "timeout"
REASON_TOO_MANY_REDIRECTS = "too_many_redirects"
REASON_BODY_TOO_LARGE = "body_too_large"
REASON_CONNECTION_FAILED = "connection_failed"
# The last-resort reason: a handler raised something nobody predicted. The
# exception is printed locally and never travels.
REASON_HANDLER_ERROR = "handler_error"

# Defaults for the fetch. Deliberately small: this is a peer-directed request
# on a daemon, not a browser.
MAX_BODY_BYTES = 1024 * 1024        # 1 MiB
FETCH_TIMEOUT_SECONDS = 10.0
MAX_REDIRECTS = 3
ALLOWED_SCHEMES = frozenset({"http", "https"})

# Bounds on the executor itself, independent of any one handler. The deadline
# is the wall clock a handler gets no matter what its own timeouts do; the
# concurrency cap is what stops a peer with a grant from opening as many
# sockets as it has nonces.
HANDLER_DEADLINE_SECONDS = 30.0
MAX_CONCURRENT_HANDLERS = 8


class HandlerError(Exception):
    """
    A registry misconfiguration: raised at construction, never at request time.

    Its whole purpose is to happen at startup. A node that advertises a
    capability with no handler behind it is misconfigured in a way that only
    shows up when a peer with a grant asks -- at which point the peer has
    passed every gate and gets nothing. Failing here means the daemon does not
    start, which is loud, local, and before any peer is involved.
    """


@dataclass(frozen=True)
class HandlerContext:
    """What a handler is told about the request it is running."""
    node_id: str
    capability: str
    task_name: str
    peer: Optional[str] = None


@dataclass(frozen=True)
class HandlerResult:
    """
    One handler's outcome.

    `output` is capability-specific and opaque to everything above it -- the
    node wraps it, signs it, and returns it, and the audit log never sees it.
    That is deliberate: for web-retrieval the output is somebody else's web
    page, and a page in the audit log is a page this node has published to
    every reader of the log.
    """
    status: str
    reason: str
    output: Any = None

    @property
    def ok(self) -> bool:
        return self.status == STATUS_COMPLETED


def completed(output: Any = None) -> HandlerResult:
    return HandlerResult(status=STATUS_COMPLETED, reason=REASON_OK, output=output)


def failed(reason: str, output: Any = None) -> HandlerResult:
    return HandlerResult(status=STATUS_FAILED, reason=reason, output=output)


# A handler is any async callable taking (payload, context).
Handler = Callable[[Dict[str, Any], HandlerContext], Awaitable[HandlerResult]]


# ---------------------------------------------------------------------------
# Address policy
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AddressPolicy:
    """
    Which addresses this node will fetch from.

    The default is the deployed one and it is closed: `is_global` and unicast,
    nothing else. The two flags exist so a test can point the real fetch path
    at a real server on 127.0.0.1 and exercise sockets, streaming, truncation
    and timeouts for real. They are constructor arguments rather than an
    environment variable on purpose -- an env var is a production bypass one
    typo away, and a test that has to construct its own opener cannot loosen
    the daemon's by accident.
    """
    allow_loopback: bool = False
    allow_private: bool = False

    def refusal(self, address: str) -> Optional[str]:
        """
        None if this address may be fetched from; a reason if it may not.

        IPv4-mapped IPv6 (`::ffff:127.0.0.1`) is unwrapped first: it is the
        same host reached through a different notation, and a check that reads
        only the outer form is a check with a documented bypass.
        """
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            # Not an address at all. Nothing that cannot be parsed is allowed
            # through; the caller turns this into a refusal.
            return REASON_ADDRESS_NOT_ALLOWED

        mapped = getattr(ip, "ipv4_mapped", None)
        if mapped is not None:
            ip = mapped

        if ip.is_loopback:
            return None if self.allow_loopback else REASON_ADDRESS_NOT_ALLOWED
        if ip.is_private:
            # is_private covers 10/8, 172.16/12, 192.168/16, 169.254/16,
            # 100.64/10, fc00::/7, fe80::/10 and the unspecified address.
            return None if self.allow_private else REASON_ADDRESS_NOT_ALLOWED
        if ip.is_multicast or ip.is_reserved or not ip.is_global:
            return REASON_ADDRESS_NOT_ALLOWED
        return None


async def resolve_host(host: str, port: int) -> List[str]:
    """
    Every address a host resolves to, as strings.

    On the running loop's resolver, which hands the blocking `getaddrinfo` to
    a thread -- a name server that takes two seconds must not take the event
    loop with it, and a handshake in flight must not wait behind somebody's
    DNS.
    """
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


Resolver = Callable[[str, int], Awaitable[List[str]]]


# ---------------------------------------------------------------------------
# web-retrieval
# ---------------------------------------------------------------------------

class WebRetrieval:
    """
    Fetch one URL a peer named, under limits, and hand back what came out.

    GET only. A peer that can choose the method can turn this node into a
    writer against anything it can reach, and nothing in this protocol needs
    that yet -- the day it does is the day it gets its own capability, with its
    own grant, rather than arriving as an extra field on this one.
    """

    def __init__(self, *,
                 policy: Optional[AddressPolicy] = None,
                 max_body_bytes: int = MAX_BODY_BYTES,
                 timeout_seconds: float = FETCH_TIMEOUT_SECONDS,
                 max_redirects: int = MAX_REDIRECTS,
                 resolver: Optional[Resolver] = None,
                 client_factory: Optional[Callable[[], httpx.AsyncClient]] = None):
        self.policy = policy if policy is not None else AddressPolicy()
        self.max_body_bytes = max_body_bytes
        self.timeout_seconds = timeout_seconds
        self.max_redirects = max_redirects
        self.resolver = resolver if resolver is not None else resolve_host
        self.client_factory = client_factory

    def _new_client(self) -> httpx.AsyncClient:
        if self.client_factory is not None:
            return self.client_factory()
        return httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout_seconds),
            follow_redirects=False,
            # A fresh client per request, closed when it finishes. It costs a
            # connection setup and buys the guarantee that nothing survives a
            # fetch: no pooled connection, no cookie jar, no default header
            # carried from one peer's request into the next one. This handler
            # is pointed by whoever holds the grant, and shared client state is
            # state one peer can leave behind for another to send somewhere.
        )

    async def _check_url(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """
        (refusal_reason, hostname). Scheme, shape, resolution, policy.

        Every address the name resolves to must pass, not just the first one:
        a name answering with one public and one private address would
        otherwise be a coin flip that eventually lands on the private one.
        """
        try:
            parts = urlsplit(url)
        except ValueError:
            return REASON_INVALID_PAYLOAD, None

        if parts.scheme.lower() not in ALLOWED_SCHEMES:
            return REASON_SCHEME_NOT_ALLOWED, None
        host = parts.hostname
        if not host:
            return REASON_INVALID_PAYLOAD, None
        try:
            port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
        except ValueError:
            # A port that is not a number, or out of range.
            return REASON_INVALID_PAYLOAD, None

        try:
            addresses = await self.resolver(host, port)
        except (socket.gaierror, OSError, UnicodeError):
            return REASON_DNS_FAILED, None
        if not addresses:
            return REASON_DNS_FAILED, None

        for address in addresses:
            refusal = self.policy.refusal(address)
            if refusal is not None:
                return refusal, host
        return None, host

    def _check_connected_peer(self, response: httpx.Response) -> Optional[str]:
        """
        Re-check the address actually connected to, before reading the body.

        The pre-flight check ran against our resolution; httpx then did its
        own. Between the two a name can change what it answers, which is the
        rebinding attack in one sentence. This reads the peer address off the
        open socket and applies the same policy to it.

        A transport that does not expose the socket -- a mock, or a future
        httpx that drops the extension -- returns None here, and the
        pre-flight check stands alone. That is a narrower guarantee and it is
        documented as one rather than being papered over.
        """
        stream = response.extensions.get("network_stream")
        if stream is None:
            return None
        try:
            server_addr = stream.get_extra_info("server_addr")
        except Exception:
            return None
        if not server_addr:
            return None
        return self.policy.refusal(str(server_addr[0]))

    async def __call__(self, payload: Dict[str, Any],
                       context: HandlerContext) -> HandlerResult:
        url = payload.get("url") if isinstance(payload, dict) else None
        if not isinstance(url, str) or not url.strip():
            return failed(REASON_INVALID_PAYLOAD)
        url = url.strip()

        client = self._new_client()
        try:
            return await self._fetch(client, url)
        finally:
            await client.aclose()

    async def _fetch(self, client: httpx.AsyncClient, url: str) -> HandlerResult:
        redirects = 0
        while True:
            refusal, _host = await self._check_url(url)
            if refusal is not None:
                return failed(refusal)

            try:
                async with client.stream("GET", url) as response:
                    connected_refusal = self._check_connected_peer(response)
                    if connected_refusal is not None:
                        # Resolved public, connected private: the name moved
                        # under us. Nothing is read.
                        return failed(connected_refusal)

                    if response.is_redirect:
                        location = response.headers.get("location")
                        if not location:
                            return failed(REASON_INVALID_PAYLOAD)
                        redirects += 1
                        if redirects > self.max_redirects:
                            return failed(REASON_TOO_MANY_REDIRECTS)
                        # Resolve relative locations against the current URL,
                        # then loop: the next pass re-checks scheme, addresses
                        # and policy from scratch.
                        url = str(httpx.URL(url).join(location))
                        continue

                    declared = response.headers.get("content-length")
                    if declared is not None:
                        try:
                            if int(declared) > self.max_body_bytes:
                                # Refused before the download, on the target's
                                # own word about the size.
                                return failed(REASON_BODY_TOO_LARGE)
                        except ValueError:
                            pass

                    body, truncated = await self._read_capped(response)
                    return completed(self._describe(response, body, truncated,
                                                    redirects))
            except (httpx.TimeoutException, asyncio.TimeoutError):
                return failed(REASON_TIMEOUT)
            except httpx.TooManyRedirects:
                return failed(REASON_TOO_MANY_REDIRECTS)
            except httpx.InvalidURL:
                return failed(REASON_INVALID_PAYLOAD)
            except httpx.HTTPError:
                # Connect refused, TLS failure, protocol error, a body that
                # stopped mid-stream. One reason: the specifics are this
                # node's view of a network the caller cannot see.
                return failed(REASON_CONNECTION_FAILED)

    async def _read_capped(self, response: httpx.Response) -> Tuple[bytes, bool]:
        """
        Read at most the cap, and say whether there was more.

        Streamed rather than `response.read()`, so a target that ignores its
        own content-length -- or never declares one -- cannot make this node
        hold an unbounded body. The iterator is abandoned as soon as the total
        passes the cap, and the connection closes with it.

        The loop stops on *passing* the cap rather than on reaching it, which
        is what makes `truncated` honest: a body whose last chunk lands exactly
        on the cap is complete, and one that has another chunk behind it is
        not, and the two are indistinguishable until the next read is
        attempted. The cost is that at most one chunk beyond the cap is read
        before the slice -- bounded by the transport's read size, not by
        anything the target chooses -- and it is dropped rather than returned.
        """
        chunks: List[bytes] = []
        received = 0
        truncated = False
        async for chunk in response.aiter_bytes():
            chunks.append(chunk)
            received += len(chunk)
            if received > self.max_body_bytes:
                truncated = True
                break
        return b"".join(chunks)[:self.max_body_bytes], truncated

    def _describe(self, response: httpx.Response, body: bytes,
                  truncated: bool, redirects: int) -> Dict[str, Any]:
        """
        What the peer gets back.

        The status is the target's, not ours: a 500 from the far end is a
        successful fetch of a failing page, and flattening it into a handler
        failure would lose the difference between "we could not fetch" and
        "we fetched, and it said 500". `truncated` is the other half of the
        body cap -- a peer must be able to tell a short page from a long one
        that was cut, which is why the flag travels with the body rather than
        being inferred from its length.
        """
        encoding = response.charset_encoding or "utf-8"
        try:
            text = body.decode(encoding, errors="replace")
        except LookupError:
            text = body.decode("utf-8", errors="replace")
        return {
            "http_status": response.status_code,
            "content_type": response.headers.get("content-type", ""),
            "body": text,
            "bytes": len(body),
            "truncated": truncated,
            "final_url": str(response.url),
            "redirects": redirects,
        }


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------

class HandlerRegistry:
    """
    capability name -> the code that runs it.

    Small on purpose. It holds the mapping, it validates an advertised list
    against it at startup, and it runs one handler under a deadline and a
    concurrency cap without ever raising. Everything else about a capability
    lives in the handler.
    """

    def __init__(self, *,
                 deadline_seconds: float = HANDLER_DEADLINE_SECONDS,
                 max_concurrent: int = MAX_CONCURRENT_HANDLERS):
        self._handlers: Dict[str, Handler] = {}
        self.deadline_seconds = deadline_seconds
        self.max_concurrent = max_concurrent
        # Created lazily, and per loop. A Semaphore binds itself to the loop
        # it first *waits* on -- not the one it is constructed on -- and
        # raises if it is later awaited from a different one. A registry is
        # built at import time, when there is no loop at all, and in tests it
        # outlives several. Keeping the loop it was made for, and rebuilding
        # when that changes, is what stops this from being a failure that only
        # appears under contention on the second loop, which is the worst
        # shape a bug like this could have.
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._semaphore_loop: Optional[asyncio.AbstractEventLoop] = None

    def register(self, capability: str, handler: Handler) -> "HandlerRegistry":
        """
        Add one capability. Refuses to replace an existing one.

        Silent replacement is how a node ends up running something other than
        what the operator thinks it runs -- two registrations of the same name
        in different modules, and which one wins depends on import order.
        """
        if not isinstance(capability, str) or not capability.strip():
            raise HandlerError("a capability name must be a non-empty string")
        name = capability.strip()
        if name in self._handlers:
            raise HandlerError(f"capability {name!r} is already registered")
        if not callable(handler):
            raise HandlerError(f"handler for {name!r} is not callable")
        self._handlers[name] = handler
        return self

    def get(self, capability: object) -> Optional[Handler]:
        if not isinstance(capability, str):
            return None
        return self._handlers.get(capability.strip())

    def names(self) -> frozenset:
        """Exactly what this registry can run -- and so what a node may advertise."""
        return frozenset(self._handlers)

    def validate_advertised(self, capabilities: Iterable[str]) -> None:
        """
        Every advertised capability must have a handler. Raises if not.

        The asymmetry is deliberate: a registered handler that is not
        advertised is fine -- it is code the node holds and does not offer,
        and is_permitted will refuse it anyway. An advertised capability with
        no handler is the broken direction, because a peer can be granted it.
        """
        missing = sorted(set(capabilities) - self.names())
        if missing:
            raise HandlerError(
                "advertised capabilities with no registered handler: "
                + ", ".join(missing)
                + f" (registered: {', '.join(sorted(self.names())) or 'none'})"
            )

    async def run(self, capability: object, payload: Dict[str, Any],
                  context: HandlerContext) -> HandlerResult:
        """
        Run one handler. Returns an outcome for every path, raises on none.

        The deadline is the executor's own, over and above whatever timeouts
        the handler sets for itself: a handler that forgets one, or holds a
        connection that never closes, still cannot occupy a slot forever. The
        semaphore bounds how many run at once -- the work is awaited, so the
        loop stays free for handshakes either way, but sockets and memory are
        finite in a way the event loop is not.
        """
        handler = self.get(capability)
        if handler is None:
            return failed(REASON_NOT_IMPLEMENTED)

        loop = asyncio.get_running_loop()
        if self._semaphore is None or self._semaphore_loop is not loop:
            self._semaphore = asyncio.Semaphore(self.max_concurrent)
            self._semaphore_loop = loop

        try:
            async with self._semaphore:
                return await asyncio.wait_for(handler(payload, context),
                                              timeout=self.deadline_seconds)
        except (asyncio.TimeoutError, TimeoutError):
            return failed(REASON_TIMEOUT)
        except asyncio.CancelledError:
            # The daemon is shutting down or the request was abandoned. Not an
            # outcome to invent a result for, and not ours to swallow.
            raise
        except Exception as exc:
            # Everything else, including whatever a third-party library does
            # on a bad day. Printed locally, never returned: a traceback on
            # the wire tells a peer the shape of this node's internals.
            print(f"[HANDLER] {capability} raised "
                  f"{type(exc).__name__}: {exc}")
            return failed(REASON_HANDLER_ERROR)


def default_registry(**kwargs) -> HandlerRegistry:
    """
    What a deployed daemon runs: web-retrieval, and nothing else.

    `code-exec` and `data-analysis` are deliberately absent. The gate in front
    of them is real, but there is no sandbox behind them, and registering a
    handler is exactly the act that would make a standing grant live. Because
    a node validates its advertised list against this registry, their absence
    is now enforced rather than merely intended: a daemon that advertises
    code-exec does not start.
    """
    return HandlerRegistry(**kwargs).register("web-retrieval", WebRetrieval())
