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

----------------------------------------------------------------------------
inference, and the things the caller does not get to choose
----------------------------------------------------------------------------

`inference` runs a prompt through a local Ollama and hands back the
completion. It is the mirror image of web-retrieval's problem: there the peer
names the target and the danger is where this node is pointed, here the peer
names nothing but the text, and the danger is everything it would otherwise be
able to name.

**The caller supplies a prompt. That is the whole of its input.** Not the
model, not the endpoint, not the token budget, not the sampling options, not
`keep_alive`. Every one of those is a constant in this module, and the request
body sent to Ollama is built from those constants plus one string. A model
name from the caller is the sharp one: this host has `gemma4:e4b` on disk at
9.6 GB against 8 GB of VRAM, so a caller that could name a model could order
this node to thrash, and `/api/generate` will also pull a model it does not
have -- which turns "run a prompt" into "fetch an arbitrary blob from a
registry and load it". `qwen3:8b` is hardcoded for that reason and not for
neatness.

**The endpoint is a literal loopback address, checked at construction.**
`http://127.0.0.1:11434/api/generate`, and `_require_loopback` refuses
anything else -- including the *name* `localhost`, because a name is resolved
and a resolver is a thing that can be changed. So there is no DNS in this path
at all, nothing to rebind, and no redirect following: unlike web-retrieval,
which must reason about addresses because the peer picks them, this handler
has exactly one address and cannot be argued into a second. The constructor
argument exists so a test can point it at a real server on 127.0.0.1; it
cannot reach off-host even then, and no deployed path passes one.

**Thinking is turned off, and that is a correctness fix rather than a taste.**
qwen3 is a reasoning model: left alone it spends the token budget on a
thinking block and returns an empty `response`, so a caller asking for a
completion gets `""` and no error. `"think": false` is sent with every
request. Confirmed against a live Ollama -- the same call with thinking on
returned `done_reason: "length"` and an empty string, and with it off returned
the answer.

**The prompt does not go in the audit log, and neither does the completion.**
That is not a rule this handler enforces -- it is enforced above, by
`log_event` building its entry from named scalars and never reading `payload`
or `output` -- but it is the reason this capability can exist at all. A prompt
is at least as sensitive as a fetched page and usually more so, because it was
written by the peer rather than published by a stranger. Nothing here prints
it either: the registry's last-resort handler prints an exception's type and
message, so the rule for this file is that no exception it raises may carry
the prompt.

**Ollama being up is not something this node can promise at construction.**
See `HandlerError`'s docstring and the note on `default_registry`: the
registry's startup check is static -- does code exist for what is advertised
-- and a live upstream is not a static property. The dynamic half is checked
by `deploy/wsl-preflight.sh` before the daemon starts, and what remains after
that is a service that can die at 03:00, which is why `upstream_unavailable`
exists as an outcome.
"""
import asyncio
import ipaddress
import math
import os
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
# inference. Four outcomes that a caller can act on differently, which is the
# whole reason they are not one reason with a message attached:
#   prompt_too_long      -- your fault, and shortening it fixes it
#   upstream_unavailable -- this node's Ollama is not answering at all
#   model_not_available  -- Ollama is up and does not have the model
#   upstream_error       -- Ollama answered, and the answer was not usable
# The last two are worth telling apart because only one of them is fixed by an
# operator running `ollama pull` on this host.
REASON_PROMPT_TOO_LONG = "prompt_too_long"
REASON_UPSTREAM_UNAVAILABLE = "upstream_unavailable"
REASON_MODEL_NOT_AVAILABLE = "model_not_available"
REASON_UPSTREAM_ERROR = "upstream_error"
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

# ---------------------------------------------------------------------------
# inference: the constants a caller cannot reach
#
# Every one of these is here rather than in the payload, and the docstring
# above says why for each. The numbers are chosen for the host that runs this
# -- an RTX 3070 mobile with 8 GB of VRAM, holding qwen3:8b at 5.2 GB -- and
# they are deliberately conservative, because this is a network daemon and the
# thing being bounded is what one granted peer can order per request.
# ---------------------------------------------------------------------------
OLLAMA_ENDPOINT = "http://127.0.0.1:11434/api/generate"
INFERENCE_MODEL = "qwen3:8b"

# 4000 characters, roughly 1000-1400 tokens: far inside qwen3's context window,
# so a long prompt is refused here rather than silently truncated by the model
# where nobody would see it happen. Measured in characters and not bytes,
# because characters are what map to tokens; the byte size is bounded anyway by
# api.py's 64 KiB cap on the request body, which refuses an oversized prompt
# one layer earlier and without parsing it.
MAX_PROMPT_CHARS = 4000

# The real lever on how long a request takes, since generation time is close to
# linear in tokens produced. 512 tokens at the ~30-40 tok/s this GPU does on an
# 8B model is 13-17 seconds of generation.
MAX_COMPLETION_TOKENS = 512

# A second, independent bound on what comes back, in case a model ignores
# num_predict. `truncated` in the output is how the caller can tell.
MAX_COMPLETION_CHARS = 8000

# Two seconds to connect: the endpoint is loopback, so a connect that does not
# complete essentially instantly means nothing is listening, and waiting longer
# only delays a refusal this node already knows it will give.
INFERENCE_CONNECT_TIMEOUT_SECONDS = 2.0

# 75 seconds for the whole exchange. A cold start dominates it: qwen3:8b is
# 5.2 GB, and the first request after the model is evicted pays for loading it
# from disk into VRAM before a single token is generated.
INFERENCE_TIMEOUT_SECONDS = 75.0

# The registry deadline this capability runs under, and it must stay ABOVE the
# handler's own timeout. If the deadline fired first, every slow inference
# would come back as the registry's generic `timeout` and the handler's own
# reasons would become unreachable -- the outcomes would still be safe and
# would stop being informative, which is the failure mode nobody notices.
# 90 > 75 leaves the handler room to lose first and say why.
INFERENCE_DEADLINE_SECONDS = 90.0

# Set this in the unit file on a host that has Ollama. Unset means the
# capability is not registered, not advertised, and not runnable -- see
# `default_registry`.
INFERENCE_ENV = "EUREKA_INFERENCE"


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
# inference
# ---------------------------------------------------------------------------

def _require_loopback(endpoint: str) -> str:
    """
    The endpoint must be a literal loopback address. Raises if it is not.

    A construction-time check, so a mistake here is a startup error on the host
    that made it rather than a request-time surprise on a node somebody trusts.

    A *name* is refused along with everything else, `localhost` included. That
    looks pedantic and is not: a name is resolved, a resolver reads
    /etc/hosts and then the network, and this handler's whole claim is that it
    has no DNS in it and therefore nothing to rebind. Requiring the literal
    address is what makes that claim checkable instead of customary.
    """
    parts = urlsplit(endpoint)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise HandlerError(
            f"inference endpoint {endpoint!r} must be http or https"
        )
    host = parts.hostname
    if not host:
        raise HandlerError(f"inference endpoint {endpoint!r} names no host")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise HandlerError(
            f"inference endpoint {endpoint!r} names a host rather than a "
            f"literal address; this handler resolves nothing, so give it "
            f"127.0.0.1 (not localhost)"
        ) from None
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if not ip.is_loopback:
        raise HandlerError(
            f"inference endpoint {endpoint!r} is not loopback; this handler "
            f"talks to an Ollama on this host and to nothing else"
        )
    return endpoint


class OllamaInference:
    """
    Run one prompt through the local Ollama and return the completion.

    The payload contributes a prompt and nothing else. Extra keys in it are not
    rejected, they are simply never read -- which is the property worth having,
    because "the request body is built from constants plus one string" is
    easier to verify than a list of keys somebody has to remember to keep
    refusing.

    Every constructor argument has a deployed default and no deployed caller
    passes one; they exist so tests can point this at a fake Ollama on
    127.0.0.1 and drive the real socket paths. `endpoint` is checked against
    loopback either way, so even a test cannot widen it into a network client.
    """

    def __init__(self, *,
                 endpoint: str = OLLAMA_ENDPOINT,
                 model: str = INFERENCE_MODEL,
                 max_prompt_chars: int = MAX_PROMPT_CHARS,
                 max_completion_tokens: int = MAX_COMPLETION_TOKENS,
                 max_completion_chars: int = MAX_COMPLETION_CHARS,
                 timeout_seconds: float = INFERENCE_TIMEOUT_SECONDS,
                 connect_timeout_seconds: float = INFERENCE_CONNECT_TIMEOUT_SECONDS,
                 client_factory: Optional[Callable[[], httpx.AsyncClient]] = None):
        self.endpoint = _require_loopback(endpoint)
        self.model = model
        self.max_prompt_chars = max_prompt_chars
        self.max_completion_tokens = max_completion_tokens
        self.max_completion_chars = max_completion_chars
        self.timeout_seconds = timeout_seconds
        self.connect_timeout_seconds = connect_timeout_seconds
        self.client_factory = client_factory

    def _new_client(self) -> httpx.AsyncClient:
        if self.client_factory is not None:
            return self.client_factory()
        return httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout_seconds,
                                  connect=self.connect_timeout_seconds),
            # Nothing is followed. Ollama does not redirect, and a redirect
            # arriving from something claiming to be Ollama is either a
            # misconfiguration or the one way this fixed endpoint could be
            # turned into a variable one.
            follow_redirects=False,
        )

    def request_body(self, prompt: str) -> Dict[str, Any]:
        """
        Exactly what goes to Ollama. One caller-supplied value, by construction.

        Public, and not for tidiness: `deploy/wsl-preflight.sh` builds its
        startup probe from this method so that what it proves at boot is the
        request the daemon actually makes. A preflight that checks a request
        nobody sends is a preflight that goes green while the real call is
        being refused.

        `think: false` is not optional -- see the module docstring. `keep_alive`
        is deliberately absent: how long this host keeps 5.2 GB resident is an
        operator's decision about the machine, not a peer's about its request,
        and Ollama's own default is the operator's to change.
        """
        return {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "think": False,
            "options": {"num_predict": self.max_completion_tokens},
        }

    async def __call__(self, payload: Dict[str, Any],
                       context: HandlerContext) -> HandlerResult:
        prompt = payload.get("prompt") if isinstance(payload, dict) else None
        if not isinstance(prompt, str) or not prompt.strip():
            return failed(REASON_INVALID_PAYLOAD)
        prompt = prompt.strip()
        if len(prompt) > self.max_prompt_chars:
            # The length is not echoed back and neither is the prompt. The
            # caller knows what it sent; the cap is documented; and a daemon
            # that quotes the input back in a refusal is a daemon that logs
            # and returns input on a path that was supposed to have neither.
            return failed(REASON_PROMPT_TOO_LONG)

        client = self._new_client()
        try:
            return await self._generate(client, prompt)
        finally:
            await client.aclose()

    async def _generate(self, client: httpx.AsyncClient,
                        prompt: str) -> HandlerResult:
        try:
            response = await client.post(self.endpoint,
                                         json=self.request_body(prompt))
        except (httpx.TimeoutException, asyncio.TimeoutError):
            return failed(REASON_TIMEOUT)
        except httpx.ConnectError:
            # Loopback refusing a connection means the service is not there.
            # This is the one that says "start Ollama", and it is separated
            # from every other transport failure because it is the only one an
            # operator can act on without looking anything up.
            return failed(REASON_UPSTREAM_UNAVAILABLE)
        except httpx.HTTPError:
            return failed(REASON_CONNECTION_FAILED)

        if response.status_code == 404:
            # Ollama's answer for a model it does not hold, confirmed against a
            # live instance: 404 with {"error": "model '...' not found"}. It is
            # not an error in the request and it is not the service being down,
            # so it gets its own reason and an operator gets `ollama pull`.
            return failed(REASON_MODEL_NOT_AVAILABLE)
        if response.status_code != 200:
            # A 400 (the model cannot generate, or rejects `think`), a 500, or
            # anything else. One reason: the body of Ollama's error is this
            # node's view of its own machine and does not travel.
            return failed(REASON_UPSTREAM_ERROR)

        try:
            data = response.json()
        except ValueError:
            return failed(REASON_UPSTREAM_ERROR)
        if not isinstance(data, dict):
            return failed(REASON_UPSTREAM_ERROR)

        completion = data.get("response")
        if not isinstance(completion, str):
            # Including the case where Ollama returned 200 with an "error"
            # key. A non-string completion is not a completion.
            return failed(REASON_UPSTREAM_ERROR)

        truncated = len(completion) > self.max_completion_chars
        if truncated:
            completion = completion[:self.max_completion_chars]
        return completed(self._describe(data, completion, truncated))

    def _describe(self, data: Dict[str, Any], completion: str,
                  truncated: bool) -> Dict[str, Any]:
        """
        What the peer gets back.

        `truncated` and `done_reason` are two different ways of being cut short
        and the caller needs both: `truncated` is this node's character cap,
        `done_reason: "length"` is the token budget, and a completion can hit
        either without hitting the other. `model` is echoed because the caller
        did not choose it and is entitled to know what answered.
        """
        # Both are typed on the way out rather than passed through. Ollama is
        # local and trusted here, so this is not defence against it -- it is
        # the same rule the rest of this file follows: what leaves this node is
        # built, not forwarded, so a field that changes shape upstream cannot
        # change the shape of what a peer receives.
        eval_count = data.get("eval_count")
        done_reason = data.get("done_reason")
        return {
            "model": self.model,
            "completion": completion,
            "chars": len(completion),
            "truncated": truncated,
            "done_reason": done_reason if isinstance(done_reason, str) else None,
            "eval_count": eval_count if isinstance(eval_count, int) else None,
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

    The deadline is per capability, falling back to the registry's own. It was
    one number for everything until inference arrived, and the reason it could
    not stay one number is that 30 seconds was chosen for an HTTP fetch: a
    model that has to be loaded into VRAM before it generates its first token
    does not fit in it, and raising the shared number to fit would hand
    web-retrieval a 90-second window it has no use for -- meaning a wedged
    fetch would sit in a concurrency slot three times as long for the sake of a
    capability it is not. How long work may take is a property of the work.
    """

    def __init__(self, *,
                 deadline_seconds: float = HANDLER_DEADLINE_SECONDS,
                 max_concurrent: int = MAX_CONCURRENT_HANDLERS):
        self._handlers: Dict[str, Handler] = {}
        self._deadlines: Dict[str, float] = {}
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

    def register(self, capability: str, handler: Handler, *,
                 deadline_seconds: Optional[float] = None) -> "HandlerRegistry":
        """
        Add one capability. Refuses to replace an existing one.

        Silent replacement is how a node ends up running something other than
        what the operator thinks it runs -- two registrations of the same name
        in different modules, and which one wins depends on import order.

        `deadline_seconds` overrides the registry's own for this capability.
        None means the shared default, which is what everything but inference
        wants.
        """
        if not isinstance(capability, str) or not capability.strip():
            raise HandlerError("a capability name must be a non-empty string")
        name = capability.strip()
        if name in self._handlers:
            raise HandlerError(f"capability {name!r} is already registered")
        if not callable(handler):
            raise HandlerError(f"handler for {name!r} is not callable")
        if deadline_seconds is not None:
            # bool before int, because True is an int and a deadline of one
            # second is not what anybody typing True meant. Finite, because
            # `inf` would silently disable the deadline -- the one setting
            # whose whole job is to be there -- and `nan` compares false
            # against everything, so neither is caught by a range test.
            if (isinstance(deadline_seconds, bool)
                    or not isinstance(deadline_seconds, (int, float))
                    or not math.isfinite(deadline_seconds)
                    or deadline_seconds <= 0):
                raise HandlerError(
                    f"deadline for {name!r} must be a positive, finite number "
                    f"of seconds, got {deadline_seconds!r}"
                )
            self._deadlines[name] = float(deadline_seconds)
        self._handlers[name] = handler
        return self

    def deadline_for(self, capability: object) -> float:
        """How long this capability gets, falling back to the registry's own."""
        if isinstance(capability, str):
            return self._deadlines.get(capability.strip(), self.deadline_seconds)
        return self.deadline_seconds

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
        connection that never closes, still cannot occupy a slot forever. It
        is the capability's if it has one -- see `register` -- and the
        registry's otherwise. The semaphore bounds how many run at once -- the
        work is awaited, so the loop stays free for handshakes either way, but
        sockets and memory are finite in a way the event loop is not.
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
                return await asyncio.wait_for(
                    handler(payload, context),
                    timeout=self.deadline_for(capability))
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


# Values accepted for INFERENCE_ENV, and nothing else is guessed at.
_TRUTHY = frozenset({"1", "true", "yes", "on"})
_FALSY = frozenset({"0", "false", "no", "off", ""})


def inference_enabled(environ: Optional[Dict[str, str]] = None) -> bool:
    """
    Whether this host offers inference. Unset means no.

    An unrecognised value raises rather than being read as either answer.
    Defaulting it to off would be the quiet failure -- a typo'd `EUREKA_INFRENCE`
    or a value of "yes please" would leave the daemon running and no longer
    advertising a capability it was deployed to serve, which looks like a
    working node right up until a peer asks. Defaulting it to on is worse.
    So it is neither, and the daemon does not start.
    """
    source = os.environ if environ is None else environ
    raw = source.get(INFERENCE_ENV, "")
    value = raw.strip().lower()
    if value in _TRUTHY:
        return True
    if value in _FALSY:
        return False
    raise HandlerError(
        f"{INFERENCE_ENV}={raw!r} is neither on nor off; use one of "
        f"{sorted(_TRUTHY)} or leave it unset"
    )


def default_registry(*, inference: Optional[bool] = None,
                     **kwargs) -> HandlerRegistry:
    """
    What a deployed daemon runs: web-retrieval always, inference where it can.

    `code-exec` and `data-analysis` are deliberately absent. The gate in front
    of them is real, but there is no sandbox behind them, and registering a
    handler is exactly the act that would make a standing grant live. Because
    a node validates its advertised list against this registry, their absence
    is now enforced rather than merely intended: a daemon that advertises
    code-exec does not start.

    **inference is per host, because Ollama is per host.** CT 101 has no
    Ollama; WSL does. Registering it unconditionally would make CT 101
    advertise a capability it cannot serve, which is precisely the lie
    `validate_advertised` exists to prevent, only moved one level down where
    that check cannot see it -- the handler would exist, so the static check
    would pass, and the discovery would come at request time. So the decision
    is read from the environment, where the unit file sets it, alongside the
    identity and trust paths that are host-specific for the same reason.

    Reading it here rather than at each call site is what keeps the answers
    consistent: api.py builds the daemon's node from this, and
    `wsl-preflight.sh` derives the advertised list from this, and the two
    cannot disagree about a host because they ask the same function on it.

    What this still cannot promise is that Ollama is *up* -- that is a
    liveness property and this is a construction-time check. The preflight
    tests the live service before the daemon starts; after that, an Ollama
    that dies is `upstream_unavailable` on the next request, which is the
    honest floor rather than a gap.
    """
    if inference is None:
        inference = inference_enabled()
    registry = HandlerRegistry(**kwargs).register("web-retrieval",
                                                  WebRetrieval())
    if inference:
        registry.register("inference", OllamaInference(),
                          deadline_seconds=INFERENCE_DEADLINE_SECONDS)
    return registry
