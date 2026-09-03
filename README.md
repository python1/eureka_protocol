# Eureka Protocol

A daemon and wire protocol for two agents on separate machines to authenticate
each other directly, without a third party holding the directory of who talks
to whom.

## What it is

Eureka is a small Python daemon that gives an agent a long-lived cryptographic
identity and lets it prove that identity to another agent over the network.
Each node holds an ed25519 keypair and a local file listing the public keys it
is willing to talk to. Two nodes authenticate by exchanging three signed
messages; if either side's key is missing from the other's list, the exchange
is refused. There is no registry to publish to, no broker to route through, and
no bootstrap server to ask. A node knows the peers its operator told it about,
and nothing else.

That constraint is the point rather than a limitation to be engineered away.
In settings where a client list is itself confidential — legal, medical,
accounting — the fact that two particular parties are in contact can be more
sensitive than the content of what they exchange, and it is exactly the fact
that a central directory would have to hold in order to be useful. The same
settings usually forbid the data leaving the network at all. Eureka is built
for deployments inside one network perimeter, where the operator provisions
trust by hand and no component outside that perimeter learns the shape of the
mesh.

This is a different shape of problem than the existing agent protocols solve.
MCP standardises how one agent reaches tools and data sources; the relationship
it describes runs between an agent and its own resources, not between two peer
agents belonging to different parties. A2A does address agent-to-agent work,
but assumes agents can be found — published agent cards, a discoverable
endpoint, a place to look peers up. Eureka assumes neither: no tool-hosting
relationship and no discoverable registry. What it assumes instead is an
operator willing to exchange public keys out of band, which is a real cost and
is the trade this design accepts in return for having no directory anywhere.

That distinction stopped being theoretical on 2026-08-29. A Hermes Agent on one
machine now fetches pages through a Eureka peer on another, and the two
protocols sit in exactly the layering described above: MCP carries the
relationship between the agent and its own tools — a local server it launches
and trusts implicitly — while Eureka carries the relationship between that
machine and a peer it has no authority over, where every request is signed,
every grant is checked, and the answer comes back signed in its own domain. The
agent asks its tool; the tool asks a stranger. Neither protocol is doing the
other's job, and neither could.

## What works today

The suite is 616 tests, all passing. Each item below is implemented and
covered; where something is narrower than its name suggests, that is stated.

### Identity

An ed25519 keypair persisted as a versioned JSON document. The `node_id` is
derived from the public key (`node_` plus the first 8 hex of its SHA-256), so a
restarted daemon comes back as the same node rather than minting a new one, and
an id cannot be claimed independently of the key behind it.

Secrets are written through a single atomic writer at mode 0600 into a 0700
directory — write to a temp file in the destination directory, fsync, rename —
so a crash cannot leave a truncated key and the bytes are never briefly
world-readable. On load, a file whose mode has been widened to group- or
world-accessible is refused rather than used. Saving over an existing identity
requires an explicit `overwrite`.

Rotation generates a fresh keypair and archives the outgoing one under the same
0600 protections; the retired key is never deleted, since it is the only thing
that can verify signatures it made while live. Rotation refuses when there is
no identity at the given path, so a mistyped path cannot silently mint a new
node instead of rotating the real one.

### Mutual handshake

Three messages. The initiator signs its own challenge; the responder verifies
it, checks its trust list, and replies with a signature over that challenge
plus a counter-challenge of its own; the initiator signs the counter-challenge.
Each side records the other only after its own verification passes.

Every signature in the protocol is computed over a context tag, a NUL byte, and
a canonical JSON encoding (sorted keys, no whitespace). The three handshake
positions have three distinct tags, as do discovery queries and audit-log
entries, so a signature harvested from one context verifies over different
bytes in another and fails. The canonical encoder is shared by signer and
verifier, since a divergence there would break every signature silently.

Replay is handled on both sides: a nonce is single-use, and one that has
already been spent is rejected with a distinct reason. A challenge older than
the freshness window (30s by default, per-node configurable) is rejected even
if its signature is perfect. The pending-challenge and seen-nonce tables have
hard caps with oldest-first eviction — age pruning alone does not bound memory,
because an attacker can request many challenges that are all legitimately
fresh.

Several checks exist specifically to stop identities being mixed mid-exchange:
the envelope and the signed body must agree on who is calling, the responder
must be the peer that was addressed, and the key that completes the handshake
must be the key that opened it. Anything that is not a well-formed challenge is
never signed, so the handshake endpoint cannot be used as a signing oracle for
arbitrary payloads.

Over HTTP the exchange runs against two endpoints. Bodies are read under a
64 KB cap, abandoned mid-stream once the cap is passed, and parsed by hand
rather than through a schema model — a model would coerce and re-shape the
payload, and the payload is the exact byte sequence a signature covers. A
completed exchange returns 200 whatever the verdict, because an authentication
failure is a protocol outcome and not a transport error. An unhandled error at
that boundary returns a generic refusal rather than a traceback.

### Trust allowlist

A JSON file mapping a human label to a public key and its grants. Every lookup
is by key, never by label: the key is what the handshake proved, and keying
authorisation any other way would let the two drift apart. An absent file is a
legitimate state and yields an empty allowlist, which trusts nobody. A file
that exists but is corrupt raises rather than degrading into an empty list —
"trusts nobody" and "failed to deploy" must not look the same.

The format is versioned, and each version accepts only its own entry shape, so
a half-finished migration fails at startup instead of granting something the
file's declared version cannot express. Two labels sharing one key is an error;
so is one label carrying two keys.

### Capability grants

Grants are per-peer, keyed by public key, and default-deny. Two gates must both
pass: the peer's key holds the grant, and this node actually advertises that
capability. The second gate means a stale or over-broad trust file cannot widen
what a peer can reach beyond what the node offers. A grant naming a capability
the node does not advertise is a load-time error, so a typo fails at startup
rather than sitting in the file looking effective.

Authorisation reads the live trust list, not the snapshot taken when the peer
handshaked, so withdrawing a grant takes effect without waiting for the peer to
reconnect.

This function now has a real caller: the assign endpoint consults it on every
request, after authentication and before anything is dispatched — see the
next section. What sits behind it is no longer a stub either: the grant gates
a registry of handlers, and two capabilities are implemented — `web-retrieval`
everywhere, and `inference` on a host that has a local Ollama to run it.

The advertised list is not written down twice. A node built with a handler
registry takes its capabilities from that registry, or is checked against it —
advertising something with no handler behind it is a construction error, which
on the daemon path is a startup error. A node cannot claim what it cannot do,
so the second gate above is now a statement about running code rather than
about a list somebody maintained by hand.

### The assign gate, and the executor behind it

`/v1/assign` was the last open endpoint on the daemon. It now takes a signed,
single-use request through the same gate the reads use, and adds the two
things a read does not need. First, authorization after authentication: the
request names a capability, and `is_permitted` — default deny, both of its
gates — decides whether this caller may run it. An authenticated, trusted
peer without the grant is refused with its own distinct reason, and a grant
for one capability confers nothing about another. Second, replay protection:
every request carries a nonce, spent on first authenticated sighting whatever
the verdict, so a captured request cannot be executed twice and a captured
refusal cannot be resubmitted to probe whether a grant has since appeared.
Within the freshness window the nonce table refuses the replay; past it, the
timestamp is already stale. The table is separate from the handshake's, so an
assign request quoting a handshake nonce cannot poison the handshake's own
replay protection.

The refusal discloses the decision and nothing else — no echo of what was
asked, no capability list, and no distinction between "not granted" and "not
offered", so it cannot be used to enumerate what this node advertises. Every
decision about an authenticated caller lands in the audit log attributed to
that caller, granted or refused, and a peer can read its own refusals back
through the log endpoint; unauthenticated noise is not logged, because an
unverified requester_id is a claim and attributing entries to claims would let
anyone write history under anyone's name.

The request has its own signing domain. An assign signature verifies in no
other domain and no other domain's signature verifies as an assign — a
signature minted to look at the peer table must be structurally unusable as a
request to execute something. The answer has a domain of its own in the other
direction: the responder signs the result it produced, so a peer keeps evidence
of what it was told rather than a string it has to take on trust, and the
signed payload carries the request's nonce and requester so a result cannot be
lifted onto a different request. Refusals stay unsigned — they are a constant
built from the reason alone, and a signature would make them tellable apart
without attesting to anything.

Behind the gate is a handler registry: capability name to the code that runs
it. A handler failure is an outcome rather than an exception — a timeout, a
refused URL, an upstream 500 and a handler that raised each come back as a
structured result with its own reason, and nothing propagates to the caller.
The gate's verdict and the work's verdict stay separate: a fetch this node
declined to make is still a request it accepted, which is a different fact from
a peer that may not ask.

Every decision lands in the audit log with the capability, the requesting peer
and the outcome — and never the request or the result. For `web-retrieval` the
result is somebody else's web page; for `inference` the request is a peer's
prompt and the result is a model's answer to it. Copying either into a signed,
peer-readable log would republish it under this node's name, so the entry is
assembled from named scalars — who asked, which capability, what came of it —
and never from the payload or the result.

### web-retrieval

It fetches a URL a peer names and returns the
status, content type and body, under limits that exist because the peer chooses
the URL: a body cap, a wall-clock timeout, a redirect cap, and http/https only.
A body over the cap is refused when the target declares the size and truncated
with a flag when it does not, so a short page and a cut one are never
confusable.

Pointing a daemon at a URL somebody else chose is server-side request forgery
waiting to happen — the peer cannot reach the network this node sits in, but
this node can. **The policy is that only globally routable unicast addresses
may be fetched:** loopback, private ranges, link-local (including the cloud
metadata address), carrier-grade NAT, multicast, reserved and unspecified
addresses are refused, in IPv4 and IPv6 and in IPv4-mapped form. The daemon's
own API needs no special case, since every address it answers on is already in
one of those ranges.

That check runs on addresses, never on the URL string: a hostname resolving
into a blocked range is the whole attack, so every address the name resolves to
must pass, not merely the first. It runs again on the address actually
connected to, read back from the open socket before any body is read, because
the HTTP client resolves the name a second time and a name can answer
differently the second time. And it runs again on every redirect — hops are
followed by hand precisely so that a URL which passes and then redirects into
the private network is refused at the hop.

### inference

It runs a prompt through a local Ollama and returns the completion. The two
capabilities have opposite shapes and it is worth saying why. `web-retrieval`
lets the peer choose the target, so almost all of its design is about where
this node may be pointed. `inference` lets the peer choose **nothing but the
text**: the model, the endpoint, the token budget, the sampling options and
the model's residency are all constants in the module, and the request sent to
Ollama is those constants plus one string.

That is not fastidiousness. A caller that could name a model could name one
larger than this host's VRAM, and Ollama will *pull* a model it does not have
— which turns "run my prompt" into "fetch an arbitrary blob from a registry
and load it". The endpoint is a literal loopback address, checked at
construction and refusing even the name `localhost`, because a name is
resolved and this handler's claim is that it resolves nothing. So there is no
DNS in the path, nothing to rebind, and no redirect to follow: where
web-retrieval must reason carefully about addresses, this handler has exactly
one and cannot be argued into a second.

The limits are a maximum prompt length, a maximum number of generated tokens,
and a timeout — the last of which is longer than a fetch's, because a model
that has to be loaded into VRAM before it emits a token does not fit in a
fetch's budget. That is why the executor's deadline became per capability
rather than one number: raising the shared one to fit a model load would have
handed `web-retrieval` a window three times longer than it has any use for.
Every failure is a distinct outcome — the prompt was too long, Ollama is not
answering, Ollama does not have the model, Ollama answered with something
unusable, it took too long — because those have different fixes and only one
of them is the operator's.

**Whether a node offers it is a property of the host, not of the code.**
Ollama is installed on some machines and not others, so registering the
handler unconditionally would make a machine without one advertise a
capability it cannot serve — the same lie the registry's startup check exists
to prevent, moved somewhere that check cannot see it. The host declares it,
the daemon's unit file is where it declares it, and an unrecognised value
stops the daemon rather than being read as either answer.

What that still cannot promise is that Ollama is *running*: the registry's
check is static, and liveness is not. The deployment's preflight closes that
by making the exact call the handler makes before the daemon starts, so a
missing service or an unpulled model is a start failure with a reason in the
journal. After that, an Ollama that dies is `upstream_unavailable` on the next
request, which is the honest floor rather than a gap.

`code-exec` and `data-analysis` have no handlers, deliberately, and so are not
advertised at all. Registering a handler is the act that makes a standing grant
live; see the note below.

### Revocation and rotation

Revoking a key is a separate act from deleting its entry. A deleted key returns
the moment someone restores an old trust file from backup; a revoked key stays
refused, records why and when, and cannot be re-added — the revocation wins,
loudly. Revoking a key that was never trusted is allowed, and is how an
operator ensures a key they were merely offered can never be provisioned by
mistake. The trusted and revoked tables are kept disjoint by construction, so
there is never a contradiction for a caller to resolve.

Rotating a peer onto a new key is one operation, not an add followed by a
revoke: doing it in two steps leaves a window where both keys authenticate, and
if the second step fails the window never closes. Grants carry across, because
a rotation replaces a peer's key and not its role.

A revocation reaches a running daemon through `reload_trust()`, which drops
peers whose key is now revoked or simply no longer listed, rather than leaving
them sitting in the peer table marked authenticated. A bad file raises and
keeps the old list, which is the honest failure: the revocation has *not* been
applied and the caller must not treat that as a warning. A `revoked` list in a
file declaring a version too old to express one is a load error, never a
quietly ignored field — every other compatibility rule here fails closed, and
that one would fail open with an operator believing a compromised key is dead.

### Pinned TLS

TLS carries the identity the node already has instead of introducing a second
one. The certificate is a self-signed wrapper around the node's existing
ed25519 key, and the client verifies it by pinning: it extracts the raw public
key from the certificate and checks it against the same trust list, with the
same revocations, that the handshake consults. No certificate authority is
involved and nothing new has to be distributed. The subject name is decorative
and hostname checking is off, because there is nothing in the name worth
checking — the key is the identity.

This is narrower than default verification, not weaker: the default context
accepts any of several hundred public CAs, while this one accepts exactly the
keys an operator listed. Minimum version is TLS 1.3. The pin is applied on
every response in the exchange, not only the first, since without connection
reuse a later request may arrive over a connection that has not earned it.

The channel is also bound to the identity: the key that terminated TLS must be
the key that signed the handshake. Without that check a peer you trust could
terminate TLS and relay a *different* trusted peer's exchange — both keys pass
their own check individually, and you would finish authenticated to one
identity over a channel held by another.

The certificate is regenerated whenever the one on disk does not wrap the
current identity key, which is what makes rotation safe; serving a stale
certificate would present peers with a key the node can no longer prove it
holds. A daemon can serve plaintext, TLS, or both from one process sharing one
node — two processes under one identity would keep two independent replay
tables and two peer tables.

### Gossip discovery

Nodes learn *where* peers are without learning *who* to trust. A query is
signed, carries a freshness timestamp, and is answered only for a caller that
is trusted, unrevoked, and has actually completed a handshake under the key it
is asking with — an unauthenticated caller gets nothing whatever it asks for.

Three rules hold: an address is never a trust decision, so learning one grants
nothing and an address for an untrusted or revoked key is dropped without
comment and cannot even be stored; an address is advice until a handshake
against it authenticates the key it was filed under, so a peer that gossips a
wrong address costs one failed connection and moves no trust; and nothing
outside the configured entry points is ever contacted. In a discovery round the
handshake happens *before* the query is sent, because the query names the keys
this node trusts and sending it first would hand that list to whoever picked
up.

The address table is bounded per-key and overall, expires unconfirmed entries,
caps address length, and accepts only `http` and `https` — a gossiped `file://`
or `unix://` can never be dialled. Revoking a peer stops its whereabouts being
disclosed immediately, with no separate cleanup step, because the table holds
no trust of its own and every check reads the live trust list.

One honest limit on scope: the daemon serves the responder side of discovery,
but the initiating round is a library function with no daemon loop, schedule,
or bootstrap configuration behind it. Deployed nodes are still pointed at each
other by hand.

### Authenticated reads

The peer table, the audit log and the full manifest are served only to a
caller that has completed a handshake, through the same gate discovery uses —
one implementation, in `signed_request.py`, rather than a second copy that
could grow a hole the first one does not have. A read is a POST carrying a
signed query, because a signature is what makes a caller someone; a GET on
those paths is refused by the router before any handler consults anything.

Three properties hold, and each is pinned by a test that has been watched
fail:

  * **A refusal discloses nothing.** It is built from the requested event and
    the rejection reason alone, without the peer table, the log, or their
    sizes being consulted. Two nodes identical but for their peer tables —
    one with peers, one that has never seen anyone — return byte-identical
    refusals to the same stranger.
  * **An authenticated caller sees only what it already knows about.** This is
    discovery's rule applied to the peer table: the caller names the public
    keys it is asking about and the answer covers only those, so
    authenticating to one node does not enumerate the mesh behind it. An
    audit-log entry is disclosed only to the peer its signed payload names.
  * **A connection is not an identity.** Terminating TLS proves only that a
    caller holds some key, and the daemon requests no client certificate, so
    on the server side a TLS peer is anonymous. Being on the trust list is not
    enough either: a trusted peer that has not handshaked is refused, and a
    peer that handshaked under one key cannot read under another.

Read access ends when trust does. The gate consults the live trust list, and
`reload_trust()` drops revoked peers from the table it checks against, so a
revocation closes reads at the same moment it closes everything else.

## What it deliberately does not do

**No trust-on-first-use.** A key is trusted because an operator put it in the
file, and there is no code path that adds one any other way and no switch to
turn the check off. The handshake never writes to the trust list; a peer cannot
talk its way onto it. This is why there is also no signed "here is my new key"
message that peers act on by themselves — a stolen key would use it to rotate
the thief into permanent trust, which is trust-on-first-use wearing a hat. Key
rotation is therefore an out-of-band re-provisioning step, and that cost is
accepted.

**No central broker.** Nothing sits between two nodes. This removes the
component that would otherwise hold the one piece of metadata the project
treats as sensitive — the map of who talks to whom — and it removes it by not
existing, rather than by promising not to look. The cost is real and is not
hidden: provisioning is manual, there is no place to look a peer up, and a mesh
of any size becomes an operator's problem.

**No code execution.** `web-retrieval` and `inference` are implemented;
`code-exec` is not, and is not advertised. Inference is not an exception to
this: it runs a fixed local model over text and executes nothing the peer
supplies. Running code a peer asked for, over a network, with no
sandbox is the one part of this design that fails catastrophically rather than
gracefully, and it stays unbuilt until there is an isolation boundary to put it
behind. The gate in front of it has been real for some time — the order was
deliberate, since an execution endpoint that grows authentication later starts
life as the hole in the fence — but a gate is not a sandbox, and the day a
handler is registered for that name is the day every standing grant for it
becomes live at once. Which is why there is no handler, and why the node
refuses to advertise the name it cannot honour.

**No public DHT, and no bootstrap server or well-known address.** A node with
an empty bootstrap list dials nothing at all; there is no fallback, because
there is nothing to fall back to. A DHT would publish exactly the participation
metadata this protocol exists to keep local — joining one announces that you
are a participant, and to whom, to strangers.

**No mutual TLS.** Evaluated and declined. Client certificates would move peer
identity into a CA store that is read once at startup, where `reload_trust()`
cannot reach it, giving revocation two homes that can disagree. Clients are
authenticated by the ed25519 handshake instead, which already consults the
trust list and its revocations. The consequence is accepted: an unauthenticated
caller can open a TLS connection, and the body cap and bounded handshake tables
are what limit what that costs.

## The disclosure trade-off in discovery

The rule discovery is meant to enforce is that a node discloses addresses only
for keys the caller already trusts. A responder cannot compute that
intersection alone — it knows its own trust list and the caller's key, and
nothing about whom the caller trusts.

So the query is caller-driven: the caller names the keys it wants, and the
responder answers only for keys it also trusts and has an address for. Nothing
is disclosed about a key the caller did not name, so the responder never
reveals that a peer the caller has never heard of exists.

The residual leak is real. The caller tells the responder which keys it is
asking about, and that is a slice of its own trust list. Someone has to speak
first, and this is the smaller of the two disclosures: it is the caller's own
choice, limited to keys it actually wants, sent to a peer it has already
authenticated. The alternatives are worse. Dumping the responder's table leaks
strictly more. A Bloom filter of the caller's trust list leaks the same thing
while adding false positives that would make the responder disclose addresses
for keys the caller does *not* trust, breaking the rule it was meant to serve.
A private set intersection would fix it properly and needs cryptography this
project does not currently depend on.

One smaller disclosure is worth stating in the same breath, since it is
deliberate rather than merely unfixed: a refused handshake distinguishes "we
revoked you" from "we have never heard of you", which tells the holder of a
revoked key that it was specifically revoked — accepted on the grounds that
losing access reveals as much.

An earlier version of this document named a second one, and it is now closed.
The daemon served `/v1/peers` and `/v1/logs` as open GETs, so anyone who could
reach the port could list the ids of every peer this node had authenticated —
the peer graph, published by the running daemon, whatever the design said.
Both are authenticated reads now; see above for what replaced them.

What stays open is `GET /v1/manifest`, and only because first contact needs
it: a caller reads the `node_id` there to address its handshake offer, so
gating it behind a completed handshake would mean no peer could ever make one.
It discloses two things. `node_id` is a truncated hash of the public key, and
over TLS the certificate hands that same public key to anyone who completes a
connection — so withholding it would hide nothing the transport has not
already given away, while breaking every first handshake. `runtime` is a
constant string, identical on every node. The capability list used to be there
and no longer is: it said what this node can be asked to do, nothing in the
handshake reads it, and it is now served only to authenticated peers. Learning
that this node exists remains a long way from learning who it talks to.

## Status

There is a working two-node deployment: two machines on separate hosts, each
holding its own identity, completing mutual handshakes over pinned TLS, with a
demonstration that runs the same exchange twice — once with real identities and
once with a throwaway key against an empty allowlist — and requires the second
to be refused for the specific reason that should refuse it. A green handshake
alone shows nothing; it means something only next to an identical one that
fails correctly. Setup, ports, paths and operational procedures are in
[DEPLOYMENT.md](DEPLOYMENT.md).

This is not a released protocol. There is no specification document apart from
the code and its comments; the wire formats carry version tags but nothing has
been frozen, and the message shapes are still free to change. Both ends of
every exchange so far have been this implementation. No second implementation
exists, so nothing here has been proven interoperable — the tests demonstrate
that this code is consistent with itself, which is a weaker claim than it can
look. Treat the on-the-wire details as provisional until something written
independently can complete a handshake against it.

## Layout

```
src/eureka_daemon/
  crypto.py         identity, canonical encoding, domain-separated signatures
  trust.py          allowlist, capability grants, revocation and rotation
  node.py           handshake state machine, replay bounds, authorisation
  client.py         three-message handshake over HTTP, with TLS pinning
  api.py            daemon endpoints, capped body reader
  server.py         plaintext and TLS listeners in one process
  tls.py            certificates from the node's own key; pinning client
  discovery.py      signed caller-driven address gossip
  reads.py          authenticated reads of the peer table, log and manifest
  assign.py         the assign gate: authorization and single-use requests
  handlers.py       the executor: registry, fetch policy, web-retrieval, inference
  signed_request.py the one gate every authenticated request passes through
  address_book.py   bounded address table with expiry
tests/              658 tests
demo.sh             trusted and untrusted handshake, side by side
```

Developed against Python 3.13. Dependencies: `cryptography`, `fastapi`, `uvicorn`, `httpx`. Run the
suite with `python -m pytest` from the repository root.
