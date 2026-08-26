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

## What works today

The suite is 503 tests, all passing. Each item below is implemented and
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

Stated plainly: this is a decision function with no caller in any request path.
Nothing on the network is gated by it yet, because there is nothing to gate —
see the section on task execution below.

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

**No task execution.** `EurekaNode.assign` returns a canned result after a
short sleep; the `/v1/assign` endpoint dispatches to it and executes nothing.
The capability machinery is finished ahead of the thing it will gate, on
purpose. Running code a peer asked for, over a network, with no sandbox is the
one part of this design that fails catastrophically rather than gracefully, and
it stays a stub until there is an isolation boundary to put it behind.

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
  signed_request.py the one gate every authenticated request passes through
  address_book.py   bounded address table with expiry
tests/              503 tests
demo.sh             trusted and untrusted handshake, side by side
```

Developed against Python 3.13. Dependencies: `cryptography`, `fastapi`, `uvicorn`, `httpx`. Run the
suite with `python -m pytest` from the repository root.
