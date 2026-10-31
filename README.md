# Eureka Protocol

Two agents on two machines authenticate each other directly, over a network
they both sit inside, with no third party holding the list of who talks to
whom.

Each node holds an ed25519 keypair and a local file naming the public keys it
will speak to. Two nodes authenticate by exchanging three signed messages; if
either side's key is absent from the other's file, the exchange is refused.
There is no registry to publish to, no broker to route through, and no
bootstrap server to ask. A node knows the peers its operator told it about,
and nothing else.

**Status: working prototype, not a released protocol.** It runs on a
three-node LAN deployment and has 658 passing tests, but the wire format is
not frozen, there is no specification apart from the code, and every exchange
so far has had this implementation on both ends. Read
[What this is not](#what-this-is-not) before you plan anything around it.

---

## The problem

In some settings the *fact* that two parties are in contact is more sensitive
than what they exchange. A law firm's client list, a clinic's referral
pattern, an accountant's roster — the relationship is the confidential thing,
and the content is often the lesser secret. Those same settings usually
forbid the data leaving the network at all.

Now put agents in that picture. If two agents on two machines are going to
work together, each has to know the other is who it claims to be. The obvious
way to arrange that is a broker: a directory, a registry, a rendezvous
service, something both parties can look each other up in.

**That component is the problem.** To be useful, a directory has to hold
exactly the fact the deployment is trying to protect — the map of who talks to
whom. It doesn't matter whether it's honest. It is a place where the
relationship graph exists, which means it is a place the graph can be
subpoenaed from, breached out of, or inferred from traffic patterns against.
A broker that promises not to look is still a broker that *could*, and that
promise is the entire security argument.

Eureka removes the component instead of trusting it. Nothing sits between two
nodes. The relationship graph is never assembled anywhere, because there is
nowhere for it to be assembled. Each node holds one slice — its own peers —
and no node can enumerate another's.

The cost is real and is not hidden: provisioning is manual. An operator
exchanges public keys out of band and writes them into files by hand. There
is no place to look a peer up, and a mesh of any size becomes an operator's
problem. That trade is the whole design. If you don't need it, you probably
want a broker, and you should use one.

### Why not MCP or A2A

They solve different shapes of problem, and Eureka composes with them rather
than competing.

**MCP** standardises how an agent reaches its own tools and data. The
relationship it describes runs between an agent and resources it already
controls — a local server it launches and trusts implicitly. It is not an
authentication protocol between two mutually suspicious parties.

**A2A** does address agent-to-agent work, but assumes agents can be *found*:
published agent cards, a discoverable endpoint, somewhere to look a peer up.
That assumption is the one this design rejects.

In the deployment this was built for, the two sit in layers. MCP carries the
relationship between an agent and its own tools; Eureka carries the
relationship between that machine and a peer it has no authority over, where
every request is signed, every grant is checked, and the answer comes back
signed in its own domain. The agent asks its tool; the tool asks a stranger.
Neither protocol is doing the other's job.

---

## Stand up two nodes

The walkthrough below is the real thing end to end — two identities, a mutual
handshake over pinned TLS, a demonstration that the check is doing something,
and one unit of real work. It takes about ten minutes on two machines on the
same LAN, and it was run from a clean clone before being written down.

Call the machines **A** (the responder, which listens and serves work) and
**B** (the initiator, which calls). Nothing about a node is fixed as one or
the other; A is simply the one that gets a daemon.

### 0. Get the code, on both machines

Requires Python 3.13 (developed against it; earlier 3.x is untested).

```bash
git clone https://github.com/python1/eureka_protocol.git eureka_protocol
python3 -m venv venv
./venv/bin/pip install -r eureka_protocol/requirements.txt
```

**The clone directory must be named `eureka_protocol`, and you run from its
parent.** The package is imported as `eureka_protocol.src.eureka_daemon`, so
the parent directory is what goes on `sys.path`. Every command below is run
from that parent, with the venv next to the checkout:

```
~/eureka/                     <- run commands from here
├── venv/
└── eureka_protocol/          <- the clone
```

Run the test suite to confirm the install:

```bash
cd eureka_protocol && ../venv/bin/python -m pytest -q && cd ..
```

### 1. Mint an identity, on each machine

An identity is one ed25519 keypair in one file. Do this once per node, at an
explicit path you have chosen.

```bash
mkdir -p -m 0700 ~/.eureka

./venv/bin/python -c "
from eureka_protocol.src.eureka_daemon.crypto import EurekaCrypto
c = EurekaCrypto()
c.save('$HOME/.eureka/identity.key')      # no overwrite=True
print(c.derive_node_id(), c.get_public_key_hex())
"
```

That prints the node id and the public key — for example:

```
node_a5ebe58a 132474d6c700c58a93c0817a958c288c51b9495fd543419585acf05c412cd3cf
```

The `node_id` is derived from the public key, so a restarted daemon comes back
as the same node and an id cannot be claimed independently of the key behind
it. `save()` without `overwrite=True` refuses to clobber an existing identity,
so this cannot silently replace a node you already have.

The file is written 0600 inside a 0700 directory, and a key whose mode has
been widened is refused on load rather than used.

### 2. Exchange public keys, out of band

Get A's public key onto B and B's onto A, over a channel you already trust —
ssh, a phone call, anything authenticated. **This step is the trust
provisioning, and there is no substitute for it.** There is no
trust-on-first-use, no key-exchange message, no fallback. A key taken from an
unauthenticated fetch is not a key you have verified, and pinning it proves
nothing.

Only public keys move. The private key never leaves the machine that made it.

### 3. Write each node's trust file

The trust file is a JSON allowlist mapping a human label to a public key and
its grants. Lookups are always by key; the label is decoration.

On **A**, trust B and grant it `web-retrieval`:

```bash
./venv/bin/python -c "
import json
from eureka_protocol.src.eureka_daemon.trust import TrustList
t = TrustList()
t.add('node-b', '<B_PUBLIC_KEY>', ['web-retrieval'])
with open('$HOME/.eureka/trust.json', 'w') as fh:
    json.dump(t.to_document(), fh, indent=2); fh.write('\n')
"
chmod 0600 ~/.eureka/trust.json
```

On **B**, trust A and grant it nothing:

```bash
./venv/bin/python -c "
import json
from eureka_protocol.src.eureka_daemon.trust import TrustList
t = TrustList()
t.add('node-a', '<A_PUBLIC_KEY>', [])
with open('$HOME/.eureka/trust.json', 'w') as fh:
    json.dump(t.to_document(), fh, indent=2); fh.write('\n')
"
chmod 0600 ~/.eureka/trust.json
```

**Trusting a key and granting it a capability are different acts**, and the
asymmetry above is deliberate rather than an omission. Trust is what B needs
in order to *call* A: it is what the TLS pin and the handshake check against.
Grants govern the other direction — what a peer may ask of *us*. B serves
nothing, so it grants nothing.

Grants are validated against what the node reading the file actually
advertises, so a grant for a capability the node cannot serve is a load-time
error rather than a line that sits in the file looking effective. B advertises
nothing, which is why writing a grant into B's file would fail outright.

An absent trust file is a legitimate state and means "trust nobody". A file
that exists but is corrupt raises instead of degrading into an empty list —
"trusts nobody" and "failed to deploy" must not look the same.

### 4. Start the responder on A

```bash
export EUREKA_IDENTITY_PATH=$HOME/.eureka/identity.key
export EUREKA_TRUST_PATH=$HOME/.eureka/trust.json

./venv/bin/python -m eureka_protocol.src.eureka_daemon.server \
    --tls-port 8443 --no-plain --tls-dir $HOME/.eureka/tls --host 0.0.0.0
```

```
Starting Eureka Daemon API as node_a5ebe58a
  listening on https://0.0.0.0:8443
  peers should pin: 132474d6c700c58a93c0817a958c288c51b9495fd543419585acf05c412cd3cf
```

`--host 0.0.0.0` is what lets B reach A. Without it every listener binds
`127.0.0.1` and only this machine can connect: being reachable from the
network is something you ask for, not a default. Pass a single LAN address
instead to listen on one interface only.

Those two environment variables are load-bearing. The identity loader
*creates* a key when the file it is pointed at does not exist, so a typo does
not fail — it quietly mints a new identity, and the node comes back under a
`node_id` no peer trusts. If a node id ever changes unexpectedly, check these
first.

`--no-plain` refuses to start without `--tls-port`, so a half-edit cannot
produce a daemon listening on nothing while looking healthy. The certificate
is self-signed around the node's own identity key and is regenerated whenever
it stops matching, so `--tls-dir` holds derived state that is safe to delete.

For running this under systemd as a hardened service account, see
[DEPLOYMENT.md](DEPLOYMENT.md) — the unit files in `deploy/` are commented at
length with the reasoning behind each setting.

### 5. Handshake from B

```bash
export EUREKA_IDENTITY_PATH=$HOME/.eureka/identity.key
export EUREKA_TRUST_PATH=$HOME/.eureka/trust.json

./venv/bin/python -c "
import asyncio, json
from eureka_protocol.src.eureka_daemon.node import EurekaNode
from eureka_protocol.src.eureka_daemon.client import handshake_over_http
n = EurekaNode.with_persistent_identity(capabilities=[])
r = asyncio.run(handshake_over_http(n, 'https://<A_ADDRESS>:8443', require_tls=True))
print(json.dumps(r, indent=2, default=str))
"
```

```json
{
  "event": "handshake_established",
  "authenticated": true,
  "reason": "authenticated",
  "peer_id": "node_a5ebe58a",
  "auth_type": "Ed25519",
  "mutual": true
}
```

`require_tls=True` means this node will not fall back to speaking in the clear
to a peer it was told to reach over TLS. There is no certificate authority
anywhere in this protocol: the client pins A's certificate against the same
trust file, so there is nothing to chain to and nothing to install.

### 6. Prove the check is real

A green handshake on its own shows nothing. It means something only next to an
identical exchange that gets refused for the one reason that should refuse it.
`demo.sh` runs both against the same peer — your real identity, then a
throwaway key with an empty allowlist — and exits non-zero unless the second
one is refused with `untrusted_key`. Run it in the same shell as step 5, so it
picks up the same identity and trust paths:

```bash
EUREKA_PYTHON=$PWD/venv/bin/python \
  ./eureka_protocol/demo.sh https://<A_ADDRESS>:8443
```

```
--- trusted peer
    authenticated : True
    mutual        : True
    reason        : authenticated
    verdict       : PASS

--- untrusted peer
    authenticated : False
    reason        : untrusted_key
    detail        : the key terminating TLS is not trusted
    verdict       : PASS
```

Run this before you believe anything else on this page.

### 7. Ask the peer to do something

`integrations/antiochus_client.py` issues a signed `/v1/assign` and verifies
the answer — that the gate accepted it, that the result carries a signature in
the assign-result domain, and that the nonce inside the signed result is the
nonce that was sent. A valid signature over somebody else's result is still
not an answer to you.

Run it with the venv interpreter, in the same shell as step 5 — it reads
`EUREKA_IDENTITY_PATH` and `EUREKA_TRUST_PATH`, and refuses to start if either
path is missing rather than minting a fresh identity that no peer trusts:

```bash
./venv/bin/python eureka_protocol/integrations/antiochus_client.py \
    --peer https://<A_ADDRESS>:8443 https://example.com
```

```json
{
  "ok": true,
  "verified": true,
  "capability": "web-retrieval",
  "responder_id": "node_a5ebe58a",
  "http_status": 200,
  "content_type": "text/html",
  "bytes": 559
}
```

That is two nodes, mutually authenticated over pinned TLS, one of them doing
work for the other under an explicit grant, with no third party involved at
any point.

---

## What it does

The suite is 658 tests. Each item below is implemented and covered; where
something is narrower than its name suggests, that is said.

### Identity

An ed25519 keypair persisted as a versioned JSON document, written through a
single atomic writer at mode 0600 into a 0700 directory — temp file in the
destination directory, fsync, rename — so a crash cannot leave a truncated key
and the bytes are never briefly world-readable. Rotation generates a fresh
keypair and archives the outgoing one under the same protections; the retired
key is never deleted, since it is the only thing that can verify signatures it
made while live.

### Mutual handshake

Three messages. The initiator signs its own challenge; the responder verifies
it, checks its trust list, and replies with a signature over that challenge
plus a counter-challenge; the initiator signs the counter-challenge. Each side
records the other only after its own verification passes.

Every signature is computed over a context tag, a NUL byte, and a canonical
JSON encoding. The three handshake positions have three distinct tags, as do
discovery queries, assign requests, assign results and audit-log entries, so a
signature harvested from one context verifies over different bytes in another
and fails. A signature minted to look at the peer table is structurally
unusable as a request to execute something.

Replay is handled on both sides: nonces are single-use, and a challenge older
than the freshness window is rejected even if its signature is perfect. The
pending-challenge and seen-nonce tables have hard caps with oldest-first
eviction — age pruning alone does not bound memory, because an attacker can
request many challenges that are all legitimately fresh.

Several checks exist to stop identities being mixed mid-exchange: the envelope
and the signed body must agree on who is calling, the responder must be the
peer that was addressed, and the key that completes the handshake must be the
key that opened it. Anything that is not a well-formed challenge is never
signed, so the endpoint cannot be used as a signing oracle.

### Capability grants, and the gate

Grants are per-peer, keyed by public key, and default-deny. Two gates must
both pass: the peer's key holds the grant, and this node actually advertises
that capability. The advertised list is not written down twice — it is derived
from the handler registry, so a node cannot claim what it has no code to do.

`/v1/assign` takes a signed, single-use request, authenticates it, authorises
it, and only then dispatches. The refusal discloses the decision and nothing
else: no echo of what was asked, no capability list, and no distinction
between "not granted" and "not offered", so it cannot be used to enumerate
what a node advertises. Authorisation reads the live trust list rather than a
snapshot taken at handshake time, so withdrawing a grant takes effect without
waiting for the peer to reconnect.

Every decision about an authenticated caller lands in the audit log with the
capability, the peer and the outcome — and never the request or the result.
For `web-retrieval` the result is somebody else's web page; for `inference`
the request is a peer's prompt. Copying either into a signed, peer-readable
log would republish it under this node's name.

### web-retrieval

Fetches a URL a peer names, under a body cap, a wall-clock timeout, a redirect
cap, and http/https only.

Pointing a daemon at a URL somebody else chose is server-side request forgery
waiting to happen — the peer cannot reach the network this node sits in, but
this node can. **Only globally routable unicast addresses may be fetched:**
loopback, private ranges, link-local (including the cloud metadata address),
carrier-grade NAT, multicast, reserved and unspecified addresses are refused,
in IPv4 and IPv6 and in IPv4-mapped form.

That check runs on addresses, never on the URL string. Every address a name
resolves to must pass, not merely the first; it runs again on the address
actually connected to, read back from the open socket before any body is read,
because the HTTP client resolves the name a second time and a name can answer
differently the second time; and it runs again on every redirect, which is why
hops are followed by hand.

### inference

Runs a prompt through a local Ollama and returns the completion. The two
capabilities have opposite shapes. `web-retrieval` lets the peer choose the
target, so most of its design is about where this node may be pointed.
`inference` lets the peer choose **nothing but the text** — model, endpoint,
token budget, sampling options and residency are all constants.

That is not fastidiousness. A caller that could name a model could name one
larger than this host's VRAM, and Ollama will *pull* a model it does not have,
turning "run my prompt" into "fetch an arbitrary blob from a registry and load
it". The endpoint is a literal loopback address that refuses even the name
`localhost`, so there is no DNS in the path, nothing to rebind, and no
redirect to follow.

Whether a node offers it is a property of the host, not of the code: it is
enabled by `EUREKA_INFERENCE=1` in the daemon's environment, and an
unrecognised value stops the daemon rather than being read as either answer.
A host without Ollama that registered the handler unconditionally would
advertise a capability it cannot serve.

### Pinned TLS

TLS carries the identity the node already has instead of introducing a second
one. The certificate is a self-signed wrapper around the node's ed25519 key,
and the client verifies it by extracting the raw public key and checking it
against the same trust list, with the same revocations, that the handshake
consults. No certificate authority is involved and nothing has to be
distributed. Hostname checking is off because the key is the identity.

This is narrower than default verification, not weaker: the default context
accepts any of several hundred public CAs, this one accepts exactly the keys
an operator listed. Minimum version is TLS 1.3, and the pin is applied on
every response in the exchange rather than only the first.

The channel is bound to the identity: the key that terminated TLS must be the
key that signed the handshake. Without that, a peer you trust could terminate
TLS and relay a *different* trusted peer's exchange, and you would finish
authenticated to one identity over a channel held by another.

### Revocation and rotation

Revoking a key is a separate act from deleting its entry. A deleted key
returns the moment someone restores an old trust file from backup; a revoked
key stays refused, records why and when, and cannot be re-added. Revoking a
key that was never trusted is allowed, and is how an operator ensures a key
they were merely offered can never be provisioned by mistake.

Rotating a peer onto a new key is one operation, not an add followed by a
revoke: two steps leave a window where both keys authenticate, and if the
second step fails the window never closes. A revocation reaches a running
daemon through `reload_trust()`, which drops peers whose key is now revoked or
no longer listed. A bad file raises and keeps the old list, which is the
honest failure — the revocation has *not* been applied and the caller must not
treat that as a warning.

### Authenticated reads

The peer table, the audit log and the full manifest are served only to a
caller that has completed a handshake, through one shared gate rather than a
second copy that could grow a hole the first one does not have. Three
properties hold, each pinned by a test that has been watched fail:

* **A refusal discloses nothing.** Two nodes identical but for their peer
  tables — one with peers, one that has never seen anyone — return
  byte-identical refusals to the same stranger.
* **An authenticated caller sees only what it already knows about.** The
  caller names the keys it is asking about and the answer covers only those,
  so authenticating to one node does not enumerate the mesh behind it.
* **A connection is not an identity.** The daemon requests no client
  certificate, so on the server side a TLS peer is anonymous. Being on the
  trust list is not enough either: a trusted peer that has not handshaked is
  refused, and a peer that handshaked under one key cannot read under another.

`GET /v1/manifest` stays open, and only because first contact needs it — a
caller reads the `node_id` there to address its handshake offer. It discloses
a truncated hash of a public key the TLS certificate already hands to anyone
who completes a connection, plus a constant string. The capability list used
to be there and is now served only to authenticated peers.

### Gossip discovery

Nodes can learn *where* peers are without learning *who* to trust. A query is
signed and answered only for a caller that is trusted, unrevoked, and has
completed a handshake under the key it is asking with. An address is never a
trust decision, so learning one grants nothing; an address is advice until a
handshake against it authenticates the key it was filed under; and nothing
outside the configured entry points is ever contacted.

The query is caller-driven — the caller names the keys it wants — because a
responder cannot compute the intersection alone, and dumping its own table
would leak strictly more. **The residual leak is real:** the caller tells the
responder a slice of its own trust list. Someone has to speak first, and this
is the smaller of the two disclosures. A private set intersection would fix it
properly and needs cryptography this project does not currently depend on.

One honest limit on scope: the daemon serves the responder side, but the
initiating round is a library function with no daemon loop, schedule, or
bootstrap configuration behind it. **Deployed nodes are still pointed at each
other by hand.**

---

## What this is not

Some of these are deliberate design decisions. Others are simply not built
yet. They are separated below, because conflating them is how a reader ends up
trusting something that was never claimed.

### Deliberate, and not on the roadmap

**No trust-on-first-use.** A key is trusted because an operator put it in a
file. There is no code path that adds one any other way and no switch to turn
the check off. The handshake never writes to the trust list. This is also why
there is no signed "here is my new key" message: a stolen key would use it to
rotate the thief into permanent trust, which is TOFU wearing a hat. Key
rotation is an out-of-band re-provisioning step, and that cost is accepted.

**No central broker, and no bootstrap server, DHT or well-known address.** A
node with an empty bootstrap list dials nothing at all — there is no fallback,
because there is nothing to fall back to. A DHT would publish exactly the
participation metadata this protocol exists to keep local.

**No code execution.** `web-retrieval` and `inference` are implemented;
`code-exec` is not, and is not advertised. Running code a peer supplied, over
a network, with no sandbox is the one part of this design that fails
catastrophically rather than gracefully, and it stays unbuilt until there is
an isolation boundary to put it behind. The gate in front of it has been real
for some time — an execution endpoint that grows authentication later starts
life as the hole in the fence — but a gate is not a sandbox, and the day a
handler is registered under that name is the day every standing grant for it
becomes live at once.

**No mutual TLS.** Evaluated and declined. Client certificates would move peer
identity into a CA store read once at startup, where `reload_trust()` cannot
reach it, giving revocation two homes that can disagree. Clients are
authenticated by the ed25519 handshake instead. The consequence is accepted:
an unauthenticated caller can open a TLS connection, and the body cap and
bounded handshake tables are what limit the cost of that.

### Not built, and you should not assume it works

**No WAN operation.** Every deployment and every test has been on a single
LAN, with nodes addressed by private IP. Nothing here has been exercised
across the public internet, and the design assumes a network perimeter that
already excludes strangers — the trust file is the only thing standing between
a node and anyone who can reach its port.

**No NAT traversal.** No STUN, no TURN, no hole punching, no relay. A
responder must be directly reachable at an address the initiator can dial. Two
nodes behind separate NATs cannot reach each other, and there is no plan in
this repository for making them.

**No second implementation, and therefore no interoperability.** Both ends of
every exchange so far have been this code. The tests demonstrate that this
implementation is consistent with *itself*, which is a weaker claim than a
green suite can look. Nothing has been written from a specification and made
to complete a handshake against it, so nothing here is proven interoperable —
treat the on-the-wire details as provisional.

**No specification.** There is no protocol document apart from the code and
its comments. The wire formats carry version tags, but nothing has been
frozen and message shapes are still free to change without a migration path.

**No packaging, no release.** No PyPI distribution, no `pyproject.toml`, no
version number, no changelog. `requirements.txt` states version floors that
the suite has been run against, not a locked or audited dependency set.
Installation is a clone in a directory of the right name, and the import path
is coupled to that layout.

**No automated discovery loop.** As above: the responder side is served, the
initiating side is a library function. Address gossip does not run on its own
anywhere.

**No security audit.** This has not been reviewed by anyone but its author.
The design decisions above are argued in the code and in DEPLOYMENT.md, and
arguing carefully is not the same as being right.

---

## Operating it

[DEPLOYMENT.md](DEPLOYMENT.md) is the operator runbook for the deployment this
was built on — three nodes across a Proxmox container, a WSL host, and a
client. It is written as a working log rather than a tutorial, and it records
what was actually run, what it produced, and what broke:

* systemd units, hardening, service accounts, crash-loop guards
* granting, revoking and rotating, with the validate-before-restart order
* moving a responder to another host while keeping its identity
* TLS material, firewall rules, reboot and sleep behaviour
* the MCP integration, and the gotchas that cost time

It contains real IPs, node ids and hostnames from that deployment. They are
private-range addresses on a LAN, published deliberately, because a runbook
with the specifics filed off is not a runbook.

The unit files in `deploy/` are heavily commented and are the best starting
point for a second deployment.

---

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
integrations/
  eureka_mcp_server.py   the MCP seam: eureka_fetch, eureka_inference, eureka_peer_status
  antiochus_client.py    the same protocol path as a CLI, with no agent in the way
deploy/             systemd units and the WSL preflight
tests/              658 tests
demo.sh             trusted and untrusted handshake, side by side
requirements.txt    runtime and test dependencies
DEPLOYMENT.md       the operator runbook
```

Developed against Python 3.13. Dependencies are in `requirements.txt`:
`cryptography`, `fastapi`, `uvicorn` and `httpx` at runtime, `pytest` for the
suite, and `mcp` — commented out — for `integrations/eureka_mcp_server.py`
alone, which the daemon never imports. Run the suite with `python -m pytest`
from the repository root.

## License

MIT — see [LICENSE](LICENSE).
