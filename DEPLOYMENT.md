# Eureka Protocol — working two-node deployment

First successful cross-machine mutual handshake: 2026-08-24, commit 976c1f1.

## Nodes

| Node | Host | node_id | public key |
|---|---|---|---|
| ct102-antiochus | CT 102 (192.168.1.174) | node_a2ed8dc7 | a718592fde751a92db31fa27ee1e88efbd6c1134753fd9a5d92b08b89d118fd1 |
| wsl-hermes | Alienware WSL2 (Ubuntu 24.04) | node_ef0a1f59 | bff5536af5a324f8f8d971e93047a4f1944f9c31dc06408826680d5b21d482ae |

Private keys live in each host's identity file, mode 0600, never copied.

## Paths

CT 102: repo /root/.openclaw/workspace/eureka_protocol, venv /root/eureka_venv,
identity /root/.eureka/identity.key, trust /root/.eureka/trust.json

WSL: repo ~/eureka/eureka_protocol, venv ~/eureka/venv,
identity ~/.eureka/identity.key, trust ~/.eureka/trust.json

## Trust file format

peers maps NAME -> an entry. Lookups are by key; the name is a human label.

    {
      "version": 3,
      "algorithm": "ed25519",
      "peers": {
        "<name>": {
          "public_key": "<64 hex chars>",
          "capabilities": ["fast-inference"]
        }
      },
      "revoked": [
        {"public_key": "<64 hex chars>",
         "reason": "laptop stolen",
         "revoked_at": "2026-08-24T09:00:00+00:00"}
      ]
    }

Each node trusts the other's public key. Empty or absent file trusts nobody.
No trust-on-first-use, no bypass.

Older versions still load: v1 (peers maps name -> bare key string) grants
nothing, v2 adds capabilities. Both are read-only history at this point --
neither can express a revocation, and a `revoked` list in a file declaring
version 1 or 2 is a load error rather than a field that is quietly ignored.
Get that wrong silently and an operator believes a compromised key is dead
when it is still authenticating.

A grant naming a capability the node does not advertise is also a load error,
so a typo fails at startup instead of sitting in the file looking effective.

## Revoking a peer

Revoking is not the same as deleting the entry. A deleted key comes back the
moment someone restores an old trust file from a backup; a revoked key stays
refused, and records why.

    /root/eureka_venv/bin/python -c "
    import sys, json; sys.path.insert(0, '/root/.openclaw/workspace')
    from eureka_protocol.src.eureka_daemon.trust import TrustList
    path = '/root/.eureka/trust.json'
    trust = TrustList.load(path)
    trust.revoke('<64 hex chars>', reason='laptop stolen')
    open(path, 'w').write(json.dumps(trust.to_document(), indent=2))
    "

A running daemon picks it up with `node.reload_trust()`, which applies the
revocation to live sessions: a peer whose key was revoked -- or simply removed
-- is dropped from the peer table rather than left marked authenticated. If
the file is corrupt the reload raises and keeps the old list, which means the
revocation has NOT been applied; treat that as an error, not a warning.

Without a reload, a revocation still takes effect on the next handshake, and
authorisation reads the live trust list rather than a handshake-time snapshot.

## Rotating a peer's key

One step, not two -- adding the new key and revoking the old one separately
leaves a window in which both authenticate:

    trust.rotate('<name>', '<new 64 hex chars>')

Grants carry across. The old key is revoked, so it cannot be re-added later.

## Transport encryption (TLS)

**CT 102 serves TLS on 8443 and nothing else. Plaintext is gone.**

    /root/eureka_venv/bin/python -m eureka_protocol.src.eureka_daemon.server \
        --tls-port 8443 --no-plain --tls-dir /var/lib/eureka

The daemon can serve both at once -- pass a port number as the first argument
and drop `--no-plain` -- and it did during the migration, because TLS cannot
share a port with plaintext: an HTTPS socket answers a plain request with a
handshake failure, not a manifest. Both listeners run in one process, not two
services, because two processes under one identity would keep two independent
replay tables (a nonce spent on one port still unspent on the other) and two
peer tables (`/v1/peers` answering differently depending which port you asked).

**The order is the whole trick.** Adding TLS beside plaintext is safe at any
time; removing plaintext strands every peer that has not moved yet. So:

1. Get current code onto the peer.
2. Verify the peer handshakes over TLS, mutually, while plaintext still runs.
3. Only then drop plaintext on this side.
4. Confirm plaintext is refused and TLS still works.

Done for wsl-hermes on 2026-08-25: verified at step 2 with `mutual: true` and
`node_ef0a1f59` unchanged, then plaintext dropped. Adding a new peer that
cannot speak TLS yet means putting 8000 back for the duration, not turning TLS
off.

`--no-plain` refuses to start without `--tls-port`, so a half-edit cannot
produce a daemon listening on nothing that looks healthy doing it. `--tls` on
its own is shorthand for TLS-only on the main port.

The certificate is generated from the node's **existing** identity key and
written to `/var/lib/eureka` as `server-cert.pem` / `server-key.pem` (mode
0600) -- not beside the identity file, so that `ProtectHome=read-only` did not
have to be relaxed to turn TLS on. Nothing new has to be distributed: peers
already hold the public key in their trust file, and that is exactly what the
client pins.

`require_tls` governs whether a *plain* connection is allowed at all; a TLS
connection is pinned either way. `demo.sh` sets it for `https://` URLs. Now
that CT 102 refuses plaintext outright, a client that omits it fails at the
transport rather than at the check -- so the flag is a belt to the transport's
braces, not the thing keeping the channel encrypted:

    await handshake_over_http(node, "https://192.168.1.174:8443", require_tls=True)

What is checked, on every response and not just the first:

- the key that terminated TLS must be on the trust list and not revoked, and
- it must be the same key that signs handshake message 2.

The second check is the one that matters: without it a peer you trust could
terminate TLS and relay a *different* trusted peer's handshake, leaving you
authenticated to one identity over a channel held by another. A connection
swapped part-way through the exchange is refused for the same reason.

`require_tls=False` (the default) allows a plain connection; it does not
disable the pin. A TLS connection is always checked.

### What this does and does not cover

Covered: confidentiality and integrity of the channel, and authentication of
the server by key pinning. TLS 1.3 only, and no certificate authority is
trusted at all — chain verification is replaced by the pin, which is narrower
than the default context's several hundred public CAs.

Not covered: **client certificates.** Callers are authenticated by the ed25519
handshake, so an unauthenticated caller can still complete a TLS handshake and
read `/v1/manifest`. Dropping plaintext did not change that -- the listener
still answers anyone, and it is the *protocol* that refuses them one message
later. That is deliberate.
mTLS was evaluated first and rejected: uvicorn does not expose the client
certificate to the application, so peer identity would have to move into a CA
bundle read once at startup — a second place to revoke a key, which
`reload_trust()` could not reach and which would need a restart to change.
One identity, one trust file, one revocation.

### After rotating an identity

The certificate is regenerated automatically on the next start, because it no
longer wraps the current key. Peers must be re-provisioned with the new public
key out of band — the same requirement rotation already had, since `node_id`
and the pin are both the key.

## Rotating this node's own key

    EurekaCrypto.rotate('/root/.eureka/identity.key')

The outgoing private key is archived beside the live one as
`identity.key.retired-<timestamp>` at mode 0600 and never deleted -- it is the
only thing that can still verify signatures it made while it was live.

**The node_id changes.** It is derived from the public key, so a rotated node
comes back as a different identity and every peer must be re-provisioned with
the new key out of band. There is deliberately no signed "here is my new key"
message that peers act on by themselves: a stolen key could use it to rotate
the thief into permanent trust, which is trust-on-first-use wearing a hat.

## Start the responder (CT 102)

CT 102 runs the daemon under systemd as `eureka-daemon.service`, enabled at
boot. It is no longer started by hand -- a daemon living in an SSH session dies
with the session, and one that inherits its identity from a shell comes back as
a different node the day someone forgets to export a variable.

    systemctl status eureka-daemon
    systemctl restart eureka-daemon
    journalctl -u eureka-daemon -f

Check both listeners:

    curl -sk https://192.168.1.174:8443/v1/manifest    # TLS (the only listener)
    curl -s  http://192.168.1.174:8000/v1/manifest     # refused: nothing there

`curl -k` skips chain verification, which is correct here and not a shortcut:
the certificate is self-signed and identity lives in the key inside it, not in
any chain. A real peer pins that key against its trust file. To check the
served key by hand:

    openssl s_client -connect 192.168.1.174:8443 </dev/null 2>/dev/null \
      | openssl x509 -pubkey -noout

The unit is version controlled at **`deploy/eureka-daemon.service`**, which is
the canonical copy; `/etc/systemd/system/eureka-daemon.service` is an install
of it. Identity and trust paths are set in the unit, not inherited. Logs go to
the journal under the identifier `eureka-daemon`.

Install, or reinstall after editing:

    cd /root/.openclaw/workspace/eureka_protocol
    install -m 0644 deploy/eureka-daemon.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now eureka-daemon

Edit the repo copy and reinstall -- never edit the installed file directly, or
the two drift and the one under version control becomes fiction. To check they
have not:

    diff deploy/eureka-daemon.service /etc/systemd/system/eureka-daemon.service

A `systemctl edit eureka-daemon` drop-in is the exception: it lands in
`/etc/systemd/system/eureka-daemon.service.d/` and deliberately survives a
reinstall, which is what you want for a host-specific tweak. `systemctl cat
eureka-daemon` shows the unit and every drop-in together.

To run it by hand anyway -- debugging, or a second node on another port -- stop
the service first so the port is free:

    systemctl stop eureka-daemon
    cd /root/.openclaw/workspace
    EUREKA_IDENTITY_PATH=/root/.eureka/identity.key \
    EUREKA_TRUST_PATH=/root/.eureka/trust.json \
    /root/eureka_venv/bin/python -m eureka_protocol.src.eureka_daemon.server \
      --tls-port 8443 --no-plain --tls-dir /var/lib/eureka

Add a port number as the first argument to get plaintext back alongside it,
which is what debugging a peer that cannot do TLS looks like.

### The restart policy, and why it looks like that

    Restart=on-failure       RestartSec=5s
    RestartSteps=4           RestartMaxDelaySec=60s
    StartLimitIntervalSec=300   StartLimitBurst=5

A crash is recovered from; a broken config is **not** retried forever. Five
start attempts inside five minutes and systemd gives up, leaving the unit in
`failed` for a human to look at.

That ceiling is the whole point. `ollama.service` on this box has
`Restart=always` with `RestartSec=3` and no start-limit override, so it runs
against systemd's default of 5 starts per 10 seconds. One start every three
seconds is about 3.3 per window, which never reaches 5, so the limiter never
trips -- it restarted 124,527 times over five days on a config error.

**The rule: `StartLimitIntervalSec` must be comfortably longer than
`RestartSec` x `StartLimitBurst`, or the guard is decorative.** Here five
attempts with backoff span about 100 seconds against a 300 second window, so
the limit is always reached before the window slides. Verified by running a
unit with these exact directives against `/bin/false`: it stopped after 5
restarts in 125s with "Start request repeated too quickly".

`Restart=on-failure` rather than `always`, so a clean exit is treated as
somebody stopping the daemon on purpose instead of something to fight.

When the unit does give up, it stays down until told otherwise:

    systemctl reset-failed eureka-daemon && systemctl start eureka-daemon

### It runs as root, and it should not

The identity and trust files are live, root-owned, mode 0600, and re-homing
them under a service account is not a thing to do casually -- the identity
loader refuses any key file that is group or world readable, so a migration
that fumbles the mode takes the node down.

The migration when someone wants it: create a system user, move
`/root/.eureka` to `/var/lib/eureka` owned by that user with the key still
0600, add `User=`/`Group=` plus `StateDirectory=eureka` to the unit, and point
the two environment variables at the new path. The node_id does not change,
because it is derived from the key and the key is the same file. Peers need no
reprovisioning.

Until then the unit is hardened instead: `NoNewPrivileges`, `PrivateTmp`,
`ProtectSystem=full`, and `ProtectHome=read-only`. That last one is load
bearing rather than decoration -- the daemon only ever *reads* `/root/.eureka`,
so the service cannot modify its own key material.

**Turning TLS on did not require relaxing it.** The certificate could have gone
next to the identity file, which would have meant making `/root` writable by
the service; instead `--tls-dir` points at `StateDirectory=eureka`
(`/var/lib/eureka`, mode 0700). What TLS actually needs is somewhere to write,
not somewhere *inside the private key's directory* to write. The certificate
and its key are derived from the identity and regenerated whenever they stop
matching it, so that directory is disposable state and never a source of
truth -- deleting it costs one restart.

## Run the handshake (WSL initiates)

`demo.sh` in this repo is the end-to-end check. It is version controlled, so
both hosts run the same one:

    cd ~/eureka/eureka_protocol
    ./demo.sh                                # TLS to CT 102 on 8443

It runs the same exchange twice, and **the contrast is the point**:

| scenario | identity and trust | expected |
|---|---|---|
| trusted | this host's real files | `authenticated`, `mutual: true` |
| untrusted | a throwaway identity, empty trust list | refused, `untrusted_key` |

A green handshake on its own does not show that anything was checked. It only
means something next to an identical exchange that gets refused, and refused
for the one reason that should refuse it -- the untrusted run insists on
`untrusted_key` specifically, so an unreachable peer (`malformed_response`)
fails the check rather than passing it by accident.

The throwaway identity is created under a temp directory and deleted
afterwards; the real identity and trust file are neither read nor written by
that scenario. Its trust path deliberately names a file that does not exist,
because an absent trust file is an empty allowlist -- the state under test,
reached without writing anything.

Exits non-zero unless both scenarios come out as expected.
Verify from the responder: `curl -sk https://localhost:8443/v1/peers`.

It takes a URL if you need a different peer or a plaintext one, though CT 102
no longer serves plaintext: `./demo.sh http://host:port`.

Nothing has to be passed to make TLS work. An `https://` URL builds a client
that **pins** the peer's key against the trust file instead of chaining to a
certificate authority -- there is no CA in this protocol, so a default HTTP
client rejects every peer with CERTIFICATE_VERIFY_FAILED. If you ever see
that, something is constructing its own client; the fix is
`tls.pinning_client()`, **never** `verify=False`, which switches the pin off
along with the chain and leaves the connection unauthenticated.

`demo.sh` picks its interpreter from `$EUREKA_PYTHON`, then `../venv`, then
CT 102's venv -- and checks each candidate can actually import the
dependencies, because more than one venv sits next to this repo on some hosts.

## Gotchas

- WSL2 is behind NAT: outbound works, inbound needs a portproxy or
  networkingMode=mirrored. WSL initiates, so neither is needed here.
- WSL clock drifts after the Windows host sleeps. Freshness window is 30s.
  Fix: sudo ntpdate pool.ntp.org
- Keys must not live on /mnt/c — Windows filesystem breaks mode 0600 and the
  loader refuses group/world-readable key files.
- SSH root password login to CT 102 is refused (OpenSSH default
  prohibit-password). Use pct exec from the Proxmox host, or set up a key.
- Run from the parent of eureka_protocol so the package resolves. On CT 102 a
  .pth in the venv handles this; on WSL use sys.path.insert or cd ~/eureka.

## Not yet done

DHT discovery (addresses are still configured by hand), NAT traversal, WAN,
the assign endpoint (deliberately unimplemented — code-exec over a network
with no sandbox). Mutual TLS is evaluated and deliberately not planned; see
the TLS section above for why.
