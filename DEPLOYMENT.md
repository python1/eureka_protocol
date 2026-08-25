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

    cd /root/.openclaw/workspace
    EUREKA_IDENTITY_PATH=/root/.eureka/identity.key \
    EUREKA_TRUST_PATH=/root/.eureka/trust.json \
    /root/eureka_venv/bin/python -m uvicorn \
      eureka_protocol.src.eureka_daemon.api:app --host 0.0.0.0 --port 8000

Check: curl -s http://192.168.1.174:8000/v1/manifest

## Run the handshake (WSL initiates)

    cd ~/eureka
    EUREKA_IDENTITY_PATH=~/.eureka/identity.key \
    EUREKA_TRUST_PATH=~/.eureka/trust.json \
    ./venv/bin/python -c "
    import sys, asyncio, json
    sys.path.insert(0, '.')
    from eureka_protocol.src.eureka_daemon.node import EurekaNode
    from eureka_protocol.src.eureka_daemon.client import handshake_over_http
    node = EurekaNode.with_persistent_identity(capabilities=['fast-inference'])
    result = asyncio.run(handshake_over_http(node, 'http://192.168.1.174:8000'))
    print(json.dumps(result, indent=2))
    "

Expect authenticated: true, mutual: true.
Verify from the responder: curl -s http://localhost:8000/v1/peers

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
transport encryption (evaluate mutual TLS before building anything custom),
the assign endpoint (deliberately unimplemented — code-exec over a network
with no sandbox).
