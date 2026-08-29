# Eureka Protocol — working two-node deployment

First successful cross-machine mutual handshake: 2026-08-24, commit 976c1f1.
Responder moved from CT 102 to its own container, CT 101, on 2026-08-28 —
see "Moving the responder to another host". CT 101's trust file was migrated
v1 -> v3 the same day and `wsl-hermes` now holds `web-retrieval`, which the
peer exercised end to end on 2026-08-29 — see "What the WSL peer proved".

## Nodes

| Node | Host | node_id | public key |
|---|---|---|---|
| eureka-node | CT 101 (192.168.1.180), Debian 13 unprivileged | node_a2ed8dc7 | a718592fde751a92db31fa27ee1e88efbd6c1134753fd9a5d92b08b89d118fd1 |
| wsl-hermes | Alienware WSL2 (Ubuntu 24.04) | node_ef0a1f59 | bff5536af5a324f8f8d971e93047a4f1944f9c31dc06408826680d5b21d482ae |

`eureka-node` was `ct102-antiochus` until the move. Only the label and the
address changed: the key is the same bytes, so `node_a2ed8dc7` and the pinned
public key are unchanged and no peer was reprovisioned. Names in a trust file
are human labels — lookups are by key — so a peer that renames its entry, or
does not, is unaffected either way.

Private keys live in each host's identity file, mode 0600. A key is copied only
to move a node between hosts, over a direct link between the operator's own
machines, and the source copy is left in place rather than moved.

## Paths

CT 101 (the live responder): repo /root/eureka_protocol, deployed runtime
/opt/eureka, identity /var/lib/eureka/identity.key, trust
/var/lib/eureka/trust.json, state owned by the `eureka` system user.
The service runs /opt/eureka/venv; there is no separate development venv on
this host, so the test suite runs against /opt/eureka/venv too.

CT 102 (192.168.1.174) still holds the origin repo at
/root/.openclaw/workspace/eureka_protocol and its development venv
/root/eureka_venv. Its daemon is stopped and disabled as of 2026-08-28 and its
/var/lib/eureka is left intact — that copy of the identity is now a backup, and
two hosts must never serve this identity at once. Its `trust.json` there is
still v1 (checked 2026-08-28) and predates the grant, so that backup restores
the identity and an allowlist that grants nothing. Same for
`/root/trust.json.v1.bak-20260828` on CT 101 — see "Granting a capability".

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
          "capabilities": ["web-retrieval"]
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

CT 101's live file has been v3 since 2026-08-28. Older versions still load:
v1 (peers maps name -> bare key string) grants nothing, v2 adds capabilities.
Both are read-only history at this point -- neither can express a revocation,
and a `revoked` list in a file declaring version 1 or 2 is a load error rather
than a field that is quietly ignored.
Get that wrong silently and an operator believes a compromised key is dead
when it is still authenticating.

A grant naming a capability the node does not advertise is also a load error,
so a typo fails at startup instead of sitting in the file looking effective.

**Which capabilities are legal is a property of the node reading the file, not
of the peer named in it.** The daemon advertises exactly one:

    web-retrieval

**It used to advertise three** -- `code-exec`, `web-retrieval` and
`data-analysis` -- written out by hand in `api.py`. They are gone because the
list is no longer written anywhere: it is derived from the handler registry,
which is the only thing that knows what this node can actually do. `code-exec`
and `data-analysis` have no handler, so advertising them was the node claiming
work it could not do, and the discovery of that came at request time to a peer
every gate had already told yes.

**This narrows what the trust file may grant.** A file granting `code-exec` or
`data-analysis` loaded fine before and does not load now, and an unloadable
trust file does not degrade the daemon, it stops it -- five attempts, then
`failed`. CT 101's file grants `wsl-hermes` exactly `web-retrieval`, so it is
unaffected; check any other file before deploying, with the load in step 3 of
"Granting a capability", which now takes its advertised list from the registry
rather than repeating it.

Note that `demo.sh` builds its client node with
`capabilities=["fast-inference"]`, which is that node's own advertised set and
has nothing to do with what the daemon accepts. That still works and is still
unrelated: a client node is built without a registry, so it advertises what it
was told and executes nothing. Using one list where the other belongs remains
the easiest way to write a file that fails at startup. **Validate before
restarting** -- see "Granting a capability".

## Granting a capability (and migrating v1 -> v3)

A v1 file authenticates peers and grants nothing, so a peer on it handshakes
normally and gets `capability_not_granted` from `/v1/assign`. That is the safe
direction to be wrong in, and it is where CT 101 sat until 2026-08-28: the file
carried over from CT 102 was v1, so `wsl-hermes` was trusted and entitled to
nothing. It was migrated that day, by the procedure below; what the run
actually produced is recorded after it.

Migrating is a load and a write -- `to_document()` always emits the current
version, so a v1 file that is read and written back comes out as v3 with the
same peers. The grant is the only deliberate change.

**Back up first, and validate before restarting.** The daemon reads this file at
startup and refuses to start if it cannot load it, so an invalid grant does not
degrade the node, it stops it -- and the crash-loop guard then holds it in
`failed` until a human intervenes. The order below never leaves the service
depending on a file nobody has loaded yet:

    # 1. back up. trust.json holds public keys only, so /root is fine.
    cp -p /var/lib/eureka/trust.json /root/trust.json.v1.bak-$(date +%Y%m%d)

    # 2. rewrite in place, as the eureka user. Editing in place preserves the
    #    inode, so owner and mode survive; a shell redirect would create a new
    #    file owned by root and unreadable by the daemon.
    cd /opt/eureka
    runuser -u eureka -- /opt/eureka/venv/bin/python -c "
    import json
    from eureka_protocol.src.eureka_daemon.trust import TrustList
    path = '/var/lib/eureka/trust.json'
    trust = TrustList.load(path)
    trust.add('wsl-hermes', trust.key_for('wsl-hermes'), ['web-retrieval'])
    with open(path, 'w') as fh:
        json.dump(trust.to_document(), fh, indent=2); fh.write('\n')
    "

    # 3. load it the way the daemon will, BEFORE restarting. Raises if wrong.
    #    The advertised list comes from the handler registry, not from a list
    #    typed here: typing one is how this check drifts from the daemon and
    #    starts passing files the daemon will refuse.
    runuser -u eureka -- /opt/eureka/venv/bin/python -c "
    from eureka_protocol.src.eureka_daemon.trust import TrustList
    from eureka_protocol.src.eureka_daemon.handlers import default_registry
    advertised = sorted(default_registry().names())
    print('this node advertises:', advertised)
    t = TrustList.load('/var/lib/eureka/trust.json', advertised=advertised)
    k = t.key_for('wsl-hermes')
    print('grants:', sorted(t.capabilities_for(k)),
          '| web-retrieval:', t.grants(k, 'web-retrieval'),
          '| code-exec:', t.grants(k, 'code-exec'))
    "

    # 4. only now. The file is read at startup, not per request.
    systemctl restart eureka-daemon

`add()` on a name already present replaces that peer's grants and keeps the key,
which is why this is one call rather than a remove and a re-add: there is no
moment when the peer is absent from the file. It refuses outright if the key is
revoked, so a revoked peer cannot be quietly re-granted by this path.

Step 3 is the one that is tempting to skip and should not be. It fails in the
shell, where a bad grant costs nothing; skipped, the same mistake surfaces as a
daemon that will not start, and the node is off the mesh until someone reads the
journal. If it raises, restore the backup and fix the grant before restarting.

Grant the narrowest capability that does the job. `code-exec` is deliberately
not granted to anyone, and is now not even advertised: there is no handler for
it, because there is no sandbox to put one behind, and registering one is the
act that would make every standing grant for it live at once. A grant written
now is a decision taken now -- and today a `code-exec` grant is not a dormant
decision but a file that will not load.

### What the run produced on CT 101, 2026-08-28

The backup from step 1 is `/root/trust.json.v1.bak-20260828`, and it is the last
v1 copy on that host. Restoring it is a rollback of the *migration*, not of the
grant: the file comes back at a version that cannot express a revocation at all,
so a key revoked after today would return trusted, and a `revoked` list written
into it is a load error rather than a field that is ignored. Keep it as the
record of what the file was, and re-migrate rather than restore.

Ask step 3 about a capability that must be *absent* as well as the one being
granted -- a check that only ever prints True cannot fail. It printed:

    grants: ['web-retrieval'] | web-retrieval: True | code-exec: False

Run today it also prints `this node advertises: ['web-retrieval']`, because the
daemon stopped advertising `code-exec` and `data-analysis` when the executor
landed. The `False` above was already the right answer; it is now the only
possible one, since a `code-exec` grant would fail to load rather than sit in
the file being refused.

The first is the grant as the daemon will read it; the second is the gate
answering for it; the third is the one to keep re-reading. `code-exec` is still
granted to nobody, and now that the file is v3 that is a checked fact rather
than a side effect of a format that could not grant anything to anyone.

The restart after it brought the daemon back as `node_a2ed8dc7`, manifest
answering on 8443. The trust file does not touch the identity, so a node_id that
moves across a grant means the wrong file was edited -- or `EUREKA_IDENTITY_PATH`
missed and a key was minted -- not that the grant was bad.

A full container restart followed, and the daemon came back `active` with nobody
starting it. That is the evidence step 4 of the move asks for and could not have
before: `enabled` is a claim, and until something restarted that host the claim
was all there was.

**The grant is not confirmed end to end, and CT 101 cannot confirm it.** There
is no self-handshake in this protocol (see "CT 101 cannot run the trusted
scenario against itself"), so the only thing that proves the grant is a signed
`/v1/assign` from `wsl-hermes` naming `web-retrieval` and getting back anything
other than `capability_not_granted`. The Alienware is powered off, so that is
outstanding as of 2026-08-28. What is proven is that the daemon loads the file
and the allowlist answers True for `web-retrieval` and False for `code-exec`;
what is not proven is that a peer on the far side of a handshake sees the same
answer. Do not read the restart as the check -- a daemon that starts has loaded
the file, which is the cheap half.

That gap closed on 2026-08-29, once the executor was deployed and the Alienware
came back: `wsl-hermes` made the signed call and got a fetched page. The
paragraph above stands as what was and was not known on the day, which is the
point of dating it. See "What the WSL peer proved".

## Revoking a peer

Revoking is not the same as deleting the entry. A deleted key comes back the
moment someone restores an old trust file from a backup; a revoked key stays
refused, and records why.

    runuser -u eureka -- /opt/eureka/venv/bin/python -c "
    import json
    from eureka_protocol.src.eureka_daemon.trust import TrustList
    path = '/var/lib/eureka/trust.json'
    trust = TrustList.load(path)
    trust.revoke('<64 hex chars>', reason='laptop stolen')
    open(path, 'w').write(json.dumps(trust.to_document(), indent=2))
    "

Run it as `eureka`, not root. Editing in place preserves the file's owner and
mode either way, but a command that creates the file fresh -- a redirect, an
editor that writes a new inode -- leaves it root-owned and unreadable by the
daemon.

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

**CT 101 serves TLS on 8443 and nothing else. Plaintext is gone.**

    /opt/eureka/venv/bin/python -m eureka_protocol.src.eureka_daemon.server \
        --tls-port 8443 --no-plain --tls-dir /var/lib/eureka/tls

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
that CT 101 refuses plaintext outright, a client that omits it fails at the
transport rather than at the check -- so the flag is a belt to the transport's
braces, not the thing keeping the channel encrypted:

    await handshake_over_http(node, "https://192.168.1.180:8443", require_tls=True)

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

    EurekaCrypto.rotate('/var/lib/eureka/identity.key')

The outgoing private key is archived beside the live one as
`identity.key.retired-<timestamp>` at mode 0600 and never deleted -- it is the
only thing that can still verify signatures it made while it was live.

**The node_id changes.** It is derived from the public key, so a rotated node
comes back as a different identity and every peer must be re-provisioned with
the new key out of band. There is deliberately no signed "here is my new key"
message that peers act on by themselves: a stolen key could use it to rotate
the thief into permanent trust, which is trust-on-first-use wearing a hat.

## Start the responder (CT 101)

CT 101 runs the daemon under systemd as `eureka-daemon.service`, enabled at
boot -- and observed coming back on its own after a full container restart on
2026-08-28, which is the first time that was evidence rather than a setting.
It is no longer started by hand -- a daemon living in an SSH session dies with
the session, and one that inherits its identity from a shell comes back as a
different node the day someone forgets to export a variable.

    systemctl status eureka-daemon
    systemctl restart eureka-daemon
    journalctl -u eureka-daemon -f

Check both listeners:

    curl -sk https://192.168.1.180:8443/v1/manifest    # TLS (the only listener)
    curl -s  http://192.168.1.180:8000/v1/manifest     # refused: nothing there

That manifest carries `node_id` and `runtime` and nothing else. It is the only
endpoint that answers an unauthenticated caller, and it stays that way because
first contact needs it -- a peer reads node_id from here to address its
handshake offer. The capability list moved behind authentication; the peer
table was never reachable from here.

`curl -k` skips chain verification, which is correct here and not a shortcut:
the certificate is self-signed and identity lives in the key inside it, not in
any chain. A real peer pins that key against its trust file. To check the
served key by hand:

    openssl s_client -connect 192.168.1.180:8443 </dev/null 2>/dev/null \
      | openssl x509 -pubkey -noout

To compare it against the pinned key as raw hex rather than by eye -- the
ed25519 public key is the last 32 bytes of the DER encoding:

    openssl s_client -connect 192.168.1.180:8443 </dev/null 2>/dev/null \
      | openssl x509 -pubkey -noout \
      | openssl pkey -pubin -outform DER \
      | tail -c 32 | od -An -tx1 | tr -d ' \n'; echo

The unit is version controlled at **`deploy/eureka-daemon.service`**, which is
the canonical copy; `/etc/systemd/system/eureka-daemon.service` is an install
of it. Identity and trust paths are set in the unit, not inherited. Logs go to
the journal under the identifier `eureka-daemon`.

Install, or reinstall after editing:

    cd /root/eureka_protocol
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

### journald in an unprivileged container

CT 101 carries exactly one drop-in, and it is host-specific in precisely the
way that rule is for. On a fresh unprivileged LXC, `systemd-journald` fails
with **`status=243/CREDENTIALS`** — the credentials machinery it is built with
is not available to the container — and until it is fixed, `journalctl` has
nothing. The daemon still runs and still logs; the logs go nowhere anyone can
read them, which is worse than a visible failure, because every verification
step in this document that reads the journal silently proves nothing:

    mkdir -p /var/log/journal
    systemctl edit systemd-journald      # clear the inherited settings:
        [Service]
        LoadCredential=
        ImportCredential=
    systemctl restart systemd-journald

Assigning the empty string resets a list the vendor unit populated; dropping
the line entirely would inherit it again. `/var/log/journal` makes the journal
persistent, so it also survives the reboot that boot-survival is tested with.

Confirm it took before trusting anything the journal says:

    systemctl is-active systemd-journald
    journalctl -u eureka-daemon -b | head

The startup lines name the node and the public key peers pin. If the journal
is empty, the daemon is not the thing to debug.

To run it by hand anyway -- debugging, or a second node on another port -- stop
the service first so the port is free:

    systemctl stop eureka-daemon
    cd /opt/eureka
    runuser -u eureka -- env \
      EUREKA_IDENTITY_PATH=/var/lib/eureka/identity.key \
      EUREKA_TRUST_PATH=/var/lib/eureka/trust.json \
      /opt/eureka/venv/bin/python -m eureka_protocol.src.eureka_daemon.server \
      --tls-port 8443 --no-plain --tls-dir /var/lib/eureka/tls

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

### It runs as a system user, not root

    User=eureka   Group=eureka

State in `/var/lib/eureka` (mode 0700, owned by that user):

| path | what | mode |
|---|---|---|
| `identity.key` | the node's private key -- **precious, back this up** | 0600 |
| `trust.json` | the peer allowlist | 0600 |
| `tls/` | certificate and its key, **derived and disposable** | 0600 |

Only `tls/` is disposable: it is regenerated from the identity whenever it
stops matching, so deleting it costs one restart. Deleting the directory
*above* it destroys the node.

`node_id` did not change, because it derives from the key and the key is the
same bytes -- verified after each move, not assumed, and no peer needed
reprovisioning. That has now held twice: once dropping from root to the
`eureka` user on CT 102, and once moving hosts to CT 101.

**The runtime had to move too, and that is the part the old plan missed.**
On CT 102 `/root` is mode 0700, so a non-root service cannot traverse it -- and
the interpreter (`/root/eureka_venv`) and the code (`/root/.openclaw/workspace`)
both lived under it. Opening `/root` up was the obvious fix and is the wrong
one: `/root/.openclaw` beneath it is 0755, so making `/root` traversable would
hand the entire agent workspace to this service account and undo most of the
point of dropping privileges.

The same split is kept on CT 101 even though there is no agent workspace there
to protect: the repo lives at `/root/eureka_protocol`, which the service still
cannot see, and only `/opt/eureka` is readable to it. A service that cannot
reach the repo cannot be surprised by an uncommitted edit in it.

So the runtime is deployed to `/opt/eureka`, root-owned and world-readable,
which the service reads and cannot write:

    /opt/eureka/venv               interpreter and dependencies
    /opt/eureka/eureka_protocol    the code the daemon runs
    /opt/eureka/DEPLOYED_COMMIT    which commit that is

The `macbook` git remote is the shared source of truth across hosts, but only
CT 102 and the MacBook itself can reach it. CT 101 has no remote at all and
cannot fetch from anywhere -- see "Advancing CT 101 to a new commit" below
before assuming a fetch there did something. On CT 101 the working copy is
`/root/eureka_protocol`. Refresh the deployment from it the same way the unit is
installed -- copy, then check:

    rsync -a --delete --exclude '.git' --exclude '__pycache__' \
      --exclude '.pytest_cache' \
      /root/eureka_protocol/ /opt/eureka/eureka_protocol/
    git -C /root/eureka_protocol rev-parse HEAD \
      > /opt/eureka/DEPLOYED_COMMIT
    chown -R root:root /opt/eureka && chmod -R u=rwX,go=rX /opt/eureka
    systemctl restart eureka-daemon

`DEPLOYED_COMMIT` is written from the repo's HEAD, so it is only honest if the
rsync and the `rev-parse` describe the same tree: refresh with a dirty working
copy and the file names a commit the deployed code does not match. `git status
--short` before, or accept that the record is decoration.

### Advancing CT 101 to a new commit

**CT 101 has no git remote at all, deliberately.** It had one until 2026-08-28:
a clone leaves `origin` pointing at whatever it was cloned from, and this host
was cloned from `/root/migrate/eureka.bundle`, the one-shot file it was seeded
from during the move. That remote was worse than useless. The default fetch
refspec is a **forced** update, so `git fetch` re-read that frozen file and
drove `origin/master` back to the seed commit -- silently, exit 0, no output.
The branch itself was never at risk (a fetch does not move local `master`), but
the tracking ref would jump backwards and `git status` would then describe the
branch as ahead of a history that had actually already been merged. It rewound
once that way before the remote was removed.

So `origin` is gone rather than repointed, and a bare `git fetch` is now inert:
no remote, no tracking ref, nothing to move. `git status` reports no upstream,
which is the honest description of a host that has no reachable remote.

Repointing it at the MacBook is not currently possible without widening access.
CT 101 holds no private key at all (`/root/.ssh` has `authorized_keys` and
`known_hosts` and nothing else) and has no `macbook` host alias. The MacBook's
port 22 *is* reachable from CT 101 -- it answers and then refuses with
`Permission denied (publickey,password,keyboard-interactive)` -- so this is an
authentication gap, not a network one. Closing it means generating a keypair on
CT 101 and authorizing it on the MacBook, which adds an inbound credential to a
laptop and turns a deliberately one-way link (MacBook -> CT 101) into a round
trip. That is a decision to take on purpose, not a step to slip into a
migration. Until someone takes it, commits reach CT 101 as bundles.

An incremental bundle carries only the range, and names the commit it must be
applied onto, so it refuses to apply to the wrong history instead of guessing:

    # 1. on CT 102, from a clean working copy.
    #    OLD is what CT 101 is on now -- ask it, do not assume:
    #    ssh macbook "ssh root@192.168.1.180 'git -C /root/eureka_protocol rev-parse HEAD'"
    OLD=<CT 101's HEAD>   NEW=<short sha of master>
    cd /root/.openclaw/workspace/eureka_protocol
    git status --short                      # must be empty, per the note above
    git bundle create /tmp/eureka-$OLD-$NEW.bundle $OLD..master
    git bundle verify /tmp/eureka-$OLD-$NEW.bundle

    # 2. hop it across -- CT 102 -> MacBook -> CT 101, the same route as the move
    scp /tmp/eureka-$OLD-$NEW.bundle macbook:/tmp/
    ssh macbook "scp /tmp/eureka-$OLD-$NEW.bundle root@192.168.1.180:/root/migrate/"

    # 3. on CT 101: verify the prerequisite is present, then fast-forward
    B=/root/migrate/eureka-$OLD-$NEW.bundle
    git -C /root/eureka_protocol bundle verify $B
    git -C /root/eureka_protocol fetch $B master
    git -C /root/eureka_protocol merge --ff-only FETCH_HEAD

`bundle verify` is the step that matters: an incremental bundle names the commit
it must be applied onto, so it refuses the wrong history instead of guessing.
Run it before the fetch and a bundle built against the wrong `OLD` says so.

Merge from `FETCH_HEAD`, and do not recreate a `refs/remotes/origin/*` ref to
merge from instead. A tracking ref under `origin` implies a remote this host can
talk to; inventing one to satisfy a habit is what made the rewind above possible
in the first place. `--ff-only` keeps this a transport rather than a merge: if it
refuses, CT 101 has commits of its own, and that is a fact to resolve rather than
to force past.

Then refresh `/opt/eureka` with the rsync above, so `DEPLOYED_COMMIT` moves with
the repo. Keep the bundles in `/root/migrate` named by range -- the filenames
are the record of how CT 101 got from one commit to the next, which is the only
audit trail a host with no reachable remote has.

The venv carries a `.pth` naming the directory the package is imported from.
In `/opt/eureka/venv` it says `/opt/eureka`; CT 102's development venv under
`/root` still says `/root/.openclaw/workspace`. Copying a venv without fixing
that gives an interpreter that silently imports the *other* tree -- so a venv
built on a new host gets the `.pth` written explicitly:

    echo /opt/eureka > /opt/eureka/venv/lib/python3.13/site-packages/eureka.pth

Because nothing the service needs lives under `/root` any more,
`ProtectHome=read-only` became **`ProtectHome=yes`**: `/root`, `/home` and
`/run/user` are masked outright in the service's mount namespace. Verified by
listing `/root` inside it -- zero entries. Alongside `NoNewPrivileges`,
`PrivateTmp` and `ProtectSystem=full`.

**Watch the two environment variables.** The identity loader *creates* a key
when the file it is pointed at does not exist, so a typo in
`EUREKA_IDENTITY_PATH` does not fail -- it quietly mints a new identity and the
node comes back under a node_id no peer trusts. They are set explicitly in the
unit, and they are the first thing to check if `node_id` ever changes.

### What the run produced on CT 101, 2026-08-28: d8dddc9 -> 7929bc3

The fifth incremental bundle in `/root/migrate`, and the first deploy that
changes what the node *advertises* rather than only what it does: `7929bc3` is
the handler registry and `web-retrieval`.

CT 101's HEAD was asked for, not assumed -- `d8dddc9`, working copy clean. The
bundle is `/root/migrate/eureka-d8dddc9-7929bc3.bundle`, 35 KB, verified on both
sides: built and verified on CT 102, verified again on CT 101 before the fetch.
Then `fetch` + `merge --ff-only` off `FETCH_HEAD`, no ref invented under
`origin`, and the rsync to `/opt/eureka` with `DEPLOYED_COMMIT` written from the
repo's HEAD afterwards. Repo, deployment and the file all read `7929bc3`.

**Validated before the restart, and the validation is the interesting part.**
Step 3 of "Granting a capability" was run against the untouched live trust file,
and printed:

    this node advertises: ['web-retrieval']
    grants: ['web-retrieval'] | web-retrieval: True | code-exec: False

That first line is new, and it is what this commit is for: the advertised list
now comes from the handler registry, so `code-exec` and `data-analysis` are gone
from it. Nothing in the trust file grants either, which is why the deploy was
uneventful -- but the failure mode has moved. A grant naming a capability with
no handler is now a **load error**, so a file that used to sit there being
refused per request will instead stop the daemon from starting. That is the
intended direction and it is a sharper edge than it was yesterday.

The suite was also run on CT 101 under `/opt/eureka/venv` -- the service
interpreter, not a development one -- and passed 616. Worth doing here rather
than trusting CT 102's run: the `.pth` above means that interpreter imports
`/opt/eureka`, so this exercised the deployed tree, which is the one that
matters.

Restart was clean: `active`, `enabled`, `NRestarts=0`, PID 1284 -> 1823, no
errors in the journal. The daemon came back as `node_a2ed8dc7` and served the
same TLS key -- the certificate's raw ed25519 key was pulled from the live
listener and compared against the pin the journal prints, `a718592f...`, and
matched exactly. No peer needs reprovisioning, and neither the identity nor the
trust file was touched by any of this.

**What is still not proven is the same thing that was not proven yesterday, and
it now matters more.** There is no self-handshake, so CT 101 cannot ask itself
for `web-retrieval`; only a signed `/v1/assign` from `wsl-hermes` proves a peer
on the far side sees what the local allowlist says. Until this deploy that
outstanding check would have returned a canned string either way. Now it would
return a real fetched page, which makes it the first assign that could actually
distinguish a working executor from a working gate. The Alienware is still
powered off.

**It was run the next day, and it distinguished them.** See "What the WSL peer
proved" -- and note that the first attempt failed on a ten-second DNS stall
that looked exactly like a protocol fault and was not one.

## Moving the responder to another host

Done on 2026-08-28, CT 102 -> CT 101, at commit 3854f00. The node kept
`node_a2ed8dc7` and the WSL peer's trust file was not touched — only the
address it dials.

**A move is not a rotation.** Rotation mints a new key and every peer must be
reprovisioned out of band; a move carries the same key to a new host and no
peer notices. That is the whole reason the identity is copied rather than
regenerated, and it is why the copy must be verified byte-for-byte instead of
assumed: a key that arrives subtly different does not fail loudly, it comes
back as a stranger that nobody trusts.

The order that keeps the mesh up:

1. **Stage the payload.** On the old host, build a git bundle of the deployed
   commit and a `pip freeze` of the *service* venv, and copy the identity and
   trust files. Checksum all four; carry the checksums with them.
2. **Transfer between your own machines only.** CT 102 has no route to CT 101,
   so the payload went CT 102 -> MacBook -> CT 101 over existing SSH key auth,
   `umask 077` at every hop, and was deleted from the intermediate host as soon
   as it landed. Never stage key material anywhere a third party stores it.
3. **Build the new host and verify the identity before creating the service.**
   Package deps, the `eureka` system user, clone from the bundle, venv from the
   freeze, `/opt/eureka` laid out with the `.pth` written explicitly, then
   `/var/lib/eureka` at 0700 with both files 0600. Confirm the checksums match
   the old host, then derive the node_id offline, as the service user:

        cd /opt/eureka
        runuser -u eureka -- /opt/eureka/venv/bin/python -c "
        from eureka_protocol.src.eureka_daemon.crypto import EurekaCrypto
        c = EurekaCrypto.load('/var/lib/eureka/identity.key')
        print(c.derive_node_id()); print(c.get_public_key_hex())
        "

   `EurekaCrypto.load` refuses a missing file, where the daemon's
   `load_or_create` would mint a new identity and look healthy doing it — so
   this is the check, and it belongs *before* a service exists to be started.
   Run the test suite here too; a node that cannot pass its own tests should
   not be handed an identity.
4. **Start it and verify locally.** Service active, manifest carrying the right
   node_id, plaintext refused, the served certificate's key equal to the pinned
   key, ownership and modes right, identity unchanged across a restart *and*
   across a reboot — `enabled` is a claim, a reboot is the evidence.
5. **Cut the peer over and prove it.** Point the peer at the new address with
   no change to its trust file, and require the full `demo.sh` contrast, not
   just a green handshake. Confirm on the responder from the journal.
6. **Only then stop the old daemon.** `systemctl disable --now eureka-daemon`,
   and confirm the old port is refused.

**Both daemons must never serve this identity at once.** Two hosts answering as
`node_a2ed8dc7` keep separate replay tables and separate peer tables, so a
nonce spent against one is still unspent against the other — the same reason
the TLS and plaintext listeners share a process. Overlap is bounded to the
verification window in step 5, when the new host is running but no peer has
been pointed at it yet.

The old host's `/var/lib/eureka` is left intact and becomes the backup copy of
the identity. It is dead weight only until the day the new host's disk fails.

### Close out the staging directory

A move leaves a second copy of the private key on the new host, in whatever
directory the payload was unpacked into -- `/root/migrate` here. That copy is
outside `/var/lib/eureka`, so nothing in the unit protects it: `StateDirectory`
does not own it, the `eureka` user does not need it, and it is exactly the kind
of file that later gets swept into a backup or an rsync by someone who does not
know what it is. As of 2026-08-28 it is **still present on CT 101** and should
be removed once the identity is confirmed installed.

Confirm the installed copy first, then delete the staged one -- in that order,
so a mismatch is found while both copies still exist:

    sha256sum /root/migrate/identity.key /var/lib/eureka/identity.key
    sha256sum /root/migrate/trust.json  /var/lib/eureka/trust.json
    # identical, and the daemon is serving the right node_id? then:
    shred -u /root/migrate/identity.key /root/migrate/trust.json

Leave the bundles: they are code, not secrets, and their filenames are this
host's only record of how it got from one commit to the next.

The seed bundle `eureka.bundle` is also worth keeping for a different reason --
it is what a fresh clone here would have to come from, and the clone that
created it is what left the `origin` remote that had to be removed. See
"Advancing CT 101 to a new commit".

## Run the handshake (WSL initiates)

`demo.sh` in this repo is the end-to-end check. It is version controlled, so
both hosts run the same one:

    cd ~/eureka/eureka_protocol
    ./demo.sh                                # TLS to CT 101 on 8443

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

Verify from the responder with the journal, not with curl -- `/v1/peers` is no
longer an open GET (see below):

    journalctl -u eureka-daemon | grep "Handshake established"

It takes a URL if you need a different peer or a plaintext one, though CT 101
no longer serves plaintext: `./demo.sh http://host:port`. Passing the address
explicitly is also how a host with a stale checkout gets pointed at a moved
responder without editing anything.

**A run that reports only the trusted scenario is a stale checkout, not a
passing check.** The untrusted case was added in `0a91e05`; before it,
`demo.sh` was 75 lines and ran one scenario. If the second block is missing,
the peer is behind -- `git -C ~/eureka/eureka_protocol log --oneline -1` says
how far -- and the run proves reachability only.

Nothing has to be passed to make TLS work. An `https://` URL builds a client
that **pins** the peer's key against the trust file instead of chaining to a
certificate authority -- there is no CA in this protocol, so a default HTTP
client rejects every peer with CERTIFICATE_VERIFY_FAILED. If you ever see
that, something is constructing its own client; the fix is
`tls.pinning_client()`, **never** `verify=False`, which switches the pin off
along with the chain and leaves the connection unauthenticated.

`demo.sh` picks its interpreter from `$EUREKA_PYTHON`, then `../venv`, then
CT 102's development venv -- and checks each candidate can actually import the
dependencies, because more than one venv sits next to this repo on some hosts.
On CT 101 neither fallback exists, so run it with
`EUREKA_PYTHON=/opt/eureka/venv/bin/python`.

### demo.sh needs the identity paths too, and fails soft without them

**Set `EUREKA_IDENTITY_PATH` and `EUREKA_TRUST_PATH` on every run, or the
trusted scenario quietly tests a node that did not exist until you ran it.**

The trusted scenario calls `with_persistent_identity()` with no path, so the
identity resolves exactly the way the daemon's does: explicit argument, then
`$EUREKA_IDENTITY_PATH`, then `~/.eureka/identity.key`. The daemon is handed
those two variables by the unit (`Environment=` lines, not defaults); a login
shell inherits neither. A run without them therefore falls through to the
default path -- where `EurekaCrypto.load_or_create` **creates a key when it
finds none** rather than failing.

That is the same shape as the trap the non-root move hit: a step that
manufactures what it was supposed to find, and reports success for it. The
create-on-miss behaviour is right for the daemon, because it is how a node gets
an identity on first boot. It is exactly wrong for a verification run, whose
entire purpose is to prove that one *specific* key still works. Nothing errors,
nothing is logged, and the summary line prints

    node_id   : node_XXXXXXXX  (must not change across runs)

with a value that looks perfectly well-formed and is meaningless.

Exporting `HOME` to reach the state directory makes it worse rather than better:
`HOME=/var/lib/eureka` lands the throwaway at
`/var/lib/eureka/.eureka/identity.key` -- beside the real key, owned by the same
user, where it reads as node state instead of litter. Seen on 2026-08-28; the
stray file was deleted and the real `identity.key` and `trust.json` were
untouched, because `load_or_create` only ever writes the path it resolved. Check
for a stray `.eureka/` under `/var/lib/eureka` after any run that reported an
unfamiliar node_id.

The full invocation on CT 101:

    cd /opt/eureka/eureka_protocol
    runuser -u eureka -- env \
      EUREKA_PYTHON=/opt/eureka/venv/bin/python \
      EUREKA_IDENTITY_PATH=/var/lib/eureka/identity.key \
      EUREKA_TRUST_PATH=/var/lib/eureka/trust.json \
      bash demo.sh https://<peer>:8443

Read `local node` on the first scenario before reading anything else: it must
say `node_a2ed8dc7`. If it says anything else the environment did not arrive,
and the rest of the run describes a node nobody has ever trusted.

Only the trusted scenario is exposed to this. The untrusted one passes explicit
paths into a temp directory, and an explicit argument beats the environment --
so it keeps passing, correctly, while the trusted one is silently wrong. A run
that reports `untrusted: PASS` and `trusted: FAIL` is the signature of a missing
environment at least as often as it is a real protocol failure.

### CT 101 cannot run the trusted scenario against itself

Pointing `demo.sh` at CT 101 *from* CT 101 fails the trusted leg every time,
with `untrusted_key` / "the key terminating TLS is not trusted". That is correct
behaviour, not a regression: CT 101's trust list contains one peer, `wsl-hermes`,
and a node does not carry its own key in its own allowlist, so pinning the
responder's TLS key against it cannot succeed. There is no self-handshake in
this protocol. The trusted scenario has to be initiated from the WSL peer; run
locally on CT 101, `demo.sh` proves the listener is up and the refusal path
works, and nothing more.

## Reading the peer table and the audit log

`/v1/peers` and `/v1/logs` used to be open GETs. Anything that could reach the
port could list every peer this node had authenticated, which is the record the
protocol exists not to publish -- so an operator habit of `curl -sk .../v1/peers`
was, in effect, a demonstration of the leak.

Both are now POST endpoints that take a signed request, and both refuse anything
else. The rules:

- A GET gets 405 from the router. Nothing is consulted to produce it.
- An unsigned, badly signed, stale, untrusted or revoked request gets a refusal
  carrying an empty result. The refusal is built from the request's event and
  the rejection reason alone, so it is identical whether or not this node has
  peers -- it cannot be used to ask whether the node talks to anybody.
- Completing TLS is not authentication. The daemon asks for no client
  certificate, so a TLS caller is anonymous to it; only the three-message
  handshake makes a caller someone. Being on the trust list is not enough
  either.
- An authenticated peer sees only what it names: the caller lists the public
  keys it is asking about, and the answer covers only the ones this node also
  has as authenticated peers. A peer the caller did not name is not disclosed,
  so authenticating to this node does not enumerate the mesh behind it.
- Audit-log entries are disclosed only to the peer they are attributed to.
  Nothing attributes entries today (`assign()` is a stub with no requesting
  peer), so over the network the log reads empty to everyone. The entries are
  in the journal, which is where an operator should read them.

**For the operator, use the journal, not the network.** It is not gated by the
trust file, it is protected by the OS, and it already records every handshake:

    journalctl -u eureka-daemon | grep "Handshake established"
    journalctl -u eureka-daemon | grep "EUREKA-LOG"

To read a peer's table from another node, that node must have handshaked first;
`reads.build_read_query` builds the signed request and `POST /v1/peers` takes
it. Revoking a peer ends its read access at the same moment as everything else,
because the gate consults the live trust list and `reload_trust()` drops revoked
peers from the table it checks against.

## Gotchas

- WSL2 is behind NAT: outbound works, inbound needs a portproxy or
  networkingMode=mirrored. WSL initiates, so neither is needed here.
- WSL clock drifts after the Windows host sleeps. Freshness window is 30s.
  Fix: sudo ntpdate pool.ntp.org
- Keys must not live on /mnt/c — Windows filesystem breaks mode 0600 and the
  loader refuses group/world-readable key files.
- SSH root password login to CT 102 is refused (OpenSSH default
  prohibit-password). Use pct exec from the Proxmox host, or set up a key.
- CT 101 takes key auth from the MacBook. CT 102 has no SSH access to CT 101,
  which is why the move went CT 102 -> MacBook -> CT 101 rather than directly.
  CT 101's 8443 does answer from CT 102 though, so the manifest is checkable
  from here (`curl -sk https://192.168.1.180:8443/v1/manifest`) even when
  nothing else about that host is reachable.
- Run from the parent of eureka_protocol so the package resolves. On CT 101 and
  CT 102 a .pth in the venv handles this; on WSL use sys.path.insert or
  cd ~/eureka.
- A fresh unprivileged LXC has no working journald until the credentials
  drop-in is applied (status=243/CREDENTIALS). See "journald in an
  unprivileged container" -- until then every journal check here reads empty
  and proves nothing.
- A capability grant is validated against what *this* node advertises, which
  is now `web-retrieval` and nothing else -- derived from the handler registry,
  not typed into `api.py`. Granting `code-exec` or `data-analysis` used to load
  and now does not, and an unloadable trust file stops the daemon. So does
  `fast-inference`, which is `demo.sh`'s client-side list and was never one of
  ours. See "Granting a capability".
- `web-retrieval` cannot reach anything on this LAN, on purpose: loopback,
  private, link-local and CGNAT addresses are all refused, after DNS
  resolution and again on every redirect. If a fetch that should work comes
  back `address_not_allowed`, the target really does resolve into one of those
  ranges -- that is the check working, not a bug. See "web-retrieval, and what
  it refuses".
- CT 101 has no git remote, on purpose: its `origin` was the seed bundle, and
  a bare fetch force-rewound `origin/master` to the seed commit. New commits
  get there by bundle -- see "Advancing CT 101 to a new commit". Do not add a
  remote back without reading that section first.
- `demo.sh` without `EUREKA_IDENTITY_PATH`/`EUREKA_TRUST_PATH` creates a
  throwaway identity instead of failing, and reports a node_id that never
  existed. See "demo.sh needs the identity paths too".
- `wsl-hermes`'s `web-retrieval` grant was exercised by the peer on
  2026-08-29 and works end to end. It sat unexercised for a day because CT 101
  cannot test it against itself, and validating the file locally stayed a
  different check from a peer getting past the gate. See "What the WSL peer
  proved".
- **CT 101's DNS was broken in a way that looked like a protocol bug.** Its
  PVE-managed `/etc/resolv.conf` listed `1.1.1.1` first, and UDP/53 to
  `1.1.1.1` and `8.8.8.8` is blocked LAN-wide -- CT 102 sees the same block.
  glibc waited out the default `timeout:5` on the first nameserver before
  falling back to one that answered, so every cold lookup cost a flat five
  seconds. `web-retrieval` resolves twice on purpose (once for the policy
  check, once inside httpx when it connects), so a fetch of a 559-byte page
  took ten seconds and the peer's client timed out before the answer came
  back. Fixed on 2026-08-29 with `pct set 101 --nameserver 192.168.1.1` on the
  Proxmox host; cold `getaddrinfo` went from 5.05s to 0.056s and the whole
  handler from ~10s to 0.16s. Editing `/etc/resolv.conf` on CT 101 does not
  hold -- PVE regenerates it.
- **A client calling /v1/assign must outlast the registry's deadline, not the
  fetch timeout.** Those are different numbers: the fetch gets 10s, but the
  pre-flight DNS resolution runs before it and is not covered by it, and 30s
  is what actually bounds a dispatch. A 10s client races the work it asked
  for. Use 60s.

## Dispatching a task (/v1/assign)

The endpoint is gated the same way the reads are, plus authorization and a
single-use nonce. An unsigned or unauthenticated POST gets a refusal that
discloses nothing. An authenticated peer must hold a grant for the capability
its request names -- `capability_not_granted` otherwise, including when the
capability is not offered here at all; the two are deliberately
indistinguishable from outside. A replayed request is refused as
`replayed_nonce` and every decision about an authenticated caller is in the
audit log under that peer's name, readable back by that peer alone through
POST /v1/logs.

`assign.build_assign_query(node, capability, task_name, payload)` builds the
signed request. Grants live in the trust file exactly as before; nothing about
provisioning changed.

The WSL peer's client is unaffected: it calls the handshake endpoints and GET
/v1/manifest only.

### What is behind the gate now

**The stub is gone.** It slept half a second and returned `Processed by
<node_id>`. A granted peer now reaches a handler registry -- capability name to
the code that runs it -- and for this daemon that means `web-retrieval` and
nothing else.

The advertised list comes from that registry (`handlers.default_registry()`),
which is what makes a capability with no implementation impossible to
advertise. To see what this node offers, ask the registry rather than reading
`api.py`:

    cd /opt/eureka
    runuser -u eureka -- /opt/eureka/venv/bin/python -c "
    from eureka_protocol.src.eureka_daemon.handlers import default_registry
    print(sorted(default_registry().names()))
    "

The answer is on the wire too, but only to an authenticated peer: POST
/v1/manifest carries the capability list, the open GET does not.

A granted request returns `reason: authenticated` with a `result` and a
`result_signature`. The result is signed by this node in the assign-result
domain -- distinct from assign queries, reads, handshake messages and audit
entries -- over a payload that includes the request's nonce and requester, so
it is evidence about one request and cannot be lifted onto another. Refusals
are not signed: they are a constant built from the reason alone, and signing
one would make refusals tellable apart without attesting to anything.

**The gate's verdict and the work's verdict are separate.** `reason` stays
`authenticated` whenever the request was accepted and run; whether the work
succeeded is inside the result, under `status` and its own `reason`. A fetch
that timed out is a request this node accepted and could not complete, which is
a different fact from a peer that may not ask -- collapsing them would tell a
peer its grant had been withdrawn every time a web server was slow.

    result.status    completed | failed
    result.reason    ok | timeout | address_not_allowed | scheme_not_allowed
                     | body_too_large | too_many_redirects | connection_failed
                     | dns_resolution_failed | invalid_payload
                     | capability_not_implemented | handler_error

### web-retrieval, and what it refuses

Payload is `{"url": "https://..."}`. It returns `http_status`, `content_type`,
`body`, `bytes`, `truncated`, `final_url` and `redirects`. GET only. A 500 from
the target is a *successful* fetch of a failing page -- `status: completed`
with `http_status: 500` -- because "could not fetch" and "fetched, and it said
500" are different answers and the caller needs both.

The limits, all because the peer chooses the URL: 1 MiB body, 10 second fetch
timeout, 3 redirects, http and https only, and a 30 second wall-clock deadline
plus a cap of 8 concurrent handlers imposed by the registry itself. An
oversized body is refused outright when the target declares the size
(`body_too_large`) and truncated with `truncated: true` when it does not, so a
short page is never confusable with a cut one.

**The address policy is the part to understand before granting this to
anyone.** Asking a daemon to fetch a URL somebody else chose is server-side
request forgery by construction: the peer cannot reach this network, and this
node can. So only globally routable unicast addresses may be fetched. Refused:

    loopback          127.0.0.0/8, ::1
    private           10/8, 172.16/12, 192.168/16, fc00::/7
    link-local        169.254/16 (the cloud metadata address), fe80::/10
    CGNAT             100.64/10
    multicast, reserved, unspecified, and IPv4-mapped forms of any of these

CT 101's own API is covered by that without a special case: it answers on
192.168.1.180 and on loopback, both refused. So is CT 102 on 192.168.1.174, and
so is everything else on the LAN -- **a `web-retrieval` grant does not let a
peer reach anything inside this perimeter, which is the only reason it is safe
to grant to a peer outside it.**

The check runs on resolved addresses, never on the URL text, and every address
a name resolves to must pass rather than just the first. It runs a second time
on the address actually connected to, read off the socket before any body is
read, because the HTTP client resolves the name again when it connects and a
name can answer differently the second time. And it runs again on every
redirect -- hops are followed by hand for exactly that reason, so a URL that
passes and then 302s to `http://169.254.169.254/` is refused at the hop.

To see the policy for yourself on the deployed node:

    cd /opt/eureka
    runuser -u eureka -- /opt/eureka/venv/bin/python -c "
    from eureka_protocol.src.eureka_daemon.handlers import AddressPolicy
    p = AddressPolicy()
    for a in ('127.0.0.1','192.168.1.180','169.254.169.254','93.184.216.34'):
        print(a, p.refusal(a) or 'allowed')
    "

### What the audit log records, and what it must not

Each dispatch writes one entry, attributed to the requesting peer, carrying the
capability, the task name and the outcome -- `completed`, or the distinct
reason it was not.

    journalctl -u eureka-daemon | grep "EUREKA-LOG"

**It does not record the body, and it must not start.** For web-retrieval the
body is somebody else's page: copying it into the log would republish it under
this node's signature, keep it for as long as the log is kept, and hand it to
that peer again through /v1/logs. The URL is not recorded either -- it is the
peer's business, and the entry is a record of what this node did, not of what
the peer was looking for. The entry is built from named scalars rather than
from the result dict, which is the thing that keeps it that way.

### What the WSL peer proved, 2026-08-29

The check this file had been deferring since the grant was written. It is the
first `/v1/assign` from a real peer, and the first that could tell a working
executor from a working gate -- the refusals were always distinguishable, but a
*granted* request returned the same canned string whether anything behind the
gate could run or not.

`wsl-hermes` (node_ef0a1f59, on the Alienware) ran one handshake and then seven
cases behind it, because `is_permitted` consults a peer record that exists only
after a handshake -- it lives in the responder's memory until the daemon
restarts, so the cases share a run but need not share a connection. Round trip
0.22s. What came back:

| | request | result |
|---|---|---|
| 1 | `web-retrieval` `https://example.com/` | `completed`, http 200, 559 bytes |
| 2 | that result's signature | verifies in assign-**result**; fails as an assign query and as a read query |
| 3 | the identical envelope resent | `replayed_nonce` |
| 4 | `code-exec` | `capability_not_granted`, unsigned |
| 5 | `web-retrieval` `http://127.0.0.1/` | gate `authenticated`, work `address_not_allowed` |
| 6 | `web-retrieval` `file:///etc/passwd` | `scheme_not_allowed` |
| 7 | `POST /v1/logs` | 5 entries, all attributed to this peer, capability and outcome present, no body |

Case 5 is the one to keep re-reading. The gate said `authenticated` and the
work said `address_not_allowed`, which is the separation this protocol is built
on: a fetch this node declined to make is still a request it accepted, and
collapsing the two would tell a peer its grant had been withdrawn every time a
web server was unreachable.

**Two things went wrong, and neither was the daemon.**

The first attempt timed out client-side at exactly ten seconds while CT 101
finished the work and had nobody to hand it to -- the DNS fault in "Gotchas",
which presented as a protocol failure and was a blocked nameserver. Worth
remembering the shape: the journal showed the dispatch and the log entry ten
seconds apart with no access line for the POST, because the client had already
gone. A missing access line after a completed dispatch means the caller left.

The second was in the checking script, and it is the more instructive one. It
asserted `reason == "ok"` on the logs answer and failed a passing system.
There are two constants called `REASON_OK`: `node.REASON_OK` is
`"authenticated"`, the gate's verdict, returned by every answer including the
reads; `handlers.REASON_OK` is `"ok"`, the work's verdict, which lives inside
`result.reason`. The check compared a gate verdict against work vocabulary --
the exact distinction the row above is about, tripped over while testing it.
Import the constants rather than typing the strings.

## Not yet done

DHT discovery (addresses are still configured by hand), NAT traversal, WAN.
`code-exec` and `data-analysis` remain unimplemented and are no longer
advertised: code execution a peer asked for, over a network, with no sandbox
stays unbuilt until there is a sandbox, and the node now refuses to claim it
rather than gating a stub. Task execution itself is no longer on this list --
`web-retrieval` runs end to end behind the gate.

Confirmed against the WSL peer on 2026-08-29: the grant and the executor have
both been exercised over the wire, so nothing on this list is waiting on that
any more. See "What the WSL peer proved".

Mutual TLS is evaluated and deliberately not planned; see the TLS section above
for why.
