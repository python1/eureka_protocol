#!/usr/bin/env bash
#
# End-to-end check: a full mutual handshake against a peer, and the refusal
# that proves the handshake was doing something.
#
# Two scenarios run against the same peer:
#
#   trusted    this host's real identity and trust file  -> authenticates
#   untrusted  a throwaway identity, empty trust list    -> untrusted_key
#
# The contrast is the point. A green handshake on its own does not show that
# anything was checked; it is only meaningful next to an identical exchange
# that gets refused for the one reason that should refuse it.
#
# Defaults to CT 102's TLS listener. Over https the peer's certificate is
# pinned against the trust file -- there is no certificate authority anywhere
# in this protocol, so there is nothing to chain to and nothing to install.
#
#   ./demo.sh                                 # TLS to CT 102
#   ./demo.sh https://192.168.1.174:8443      # explicit peer
#
# Exits non-zero unless BOTH scenarios came out as expected.
set -euo pipefail

PEER="${1:-https://192.168.1.174:8443}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT="$(cd "$HERE/.." && pwd)"

# Candidates are checked for the dependencies, not just for existing -- there
# is more than one venv next to this repo on some hosts, and picking the wrong
# one fails later with a confusing ModuleNotFoundError.
PY="${EUREKA_PYTHON:-}"
if [ -z "$PY" ]; then
  for candidate in "$PARENT/venv/bin/python" /root/eureka_venv/bin/python; do
    if [ -x "$candidate" ] && "$candidate" -c "import cryptography, httpx" 2>/dev/null; then
      PY="$candidate"; break
    fi
  done
fi
if [ -z "${PY:-}" ] || ! "$PY" -c "import cryptography, httpx" 2>/dev/null; then
  echo "no python with cryptography+httpx found; set EUREKA_PYTHON" >&2
  exit 2
fi

echo "peer   : $PEER"
echo "python : $PY"

PEER="$PEER" PARENT="$PARENT" "$PY" - <<'PYEOF'
import asyncio, json, os, shutil, sys, tempfile

peer = os.environ["PEER"]
sys.path.insert(0, os.environ["PARENT"])

from eureka_protocol.src.eureka_daemon.node import EurekaNode

# https gets require_tls: this node will not fall back to speaking in the clear
# to a peer it was told to reach over TLS. The pin applies either way.
over_tls = peer.strip().lower().startswith("https://")


async def handshake(node):
    from eureka_protocol.src.eureka_daemon.client import handshake_over_http
    # No client is passed: an https URL builds a pinning client on its own.
    return await handshake_over_http(node, peer, require_tls=over_tls)


def report(label, node, result, ok, expectation):
    print(f"\n--- {label}")
    print(f"    local node    : {node.node_id}")
    print(f"    expected      : {expectation}")
    print(f"    authenticated : {result.get('authenticated')}")
    print(f"    mutual        : {result.get('mutual')}")
    print(f"    peer          : {result.get('peer_id')}")
    print(f"    reason        : {result.get('reason')}")
    if result.get("detail"):
        print(f"    detail        : {result['detail']}")
    print(f"    verdict       : {'PASS' if ok else 'FAIL'}")
    return ok


# --- 1. trusted: this host's real identity and trust file ------------------
trusted = EurekaNode.with_persistent_identity(capabilities=["fast-inference"])
result = asyncio.run(handshake(trusted))
first = report(
    "trusted peer", trusted, result,
    result.get("authenticated") is True and result.get("mutual") is True,
    "authenticated in both directions",
)

# --- 2. untrusted: a throwaway identity that trusts nobody -----------------
# Explicit paths inside a temp directory, so the real identity and trust file
# are neither read nor written here. The trust path deliberately names a file
# that does not exist: an absent trust file is an empty allowlist, which is
# the state under test, and it is reached without writing anything.
scratch = tempfile.mkdtemp(prefix="eureka-demo-untrusted-")
try:
    stranger = EurekaNode.with_persistent_identity(
        capabilities=["fast-inference"],
        identity_path=os.path.join(scratch, "identity.key"),
        trust_path=os.path.join(scratch, "trust.json"),
    )
    assert len(stranger.trust_list) == 0, "the stranger was supposed to trust nobody"
    result = asyncio.run(handshake(stranger))
    second = report(
        "untrusted peer", stranger, result,
        result.get("authenticated") is False
        and result.get("reason") == "untrusted_key",
        "refused with untrusted_key",
    )
finally:
    shutil.rmtree(scratch, ignore_errors=True)

print()
print(f"trusted   : {'PASS' if first else 'FAIL'}")
print(f"untrusted : {'PASS' if second else 'FAIL'}")
print(f"node_id   : {trusted.node_id}  (must not change across runs)")
sys.exit(0 if (first and second) else 1)
PYEOF
