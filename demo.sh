#!/usr/bin/env bash
#
# End-to-end check: a full mutual handshake against a peer.
#
# Defaults to CT 102's TLS listener. Over https the peer's certificate is
# pinned against this node's trust file -- there is no certificate authority
# anywhere in this protocol, so there is nothing to chain to and nothing to
# install. Over http nothing is pinned, because there is no certificate.
#
#   ./demo.sh                                 # TLS to CT 102
#   ./demo.sh http://192.168.1.174:8000       # plaintext, if it still listens
#
# Exits non-zero unless the exchange authenticated in BOTH directions.
set -euo pipefail

PEER="${1:-https://192.168.1.174:8443}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT="$(cd "$HERE/.." && pwd)"

# The venv, in the order worth trying: an explicit override, the WSL layout,
# then CT 102's.
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
import asyncio, json, os, sys

peer = os.environ["PEER"]
sys.path.insert(0, os.environ["PARENT"])

from eureka_protocol.src.eureka_daemon.node import EurekaNode
from eureka_protocol.src.eureka_daemon.client import handshake_over_http

# https gets require_tls: this node will not fall back to speaking in the
# clear to a peer it was told to reach over TLS. The pin applies either way.
over_tls = peer.strip().lower().startswith("https://")

async def main():
    node = EurekaNode.with_persistent_identity(capabilities=["fast-inference"])
    print(f"local  : {node.node_id}")
    print(f"key    : {node.public_key_hex}")
    # No client is passed: an https URL builds a pinning client on its own.
    result = await handshake_over_http(node, peer, require_tls=over_tls)
    return node, result

node, result = asyncio.run(main())
print(json.dumps(result, indent=2))

ok = result.get("authenticated") is True and result.get("mutual") is True
print()
print(f"authenticated : {result.get('authenticated')}")
print(f"mutual        : {result.get('mutual')}")
print(f"peer          : {result.get('peer_id')}")
print(f"node_id       : {node.node_id}  (must not change across runs)")
if not ok:
    print(f"reason        : {result.get('reason')}")
    print(f"detail        : {result.get('detail')}")
sys.exit(0 if ok else 1)
PYEOF
