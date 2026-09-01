#!/usr/bin/env bash
#
# Refuse to start unless this host is still the node it claims to be.
#
# This exists because two things in the library are deliberately forgiving, and
# on a host with no unit file to set the environment, that forgiveness is how a
# node quietly stops being itself:
#
#   * EurekaCrypto.load_or_create() CREATES a key when the path it is given
#     does not exist. A typo'd or unexported EUREKA_IDENTITY_PATH therefore
#     does not fail -- it mints a new identity, and the daemon comes up under a
#     node_id no peer has ever trusted, looking perfectly healthy.
#   * TrustList.load_or_empty() treats a MISSING trust file as an empty
#     allowlist. That is correct for a node with no peers yet, and it is
#     indistinguishable from a trust file that failed to deploy: the daemon
#     starts and refuses every handshake.
#
# Both are right for the library. Neither is right for a redeploy of a node
# whose whole job is to keep answering to node_ef0a1f59. So the paths are
# required rather than defaulted, the files must already exist, and the
# identity must hash to the node_id named in the unit -- checked before uvicorn
# binds anything, so a provisioning mistake is a start failure with a reason in
# the journal instead of a running daemon that is wrong.
#
# Run by ExecStartPre=. A non-zero exit here stops ExecStart from running at
# all; the unit's StartLimitBurst then holds the service in `failed` for a
# human rather than retrying a mistake forever.
set -euo pipefail

# ${VAR:?} rather than a default: a default is the bug this script is here to
# catch. Unset or empty stops the start with the variable's name in the message.
: "${EUREKA_PYTHON:?not set -- the interpreter that has the deps}"
: "${EUREKA_IDENTITY_PATH:?not set -- refusing to fall back to ~/.eureka/identity.key, which would be created if absent}"
: "${EUREKA_TRUST_PATH:?not set -- refusing to fall back to ~/.eureka/trust.json, whose absence reads as an empty allowlist}"
: "${EUREKA_EXPECT_NODE_ID:?not set -- without it nothing here checks that the identity on disk is the one peers trust}"

fail() { echo "preflight: $*" >&2; exit 1; }

[ -x "$EUREKA_PYTHON" ]        || fail "interpreter not executable: $EUREKA_PYTHON"
# -f, not -e: a directory at either path is a provisioning mistake that would
# otherwise surface as an unreadable-file traceback further in.
[ -f "$EUREKA_IDENTITY_PATH" ] || fail "no identity file at $EUREKA_IDENTITY_PATH (NOT creating one: a new key here is a new node_id)"
[ -f "$EUREKA_TRUST_PATH" ]    || fail "no trust file at $EUREKA_TRUST_PATH (an absent trust file loads as an empty allowlist and refuses every peer)"

# The rest is done in Python because it has to agree with the daemon exactly:
# same loader, same advertised list, same derivation of node_id from the key.
"$EUREKA_PYTHON" - <<'PY'
import os
import sys

from eureka_protocol.src.eureka_daemon.crypto import EurekaCrypto
from eureka_protocol.src.eureka_daemon.handlers import default_registry
from eureka_protocol.src.eureka_daemon.trust import TrustError, TrustList

identity_path = os.environ["EUREKA_IDENTITY_PATH"]
trust_path = os.environ["EUREKA_TRUST_PATH"]
expected = os.environ["EUREKA_EXPECT_NODE_ID"].strip()


def fail(message):
    print(f"preflight: {message}", file=sys.stderr)
    raise SystemExit(1)


# load(), never load_or_create(): this must read an identity, not make one.
try:
    crypto = EurekaCrypto.load(identity_path)
except Exception as exc:
    fail(f"cannot load identity {identity_path}: {type(exc).__name__}: {exc}")

actual = crypto.derive_node_id()
if actual != expected:
    fail(
        f"identity at {identity_path} is {actual}, expected {expected}. "
        f"Either the path is wrong or the key changed; peers trust the key, "
        f"so serving this one would put an unknown node on the mesh."
    )

# The advertised list comes from the handler registry, exactly as the daemon
# derives it. Typing a list here is how this check drifts from the daemon and
# starts passing trust files the daemon will refuse.
advertised = sorted(default_registry().names())

# load(), not load_or_empty(): a missing file has already been caught above,
# and here a corrupt one must raise rather than degrade to trusting nobody.
try:
    trust = TrustList.load(trust_path, advertised=advertised)
except TrustError as exc:
    fail(f"trust file will not load: {exc}")

peers = sorted(trust.names())
if not peers:
    fail(
        f"trust file {trust_path} loads but names no peers -- this daemon "
        f"would refuse every handshake it receives"
    )

print(f"preflight: {actual} ok")
print(f"preflight:   identity   {identity_path}")
print(f"preflight:   trust      {trust_path} ({len(peers)} peers: {', '.join(peers)})")
print(f"preflight:   advertises {', '.join(advertised) or '(nothing)'}")
for name in peers:
    key = trust.key_for(name)
    granted = sorted(trust.capabilities_for(key))
    print(f"preflight:   grants     {name}: {', '.join(granted) or '(nothing)'}")
PY
