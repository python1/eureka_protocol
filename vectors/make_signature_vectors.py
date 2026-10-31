"""
Regenerate vectors/signatures-v1.json: the canonical bytes and Ed25519
signatures every implementation of this protocol must reproduce.

Run from the parent of the checkout, like everything else here:

    ./venv/bin/python -m eureka_protocol.vectors.make_signature_vectors

The key is derived from a published seed. It is a TEST key: it signs these
vectors and nothing else, and no node should ever trust it. Ed25519 signing is
deterministic, so the same seed always produces the same file, and the test
suite checks that it does.

The payloads are chosen to catch encoders that disagree with Python's
json.dumps(sort_keys=True, separators=(',', ':')) with its default
ensure_ascii=True: non-ASCII text escaped as \\uXXXX (with surrogate pairs above
U+FFFF), DEL (0x7f) escaped although it is ASCII, control characters, U+2028
and U+2029, keys sorted by code point including non-ASCII and astral keys, and
nested containers. Integers only: floats are not part of the canonical form any
implementation is asked to match.
"""
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

from ..src.eureka_daemon import crypto as C

SEED = hashlib.sha256(b"eureka signature test vectors v1 -- never trust this key").digest()
PATH = Path(__file__).with_name("signatures-v1.json")

DOMAINS = {
    "handshake_offer": C.DOMAIN_HANDSHAKE_OFFER,
    "handshake": C.DOMAIN_HANDSHAKE,
    "handshake_confirm": C.DOMAIN_HANDSHAKE_CONFIRM,
    "read_query": C.DOMAIN_READ_QUERY,
    "assign_query": C.DOMAIN_ASSIGN_QUERY,
    "assign_result": C.DOMAIN_ASSIGN_RESULT,
}

PAYLOADS = [
    {"protocol": "eureka/1.0", "event": "handshake_challenge", "nonce": "00ff",
     "timestamp": "2026-10-30T12:00:00.123Z"},
    {"text": "Rowan said “stake the beds” — naïve café, 日本語, "
             "emoji \U0001F642\U0001F331, tab\tnewline\nquote\" backslash\\ del\x7f "
             "nul\x00 bell\x07 slash/"},
    {"z": 1, "a": [3, -2, 0, True, False, None], "m": {"b": {"y": [], "x": {}}, "a": ""},
     "big": 9007199254740991},
    {"é": 1, "e": 2, "\U0001F600": 3, "～": 4, "Z": 5, "_": 6},
    {"separators": "   line separators", "ctrl": "\x1f\x1b"},
]


def build():
    key = ed25519.Ed25519PrivateKey.from_private_bytes(SEED)
    public = key.public_key().public_bytes_raw().hex()
    vectors = []
    for name, domain in DOMAINS.items():
        for payload in PAYLOADS:
            signed = C.domain_separated_bytes(domain, payload)
            vectors.append({
                "domain": name,
                "domain_tag": domain.decode("ascii"),
                "payload": payload,
                "signed_bytes_hex": signed.hex(),
                "signature": base64.b64encode(key.sign(signed)).decode("ascii"),
            })
    return {
        "format": "eureka-signature-vectors",
        "version": 1,
        "note": "Test key only; never trust it. Regenerate with vectors/make_signature_vectors.py.",
        "public_key": public,
        "node_id": "node_" + hashlib.sha256(bytes.fromhex(public)).hexdigest()[:8],
        "vectors": vectors,
    }


def render(document) -> str:
    # ensure_ascii so the file itself is plain ASCII and survives any editor.
    return json.dumps(document, indent=1, ensure_ascii=True) + "\n"


if __name__ == "__main__":
    PATH.write_text(render(build()))
    print(f"wrote {PATH} ({len(build()['vectors'])} vectors)")
