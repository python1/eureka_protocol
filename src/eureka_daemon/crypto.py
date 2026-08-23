import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import binascii
import json
import base64


def canonical_json_bytes(payload: dict) -> bytes:
    """
    Deterministic JSON encoding used for every signature in the protocol.

    Keys are sorted and the separators carry no whitespace, so two
    implementations that agree on the payload also agree on the exact bytes
    that were signed. sign_json and verify_json MUST share this helper --
    if they diverge, every signature silently fails to verify.
    """
    return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')


# ---------------------------------------------------------------------------
# Domain separation
#
# Every signature in the protocol is computed over a context tag followed by
# the canonical payload. Because the tag is part of the signed bytes, a
# signature minted in one context cannot be lifted into another: a handshake
# signature presented as an audit-log signature verifies over different bytes
# and fails. The tags live here, next to sign/verify, so the two sides cannot
# drift apart -- that is the whole point of the separation.
# ---------------------------------------------------------------------------
DOMAIN_HANDSHAKE = b"eureka/handshake/v1"
DOMAIN_AUDIT_LOG = b"eureka/audit-log/v1"


def domain_separated_bytes(domain: bytes, payload: dict) -> bytes:
    """
    The exact byte string that gets signed: tag, NUL, canonical payload.

    The NUL byte keeps the boundary unambiguous, so no tag can ever be a
    prefix of another tag plus the start of a payload.
    """
    if not isinstance(domain, bytes):
        raise TypeError(f"domain tag must be bytes, got {type(domain).__name__}")
    return domain + b"\x00" + canonical_json_bytes(payload)


class EurekaCrypto:
    """
    Handles Ed25519 identity generation, signing, and verification 
    for the Eureka Protocol.
    """
    def __init__(self, private_key_hex=None):
        if private_key_hex:
            self.private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(private_key_hex)
            )
        else:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
        
        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes_raw()
        self.private_key_bytes = self.private_key.private_bytes_raw()

    def get_public_key_hex(self):
        return self.public_key_bytes.hex()

    def sign_data(self, data: bytes) -> str:
        """Signs bytes and returns a base64 encoded signature."""
        signature = self.private_key.sign(data)
        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def verify_signature(public_key_hex: str, signature_base64: str, data: bytes) -> bool:
        """
        Verifies a base64 encoded signature against a hex public key.

        Returns False only for a genuine authentication failure: a bad
        signature, an unparseable key, or malformed base64. Any other
        exception is a bug and is allowed to propagate rather than being
        silently downgraded into "not authenticated".
        """
        try:
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(public_key_hex)
            )
            # validate=True: without it b64decode discards non-alphabet
            # characters, so "!!!!" would decode to b"" instead of raising.
            signature = base64.b64decode(signature_base64, validate=True)
            pub_key.verify(signature, data)
            return True
        except (InvalidSignature, binascii.Error, ValueError):
            # binascii.Error subclasses ValueError; both are listed to keep
            # the intent (bad signature / bad encoding) explicit.
            return False

    def sign_json(self, payload: dict, domain: bytes) -> str:
        """
        Signs a JSON-serializable dictionary inside a signing domain.

        `domain` is required: there is no such thing as an untagged signature
        in this protocol, and a default would let a caller mint one in
        whichever context happened to be the default. Prefer the bound helpers
        below, which pin the tag at the call site.
        """
        return self.sign_data(domain_separated_bytes(domain, payload))

    @staticmethod
    def verify_json(public_key_hex: str, signature_base64: str, payload: dict,
                    domain: bytes) -> bool:
        """Verifies a signature against a JSON dictionary in a signing domain."""
        return EurekaCrypto.verify_signature(
            public_key_hex, signature_base64, domain_separated_bytes(domain, payload)
        )

    # -- Bound helpers. Protocol code uses these, never the raw domain arg. --

    def sign_handshake(self, payload: dict) -> str:
        return self.sign_json(payload, domain=DOMAIN_HANDSHAKE)

    @staticmethod
    def verify_handshake(public_key_hex: str, signature_base64: str, payload: dict) -> bool:
        return EurekaCrypto.verify_json(
            public_key_hex, signature_base64, payload, domain=DOMAIN_HANDSHAKE
        )

    def sign_audit_log(self, payload: dict) -> str:
        return self.sign_json(payload, domain=DOMAIN_AUDIT_LOG)

    @staticmethod
    def verify_audit_log(public_key_hex: str, signature_base64: str, payload: dict) -> bool:
        return EurekaCrypto.verify_json(
            public_key_hex, signature_base64, payload, domain=DOMAIN_AUDIT_LOG
        )

if __name__ == "__main__":
    # Quick unit test for the crypto module
    crypto = EurekaCrypto()
    msg = b"Eureka Protocol Handshake Test"
    sig = crypto.sign_data(msg)
    print(f"Public Key: {crypto.get_public_key_hex()}")
    print(f"Signature: {sig}")
    is_valid = EurekaCrypto.verify_signature(crypto.get_public_key_hex(), sig, msg)
    print(f"Verification Success: {is_valid}")
