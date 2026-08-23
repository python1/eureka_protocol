import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import binascii
import hashlib
import json
import base64
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

# Where a node's long-term identity lives. The default filename ends in .key,
# which the repository .gitignore already excludes -- a private key must not
# become committable by accident.
IDENTITY_PATH_ENV_VAR = "EUREKA_IDENTITY_PATH"
DEFAULT_IDENTITY_PATH = Path.home() / ".eureka" / "identity.key"

# On-disk identity format. Versioned so the file can be recognised and
# migrated later rather than being an anonymous blob of hex.
IDENTITY_FILE_VERSION = 1
IDENTITY_ALGORITHM = "ed25519"


class IdentityError(RuntimeError):
    """Raised when a stored identity cannot be loaded or safely written."""


def resolve_identity_path(path: Optional[Union[str, Path]] = None) -> Path:
    """
    Explicit argument wins, then $EUREKA_IDENTITY_PATH, then the default.

    Resolved in one place so every caller agrees on which file *is* the
    node's identity.
    """
    if path is not None:
        return Path(path).expanduser()
    from_env = os.environ.get(IDENTITY_PATH_ENV_VAR)
    if from_env:
        return Path(from_env).expanduser()
    return DEFAULT_IDENTITY_PATH


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

    def get_private_key_hex(self) -> str:
        return self.private_key_bytes.hex()

    def derive_node_id(self) -> str:
        """
        The node's name, derived from its public key.

        Deriving rather than randomising is what makes the identity coherent:
        the same key always yields the same node_id, so a restarted node comes
        back as itself. The shape (node_ + 8 hex) matches the ids this daemon
        already emitted, so nothing on the wire changes form.
        """
        digest = hashlib.sha256(self.public_key_bytes).hexdigest()
        return f"node_{digest[:8]}"

    # -- Persistence ------------------------------------------------------

    @classmethod
    def load_or_create(cls, path: Optional[Union[str, Path]] = None) -> "EurekaCrypto":
        """
        Load this node's long-term identity, generating it on first run.

        An existing key is *always* loaded, never regenerated: silently
        minting a new key would change the node's identity and invalidate
        every peer relationship built on the old one.
        """
        target = resolve_identity_path(path)
        if target.exists():
            return cls.load(target)
        crypto = cls()
        crypto.save(target)
        return crypto

    @classmethod
    def load(cls, path: Optional[Union[str, Path]] = None) -> "EurekaCrypto":
        """Load an identity from disk, refusing anything unsafe or unreadable."""
        target = resolve_identity_path(path)
        try:
            raw = target.read_text()
        except FileNotFoundError as exc:
            raise IdentityError(f"no identity file at {target}") from exc

        mode = stat.S_IMODE(target.stat().st_mode)
        if mode & 0o077:
            # We always create at 0600, so a widened mode means something
            # else changed it. Fail loudly rather than use an exposed key.
            raise IdentityError(
                f"identity file {target} is group/world accessible "
                f"(mode {mode:04o}); expected 0600"
            )

        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise IdentityError(f"identity file {target} is not valid JSON") from exc

        if document.get("version") != IDENTITY_FILE_VERSION:
            raise IdentityError(
                f"identity file {target} has unsupported version "
                f"{document.get('version')!r}"
            )
        if document.get("algorithm") != IDENTITY_ALGORITHM:
            raise IdentityError(
                f"identity file {target} has unsupported algorithm "
                f"{document.get('algorithm')!r}"
            )

        private_key_hex = document.get("private_key_hex")
        if not isinstance(private_key_hex, str):
            raise IdentityError(f"identity file {target} has no private_key_hex")

        try:
            return cls(private_key_hex=private_key_hex)
        except (ValueError, binascii.Error) as exc:
            raise IdentityError(
                f"identity file {target} does not contain a usable key: {exc}"
            ) from exc

    def save(self, path: Optional[Union[str, Path]] = None,
             overwrite: bool = False) -> Path:
        """
        Write this identity to disk atomically, mode 0600.

        Refuses to clobber an existing file unless explicitly told to:
        overwriting an identity destroys it irrecoverably, and the caller
        should have to mean it.
        """
        target = resolve_identity_path(path)
        if target.exists() and not overwrite:
            raise IdentityError(
                f"refusing to overwrite existing identity at {target} "
                f"(pass overwrite=True to replace it)"
            )

        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        document = {
            "version": IDENTITY_FILE_VERSION,
            "algorithm": IDENTITY_ALGORITHM,
            "private_key_hex": self.get_private_key_hex(),
            "public_key_hex": self.get_public_key_hex(),
            "node_id": self.derive_node_id(),
            "created": datetime.now(timezone.utc).isoformat(),
        }

        # Write-then-rename so a crash mid-write cannot leave a truncated
        # identity behind; the key is never briefly world-readable because
        # the temp file is created 0600 in the destination directory.
        fd, temp_name = tempfile.mkstemp(
            dir=str(target.parent), prefix=".identity-", suffix=".tmp"
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as handle:
                json.dump(document, handle, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, target)
        except BaseException:
            # Never leave a stray copy of the private key lying around.
            if os.path.exists(temp_name):
                os.unlink(temp_name)
            raise
        return target

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
