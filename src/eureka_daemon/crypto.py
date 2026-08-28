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

# A rotated-out identity is archived next to the live one under this suffix.
# Microseconds are in the stamp so two rotations in the same second do not
# collide -- a collision would mean refusing to rotate, or worse, overwriting
# the only copy of a retired key.
RETIRED_SUFFIX = ".retired-%Y%m%dT%H%M%S.%f"


class IdentityError(RuntimeError):
    """Raised when a stored identity cannot be loaded or safely written."""


def write_private_file(target: Path, data: bytes) -> Path:
    """
    Write secret bytes atomically at mode 0600, creating the directory 0700.

    Every private file this daemon writes goes through here -- the identity
    file and the TLS key alike. A second implementation somewhere else is how
    one of them ends up world-readable while the other stays correct.

    Write-then-rename, so a crash mid-write cannot leave a truncated secret
    behind; the bytes are never briefly world-readable because the temp file is
    created 0600 in the destination directory.
    """
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp_name = tempfile.mkstemp(
        dir=str(target.parent), prefix=".identity-", suffix=".tmp"
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, target)
    except BaseException:
        # Never leave a stray copy of a secret lying around.
        if os.path.exists(temp_name):
            os.unlink(temp_name)
        raise
    return target


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
# The handshake is three messages, and each position gets its own tag. A
# signature harvested from one position covers different bytes than the same
# payload would in another, so it cannot be replayed into a different step of
# the exchange. Message 2 keeps the original tag: it is the direct successor
# of the old single-response handshake.
DOMAIN_HANDSHAKE_OFFER = b"eureka/handshake/offer/v1"      # message 1
DOMAIN_HANDSHAKE = b"eureka/handshake/v1"                  # message 2
DOMAIN_HANDSHAKE_CONFIRM = b"eureka/handshake/confirm/v1"  # message 3
DOMAIN_AUDIT_LOG = b"eureka/audit-log/v1"
# Discovery queries get their own tag like everything else, so a signature
# harvested from a handshake cannot be presented as a request for addresses.
# Only the query is signed; the answer is not, because an address is advice
# that a handshake either confirms or does not -- see discovery.py.
DOMAIN_DISCOVERY_QUERY = b"eureka/discovery/query/v1"
# Authenticated reads of this node's own records -- the peer table, the audit
# log, the full manifest. Its own tag, so a discovery query cannot be replayed
# as a request to read the peer table: the two carry the same envelope fields
# and would otherwise verify over identical bytes. Which record is being asked
# for is pinned by the `event` field INSIDE the signed payload, exactly as the
# discovery query pins its own, so a signature minted to read one record does
# not read another.
DOMAIN_READ_QUERY = b"eureka/read/query/v1"
# A request to run a task. Separate from the read domain even though the
# envelope is the same shape, because the stakes are not: a read discloses,
# an assign *does*. A signature minted to look at the peer table must be
# structurally unusable as a request to execute anything.
DOMAIN_ASSIGN_QUERY = b"eureka/assign/query/v1"
# The answer to one of those: what this node did, signed by the node that did
# it. Its own tag, in the other direction from the query -- a responder signs
# results and an initiator signs requests, and neither signature is usable as
# the other. Without the separation a result harvested from this node could be
# presented back to it as a request to run something, since both are a signed
# dict of protocol fields; with it, the bytes differ before the key is ever
# consulted. It is also what makes a result evidence: the peer keeps a
# signature over what this node returned, in a domain nothing else in the
# protocol can mint.
DOMAIN_ASSIGN_RESULT = b"eureka/assign/result/v1"


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

        return self._write_document(target, self._identity_document())

    def _identity_document(self) -> dict:
        return {
            "version": IDENTITY_FILE_VERSION,
            "algorithm": IDENTITY_ALGORITHM,
            "private_key_hex": self.get_private_key_hex(),
            "public_key_hex": self.get_public_key_hex(),
            "node_id": self.derive_node_id(),
            "created": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def _write_document(target: Path, document: dict) -> Path:
        """
        Write an identity document atomically at mode 0600.

        Shared by save() and by rotate()'s archive step so a retired key is
        stored under exactly the same protections as a live one -- an archive
        written any other way is a private key with weaker permissions.
        """
        return write_private_file(
            target, (json.dumps(document, indent=2) + "\n").encode("utf-8")
        )

    @classmethod
    def rotate(cls, path: Optional[Union[str, Path]] = None) -> tuple:
        """
        Replace this node's identity with a fresh keypair.

        Returns (new_crypto, archive_path). The outgoing private key is copied
        to the archive path and never deleted: a retired key is still the only
        thing that can verify signatures it made while it was live, and a
        rotation that destroys it is unrecoverable if the new key turns out to
        be the wrong one.

        Note what this does NOT do. The node_id is derived from the public key,
        so rotating changes it -- the node comes back as a different identity,
        and every peer must be re-provisioned with the new key out of band.
        There is deliberately no signed "here is my new key" message that peers
        act on by themselves: a stolen key could use it to rotate the thief
        into permanent trust, which is trust-on-first-use wearing a hat.

        Refuses when there is no identity to rotate. Creating one here would
        make a typo'd path silently mint a brand new node instead of rotating
        the real one.
        """
        target = resolve_identity_path(path)
        if not target.exists():
            raise IdentityError(
                f"no identity to rotate at {target}; nothing was changed"
            )
        # Loading first also enforces the 0600 check, so a rotation is never
        # the thing that quietly accepts an exposed key file.
        outgoing = cls.load(target)

        stamp = datetime.now(timezone.utc).strftime(RETIRED_SUFFIX)
        archive = target.with_name(target.name + stamp)
        if archive.exists():
            raise IdentityError(
                f"refusing to overwrite retired identity at {archive}"
            )

        # Archive the outgoing key BEFORE writing the new one. If this crashes
        # in between, the live identity is still the old one and the archive is
        # a harmless duplicate -- the rotation simply did not happen. The other
        # order risks a window with no copy of the outgoing key at all.
        outgoing._write_document(archive, outgoing._identity_document())

        replacement = cls()
        replacement.save(target, overwrite=True)
        return replacement, archive

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

    def sign_handshake_offer(self, payload: dict) -> str:
        """Message 1: the initiator's signature over its own challenge."""
        return self.sign_json(payload, domain=DOMAIN_HANDSHAKE_OFFER)

    @staticmethod
    def verify_handshake_offer(public_key_hex: str, signature_base64: str,
                               payload: dict) -> bool:
        return EurekaCrypto.verify_json(
            public_key_hex, signature_base64, payload,
            domain=DOMAIN_HANDSHAKE_OFFER,
        )

    def sign_handshake_confirm(self, payload: dict) -> str:
        """Message 3: the initiator's signature over the responder's challenge."""
        return self.sign_json(payload, domain=DOMAIN_HANDSHAKE_CONFIRM)

    @staticmethod
    def verify_handshake_confirm(public_key_hex: str, signature_base64: str,
                                 payload: dict) -> bool:
        return EurekaCrypto.verify_json(
            public_key_hex, signature_base64, payload,
            domain=DOMAIN_HANDSHAKE_CONFIRM,
        )

    def sign_handshake(self, payload: dict) -> str:
        """Message 2: the responder's signature over the initiator's challenge."""
        return self.sign_json(payload, domain=DOMAIN_HANDSHAKE)

    @staticmethod
    def verify_handshake(public_key_hex: str, signature_base64: str, payload: dict) -> bool:
        return EurekaCrypto.verify_json(
            public_key_hex, signature_base64, payload, domain=DOMAIN_HANDSHAKE
        )

    def sign_discovery_query(self, payload: dict) -> str:
        """A request for peer addresses, signed so the responder knows who asks."""
        return self.sign_json(payload, domain=DOMAIN_DISCOVERY_QUERY)

    @staticmethod
    def verify_discovery_query(public_key_hex: str, signature_base64: str,
                               payload: dict) -> bool:
        return EurekaCrypto.verify_json(
            public_key_hex, signature_base64, payload,
            domain=DOMAIN_DISCOVERY_QUERY,
        )

    def sign_read_query(self, payload: dict) -> str:
        """A request to read one of this node's records, signed by the caller."""
        return self.sign_json(payload, domain=DOMAIN_READ_QUERY)

    @staticmethod
    def verify_read_query(public_key_hex: str, signature_base64: str,
                          payload: dict) -> bool:
        return EurekaCrypto.verify_json(
            public_key_hex, signature_base64, payload,
            domain=DOMAIN_READ_QUERY,
        )

    def sign_assign_query(self, payload: dict) -> str:
        """A request to run a task on a peer, signed by the caller."""
        return self.sign_json(payload, domain=DOMAIN_ASSIGN_QUERY)

    @staticmethod
    def verify_assign_query(public_key_hex: str, signature_base64: str,
                            payload: dict) -> bool:
        return EurekaCrypto.verify_json(
            public_key_hex, signature_base64, payload,
            domain=DOMAIN_ASSIGN_QUERY,
        )

    def sign_assign_result(self, payload: dict) -> str:
        """The responder's signature over the result of a task it ran."""
        return self.sign_json(payload, domain=DOMAIN_ASSIGN_RESULT)

    @staticmethod
    def verify_assign_result(public_key_hex: str, signature_base64: str,
                             payload: dict) -> bool:
        return EurekaCrypto.verify_json(
            public_key_hex, signature_base64, payload,
            domain=DOMAIN_ASSIGN_RESULT,
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
