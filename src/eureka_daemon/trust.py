"""
The peer trust list: which public keys this node is willing to authenticate.

A valid signature only proves the responder holds the keypair it presented,
and anyone can generate a keypair. The trust list is what turns "some peer"
into "a peer we know". It is an allowlist keyed by public key, and an empty
allowlist trusts nobody -- there is deliberately no trust-on-first-use and no
way to switch the check off.
"""
import json
import os
from pathlib import Path
from typing import Dict, Iterator, Optional, Union

# Where the trust list lives. Resolution order matches the identity file:
# explicit argument, then the environment, then the default location.
TRUST_PATH_ENV_VAR = "EUREKA_TRUST_PATH"
DEFAULT_TRUST_PATH = Path.home() / ".eureka" / "trust.json"

# Versioned like the identity file so the format can be recognised and
# migrated rather than being guessed at.
TRUST_FILE_VERSION = 1
TRUST_ALGORITHM = "ed25519"

# An ed25519 public key is 32 bytes, so 64 hex characters. Anything else is
# not a key this protocol can ever use.
PUBLIC_KEY_HEX_LENGTH = 64


class TrustError(RuntimeError):
    """
    Raised when a trust file exists but cannot be read as a valid allowlist.

    Deliberately distinct from "no trust file": a corrupt or unreadable file
    must never degrade into an empty allowlist, because an empty allowlist is
    indistinguishable from a trust file that failed to deploy. One rejects
    everyone silently; the other tells you why.
    """


def resolve_trust_path(path: Optional[Union[str, Path]] = None) -> Path:
    """Explicit argument wins, then $EUREKA_TRUST_PATH, then the default."""
    if path is not None:
        return Path(path).expanduser()
    from_env = os.environ.get(TRUST_PATH_ENV_VAR)
    if from_env:
        return Path(from_env).expanduser()
    return DEFAULT_TRUST_PATH


def _normalise_public_key(public_key_hex: object, context: str) -> str:
    """Validate a public key and return it in canonical lowercase hex."""
    if not isinstance(public_key_hex, str):
        raise TrustError(
            f"{context}: public key must be a string, "
            f"got {type(public_key_hex).__name__}"
        )
    candidate = public_key_hex.strip().lower()
    if len(candidate) != PUBLIC_KEY_HEX_LENGTH:
        raise TrustError(
            f"{context}: public key must be {PUBLIC_KEY_HEX_LENGTH} hex "
            f"characters, got {len(candidate)}"
        )
    try:
        bytes.fromhex(candidate)
    except ValueError as exc:
        raise TrustError(f"{context}: public key is not valid hex: {exc}") from exc
    return candidate


class TrustList:
    """
    An allowlist of peer name -> ed25519 public key.

    Lookups are by key, not by name: the name is a label for humans, while the
    key is the thing that was actually proven during the handshake.
    """

    def __init__(self, peers: Optional[Dict[str, str]] = None):
        self._by_key: Dict[str, str] = {}
        for name, public_key_hex in (peers or {}).items():
            self.add(name, public_key_hex)

    # -- Queries ----------------------------------------------------------

    def trusts(self, public_key_hex: object) -> bool:
        """True only if this exact public key is on the allowlist."""
        if not isinstance(public_key_hex, str):
            return False
        return public_key_hex.strip().lower() in self._by_key

    def name_for(self, public_key_hex: str) -> Optional[str]:
        """The label recorded for a trusted key, if any."""
        if not isinstance(public_key_hex, str):
            return None
        return self._by_key.get(public_key_hex.strip().lower())

    def names(self) -> Iterator[str]:
        return iter(self._by_key.values())

    def __contains__(self, public_key_hex: object) -> bool:
        return self.trusts(public_key_hex)

    def __len__(self) -> int:
        return len(self._by_key)

    def __repr__(self) -> str:
        return f"<TrustList {len(self._by_key)} peer(s)>"

    # -- Provisioning -----------------------------------------------------

    def add(self, name: object, public_key_hex: object) -> None:
        """
        Register a trusted peer.

        This is an explicit provisioning step for an operator or a test. The
        handshake never calls it: a peer cannot talk its way onto the list.
        """
        if not isinstance(name, str) or not name:
            raise TrustError(f"peer name must be a non-empty string, got {name!r}")
        key = _normalise_public_key(public_key_hex, f"peer {name!r}")
        existing = self._by_key.get(key)
        if existing is not None and existing != name:
            # Two names for one key means the file is ambiguous about who a
            # given signature belongs to.
            raise TrustError(
                f"duplicate public key: {existing!r} and {name!r} share a key"
            )
        self._by_key[key] = name

    # -- Loading ----------------------------------------------------------

    @classmethod
    def load(cls, path: Optional[Union[str, Path]] = None) -> "TrustList":
        """Load a trust file, raising TrustError if it is missing or invalid."""
        target = resolve_trust_path(path)
        try:
            raw = target.read_text()
        except FileNotFoundError as exc:
            raise TrustError(f"no trust file at {target}") from exc
        except OSError as exc:
            raise TrustError(f"cannot read trust file {target}: {exc}") from exc

        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise TrustError(f"trust file {target} is not valid JSON: {exc}") from exc

        if not isinstance(document, dict):
            raise TrustError(f"trust file {target} must contain a JSON object")
        if document.get("version") != TRUST_FILE_VERSION:
            raise TrustError(
                f"trust file {target} has unsupported version "
                f"{document.get('version')!r}"
            )
        if document.get("algorithm") != TRUST_ALGORITHM:
            raise TrustError(
                f"trust file {target} has unsupported algorithm "
                f"{document.get('algorithm')!r}"
            )

        peers = document.get("peers")
        if not isinstance(peers, dict):
            raise TrustError(
                f"trust file {target} must have a 'peers' object mapping "
                f"name to public key hex"
            )

        trust_list = cls()
        for name, public_key_hex in peers.items():
            try:
                trust_list.add(name, public_key_hex)
            except TrustError as exc:
                raise TrustError(f"trust file {target}: {exc}") from exc
        return trust_list

    @classmethod
    def load_or_empty(cls, path: Optional[Union[str, Path]] = None) -> "TrustList":
        """
        Load the trust file, treating only a *missing* file as an empty list.

        A missing file is a legitimate state -- a node that has not been given
        any peers yet -- and an empty list trusts nobody, so this is safe. A
        file that exists but is corrupt still raises.
        """
        target = resolve_trust_path(path)
        if not target.exists():
            return cls()
        return cls.load(target)

    # -- Serialisation ----------------------------------------------------

    def to_document(self) -> Dict[str, object]:
        """The on-disk representation of this allowlist."""
        return {
            "version": TRUST_FILE_VERSION,
            "algorithm": TRUST_ALGORITHM,
            "peers": {name: key for key, name in self._by_key.items()},
        }
