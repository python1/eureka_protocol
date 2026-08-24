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
from typing import Dict, FrozenSet, Iterable, Iterator, Optional, Union

# Where the trust list lives. Resolution order matches the identity file:
# explicit argument, then the environment, then the default location.
TRUST_PATH_ENV_VAR = "EUREKA_TRUST_PATH"
DEFAULT_TRUST_PATH = Path.home() / ".eureka" / "trust.json"

# Versioned like the identity file so the format can be recognised and
# migrated rather than being guessed at.
#
# v1: peers maps name -> public key hex.
# v2: peers maps name -> {"public_key": hex, "capabilities": [...]}.
#
# v1 files still load and grant nothing. That is the safe direction: an
# operator who has not yet written grants gets a peer that can authenticate
# and do nothing, never a peer that inherits blanket permission.
TRUST_FILE_VERSION = 2
TRUST_FILE_VERSION_LEGACY = 1
SUPPORTED_TRUST_VERSIONS = (TRUST_FILE_VERSION_LEGACY, TRUST_FILE_VERSION)
TRUST_ALGORITHM = "ed25519"

# The keys a v2 peer entry may carry. Anything else is a typo -- "capabilties"
# silently granting nothing is exactly the failure this catches.
PEER_ENTRY_KEYS = frozenset(("public_key", "capabilities"))

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


def _normalise_capabilities(capabilities: object, context: str) -> FrozenSet[str]:
    """Validate a grant list and return it as a frozen set of capability names."""
    if capabilities is None:
        return frozenset()
    if isinstance(capabilities, (str, bytes)) or not isinstance(capabilities, (list, tuple)):
        # A bare string would silently iterate into single characters.
        raise TrustError(
            f"{context}: capabilities must be a list, "
            f"got {type(capabilities).__name__}"
        )
    granted = set()
    for entry in capabilities:
        if not isinstance(entry, str) or not entry.strip():
            raise TrustError(
                f"{context}: capability must be a non-empty string, got {entry!r}"
            )
        granted.add(entry.strip())
    return frozenset(granted)


class TrustList:
    """
    An allowlist of peer name -> ed25519 public key, plus what each may do.

    Both trust and grants are keyed by public key, not by name: the name is a
    label for humans, while the key is the thing that was actually proven
    during the handshake. Keying grants any other way would let the two drift
    apart, so that a peer could be authenticated as one identity and
    authorised as another.
    """

    def __init__(self, peers: Optional[Dict[str, str]] = None,
                 capabilities: Optional[Dict[str, object]] = None):
        self._by_key: Dict[str, str] = {}
        # Grants, keyed by public key exactly as trust is.
        self._grants: Dict[str, FrozenSet[str]] = {}
        for name, public_key_hex in (peers or {}).items():
            self.add(name, public_key_hex,
                     (capabilities or {}).get(name))

    # -- Queries ----------------------------------------------------------

    def capabilities_for(self, public_key_hex: object) -> FrozenSet[str]:
        """
        What this key has been granted. Empty for an untrusted or ungranted
        key -- there is no distinction to draw, since neither may do anything.
        """
        if not isinstance(public_key_hex, str):
            return frozenset()
        return self._grants.get(public_key_hex.strip().lower(), frozenset())

    def grants(self, public_key_hex: object, capability: object) -> bool:
        """
        True only if this exact key holds this exact grant.

        Default deny: an unknown key, an unknown capability, and a trusted
        peer with no grants all answer False.
        """
        if not isinstance(capability, str) or not capability.strip():
            return False
        return capability.strip() in self.capabilities_for(public_key_hex)

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

    def add(self, name: object, public_key_hex: object,
            capabilities: object = None) -> None:
        """
        Register a trusted peer, optionally with the capabilities it is
        granted. Omitting them grants nothing.

        This is an explicit provisioning step for an operator or a test. The
        handshake never calls it: a peer cannot talk its way onto the list,
        and it certainly cannot talk its way into a grant.
        """
        if not isinstance(name, str) or not name:
            raise TrustError(f"peer name must be a non-empty string, got {name!r}")
        key = _normalise_public_key(public_key_hex, f"peer {name!r}")
        granted = _normalise_capabilities(capabilities, f"peer {name!r}")
        existing = self._by_key.get(key)
        if existing is not None and existing != name:
            # Two names for one key means the file is ambiguous about who a
            # given signature belongs to.
            raise TrustError(
                f"duplicate public key: {existing!r} and {name!r} share a key"
            )
        self._by_key[key] = name
        self._grants[key] = granted

    # -- Loading ----------------------------------------------------------

    @classmethod
    def load(cls, path: Optional[Union[str, Path]] = None,
             advertised: Optional[Iterable[str]] = None) -> "TrustList":
        """
        Load a trust file, raising TrustError if it is missing or invalid.

        `advertised` is what the loading node actually offers. When given, a
        grant naming anything outside it is a load-time error rather than a
        grant that silently does nothing: a typo like 'code-exex' would
        otherwise sit in the file looking effective for as long as nobody
        tested it. Omitting it loads without that check, for callers that are
        reading a trust file rather than enforcing against one.
        """
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
        version = document.get("version")
        if version not in SUPPORTED_TRUST_VERSIONS:
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

        offered = None if advertised is None else {
            name.strip() for name in advertised
            if isinstance(name, str) and name.strip()
        }

        trust_list = cls()
        for name, entry in peers.items():
            try:
                public_key_hex, capabilities = cls._read_peer_entry(
                    name, entry, version
                )
                granted = _normalise_capabilities(capabilities, f"peer {name!r}")
                if offered is not None:
                    unadvertised = sorted(granted - offered)
                    if unadvertised:
                        raise TrustError(
                            f"peer {name!r}: granted capability "
                            f"{', '.join(repr(c) for c in unadvertised)} "
                            f"that this node does not advertise"
                        )
                trust_list.add(name, public_key_hex, sorted(granted))
            except TrustError as exc:
                raise TrustError(f"trust file {target}: {exc}") from exc
        return trust_list

    @staticmethod
    def _read_peer_entry(name: object, entry: object, version: int):
        """
        Unpack one peers entry into (public_key_hex, capabilities).

        A v1 entry is a bare key string and grants nothing. A v2 entry is an
        object. Each version accepts only its own shape: silently accepting a
        v1 string inside a v2 file would hide a half-finished migration, and
        accepting a v2 object inside a v1 file would grant capabilities from a
        file whose version says it cannot express them.
        """
        if version == TRUST_FILE_VERSION_LEGACY:
            if isinstance(entry, dict):
                raise TrustError(
                    f"peer {name!r}: v1 entries are a public key string; "
                    f"set version to {TRUST_FILE_VERSION} to grant capabilities"
                )
            return entry, None

        if not isinstance(entry, dict):
            raise TrustError(
                f"peer {name!r}: v{TRUST_FILE_VERSION} entries must be an "
                f"object with 'public_key', got {type(entry).__name__}"
            )
        unknown = set(entry) - PEER_ENTRY_KEYS
        if unknown:
            raise TrustError(
                f"peer {name!r}: unexpected field(s) {', '.join(sorted(unknown))}"
            )
        if "public_key" not in entry:
            raise TrustError(f"peer {name!r}: missing 'public_key'")
        return entry["public_key"], entry.get("capabilities")

    @classmethod
    def load_or_empty(cls, path: Optional[Union[str, Path]] = None,
                      advertised: Optional[Iterable[str]] = None) -> "TrustList":
        """
        Load the trust file, treating only a *missing* file as an empty list.

        A missing file is a legitimate state -- a node that has not been given
        any peers yet -- and an empty list trusts nobody, so this is safe. A
        file that exists but is corrupt still raises.
        """
        target = resolve_trust_path(path)
        if not target.exists():
            return cls()
        return cls.load(target, advertised=advertised)

    # -- Serialisation ----------------------------------------------------

    def to_document(self) -> Dict[str, object]:
        """The on-disk representation of this allowlist, always current version."""
        return {
            "version": TRUST_FILE_VERSION,
            "algorithm": TRUST_ALGORITHM,
            "peers": {
                name: {
                    "public_key": key,
                    "capabilities": sorted(self._grants.get(key, frozenset())),
                }
                for key, name in self._by_key.items()
            },
        }
