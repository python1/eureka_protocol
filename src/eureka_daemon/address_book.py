"""
The address table: where peers might be, held under a hard bound.

Deliberately dumb. It stores addresses and expires them, and makes no trust
decisions at all -- every trust check lives in discovery.py, which reads the
node's *live* trust list so a revocation applies to disclosure and to dialling
immediately rather than whenever some cached copy is refreshed.

Kept in its own module so the node can own an address book without importing
the discovery protocol, which imports the node.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Bounds on the address table.
#
# The number of *keys* is already bounded by the trust list, because nothing
# that is not trusted can be stored. MAX_TRACKED_KEYS is a second belt: a huge
# trust file should not turn into an unbounded table by way of gossip.
MAX_TRACKED_KEYS = 256
MAX_ADDRESSES_PER_KEY = 4

# How long an address may sit unconfirmed before it is forgotten. Confirmed
# addresses survive: they are the ones a handshake actually reached.
UNCONFIRMED_TTL_SECONDS = 3600.0

# An address longer than this is not an address we are going to dial.
MAX_ADDRESS_LENGTH = 255


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalise_key(value: object) -> Optional[str]:
    """Canonical lowercase hex, or None if this cannot be a public key."""
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    if len(candidate) != 64:
        return None
    try:
        bytes.fromhex(candidate)
    except ValueError:
        return None
    return candidate


def normalise_address(value: object) -> Optional[str]:
    """
    A dialable address, or None.

    Deliberately conservative: an address arrives from a peer, is stored, and
    is later handed to an HTTP client. Only http and https are accepted, so a
    gossiped 'file://' or 'unix://' can never be dialled.
    """
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or len(candidate) > MAX_ADDRESS_LENGTH:
        return None
    if not (candidate.startswith("http://") or candidate.startswith("https://")):
        return None
    return candidate.rstrip("/")


class AddressBook:
    """
    A bounded table of where peers might be, keyed by public key.

    Deliberately dumb: it stores and expires, and makes no trust decisions.
    Every trust check lives in the module functions below, which read the
    node's *live* trust list, so a revocation applies to disclosure and to
    dialling immediately rather than when some cached copy is refreshed.
    """

    def __init__(self, max_keys: int = MAX_TRACKED_KEYS,
                 max_addresses_per_key: int = MAX_ADDRESSES_PER_KEY,
                 unconfirmed_ttl_seconds: float = UNCONFIRMED_TTL_SECONDS):
        self.max_keys = max_keys
        self.max_addresses_per_key = max_addresses_per_key
        self.unconfirmed_ttl_seconds = unconfirmed_ttl_seconds
        self._by_key: Dict[str, List[Dict[str, Any]]] = {}

    # -- Storage ----------------------------------------------------------

    def add(self, public_key: object, address: object,
            source: Optional[str] = None, now: Optional[datetime] = None) -> bool:
        """
        Record an address. Returns whether it was stored.

        Storing is not endorsing: a stored address is unconfirmed until a
        handshake against it reaches the key it was filed under.
        """
        key = normalise_key(public_key)
        candidate = normalise_address(address)
        if key is None or candidate is None:
            return False

        moment = (now or _utc_now()).timestamp()
        entries = self._by_key.get(key)
        if entries is None:
            if len(self._by_key) >= self.max_keys:
                return False
            entries = self._by_key[key] = []

        for entry in entries:
            if entry["address"] == candidate:
                # Already known. Refresh when it was last offered so a
                # repeatedly gossiped address does not age out mid-use, but do
                # not let a re-offer confirm anything.
                entry["learned_at"] = moment
                return True

        if len(entries) >= self.max_addresses_per_key:
            if not self._evict_one(entries):
                return False
        entries.append({
            "address": candidate,
            "learned_at": moment,
            "confirmed_at": None,
            "source": source,
        })
        return True

    @staticmethod
    def _evict_one(entries: List[Dict[str, Any]]) -> bool:
        """
        Make room for one address. Unconfirmed entries go first.

        Confirmed entries are evicted only when every slot is confirmed, oldest
        confirmation first -- otherwise a peer that legitimately moves could
        never be learned again, because its old confirmed addresses would hold
        every slot forever.
        """
        unconfirmed = [e for e in entries if e["confirmed_at"] is None]
        if unconfirmed:
            victim = min(unconfirmed, key=lambda e: e["learned_at"])
        elif entries:
            victim = min(entries, key=lambda e: e["confirmed_at"])
        else:
            return False
        entries.remove(victim)
        return True

    def confirm(self, public_key: object, address: object,
                now: Optional[datetime] = None) -> bool:
        """Mark an address as one a handshake actually reached."""
        key = normalise_key(public_key)
        candidate = normalise_address(address)
        if key is None or candidate is None:
            return False
        for entry in self._by_key.get(key, []):
            if entry["address"] == candidate:
                entry["confirmed_at"] = (now or _utc_now()).timestamp()
                return True
        return False

    def forget(self, public_key: object) -> bool:
        """Drop everything known about a key, e.g. once it is revoked."""
        key = normalise_key(public_key)
        return self._by_key.pop(key, None) is not None if key else False

    # -- Queries ----------------------------------------------------------

    def addresses(self, public_key: object) -> List[str]:
        """
        Known addresses for a key, best first.

        Confirmed addresses lead, most recently confirmed first, so a caller
        that dials in order tries what worked before reaching for hearsay.
        """
        key = normalise_key(public_key)
        if key is None:
            return []
        entries = sorted(
            self._by_key.get(key, []),
            key=lambda e: (e["confirmed_at"] is None,
                           -(e["confirmed_at"] or e["learned_at"])),
        )
        return [entry["address"] for entry in entries]

    def entries(self, public_key: object) -> List[Dict[str, Any]]:
        key = normalise_key(public_key)
        return [dict(entry) for entry in self._by_key.get(key or "", [])]

    def is_confirmed(self, public_key: object, address: object) -> bool:
        key = normalise_key(public_key)
        candidate = normalise_address(address)
        if key is None or candidate is None:
            return False
        return any(entry["address"] == candidate and entry["confirmed_at"] is not None
                   for entry in self._by_key.get(key, []))

    def keys(self) -> List[str]:
        return list(self._by_key)

    def total_addresses(self) -> int:
        return sum(len(entries) for entries in self._by_key.values())

    def __len__(self) -> int:
        return len(self._by_key)

    def __repr__(self) -> str:
        return (f"<AddressBook {len(self._by_key)} key(s), "
                f"{self.total_addresses()} address(es)>")

    # -- Expiry -----------------------------------------------------------

    def prune(self, now: Optional[datetime] = None) -> int:
        """
        Forget unconfirmed addresses past the window. Returns how many went.

        Confirmed addresses are kept: a handshake reached them, and forgetting
        them would send the node back to gossip for something it already knows.
        """
        moment = (now or _utc_now()).timestamp()
        dropped = 0
        for key, entries in list(self._by_key.items()):
            keep = [
                entry for entry in entries
                if entry["confirmed_at"] is not None
                or (moment - entry["learned_at"]) <= self.unconfirmed_ttl_seconds
            ]
            dropped += len(entries) - len(keep)
            if keep:
                self._by_key[key] = keep
            else:
                del self._by_key[key]
        return dropped
