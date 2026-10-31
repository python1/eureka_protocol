"""
Browser access: which web pages may read this daemon's answers.

Off unless the operator names origins. A browser page -- a Knights Circle room
is one -- can only talk to the daemon if the daemon's answers carry CORS
headers for that page's exact origin; without them the browser refuses to hand
the page anything, signed or not.

This is not authentication and grants nothing. Every request still has to pass
the handshake, the trust file and the grants, exactly as from a Python peer. A
CORS origin decides only which page the browser lets *read the reply*, so the
list is exact origins and nothing looser: no wildcard, no suffix match, no
path, and plain http only for a page on this machine's loopback.
"""
import ipaddress
import os
from typing import Iterable, Tuple
from urllib.parse import urlsplit

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

ORIGINS_ENV = "EUREKA_CORS_ORIGINS"

_LOOPBACK_NAMES = frozenset({"localhost"})


def _is_loopback(host: str) -> bool:
    if host in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalise_origin(value: str) -> str:
    """One origin, checked and in the form a browser sends it. Raises ValueError."""
    text = value.strip()
    if not text or "*" in text:
        raise ValueError(f"CORS origin {value!r}: give one exact origin, no wildcards")
    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in ("https", "http") or not parts.hostname:
        raise ValueError(f"CORS origin {value!r} must look like https://host")
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username or parts.password:
        raise ValueError(f"CORS origin {value!r} is an origin, not a URL: drop the path")
    host = parts.hostname.lower()
    if scheme == "http" and not _is_loopback(host):
        raise ValueError(f"CORS origin {value!r}: plain http is only allowed for a page on loopback")
    shown = f"[{host}]" if ":" in host else host
    port = parts.port
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{shown}" + (f":{port}" if port and port != default else "")


def origins_from(values: Iterable[str] = (), environ=None) -> Tuple[str, ...]:
    """Command-line origins plus EUREKA_CORS_ORIGINS (comma separated), checked and de-duplicated."""
    source = os.environ if environ is None else environ
    named = [*values, *(v for v in source.get(ORIGINS_ENV, "").split(",") if v.strip())]
    out = []
    for value in named:
        origin = normalise_origin(value)
        if origin not in out:
            out.append(origin)
    return tuple(out)


def install(app: FastAPI, origins: Iterable[str]) -> None:
    """Let exactly these origins read replies. Does nothing for an empty list."""
    origins = [normalise_origin(o) for o in origins]
    if not origins:
        return
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_methods=["GET", "POST"],
        allow_headers=["content-type"],
        # No cookies or HTTP auth exist here; identity is the signed handshake.
        allow_credentials=False,
        max_age=600,
    )
