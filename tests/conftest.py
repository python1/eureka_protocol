"""
Session-wide test setup.

Importing the daemon now loads (and on first run creates) the node's
persistent identity. Point that at a throwaway directory for the whole test
session so running the suite never writes a private key into the developer's
home directory -- and so tests never depend on one being there already.

This runs at conftest import time, which pytest does before importing any test
module, so it is in place before api.py is ever imported.
"""
import atexit
import os
import shutil
import tempfile
from pathlib import Path

from eureka_protocol.src.eureka_daemon.crypto import IDENTITY_PATH_ENV_VAR

_IDENTITY_DIR = tempfile.mkdtemp(prefix="eureka-test-identity-")
# setdefault: an explicitly exported path still wins.
os.environ.setdefault(
    IDENTITY_PATH_ENV_VAR, str(Path(_IDENTITY_DIR) / "identity.key")
)

atexit.register(shutil.rmtree, _IDENTITY_DIR, True)
