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
from eureka_protocol.src.eureka_daemon.handlers import INFERENCE_ENV
from eureka_protocol.src.eureka_daemon.trust import TRUST_PATH_ENV_VAR

_IDENTITY_DIR = tempfile.mkdtemp(prefix="eureka-test-identity-")
# setdefault: an explicitly exported path still wins.
os.environ.setdefault(
    IDENTITY_PATH_ENV_VAR, str(Path(_IDENTITY_DIR) / "identity.key")
)
# Same for the trust list: point it at a path inside the throwaway directory
# so no test can read or write the real ~/.eureka/trust.json. Nothing creates
# this file, so the default state under test is "absent" -- an empty
# allowlist, which trusts nobody.
os.environ.setdefault(
    TRUST_PATH_ENV_VAR, str(Path(_IDENTITY_DIR) / "trust.json")
)

atexit.register(shutil.rmtree, _IDENTITY_DIR, True)

# Assignment, not setdefault, and that difference is on purpose. The two paths
# above use setdefault so a developer can point the suite at their own files;
# this one must not be overridable, because it decides what default_registry()
# builds. An exported EUREKA_INFERENCE would silently change the advertised
# list under every test that calls it, turning a green suite into a statement
# about one machine's environment. Tests that want inference registered ask
# for it explicitly with default_registry(inference=True).
os.environ[INFERENCE_ENV] = "0"
