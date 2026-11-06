#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""
Writes rust/THIRD_PARTY_LICENSES.txt: the licence and notice files of every crate that can be
linked into eureka-daemon, on any target, taken from the crates' own sources. Licence texts that
are identical are printed once. With --check, fails if the file is out of date and changes nothing.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

RUST = Path(__file__).resolve().parent.parent
OUTPUT = RUST / "THIRD_PARTY_LICENSES.txt"
NOTICE_FILE = re.compile(r"(?i)^(licen[cs]e|copying|notice|copyright)")
RULE = "=" * 78

# Linked in, but not crates, so their notices can't be collected from a crate's sources.
LINKED = """\
eureka-daemon also contains:

- The Rust standard library, in every build. MIT OR Apache-2.0,
  Copyright (c) The Rust Project Contributors. https://www.rust-lang.org/policies/licenses
  Both licence texts appear below.
- musl libc, in the static Linux builds. MIT, Copyright (c) 2005-2020 Rich Felker, et al.
  Its full notices, including those for code it includes from others, are at
  https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT
  The MIT licence text appears below.
"""


def cargo(*args):
    return subprocess.run(["cargo", *args], cwd=RUST, check=True, capture_output=True, text=True).stdout


def shipped_crates():
    """Normal dependencies only: build tools and test crates don't end up in the binary."""
    tree = cargo("tree", "--locked", "-e", "normal", "--target", "all", "--prefix", "none", "-f", "{p}")
    found = {tuple(match.groups()) for match in re.finditer(r"(?m)^(\S+) v(\S+)", tree)}
    return found - {("eureka-daemon", crate_version())}


def crate_version():
    return re.search(r'(?m)^version = "(.*)"$', (RUST / "Cargo.toml").read_text()).group(1)


def render():
    cargo("fetch", "--locked")
    metadata = json.loads(cargo("metadata", "--format-version", "1", "--locked"))
    packages = {(p["name"], p["version"]): p for p in metadata["packages"]}
    texts = {}
    summary = []
    for key in sorted(shipped_crates()):
        package = packages[key]
        label = f"{key[0]} {key[1]}"
        summary.append(f"{label}: {package['license']}")
        folder = Path(package["manifest_path"]).parent
        files = sorted(f for f in folder.iterdir() if f.is_file() and NOTICE_FILE.match(f.name))
        if not files:
            sys.exit(f"{label} has no licence file: add its notice by hand before shipping")
        for file in files:
            text = file.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").strip() + "\n"
            entry = texts.setdefault(hashlib.sha256(text.encode()).hexdigest(), {"text": text, "users": []})
            entry["users"].append(f"{label} ({file.name})")
    parts = ["Third-party software in eureka-daemon\n", LINKED, RULE, "Crates and their licences\n", RULE, "\n".join(summary), ""]
    for entry in sorted(texts.values(), key=lambda e: e["users"][0]):
        parts += [RULE, "Used by:", *[f"  {user}" for user in entry["users"]], RULE, entry["text"]]
    return "\n".join(parts).rstrip() + "\n"


def main():
    text = render()
    if "--check" in sys.argv[1:]:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != text:
            sys.exit(f"{OUTPUT.name} is out of date. Run: python3 rust/ci/third-party-licenses.py")
        print(f"{OUTPUT.name}: up to date")
        return
    OUTPUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUTPUT.name}")


if __name__ == "__main__":
    main()
