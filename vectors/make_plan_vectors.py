"""
Regenerate vectors/plans-v1.json: the plan hashes and passkey approvals that the
daemon and Knights Circle must agree on, for the "Approve plan" feature.

    ./venv/bin/python vectors/make_plan_vectors.py

Standalone on purpose: it implements the canonical form (Python's
json.dumps(sort_keys=True, separators=(',', ':')), ensure_ascii on) and WebAuthn
itself, with the `cryptography` package, so it is a second implementation to
check the Rust daemon and the browser against, not a copy of either.

The P-256 key comes from a published seed. It is a TEST key: no seat should ever
pin it. Signing is deterministic (RFC 6979), so the same script always writes
the same file.

The plans listed as invalid carry the code every implementation must refuse
them with. This script doesn't check plans; the codes are the contract.
"""
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

PATH = Path(__file__).with_name("plans-v1.json")
SEED = hashlib.sha256(b"eureka plan approval test vectors v1 -- never trust this key").digest()
DOMAIN_PLAN = b"eureka/plan/v1"
DOMAIN_APPROVAL = b"eureka/plan/approval/v1"
ORIGIN = "https://knights-circle.vercel.app"
RP_ID = "knights-circle.vercel.app"
CREDENTIAL_ID = hashlib.sha256(b"test credential id").digest()[:16]
UP, UV = 0x01, 0x04

KEY = ec.derive_private_key(int.from_bytes(SEED, "big") % 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551, ec.SECP256R1())
SPKI = KEY.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def signed_bytes(domain, value):
    return domain + b"\x00" + canonical(value).encode("ascii")


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


GOOD = {
    "eureka_plan": 1,
    "title": "Add a dark-mode toggle",
    "project": "site",
    "steps": ["Add a .dark theme to src/theme.css", "Add a toggle to src/app.js that sets it"],
    "edit": ["src/theme.css", "src/app.js"],
}


def plan_entry(name, plan, text=None):
    text = text if text is not None else json.dumps(plan, ensure_ascii=False, indent=2)
    return {
        "name": name,
        "plan_json": text,
        "canonical": canonical(json.loads(text)),
        "signed_bytes_hex": signed_bytes(DOMAIN_PLAN, json.loads(text)).hex(),
        "plan_hash": hashlib.sha256(signed_bytes(DOMAIN_PLAN, json.loads(text))).hexdigest(),
    }


def changed(**fields):
    return json.dumps({**GOOD, **fields}, ensure_ascii=False)


PLANS = [
    plan_entry("basic", GOOD),
    plan_entry("same plan, other key order and spacing", None,
               '{"edit":["src/theme.css","src/app.js"],"steps":["Add a .dark theme to src/theme.css","Add a toggle to src/app.js that sets it"],"title":"Add a dark-mode toggle","project":"site","eureka_plan":1}'),
    plan_entry("non-ASCII text is hashed escaped", {**GOOD, "title": "Café — résumé \U0001F600", "steps": ["日本語の手順"]}),
    plan_entry("globs", {**GOOD, "edit": ["src/**/*.css", "docs/*.md", "**/test_*.py", ".github/workflows/ci.yml"]}),
]

INVALID = [
    ("not an object", "[1]", "not_a_plan"),
    ("not JSON", "{", "not_json"),
    ("an unknown key", changed(run="rm -rf ~"), "unknown_key"),
    ("a missing key", json.dumps({k: v for k, v in GOOD.items() if k != "edit"}), "missing_key"),
    ("version 2", changed(eureka_plan=2), "bad_version"),
    ("version true", changed(eureka_plan=True), "bad_version"),
    ("version 1.0", changed(eureka_plan=1.0), "bad_version"),
    ("an empty title", changed(title="  "), "bad_title"),
    ("a 121-character title", changed(title="x" * 121), "bad_title"),
    ("a project path", changed(project="../etc"), "bad_project"),
    ("an upper-case project", changed(project="Site"), "bad_project"),
    ("no steps", changed(steps=[]), "bad_steps"),
    ("21 steps", changed(steps=["s"] * 21), "bad_steps"),
    ("a newline in a step", changed(steps=["one\ntwo"]), "bad_text"),
    ("a right-to-left override in the title", changed(title="ok‮ok"), "bad_text"),
    ("an absolute path", changed(edit=["/etc/passwd"]), "bad_edit"),
    ("a home path", changed(edit=["~/.ssh/config"]), "bad_edit"),
    ("a parent segment", changed(edit=["src/../../x"]), "bad_edit"),
    ("git's folder", changed(edit=["src/.GIT/hooks/pre-commit"]), "bad_edit"),
    ("git attributes", changed(edit=[".gitattributes"]), "bad_edit"),
    ("every file", changed(edit=["**/*"]), "bad_edit"),
    ("braces", changed(edit=["src/*.{js,css}"]), "bad_edit"),
    ("a backslash", changed(edit=["src\\app.js"]), "bad_edit"),
    ("a duplicate", changed(edit=["a", "a"]), "bad_edit"),
    ("over 8000 characters", changed(steps=["x" * 999] * 9), "too_long"),
]

MATCHES = [
    ["src/app.js", "src/app.js", True],
    ["src/*.js", "src/lib/app.js", False],
    ["src/**/*.js", "src/app.js", True],
    ["src/**/*.js", "src/a/b/app.js", True],
    ["src/**", "src/a/b", True],
    ["src/**", "src", False],
    ["**/test_*.py", "test_a.py", True],
    ["doc?.md", "doc.md", False],
    ["src/App.js", "src/app.js", False],
]

NOW = 1800000000
SEAT, ROOM_KEY, ROOM = "node_0123abcd", "node_89abcdef", "7d3c1f2e-0000-4000-8000-000000000001"
PLAN_HASH = PLANS[0]["plan_hash"]


def approval(**fields):
    value = {"kind": "run", "plan_hash": PLAN_HASH, "seat_id": SEAT, "requester_id": ROOM_KEY, "room_id": ROOM,
             "approval_id": hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()[:32],
             "issued_at": NOW - 5, "expires_at": NOW + 595}
    value.update(fields)
    return value


def challenge(value):
    return hashlib.sha256(signed_bytes(DOMAIN_APPROVAL, value)).digest()


def assertion(value, *, origin=ORIGIN, rp_id=RP_ID, flags=UP | UV, kind="webauthn.get", cross="false", over=None, credential=CREDENTIAL_ID):
    client = ('{"type":"%s","challenge":"%s","origin":"%s","crossOrigin":%s}'
              % (kind, b64url(challenge(over or value)), origin, cross)).encode()
    auth = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + (0).to_bytes(4, "big")
    signature = KEY.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    return {"credential_id": b64url(credential), "authenticator_data": b64url(auth),
            "client_data_json": b64url(client), "signature": b64url(signature)}


def expected(**fields):
    value = {"seat_id": SEAT, "requester_id": ROOM_KEY, "room_id": ROOM, "plan_hash": PLAN_HASH}
    value.update(fields)
    return value


RUN = approval()
TARGET = {"run_id": "a1" * 16, "diff_hash": "d4" * 32, "base_commit": "c0ffee" + "0" * 34}
APPLY = approval(kind="apply", **TARGET)

APPROVALS = [
    ("a good run approval", RUN, assertion(RUN), expected(), NOW, "ok"),
    ("a good apply approval", APPLY, assertion(APPLY), expected(apply=TARGET), NOW, "ok"),
    ("signed on another site", RUN, assertion(RUN, origin="https://evil.example"), expected(), NOW, "bad_approval"),
    ("for another relying party", RUN, assertion(RUN, rp_id="evil.example"), expected(), NOW, "bad_approval"),
    ("the user not verified", RUN, assertion(RUN, flags=UP), expected(), NOW, "bad_approval"),
    ("a registration, not an assertion", RUN, assertion(RUN, kind="webauthn.create"), expected(), NOW, "bad_approval"),
    ("inside another site's frame", RUN, assertion(RUN, cross="true"), expected(), NOW, "bad_approval"),
    ("signed over a different approval", RUN, assertion(RUN, over=approval(room_id="other")), expected(), NOW, "bad_approval"),
    ("another passkey's credential", RUN, assertion(RUN, credential=b"other credential"), expected(), NOW, "bad_approval"),
    ("for another seat", RUN, assertion(RUN), expected(seat_id="node_ffffffff"), NOW, "bad_approval"),
    ("from another room key", RUN, assertion(RUN), expected(requester_id="node_ffffffff"), NOW, "bad_approval"),
    ("a run approval used to apply", RUN, assertion(RUN), expected(apply=TARGET), NOW, "bad_approval"),
    ("for another plan", RUN, assertion(RUN), expected(plan_hash="4" * 64), NOW, "plan_mismatch"),
    ("for another diff", APPLY, assertion(APPLY), expected(apply={**TARGET, "diff_hash": "e5" * 32}), NOW, "plan_mismatch"),
    ("expired", RUN, assertion(RUN), expected(), NOW + 596, "expired"),
    ("issued in the future", RUN, assertion(RUN), expected(), NOW - 70, "bad_approval"),
]


def main():
    doc = {
        "about": "Shared vectors for approved plans. Generated by vectors/make_plan_vectors.py; do not edit by hand. "
                 "The P-256 key is a published TEST key: never pin it.",
        "domains": {"plan": DOMAIN_PLAN.decode(), "approval": DOMAIN_APPROVAL.decode()},
        "plans": PLANS,
        "invalid_plans": [{"name": n, "plan_json": t, "code": c} for n, t, c in INVALID],
        "pattern_matches": MATCHES,
        "approver": {"credential_id": b64url(CREDENTIAL_ID), "public_key": b64url(SPKI), "origin": ORIGIN, "rp_id": RP_ID,
                     "fingerprint": " ".join(hashlib.sha256(SPKI).hexdigest()[i:i + 4] for i in range(0, 16, 4))},
        "approvals": [{"name": n, "approval": a, "challenge": b64url(challenge(a)), "assertion": s, "expected": e, "now": t, "result": r}
                      for n, a, s, e, t, r in APPROVALS],
    }
    PATH.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {PATH} ({len(PLANS)} plans, {len(INVALID)} invalid, {len(APPROVALS)} approvals)")


if __name__ == "__main__":
    main()
