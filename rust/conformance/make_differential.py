"""
Regenerate rust/tests/fixtures/python-differential.json: what Python itself
makes of thousands of inputs the Rust port has to agree with.

    python3 rust/conformance/make_differential.py

Three tables, each produced by the exact Python call the daemon makes:
  * floats: repr() of doubles (via the canonical encoder),
  * timestamps: datetime.fromisoformat() -> UTC microseconds, or null,
  * documents: json.loads() then the canonical json.dumps(), or null.
The seed is fixed, so the file only changes when Python's behaviour does.
"""
import json
import random
import struct
from datetime import datetime, timezone
from pathlib import Path

rng = random.Random(20261031)
OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "python-differential.json"


def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"))


def floats():
    out = []
    specials = [0.1, 1e16, 1e15, 9999999999999998.0, 1e-4, 1e-5, 5e-324, 2.2250738585072014e-308,
                1.7976931348623157e308, 123456789.125, 0.000123, -2.5e-7, 1e22, 1e21]
    for x in specials:
        out.append([struct.pack(">d", x).hex(), canonical(x)])
    for _ in range(3000):
        bits = rng.getrandbits(64)
        x = struct.unpack(">d", bits.to_bytes(8, "big"))[0]
        if x != x or x in (float("inf"), float("-inf")):
            continue
        out.append([bits.to_bytes(8, "big").hex(), canonical(x)])
    for _ in range(2000):
        x = round(rng.uniform(-1e6, 1e6), rng.randint(0, 12)) * 10 ** rng.randint(-25, 25)
        out.append([struct.pack(">d", x).hex(), canonical(x)])
    return out


def timestamps():
    pieces = ["2026", "-", "10", "31", "W", "44", "6", "T", " ", "X", "12", ":", "00", "59", "60", "24",
              ".", ",", "123", "1234567", "Z", "+", "05", "30", "0530", "-", "00:00:30.5", "1", "", "9999", "0001"]
    seen, out = set(), []
    base = ["2026-10-31T12:00:00Z", "2026-10-31T12:00:00.123Z", "2026-10-31T12:00:00.123456+00:00",
            "2026-10-31 12:00", "20261031T120000", "2026-10-31", "2026-W44-6", "2026W446", "2026W44",
            "2026-W44", "2026-10-31T24:00:00", "2026-02-29", "2024-02-29T00:00", "2026-10-31T12:00:00+24:00",
            "2026-10-31T12:00:00-23:59:59.999999", "0001-01-01T00:00:00+00:01", "9999-12-31T23:59:59-00:01"]
    for s in base:
        seen.add(s)
    for _ in range(6000):
        s = "".join(rng.choice(pieces) for _ in range(rng.randint(3, 12)))
        seen.add(s)
    for s in sorted(seen):
        try:
            d = datetime.fromisoformat(s)
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            delta = d - datetime(1970, 1, 1, tzinfo=timezone.utc)
            micros = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
            out.append([s, str(micros)])
        except (ValueError, OverflowError):
            out.append([s, None])
    return out


def documents():
    atoms = ['0', '-0', '1', '-12', '9007199254740993', '123456789012345678901234567890', '1.5', '1e5',
             '1E-7', '-0.0', '2.50', 'NaN', 'Infinity', '-Infinity', 'true', 'false', 'null',
             '"a"', '"\\u00e9"', '"\\ud83d\\ude00"', '"\\u2028\\u007f\\u0000"', '"tab\\t"', '"\\/"',
             '"é"', '"日本"', '"🙂"', '""', '[]', '{}', '01', '1.', '.5', '+1', '"\\x"', "'a'", '[1,]']
    out = []
    for _ in range(3000):
        def build(depth):
            if depth > 2 or rng.random() < 0.4:
                return rng.choice(atoms)
            if rng.random() < 0.5:
                return "[" + ",".join(build(depth + 1) for _ in range(rng.randint(0, 3))) + "]"
            keys = ['"b"', '"a"', '"é"', '"😀"', '"～"', '"Z"', '"_"', '"a"']
            return "{" + ",".join(f"{rng.choice(keys)}:{build(depth + 1)}" for _ in range(rng.randint(0, 3))) + "}"
        text = build(0)
        if rng.random() < 0.2:
            text = rng.choice([" ", "\n", "\t"]) + text + rng.choice(["", " ", "\r\n", " x"])
        try:
            out.append([text, canonical(json.loads(text))])
        except ValueError:
            out.append([text, None])
    return out


OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps({"floats": floats(), "timestamps": timestamps(), "documents": documents()},
                          ensure_ascii=False, indent=0) + "\n")
print(f"wrote {OUT}")
