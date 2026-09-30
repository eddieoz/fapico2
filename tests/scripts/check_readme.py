#!/usr/bin/env python3
"""S-392-1 gate: README requirements (US-392).

Fails while fapico2/README.md:
  - exceeds 250 lines, or
  - misses a required section: app/AID table, flashing section referencing
    docs/bootsel.md, the provisional USB identity note (FA20:0002), or the
    migration section (pointer to the feasibility doc).
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
README = ROOT / "README.md"

REQUIRED = [
    ("one-firmware claim", r"(?i)one firmware|single firmware"),
    ("app/AID table", r"(?i)app/AID|AID table|D2 76 00 01 24 01"),
    ("flashing -> docs/bootsel.md", r"docs/bootsel\.md"),
    ("physical BOOTSEL+RESET (Rust)", r"(?i)physical BOOTSEL"),
    ("rescue APDU (C firmware)", r"(?i)bootsel\.py|rescue APDU"),
    ("USB identity FA20:0002", r"(?i)FA20[.:]?0002|0xFA20"),
    ("provisional VID note", r"(?i)provisional"),
    ("migration section", r"(?i)## .*migration"),
    ("migration silent classes", r"(?i)silent"),
    ("migration PW1/PIN step", r"(?i)PW1/PIN|one-time|needs passphrase"),
    ("not-migratable classes", r"(?i)not.?migratable"),
    ("feasibility doc pointer", r"us413-migration-feasibility\.md"),
    ("build: host", r"(?i)host"),
    ("build: device", r"(?i)device build"),
    ("build: emulation", r"(?i)emulation"),
    ("trim switches / cargo features", r"(?i)trim|feature"),
    ("PIV deferred", r"(?i)PIV[^\n]*deferred"),
]


def main() -> int:
    if not README.exists():
        print(f"FAIL: {README} missing")
        return 1
    text = README.read_text(encoding="utf-8")
    lines = text.count("\n") + (0 if text.endswith("\n") else 1)
    failures = []
    if lines > 250:
        failures.append(f"README is {lines} lines (limit 250)")
    for label, pattern in REQUIRED:
        if not re.search(pattern, text):
            failures.append(f"missing required content: {label}")
    if failures:
        print("FAIL: check_readme (US-392)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"PASS: check_readme (US-392) — {lines} lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
