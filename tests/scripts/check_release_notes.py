#!/usr/bin/env python3
"""S-393-1 gate: release-notes section check (US-393).

Fails while docs/release-notes-v1.0.0.md lacks a required section or key
content: cutover decision, v1.0.0 scope (app list, PIV deferral, OATH
app-restore note, FIDO shell note), migration section (classes, silent vs
PW1/PIN, not-migratable, E2E evidence pointer), hardware-matrix pointer,
identity + provisional-VID note.
"""
import pathlib
import re
import sys

DOC = pathlib.Path(__file__).resolve().parents[2] / "docs" / "release-notes-v1.0.0.md"

REQUIRED = [
    ("cutover decision", r"(?i)## .*cutover"),
    ("C tree frozen but shippable", r"(?i)frozen but shippable"),
    ("PIV served by C post-cutover", r"(?i)PIV[^\n]*C (tree|firmware)|C (tree|firmware)[^\n]*PIV"),
    ("scope section", r"(?i)## .*scope"),
    ("app list", r"(?i)OpenPGP 3\.4"),
    ("PIV deferred in scope", r"(?i)PIV[^\n]*deferred"),
    ("OATH app-restore post-cutover", r"(?i)OATH[^\n]*app.restore|app.restore[^\n]*OATH"),
    ("FIDO shell capability note", r"(?i)shell"),
    ("migration section", r"(?i)## .*migration"),
    ("silent classes", r"(?i)silent"),
    ("PW1/PIN classes", r"(?i)PW1"),
    ("not-migratable classes", r"(?i)not.?migratable"),
    ("E2E evidence pointer", r"us413-hardware-e2e\.md"),
    ("hardware-matrix pointer", r"hardware-matrix\.md"),
    ("identity", r"fa20:0002"),
    ("provisional VID note", r"(?i)provisional[^\n]*VID|VID[^\n]*provisional|not[^\n]*USB-IF"),
]


def main() -> int:
    if not DOC.exists():
        print(f"FAIL: {DOC} missing")
        return 1
    text = DOC.read_text(encoding="utf-8")
    failures = [label for label, pat in REQUIRED if not re.search(pat, text)]
    if failures:
        print("FAIL: check_release_notes (US-393)")
        for f in failures:
            print(f"  - missing required content: {f}")
        return 1
    print("PASS: check_release_notes (US-393)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
