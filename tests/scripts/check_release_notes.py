#!/usr/bin/env python3
"""S-393-1 gate: release-notes section check (US-393).

Fails while docs/release-notes-v1.0.0.md lacks a required section or key
content: cutover decision, v1.0.0 scope (app list, PIV deferral, OATH
app-restore note, FIDO shell note), migration section (classes, silent vs
PW1/PIN, not-migratable, E2E evidence pointer), hardware-matrix pointer,
identity + provisional-VID note.

ALSO: the identity the notes state must BE the identity the board file
declares. That check exists because of a real defect, not a hypothetical
one — v1.0.0's own release notes told the reader the device enumerated as
"EddieOz" while the firmware it shipped with had carried "The BLOCO
Community" since 2026-09-28. The firmware was right and the published
release page was wrong, which is worse than a wrong build in one specific
way: the wrong build would have been noticed by anyone who ran `lsusb`,
whereas the wrong release notes are what a person reads BEFORE flashing,
and they are what they trust.

Nothing enforced the two agreeing. The board file is the single source of
truth for the identity (US-1080 says so at length) and the notes are
prose, so a rename has to be applied in two places by hand, and the
hand-remembering failed silently for a month.
"""
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import minitoml  # noqa: E402  — the repository's only TOML reader

DOC = pathlib.Path(__file__).resolve().parents[2] / "docs" / "release-notes-v1.0.0.md"
BOARD = pathlib.Path(__file__).resolve().parents[2] / "firmware" / "boards" / "pico2.toml"

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


def identity_failures(text: str) -> list[str]:
    """The notes must state the identity the board file actually declares.

    The board file is the source of truth (US-1080). This compares the two
    rather than restating either, so a rename in `pico2.toml` turns this gate
    red until the notes follow it — which is the whole point.
    """
    try:
        board = minitoml.read_toml(BOARD)
    except Exception as exc:  # noqa: BLE001 — a parse failure is a failure
        return [f"cannot read {BOARD}: {exc}"]
    usb = board.get("usb") or {}
    manufacturer = usb.get("manufacturer")
    product = usb.get("product")
    vidpid = (usb.get("vidpid") or "").lower()
    problems: list[str] = []
    if not (manufacturer and product and vidpid):
        return [f"{BOARD} does not declare a complete [usb] identity "
                f"(manufacturer={manufacturer!r} product={product!r} "
                f"vidpid={usb.get('vidpid')!r})"]

    # The notes must name the current manufacturer as the enumerating one.
    # Scoped to the identity section so a historical mention elsewhere (there
    # are several, and they are legitimate) is not mistaken for a claim.
    identity_block = re.search(
        r"(?is)##\s*USB identity.*?(?=\n##\s|\Z)", text)
    block = identity_block.group(0) if identity_block else text

    if manufacturer not in block:
        present = [m for m in (manufacturer, "EddieOz") if m in block]
        problems.append(
            f"the release notes do not state the shipping manufacturer "
            f"{manufacturer!r} (found: {present or 'neither'}).\n"
            f"  The board file {BOARD.name} is the source of truth and says "
            f"manufacturer = {manufacturer!r}; a reader who trusts these notes "
            f"will expect the device to enumerate as something it does not.")
    if product and product not in block:
        problems.append(f"the release notes do not state the product {product!r}")
    if vidpid and vidpid not in block.lower():
        problems.append(f"the release notes do not state vidpid {vidpid!r}")
    return problems


def main() -> int:
    if not DOC.exists():
        print(f"FAIL: {DOC} missing")
        return 1
    text = DOC.read_text(encoding="utf-8")
    failures = [label for label, pat in REQUIRED if not re.search(pat, text)]
    failures += identity_failures(text)
    if failures:
        print("FAIL: check_release_notes (US-393)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("PASS: check_release_notes (US-393)")
    print(f"  identity checked against {BOARD.name}: "
          f"{minitoml.read_toml(BOARD).get('usb', {})}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
