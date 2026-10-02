#!/usr/bin/env python3
"""S-392-3 gate: wrap-up cross-references (US-392).

Fails while:
  - the workspace-level `docs/tasks/EPIC-merged-firmware.md` (unversioned,
    outside the fapico2 repo) lacks the pointer note to the fapico2 Rust
    migration epic, or
  - `fapico2/docs/bootsel.md` lacks the corrected button note (C firmware:
    bootsel.py rescue APDU entered BOOTSEL with no button press, verified
    2026-09-08).

**2026-10-02 correction.** This gate used to require `docs/bootsel.md` to
carry the sentence *"no rescue APDU in v1.0.0"*, on the reasoning that the
Rust build has no rescue applet. It does: `apps/rescue/src/lib.rs`
implements the same AID, the same CLA `0x80` and the same `INS 0x1F` the C
firmware speaks, and it is registered on the **device** build
(`firmware/Cargo.toml` → `fapico2-rescue/device`; `firmware/src/main.rs`
→ `boot::RESCUE_APP` → `register_ccid_apps`). A gate that required the false
claim was not a safety net — it was a ratchet holding the documentation to
the wrong answer, and it is the exact kind of check that makes an operator
carry a board to a desk to press BOOTSEL by hand for no reason.

The assertions below now require the **true** statements, which is the same
kind of check pointed the other way: if the rescue applet is ever removed from
the device build, the page that tells an operator how to re-flash stops
agreeing with it and this gate says so.
"""
import pathlib
import sys

PICO = pathlib.Path(__file__).resolve().parents[3]  # git/pico/
MERGED = PICO / "docs" / "tasks" / "EPIC-merged-firmware.md"
BOOTSEL = PICO / "fapico2" / "docs" / "bootsel.md"

failures = []

if not MERGED.exists():
    failures.append(f"{MERGED} missing")
else:
    t = MERGED.read_text(encoding="utf-8")
    if "EPIC-rust-migration-fapico2.md" not in t or "fapico2" not in t:
        failures.append("EPIC-merged-firmware.md: no pointer to the fapico2 Rust migration epic")
    if "EPIC-fapico2-phase6-acceptance-migration.md" not in t:
        failures.append("EPIC-merged-firmware.md: no pointer to the Phase-6 acceptance epic")

if not BOOTSEL.exists():
    failures.append(f"{BOOTSEL} missing")
else:
    t = BOOTSEL.read_text(encoding="utf-8")
    if "no button press" not in t or "2026-09-08" not in t:
        failures.append("bootsel.md: C-firmware no-button-press verification note missing")
    if "Button sequence (always works, both firmwares)" not in t:
        failures.append(
            "bootsel.md: the button sequence must remain documented as working "
            "on both firmwares — it is the fallback for a Rust image too old to "
            "have apps/rescue (pre-US-161)"
        )
    # The rescue applet IS on the Rust device build. Require the page to say
    # so. The anchors are single-occurrence phrases on purpose: a substring
    # like "apps/rescue" also occurs in "apps/rescue/src/lib.rs", so gating on
    # it would pass with the claim deleted (the mutation harness caught
    # exactly that when this check was first written — see _B_WRAPUP).
    if "same AID, same APDU, same script" not in t:
        failures.append(
            "bootsel.md: the table no longer says the Rust device build "
            "speaks the same rescue APDU — apps/rescue (US-161/162/163) is "
            "registered on the device, not only the emulator, and the page "
            "that tells an operator how to re-flash must say so"
        )
    if "80 1F 01 00 00" not in t or "the mode byte is in **P1**" not in t:
        failures.append(
            "bootsel.md: the REBOOT BOOTSEL APDU (80 1F 01 00 00) and the fact "
            "that its mode byte is P1 are missing — P2 is what a reader "
            "assumes, and assuming it gets a plain reboot that then looks like "
            "a firmware which ignored the command"
        )
    # The auto-detect footgun: `pick_reader` matches "pico", which is the
    # REFERENCE board's name. On a two-board desk that targets the wrong device
    # and the run then looks exactly like a no-op.
    if "Auto-detect picks the wrong board" not in t:
        failures.append(
            "bootsel.md: the pick_reader/`--reader` auto-detect footgun is not "
            "recorded — scripts/bootsel.py matches the substring 'pico', which "
            "is the reference C board's reader name, so auto-detect on a "
            "two-board desk drives the WRONG device and the fapico2 looks like "
            "it ignored a successful command"
        )

if failures:
    print("FAIL: check_wrapup (US-392)")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print("PASS: check_wrapup (US-392)")
