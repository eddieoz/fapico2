#!/usr/bin/env python3
"""S-392-3 gate: wrap-up cross-references (US-392).

Fails while:
  - the workspace-level `docs/tasks/EPIC-merged-firmware.md` (unversioned,
    outside the fapico2 repo) lacks the pointer note to the fapico2 Rust
    migration epic, or
  - `fapico2/docs/bootsel.md` lacks the corrected button note (C firmware:
    bootsel.py rescue APDU entered BOOTSEL with no button press, verified
    2026-09-08; Rust build: physical BOOTSEL+RESET only).
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
    if "physical BOOTSEL+RESET" not in t:
        failures.append("bootsel.md: Rust physical BOOTSEL+RESET note missing")
    if "no rescue APDU in v1.0.0" not in t:
        failures.append("bootsel.md: Rust no-rescue-APDU note missing")

if failures:
    print("FAIL: check_wrapup (US-392)")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print("PASS: check_wrapup (US-392)")
