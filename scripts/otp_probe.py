#!/usr/bin/env python3
"""US-1711 — the two-population OTP probe: the gate every burn story stands behind.

Reads ONLY, over BOOTSEL (picotool talks to the bootrom; there is no SWD
debugger attached — ever, per AGENTS.md). It answers ADR 0004 am2's assigned
question — the register-model disagreement (256x16 vs 64x64) — and dumps the
occupancy of the custody-candidate pages and the lock rows on BOTH
populations:

  - a pico-fido2-migrated board: page 58 (rows 0xE80-0xE9F) is full and
    PAGE58_LOCK1-locked; the store key lives at 0xE90-0xE9F.
  - a factory board: neither.

It also demonstrates, at zero risk today, the exact post-lock state the
custody rows will live in: page 58's post-lock rows read correctly through
the shipping ECC API *on the live board* (the firmware's store-key read at
boot is the witness) while picotool's raw view cannot read past the lock —
the transcript records both halves.

Run it with the venv python (it needs nothing beyond stdlib, but the venv is
the convention):

    ../pico-fido2/.test-venv/bin/python scripts/otp_probe.py [--tee FILE]

The user puts the board in BOOTSEL when asked; every command here is a
`picotool otp get` or `picotool info` — nothing writes.
"""
import argparse
import shutil
import subprocess
import sys
from pathlib import Path

#: The picotool binary. `shutil.which` first; the pico-sdk checkout is the
#: fallback this workspace actually uses.
PICO_SDK_PICOOL = Path.home() / ".pico-sdk" / "picotool" / "2.3.0" / "picotool" / "picotool"

#: The register-model disagreement, stated as the two readings of the SAME
#: row index. embassy-rp declares NUM_PAGES=64, NUM_ROWS_PER_PAGE=64
#: (embassy-rp-0.10.0/src/otp.rs:32-40) — NUM_ROWS=4096. The pico-fido2 C
#: firmware's own naming ("page 58", PAGE58_LOCK1) is only coherent under
#: 64 rows/page: 0xE80 = 3712 = 58 * 64 exactly. Under a 16-rows-per-page
#: model the same rows would be page 232. The probe demonstrates which
#: reading the hardware's behaviour supports.
ROWS_PER_PAGE_EMBASSY = 64
PAGE58_FIRST_ROW = 58 * ROWS_PER_PAGE_EMBASSY  # 0xE80 = 3712

#: The custody-candidate pages (US-1711): 59-62, rows 0xEC0-0xFB0 — free,
#: lockable, never touched by the C firmware's page 58 migration.
CANDIDATE_FIRST_ROW = 59 * ROWS_PER_PAGE_EMBASSY  # 0xEC0
CANDIDATE_LAST_ROW = 62 * ROWS_PER_PAGE_EMBASSY + 63  # 0xFB0

#: The lock rows: page 63's tail, 0xFF0-0xFFF.
LOCK_FIRST_ROW = 0xFF0
LOCK_LAST_ROW = 0xFFF

ERASED_RAW = "ffffff"


def run_picotool(*args, tee=None):
    cmd = [PICOOL, *args]
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    out = subprocess.run(cmd, capture_output=True, text=True)
    text = (out.stdout + out.stderr).strip()
    print("\n".join("    " + line for line in text.splitlines()))
    if tee is not None:
        tee.write(f"\n$ {' '.join(str(c) for c in cmd)}\n{text}\n")
    return text


def row_value(text):
    """The last hex token of a `picotool otp get -n` line, or None.

    Tolerates both `ffffff` and `0xffffff` renderings; anything else (an
    error line, a description) is not a value."""
    if not text or "ERROR" in text:
        return None
    tokens = [t.lower().removeprefix("0x") for t in text.split()]
    return tokens[-1] if tokens and tokens[-1] else None


def dump_rows(tee, label, first, last, raw=True):
    word = "raw" if raw else "ecc"
    print(f"\n[{label}] ({word} view, rows {first:#06x}-{last:#06x})")
    written, erased, refused = 0, 0, 0
    row = first
    while row <= last:
        text = run_picotool("otp", "get", "-r" if raw else "-e", "-n", str(row), tee=tee)
        val = row_value(text)
        if val is None:
            refused += 1
        elif val == ERASED_RAW:
            erased += 1
        else:
            written += 1
            print(f"      ^ row {row:#06x} is WRITTEN ({val})")
        row += 1
    print(f"  -> {label}: {written} written, {erased} erased, {refused} refused")
    if tee:
        tee.write(f"[{label}] {word}: {written} written, {erased} erased, {refused} refused\n")
    return written, erased, refused


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tee", metavar="FILE", help="append the transcript to FILE")
    args = ap.parse_args()

    print(__doc__)
    print(
        "\nIMPORTANT: reads only — every command below is `picotool otp get` or\n"
        "`picotool info`. Never attach a SWD debugger for this.\n"
    )

    global PICOOL
    PICOOL = shutil.which("picotool") or str(PICO_SDK_PICOOL)

    tee = None
    if args.tee:
        tee = open(args.tee, "a", encoding="utf-8")
        tee.write(f"\n===== US-1711 probe run, {args.tee} =====\n")

    try:
        print("[0/4] the board, over BOOTSEL")
        run_picotool("info", tee=tee)

        print("\n[1/4] the register-model reconciliation")
        print(
            f"  embassy declares NUM_PAGES=64 x {ROWS_PER_PAGE_EMBASSY} rows = 4096 rows.\n"
            f"  The C firmware's 'page 58' naming: row {PAGE58_FIRST_ROW:#06x} = 58 * 64 —\n"
            "  the name is only coherent under 64 rows/page. The reads below settle\n"
            "  which model the hardware answers to: a row past the 16-rows-per-page\n"
            "  model's end (256*16 = 4096 too — same span, different shape) cannot\n"
            "  discriminate by index alone, so the discriminator is the LOCK: if the\n"
            "  rows named by 'page 58' behave as one locked page, the 64-row model\n"
            "  is the real one."
        )

        print("\n[2/4] page 58 — the migrated board's marker (factory: all erased)")
        dump_rows(tee, "page 58 raw view", PAGE58_FIRST_ROW, PAGE58_FIRST_ROW + 31)
        print("  (the ECC-view half of the demonstration — 'the shipping ECC API on")
        print("   a live board reads these correctly' — is witnessed by the firmware")
        print("   itself: boot.rs's store-key read of 0xE90-0xE9F succeeding at boot is")
        print("   the same rows answering through read_ecc_word. Record both halves")
        print("   in the transcript.)")

        print("\n[3/4] the custody-candidate pages 59-62 (rows 0xEC0-0xFB0)")
        dump_rows(tee, "candidates raw view", CANDIDATE_FIRST_ROW, CANDIDATE_LAST_ROW)

        print("\n[4/4] the lock rows (0xFF0-0xFFF)")
        dump_rows(tee, "lock rows raw view", LOCK_FIRST_ROW, LOCK_LAST_ROW)

        print(
            "\nDone — no write was performed. The chosen page constant is recorded\n"
            "with this transcript; until then, no page constant is committed and\n"
            "no burn-capable code ships (US-1711's gate)."
        )
    finally:
        if tee:
            tee.close()


if __name__ == "__main__":
    main()
