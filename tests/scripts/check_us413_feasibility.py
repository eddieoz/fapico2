#!/usr/bin/env python3
"""US-413 S-413-1 gate: migration epic + feasibility doc completeness.

Fails while either document lacks a required section/verdict marker.
Stdlib only. Exits 0 on pass, 1 on fail.
"""
import os
import re
import sys

DOCS = os.path.join(os.path.dirname(__file__), "..", "..", "docs")

EPIC = os.path.join(DOCS, "migration-epic.md")
FEAS = os.path.join(DOCS, "migration-feasibility.md")

EPIC_SECTIONS = [
    r"(?im)^#+\s*.*\bGoal\b",
    r"(?im)^#+\s*.*\bScope\b",
    r"(?im)S-413-1",
    r"(?im)S-413-7",
    r"(?im)^#+\s*.*Release contract",
    r"(?im)^#+\s*.*Out of scope",
    r"(?im)^#+\s*.*Test strategy",
    r"(?im)vendor-wrapped",          # not-migratable class named
    r"(?im)EF_KEY_DEV_ENC",          # evidence anchor
    r"(?im)NEEDS_PASSPHRASE",        # conditional class named
]

FEAS_SECTIONS = [
    # C FS byte format
    r"(?im)^#+\s*.*C (flash )?(file|FS).*format|C flash FS",
    r"(?im)0xEFEFEFEF|0xefefefef",   # factory sentinels
    r"(?im)FLASH_FILE_EXTENDED_LENGTH|0xFFFF.*u32|extended",
    r"(?im)end_data_pool",
    r"(?im)flash\.c:42",
    r"(?im)file\.c:327",
    # PKOR / PKOC layouts
    r"(?im)PKOC",
    r"(?im)PKOR",
    r"(?im)PKRI",
    r"(?im)0x46325350|0x4632_5350",
    r"(?im)record_id u64",
    r"(?im)PKOC/manifest/v1",
    r"(?im)PKOC/object/v1",
    r"(?im)PKOC/domain/v1",
    r"(?im)AUTHENTICATED_PUBLIC",
    # key derivation + OTP
    r"(?im)HKDF",
    r"(?im)DEVICE/ROOT",
    r"(?im)0xE90",
    r"(?im)pico_serial_hash",
    r"(?im)otp_rp2350\.c:33",
    r"(?im)crypto_utils\.c:34",
    r"(?im)serial\.c:250",
    # keydev formats
    r"(?im)EF_KEY_DEV",
    r"(?im)0xCC00",
    r"(?im)0xCC01",
    r"(?im)61.?B|61-byte",
    r"(?im)AES-256-CBC",
    # per-class FID tables
    r"(?im)0xBA00",
    r"(?im)0xBB00",
    r"(?im)0x10D1|0x10d1",
    r"(?im)0x1099",
    r"(?im)0x1122",
    r"(?im)0xCF00",
    # C data partition
    r"(?im)0x102000",
    r"(?im)3064",
    r"(?im)0xffffded3",
    r"(?im)pt\.json",
    r"(?im)rom_load_partition_table",
    # Rust re-seed targets
    r"(?im)0x103F0000|0x103f0000",
    r"(?im)0x103F3000|0x103f3000",
    r"(?im)fido\.hkey",
    r"(?im)fido\.keystore\.v1",
    r"(?im)piv\.keystore\.v1",
    r"(?im)EF_DEV_CONF",
    # verdicts (each class labelled explicitly)
    r"(?im)[Ss]ilent",
    r"(?im)[Cc]onditional",
    r"(?im)[Nn]ot.?migratable",
    r"(?im)NEVERBOOTC|NeverBootC",
    r"(?im)NEEDS_PASSPHRASE",
]


def check(path, patterns, what):
    errors = []
    if not os.path.exists(path):
        return [f"{what}: MISSING file {path}"]
    with open(path, encoding="utf-8") as f:
        text = f.read()
    for pat in patterns:
        if not re.search(pat, text):
            errors.append(f"{what}: required pattern absent: {pat}")
    return errors


def main():
    errors = []
    errors += check(EPIC, EPIC_SECTIONS, "epic")
    errors += check(FEAS, FEAS_SECTIONS, "feasibility")
    if errors:
        print("check_us413_feasibility: FAIL")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("check_us413_feasibility: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
