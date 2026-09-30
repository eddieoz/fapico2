#!/usr/bin/env python3
"""Debug-machinery strip gate for S-391-13 (EPIC-fapico2-phase6-acceptance-migration).

Host-only, stdlib only (no third-party imports). TDD red/green script for
S-391-13 ("E8 — strip bring-up debug machinery"):

  red   = bisect/bring-up scaffolding symbols are still present in the
          device sources
  green = the shipping tree is free of them, so the flashed image matches
          a clean tree

It scans every Rust source under `firmware/src/` (the device crate,
including `firmware/src/bin/`) for the bring-up debug machinery that the
boot-ladder bisect introduced and S-391-13 strips:

    fapico2_reset  — the global-asm replacement reset handler (post-link
                     VT[1] patch target; E2/E2b discriminator)
    clean_slate    — the bootrom-residue clean-slate backstop
    dbg_blink      — the busy-wait boot-marker blinker (+ its stage gates)

Bring-up binaries that legitimately stay (bringup.rs, hwtest.rs, bridge.rs)
do not use these symbols, so a plain scan is enough — no allowlist.

Exit status: 0 when no symbol is found (green), 1 otherwise (red, with a
per-file report).

Usage:
    python3 tests/scripts/check_debug_strip.py [firmware/src/dir]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# fapico2/tests/scripts/check_debug_strip.py -> parents[2] == fapico2/
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SRC = REPO_ROOT / "firmware" / "src"

# The bisect scaffolding S-391-13 removes. Word-bounded so e.g. a comment
# mentioning "reset vector" doesn't trip; `dbg_blink` matches its call
# sites and the definition alike.
DEBUG_SYMBOLS = re.compile(r"\b(fapico2_reset|clean_slate|dbg_blink)\b")


def main(argv: list[str]) -> int:
    src = Path(argv[1]) if len(argv) > 1 else DEFAULT_SRC
    print(f"scanning: {src}\n")
    if not src.is_dir():
        print("RESULT: FAIL (source dir missing)")
        return 1

    offenders: list[tuple[Path, int, str]] = []
    scanned = 0
    for path in sorted(src.rglob("*.rs")):
        scanned += 1
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            m = DEBUG_SYMBOLS.search(line)
            if m:
                offenders.append((path, lineno, m.group(1)))

    print(f"  scanned {scanned} .rs file(s) under {src}")
    for path, lineno, sym in offenders:
        print(f"  [FAIL] {path.relative_to(REPO_ROOT)}:{lineno}: {sym}")
    if offenders:
        n = len(offenders)
        print(f"\nRESULT: FAIL ({n} debug-machinery occurrence(s) — strip not complete)")
        return 1
    print("  [PASS] no fapico2_reset / clean_slate / dbg_blink in device sources")
    print("\nRESULT: PASS (debug strip gate green)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
