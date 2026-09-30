#!/usr/bin/env python3
"""One-persist-implementation name gate for SECURE-PERSIST (US-429).

Host-only, stdlib only (no third-party imports). TDD red/green script for
the "one persist implementation" invariant (plan Global Constraint #3):

    the snapshot/program sequence that durably writes the secure-partition
    image lives ONCE in ``platform/src/persist.rs`` (+ its sink in
    ``persist_sink.rs``). No transport may re-implement it. The three
    historical names below were the pre-split per-transport implementations
    that Phase B deleted:

        snapshot_secure_partition  — device snapshot helper (deleted)
        persist_secure_partition   — transport-sequenced persist (deleted)
        persist_partition_image    — the pre-US-422 image writer (deleted)

If any of these names reappears in *code* anywhere in the tree (a new
manual snapshot/program path), the gate trips. The two platform files are
the only place the names may appear (they document the one implementation).

Comment-aware (mandatory, Phase B N2): Rust line comments (``//``, ``///``,
``//!``) and block comments (``/* */``, nestable) are stripped BEFORE
matching, because doc comments in ``firmware/src/emul_main.rs`` (the
``FileImageSink`` doc) and ``firmware/src/main.rs`` name the deleted
functions while explaining the design. A comment-only mention is legal; a
code-level occurrence is not.

String-literal caveat (documented limitation): the state machine tracks
ordinary string literals (``"..."`` with ``\\`` escapes) so a ``//`` inside
a string (e.g. a URL) is not mistaken for a line comment, and drops the
string *contents* so a name inside a string literal is not treated as code.
It does NOT fully model raw string literals (``r#"..."#``) or char literals;
a forbidden identifier inside such a literal is a documented false-positive
caveat and does not occur in this tree.

Exit status: 0 when no code-level occurrence is found (green), 1 otherwise
(red, with a per-file report). Same output shape as ``check_debug_strip.py``.

Usage:
    python3 tests/scripts/check_persist_gate.py [scan-root-dir]

``scan-root-dir`` defaults to the repository root (the parent of the
``tests/`` directory). The ``.git``/``target``/venv cruft dirs are skipped.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

# tests/scripts/check_persist_gate.py -> parents[2] == fapico2/
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ROOT = REPO_ROOT

# The pre-split per-transport persist implementations Phase B deleted.
# Word-bounded so a longer identifier (e.g. `snapshot_secure_partition_v2`)
# does not trip; the three names above do.
PERSIST_SYMBOLS = re.compile(
    r"\b(snapshot_secure_partition|persist_secure_partition|persist_partition_image)\b"
)

# Directories that never hold hand-written Rust source.
SKIP_DIRS = {".git", "target", ".test-venv", ".serena", "node_modules", ".cargo"}

# The only files where the names may appear (the one persist implementation).
_ALLOWED_TAILS = (
    ("platform", "src", "persist.rs"),
    ("platform", "src", "persist_sink.rs"),
)


def _is_allowed(path: Path) -> bool:
    parts = path.parts
    for tail in _ALLOWED_TAILS:
        if parts[-len(tail):] == tail:
            return True
    return False


def strip_comments(src: str) -> str:
    """Strip Rust line and block comments (and ordinary string contents).

    Line numbers are preserved for all ordinary comments and strings:
    every newline outside a line comment is re-emitted, and ordinary
    string literals cannot span newlines, so ``splitlines()`` on the result
    aligns with the original line numbers. Block-comment nesting (a Rust
    extension) is tracked.

    Limitation: raw string literals (``r#"..."#``) are not stripped — a
    multi-line raw string's inner newlines would be dropped, desynchronizing
    the line numbering. No ``.rs`` file in this tree uses raw strings, so
    PASS/FAIL behavior is unaffected.
    """
    out: list[str] = []
    i = 0
    n = len(src)
    in_line = False
    in_block = 0  # block-comment nesting depth
    in_string = False
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if in_line:
            if c == "\n":
                in_line = False
                out.append(c)
            i += 1
            continue
        if in_block:
            if c == "/" and nxt == "*":
                in_block += 1
                i += 2
                continue
            if c == "*" and nxt == "/":
                in_block -= 1
                i += 2
                continue
            if c == "\n":
                out.append(c)  # preserve line numbering across multi-line blocks
            i += 1
            continue
        if in_string:
            # Drop the string body; a name inside a literal is not code.
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            i += 1
            continue
        if c == "/" and nxt == "/":
            in_line = True
            i += 2
            continue
        if c == "/" and nxt == "*":
            in_block = 1
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _rs_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(".rs"):
                yield Path(dirpath) / name


def scan_file(path: Path) -> list[tuple[int, str]]:
    """Return (lineno, name) for each code-level occurrence in one file."""
    text = path.read_text(encoding="utf-8")
    code = strip_comments(text)
    hits: list[tuple[int, str]] = []
    for lineno, line in enumerate(code.splitlines(), 1):
        m = PERSIST_SYMBOLS.search(line)
        if m:
            hits.append((lineno, m.group(1)))
    return hits


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else DEFAULT_ROOT
    print(f"scanning: {root}")
    if not root.is_dir():
        print("RESULT: FAIL (scan root missing)")
        return 1

    offenders: list[tuple[Path, int, str]] = []
    scanned = 0
    for path in sorted(_rs_files(root)):
        if _is_allowed(path):
            continue
        scanned += 1
        for lineno, sym in scan_file(path):
            offenders.append((path, lineno, sym))

    print(f"  scanned {scanned} .rs file(s) under {root}")
    for path, lineno, sym in offenders:
        try:
            rel = path.relative_to(REPO_ROOT)
        except ValueError:
            rel = path
        print(f"  [FAIL] {rel}:{lineno}: {sym}")
    if offenders:
        n = len(offenders)
        print(
            f"\nRESULT: FAIL ({n} code-level persist-symbol occurrence(s) — "
            "a transport re-sequenced persistence; use platform/src/persist.rs)"
        )
        return 1
    print("  [PASS] no code-level snapshot_/persist_secure_partition/persist_partition_image")
    print("\nRESULT: PASS (one-persist-implementation gate green)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
