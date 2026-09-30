#!/usr/bin/env python3
"""PicoForge-compatibility docs gate for US-164.

Host-only, stdlib only (no third-party imports), same shape as
``check_readme.py`` (the other docs gate) with ``check_attestation_gate.py``'s
"each violation names the fact and where it belongs" reporting.

Structural proof that ``README.md``'s *PicoForge compatibility* section still
records the **client-side** single-reader constraint:

    PicoForge takes the first PC/SC reader ``list_readers()`` returns and
    never iterates, filters by name, or falls back to a second reader. On a
    multi-reader host the SELECT lands on the wrong card, which answers
    6A82, and the client returns ``Err`` (a "Rescue Applet not found ...
    Is it in FIDO mode?" message) rather than ``None``.

Why a gate at all: the constraint is in the *client*, so no firmware change
can ever make it go away, and a README rewrite that drops the caveat strands
every multi-reader user with a misleading error and no way to tell it apart
from a device fault. The mitigation is likewise client-side, so the section is
the only place it can live.

The gate covers the three things the section is required to carry:

  1. the ``readers.next()`` behaviour plus the wrong-card / 6A82 / Err-not-None
     outcome, with the client ``file:line`` citations;
  2. the explicit "not fixable from the firmware" statement and the
     client-side mitigation;
  3. the ``libccid_Info.plist`` VID/PID cross-reference and the borrowed
     RS-Key AAGUID note (R-3).

The "not fixable from the firmware" statement is the load-bearing one: a
maintainer who assumes the opposite goes looking for a firmware knob that does
not exist, and the caveat is worthless without it.

Matching is on **substantive phrases and the client file:line citations**, not
on prose a reword would break — the message text, the surrounding sentence
structure and the path prefix (`picoforge/` or not) are all free to change. The
prose-shaped items are alternations of every wording the section legitimately
uses, so rewording to a synonym still passes while deletion still fails. A
minimum word count backstops the "kept the heading, hollowed out the body"
failure mode that per-fact checks alone would not catch.

Exit status: 0 when the section carries its substance (green), 1 otherwise
(red, one line per missing fact).

Usage:
    python3 tests/scripts/check_picoforge_compat_docs.py [readme-path]

``readme-path`` defaults to ``README.md`` at the repository root (the parent of
the ``tests/`` directory). Resolved from ``__file__``, never from the CWD, so
the gate says the same thing wherever it is invoked from.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# tests/scripts/check_picoforge_compat_docs.py -> parents[2] == fapico2/
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_README = REPO_ROOT / "README.md"

# The section heading the story asks for. Matched as a whole line so a
# subsection titled "... compatibility notes" cannot satisfy it.
HEADING = "## PicoForge compatibility"

# Fact -> (regexes that must ALL match the section, where the fact belongs).
#
# Every entry is a fact, not a sentence: the message text and the sentence
# shape around it are free to change, only the fact is pinned. The alternations
# cover each wording the section legitimately uses.
FACTS: tuple[tuple[str, tuple[re.Pattern, ...], str], ...] = (
    (
        "PicoForge's reader-next() behaviour — it takes the first reader "
        "list_readers() returns and never iterates, filters or falls back",
        (
            re.compile(r"list_readers\(\)"),
            re.compile(r"readers\.next\(\)|\*\*first\*\* reader|first reader", re.I),
            re.compile(r"never iterat|never filtering|never falls back", re.I),
        ),
        "the *PicoForge compatibility* section: the client takes "
        "readers.next() off list_readers() and never iterates or filters",
    ),
    (
        "the wrong-card mechanism — a foreign PC/SC reader enumerated first "
        "receives the SELECT",
        (
            re.compile(r"wrong card|wrong reader|different card|foreign (pc/sc )?reader", re.I),
            re.compile(r"enumerat", re.I),
        ),
        "the *PicoForge compatibility* section: on a multi-reader host the "
        "SELECT goes to the wrong card",
    ),
    (
        "the 6A82 answer and the Err-not-None outcome with its client citation",
        (
            re.compile(r"6A82"),
            re.compile(r"`?Err\b[^\n]*?\bNone\b", re.S),
            re.compile(r"pcsc\.rs:6\d-\d\d"),
        ),
        "the *PicoForge compatibility* section: the wrong card answers 6A82 "
        "and try_rescue() returns Err rather than None (pcsc.rs:66-71)",
    ),
    (
        "the per-slot LED amplification — four independent connects, one per "
        "LED slot, each re-running list_readers()",
        (
            re.compile(r"per\s+\*{0,2}LED slot\*{0,2}|one per LED slot", re.I),
            re.compile(r"io\.rs:199-205"),
        ),
        "the *PicoForge compatibility* section: write_led_config opens a "
        "fresh connection per LED slot (picoforge/src/hal/io.rs:199-205), so "
        "a half-written LED profile can report success",
    ),
    (
        "the client-side mitigation — keep the token as the host's only reader",
        (
            re.compile(r"only reader"),
            re.compile(r"client-side|client side|upstream", re.I),
        ),
        "the *PicoForge compatibility* section: keep the token as the only "
        "reader on the host, or report it upstream",
    ),
    (
        "the explicit 'not fixable from the firmware' statement",
        (re.compile(r"not fixable from the firmware", re.I),),
        "the *PicoForge compatibility* section: the constraint is "
        "client-side and NOT fixable from the firmware",
    ),
    (
        "the libccid_Info.plist VID/PID cross-reference, applying to any "
        "PC/SC application",
        (
            re.compile(r"libccid_Info\.plist"),
            re.compile(r"0xFA20", re.I),
            re.compile(r"0x0002", re.I),
            re.compile(r"#usb-identity-provisional"),
            re.compile(r"any\s+(pc/sc\s+)?(pc/sc\s+)?application", re.I),
        ),
        "the *PicoForge compatibility* section: cross-reference the "
        "#usb-identity-provisional Requirements text (0xFA20 / 0x0002 "
        "libccid_Info.plist allowlist) and say it binds any PC/SC application",
    ),
    (
        # Rewritten 2026-09-28, and the reason it is worth writing down: this
        # gate existed to stop the README dropping the *borrowed*-AAGUID note.
        # The borrow is now over — `DEFAULT_AAGUID` is fapico2's own — so the
        # fact it protected is false and keeping the requirement would mean
        # either shipping a lie or deleting the gate. The requirement follows
        # the truth instead: the AAGUID must still be named, the value still
        # pinned, and the consequence of the flip still stated, because *that*
        # consequence (an unclassifiable device until upstream catches up) is
        # the thing a reader of this section most needs and most easily misses.
        "the AAGUID identity note (R-3, and what replaced the borrow)",
        (
            re.compile(r"2479C7BF6B3056839EC80E8171A918B7", re.I),
            re.compile(r"DEFAULT_AAGUID|identity\.rs|identity block", re.I),
            re.compile(r"66617069|fapico2.s own|own AAGUID", re.I),
            re.compile(r"R-3|borrow", re.I),
        ),
        "the *PicoForge compatibility* section: fapico2's AAGUID, the fact that "
        "it is now its own rather than borrowed from RS-Key "
        "(2479C7BF6B3056839EC80E8171A918B7, reachable only as the documented "
        "build override), and that a default build stays unclassifiable by the "
        "app until upstream adds it (risk R-3)",
    ),
)

# Backstop for the "heading kept, body hollowed out" shape: a section that
# drops whole facts still satisfies any single alternation if the rewriter got
# lucky, and a bare pointer stub ("see the upstream client") is exactly the
# rewrite this gate exists to stop. Well under the ~300-word section.
MIN_WORDS = 150


def read_section(text: str) -> str | None:
    """Return the body of the *PicoForge compatibility* section, or None.

    The section runs from its heading to the next ``## `` heading (or EOF).
    Slicing the real section — not matching the whole file — is the point: the
    gate must not be satisfiable by the same phrases appearing somewhere else
    in the README, which is how a caveat rots while the words survive.
    """
    m = re.search(r"^" + re.escape(HEADING) + r"[ \t]*$", text, re.M)
    if not m:
        return None
    rest = text[m.end() :]
    nxt = re.search(r"^## ", rest, re.M)
    return rest[: nxt.start()] if nxt else rest


def check(text: str) -> list[str]:
    """Return one human-readable line per fact the section fails to carry."""
    section = read_section(text)
    if section is None:
        return [
            f"no '{HEADING}' section in README.md — the single-reader caveat "
            "must live in its own section; add it back under that heading"
        ]

    findings: list[str] = []
    for label, patterns, where in FACTS:
        missing = [p.pattern for p in patterns if not p.search(section)]
        if missing:
            findings.append(
                f"missing fact: {label}\n"
                f"    absent: {missing}\n"
                f"    belongs in: {where}"
            )
    return findings


def main(argv: list[str]) -> int:
    readme = Path(argv[1]) if len(argv) > 1 else DEFAULT_README
    if not readme.is_file():
        print(f"FAIL: check_picoforge_compat_docs (US-164) — {readme} missing")
        return 1

    text = readme.read_text(encoding="utf-8")
    findings = check(text)
    section = read_section(text) or ""
    words = len(section.split())

    if findings:
        print("FAIL: check_picoforge_compat_docs (US-164) — the README's "
              "PicoForge compatibility section lost its substance:")
        for f in findings:
            print(f"  - {f}")
        return 1

    if words < MIN_WORDS:
        print(
            f"FAIL: check_picoforge_compat_docs (US-164) — the section is only "
            f"{words} words (floor {MIN_WORDS}); a heading plus a pointer stub "
            f"is not the caveat. Restore the full text."
        )
        return 1

    print(
        f"PASS: check_picoforge_compat_docs (US-164) — {len(FACTS)} fact(s) "
        f"documented, section is {words} words"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
