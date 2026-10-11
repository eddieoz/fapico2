#!/usr/bin/env python3
"""GPIO25 LED polarity gate (US-1303).

The hardware fact, and the only source for it
--------------------------------------------

**The Pico 2's board LED on GPIO25 is active-HIGH: driving the pin high lights
the LED, driving it low puts it out.**

The oracle is the C reference implementation, not a guess and not a reading of
this repository. `pico-fido/pico-keys-sdk/src/led/led_pico.c:50` writes

    gpio_put(gpio, progress >= 0.5);

to express "on", with no `PICO_DEFAULT_LED_PIN_INVERTED` defined for a stock
Pico 2 — so the level it writes for "on" is the level that lights the LED. The
same SDK drives the pin high for a solid "on" and low for "off" at its other
call sites.

Against that fact, twelve sites in this tree claimed the opposite and, in four
of them, *behaved* accordingly. A human standing at a board could therefore not
tell a healthy boot from a frozen one, because "solid LED" meant "on" in the
comments and "off" in the hardware.

What this gate checks, and what it deliberately does not
------------------------------------------------------

It fails when any **LED** site in `firmware/` or `platform/` carries an
`active-low` claim, because no such claim can be true on this board.

It is a comment-claim gate, not a driver gate. Pin behaviour is verified on
hardware and recorded in US-1303; what a source scan *can* prove cheaply and
permanently is that nobody re-asserts a polarity the hardware does not have.
Re-inverting a driver is caught by the hardware run, re-writing the claim is
caught here.

Scope exclusion — by path, not by pattern
----------------------------------------

`firmware/src/button.rs:80` says of the BOOTSEL button:

    /// Poll the board BOOTSEL button (active low) and latch press edges.

That claim is **correct**. The Pico 2 wires BOOTSEL to the QSPI chip-select
line, which is pulled up and pulled low by the button — genuinely active-low,
and nothing to do with the LED. It is excluded by **path plus subject**, not
by a pattern, for two reasons:

  * a bare `active.low` pattern would also hide a *new, wrong* claim written
    into `button.rs` itself, which is precisely where one is most likely to be
    copied from the two correct lines that remain in the same file;
  * a path-wide exemption for `button.rs` would be a bigger hole than the
    defect. The file also owns the touch-prompt LED, whose `active-low` claims
    are wrong, so exempting it wholesale would silence two of the twelve.

So the exclusion is a `(path, subject)` pair below: the BOOTSEL **button** in
that one file. Everything else in `button.rs` — including its LED claims — is
in scope, and the gate reports those.

Exit status: 0 when no LED site claims `active-low` (green), 1 otherwise
(red, with a per-site report naming the file and line).

Usage:
    python3 tests/scripts/check_led_polarity.py [scan-root-dir]

``scan-root-dir`` defaults to the repository root (the parent of `tests/`).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ROOT = REPO_ROOT

# The claim under gate. Case-insensitive because the sites disagree on case —
# `device.rs:581` writes "Active-low" while its neighbours write "active-low",
# and a case-sensitive scan would have reported six hits instead of twelve and
# quietly left six sites behind.
ACTIVE_LOW = re.compile(r"active[\s\-_]*low", re.IGNORECASE)

# A line is only in scope if it is about the LED. Without this, a legitimate
# `active-low` claim about any other pin added later would trip the gate and
# the first response would be to widen the exemption — which is how a gate
# rots. The LED vocabulary on this tree: GPIO25 / PIN_25 / LED_PIN, and the
# `led` binding every write site uses.
LED_CONTEXT = re.compile(r"\bled\b|LED_PIN|PIN_25|GPIO\s*25", re.IGNORECASE)

# (path, subject) pairs whose `active-low` claim is TRUE and must not be
# reported. See "Scope exclusion" in the module doc for why this is keyed on
# the path *and* a subject rather than on a pattern or the whole file.
ALLOWED: dict[str, str] = {
    "firmware/src/button.rs": "bootsel",
}

# Scanned roots, relative to the repo root. Only Rust sources: the C SDK that
# serves as the oracle is a vendored external tree, not this project.
SCAN_DIRS = ("firmware/src", "platform/src")


def _allowed(rel_path: str, line: str) -> bool:
    """True when this `active-low` claim is the allowlisted, correct one."""
    subject = ALLOWED.get(rel_path)
    return subject is not None and subject in line.lower()


def find_violations(root: Path) -> list[tuple[str, int, str]]:
    """`[(relative path, line number, line)]` for every in-scope claim."""
    hits: list[tuple[str, int, str]] = []
    for scan in SCAN_DIRS:
        base = root / scan
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.rs")):
            rel = path.relative_to(root).as_posix()
            for number, line in enumerate(
                path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
            ):
                if not ACTIVE_LOW.search(line):
                    continue
                if not LED_CONTEXT.search(line):
                    continue  # not about the LED — another pin, out of scope
                if _allowed(rel, line):
                    continue
                hits.append((rel, number, line.strip()))
    return hits


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else DEFAULT_ROOT
    print(f"LED polarity gate (US-1303) — GPIO25 on the Pico 2 is ACTIVE-HIGH.")
    print(f"Citation: pico-fido/pico-keys-sdk/src/led/led_pico.c:50 — "
          f"gpio_put(gpio, progress >= 0.5) with no PICO_DEFAULT_LED_PIN_INVERTED.")
    print(f"Scanning {', '.join(SCAN_DIRS)} under {root}")

    hits = find_violations(root)
    if not hits:
        print("OK: no LED site claims active-low.")
        return 0

    print()
    print(f"FAIL: {len(hits)} LED site(s) claim the LED is active-low.")
    print("The Pico 2's GPIO25 LED is active-high. A wrong claim here does not")
    print("just mislead a reader — at these sites it inverts the behaviour, so")
    print("'LED on' and 'LED off' mean the opposite of what the code intends.")
    print()
    for rel, number, line in hits:
        print(f"  {rel}:{number}: {line}")
    print()
    print("Fix: correct the claim AND the level it justifies (US-1305).")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
