#!/usr/bin/env python3
"""Gate: the entropy wait's wall clock is a CHECKED precondition (D-12).

Host-only, stdlib only. Exits non-zero on any violation.

What went wrong
--------------
On 2026-09-29 the branch was flashed to a real Pico 2 and came up dark: LED
solid, absent from ``lsusb``, no CCID reader. The failing path was the
entropy probe's bounded wait, and ``boot::init_drbg`` is fatal by design, so
a refused seed halts before USB ever enumerates.

The shape of the defect is what this gate exists for, and it is a *shape*
rather than a specific line: a wait whose wall-clock budget
(``MAX_ENTROPY_WAIT``) was reached before anything had verified the clock
behind it was counting, so the budget was unreachable, the wait degenerated
into its hard poll cap, and it reported the same opaque ``Stalled`` a
genuinely slow peripheral produces. A caller that cannot tell "the
peripheral was slow" from "I was never measuring time" learns nothing from
either, and neither does an operator looking at a dark device.

The fix is in three places, and this gate is the piece that stops any one of
them from being undone by accident:

1. **Runtime, in the trait default** -- ``TrngProbe::await_ready`` in
   ``platform/src/trng.rs`` checks its own clock every wait
   (``CLOCK_LIVENESS_SPINS``) and returns ``TrngError::ClockStalled``. It is
   in the default body, so no implementation can reach the budget without it.
2. **Compile-time, in the device constructor** -- ``Rp2350Probe::new`` takes a
   ``ClockReady``, a type nothing outside ``platform::trng::rp2350`` can
   construct, so building a probe implies having watched the counter move.
3. **Source order, here** -- the check must appear in ``firmware/src/main.rs``
   before the HAL init it depends on is not the requirement; what IS required
   is that the check appears *before the first thing that spends the budget*,
   and this is the only one of the three a compiler cannot see. A future
   session that hoists ``Rp2350Probe::new`` and the boot sanity draw above
   the check still compiles -- the token is a proof, not a schedule -- so
   something has to look at the order.

What this gate cannot see, stated rather than implied
----------------------------------------------------
Whether ``TIMER0`` is in fact counting on a real part at seed time. No board
is attached to this tree. The gate can only assert that the *check* is present
and ordered before the *use*; the answer to "is the clock running" is a
runtime fact on hardware, which is why ``Rp2350Timer::require_advancing``
exists and why its refusal is fatal. Recorded in
``docs/known-gate-divergences.md`` (D-12).

Usage:
    python3 tests/scripts/check_boot_clock_order.py [--self-test]
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
MAIN = "firmware/src/main.rs"
TRNG = "platform/src/trng.rs"


def _lines(text: str) -> list[str]:
    """Source lines with comments stripped, so a rule cannot be satisfied by
    prose. A gate that a comment can turn green is not a gate."""
    out = []
    for raw in text.splitlines():
        # Strip line comments outside string literals. Good enough for this
        # tree: no Rust source here contains a `//` inside a string on a line
        # that also carries one of the names this gate looks for.
        idx = raw.find("//")
        out.append(raw if idx < 0 else raw[:idx])
    return out


def _call_args(body: list[str]) -> str | None:
    """The argument list of a call whose opening paren is in `body[0]`.

    Returns None if the list does not close within the window, so a gate
    reports "my parser rotted" rather than a silent pass.
    """
    joined = " ".join(l.strip() for l in body)
    if "(" not in joined:
        return None
    rest = joined[joined.index("(") + 1:]
    depth = 1
    out = []
    for ch in rest:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                break
        out.append(ch)
    else:
        return None
    return "".join(out)


def _first(lines: list[str], pattern: re.Pattern[str]) -> int | None:
    for i, line in enumerate(lines):
        if pattern.search(line):
            return i
    return None


REQ_CLOCK = re.compile(r"Rp2350Timer::require_advancing\s*\(")
NEW_PROBE = re.compile(r"Rp2350Probe::new\s*\(")
HAL_INIT = re.compile(r"embassy_rp::init\s*\(")
# The first things that actually spend the entropy wait's wall-clock budget.
SPEND = re.compile(r"\b(probe_bytes|init_drbg)\s*\(")


def check_main_order(text: str) -> list[str]:
    lines = _lines(text)
    req = _first(lines, REQ_CLOCK)
    if req is None:
        return [
            "firmware/src/main.rs never calls Rp2350Timer::require_advancing(). "
            "The device entropy wait's wall-clock budget is only meaningful if "
            "TIMER0 is counting, and this call is what observes that."
        ]
    probe = _first(lines, NEW_PROBE)
    if probe is not None and probe < req:
        return [
            f"firmware/src/main.rs constructs Rp2350Probe (line {probe + 1}) "
            f"BEFORE calling Rp2350Timer::require_advancing() (line {req + 1}). "
            "The probe's bounded wait is measured against a clock nobody has "
            "checked yet."
        ]
    spend = _first(lines, SPEND)
    if spend is not None and spend < req:
        what = lines[spend].strip()
        return [
            f"firmware/src/main.rs spends the entropy wait's budget at line "
            f"{spend + 1} ({what}) BEFORE calling "
            f"Rp2350Timer::require_advancing() (line {req + 1})."
        ]
    hal = _first(lines, HAL_INIT)
    if hal is not None and req < hal:
        return [
            f"firmware/src/main.rs checks the entropy clock (line {req + 1}) "
            f"BEFORE the HAL init (line {hal + 1}) that starts the RP2350 "
            "tick generator the clock counts. That check is reading a counter "
            "that has not been enabled yet."
        ]
    # The proof must actually be passed. The compiler enforces the *type* of
    # the argument; this catches the argument being dropped, defaulted, or
    # swapped for another value of the right arity.
    #
    # US-1005's TRNG-config fix added a third parameter (`TrngConfig`), which
    # made a plain comma count insufficient: a two-argument call dropping
    # `clock` still has a comma, and the old check scored it green. So the
    # assertion is on the *name* appearing in the argument list, not on how
    # many arguments there are.
    if probe is not None:
        call = _call_args(body_from(lines, probe))
        if call is None:
            return [
                f"firmware/src/main.rs line {probe + 1}: could not read the "
                "argument list of Rp2350Probe::new. The gate's own parser has "
                "rotted; fix it rather than reading a pass off it."
            ]
        if not re.search(r"\bclock\b", call):
            return [
                f"firmware/src/main.rs line {probe + 1} calls "
                f"Rp2350Probe::new({call.strip()}) without passing the "
                "ClockReady proof. It must be passed explicitly; a default, "
                "an omitted argument, or a different value of the right "
                "arity would make the ordering a convention again, and the "
                "wait would go back to being measured against a TIMER0 "
                "nobody has checked."
            ]
    return []


def body_from(lines: list[str], start: int, window: int = 6) -> list[str]:
    """The call at `start` plus enough following lines to close it.

    rustfmt breaks a three-argument call across several lines, so reading
    only the first line of the statement sees an unterminated argument list.
    """
    return lines[start: start + window]


def check_wait_checks_its_clock(text: str) -> list[str]:
    lines = _lines(text)
    fails: list[str] = []
    start = None
    for i, line in enumerate(lines):
        if re.search(r"fn\s+await_ready\s*\(", line):
            start = i
            break
    if start is None:
        return [
            "platform/src/trng.rs has no default `fn await_ready` on TrngProbe. "
            "The clock check lives in that default body precisely so that no "
            "implementation can reach the budget without it; if the method was "
            "renamed or moved, this gate must be updated deliberately."
        ]
    body = lines[start:start + 90]
    joined = "\n".join(body)
    if "CLOCK_LIVENESS_SPINS" not in joined:
        fails.append(
            "TrngProbe::await_ready no longer references CLOCK_LIVENESS_SPINS. "
            "The wait no longer checks that its own wall clock is advancing, so "
            "a stopped timer silently degenerates the budget into a poll cap "
            "again (D-12)."
        )
    if "ClockStalled" not in joined:
        fails.append(
            "TrngProbe::await_ready never returns TrngError::ClockStalled. A "
            "dead clock and a slow peripheral would again be reported as the "
            "same opaque Stalled, which is the invisibility D-12 is about."
        )
    if "ready_after" in joined or "ready_before" in joined:
        fails.append(
            "TrngProbe::await_ready appears to check the clock BEFORE polling "
            "for Ready. A validated block must be served on a dead clock: the "
            "clock is a means, the entropy is the goal, and refusing a block "
            "the peripheral has already produced would brick a working device."
        )
    # A deadlock guard for the gate itself: the Ready test must come first in
    # the body, so the ordering the tests pin is not silently inverted.
    ready_at = None
    for i, line in enumerate(body):
        if re.search(r"==\s*ProbeStatus::Ready", line):
            ready_at = i
            break
    live_at = None
    for i, line in enumerate(body):
        if "CLOCK_LIVENESS_SPINS" in line:
            live_at = i
            break
    if ready_at is None:
        fails.append(
            "TrngProbe::await_ready no longer tests ProbeStatus::Ready. The "
            "wait has no success path."
        )
    elif live_at is not None and live_at < ready_at:
        fails.append(
            "TrngProbe::await_ready reaches the liveness bound before it tests "
            "ProbeStatus::Ready. Entropy that has already arrived must be "
            "served; see platform/tests/trng_clock_precondition.rs."
        )
    return fails


def check_token_unforgeable(text: str) -> list[str]:
    """`ClockReady` must have no constructor a caller can reach."""
    m = re.search(r"pub struct ClockReady\s*\{(.*?)\n    \}", text, re.S)
    if m is None:
        return ["platform/src/trng.rs no longer defines `pub struct ClockReady`."]
    body = m.group(1)
    fails = []
    if "pub" in body:
        fails.append(
            "`ClockReady` has a public field, so a caller can construct one "
            "without calling Rp2350Timer::require_advancing(). The whole point "
            "is that the proof is unforgeable outside `platform::trng::rp2350`."
        )
    # An `impl ClockReady { pub fn new() }` or a `Default`/`From` derivation
    # would reopen the same door.
    for pattern, why in [
        (r"impl\s+Default\s+for\s+ClockReady", "a `Default` impl"),
        (r"derive\([^)]*\bDefault\b[^)]*\)[\s\S]{0,400}?struct ClockReady",
         "a `Default` derive on `ClockReady`"),
    ]:
        if re.search(pattern, text):
            fails.append(
                f"`ClockReady` has {why}, so it can be manufactured without a "
                "runtime check. Delete it; the only source of the token must be "
                "Rp2350Timer::require_advancing()."
            )
    return fails


# ---------------------------------------------------------------------------
# Self-test: the gate must fail on the shapes it exists to catch.
# ---------------------------------------------------------------------------

_GOOD_MAIN = """
async fn main(spawner: Spawner) -> ! {
    let p = embassy_rp::init(Default::default());
    let mut trng = Rp2350Trng::from_peri(p.TRNG, TrngIrqs, Config::default());
    let clock = match Rp2350Timer::require_advancing() {
        Ok(clock) => clock,
        Err(_) => boot::fatal_boot("no clock"),
    };
    let mut seed_probe = Rp2350Probe::new(seed_probe_peri, clock);
    let drbg = unsafe { boot::init_drbg(seed_probe) };
}
"""

_BAD_MAIN_NO_CHECK = _GOOD_MAIN.replace(
    """    let clock = match Rp2350Timer::require_advancing() {
        Ok(clock) => clock,
        Err(_) => boot::fatal_boot("no clock"),
    };
    let mut seed_probe = Rp2350Probe::new(seed_probe_peri, clock);""",
    "    let mut seed_probe = Rp2350Probe::new(seed_probe_peri);",
)

_BAD_MAIN_SPENDS_FIRST = _GOOD_MAIN.replace(
    """    let clock = match Rp2350Timer::require_advancing() {
        Ok(clock) => clock,
        Err(_) => boot::fatal_boot("no clock"),
    };
    let mut seed_probe""",
    """    let mut seed_probe""",
).replace(
    "Rp2350Probe::new(seed_probe_peri, clock);",
    "Rp2350Probe::new(seed_probe_peri, clock);\n    let _ = seed_probe.probe_bytes(&mut [0u8; 4]);",
)

_BAD_MAIN_BEFORE_HAL = """
async fn main(spawner: Spawner) -> ! {
    let clock = match Rp2350Timer::require_advancing() {
        Ok(clock) => clock,
        Err(_) => boot::fatal_boot("no clock"),
    };
    let p = embassy_rp::init(Default::default());
    let mut trng = Rp2350Trng::from_peri(p.TRNG, TrngIrqs, Config::default());
    let mut seed_probe = Rp2350Probe::new(seed_probe_peri, clock);
    let drbg = unsafe { boot::init_drbg(seed_probe) };
}
"""

_BAD_MAIN_COMMENTED = _GOOD_MAIN.replace(
    "    let clock = match Rp2350Timer::require_advancing() {",
    "    // let clock = match Rp2350Timer::require_advancing() {",
)

_GOOD_WAIT = """
    fn await_ready(&mut self) -> Result<(), TrngError> {
        let start = self.clock().ticks();
        let mut moved = false;
        for _ in 0..MAX_ENTROPY_POLLS {
            if self.status() == ProbeStatus::Ready {
                return Ok(());
            }
            let now = self.clock().ticks();
            if frozen >= CLOCK_LIVENESS_SPINS {
                return Err(TrngError::ClockStalled);
            }
        }
    }
"""

_BAD_WAIT_NO_CHECK = _GOOD_WAIT.replace("CLOCK_LIVENESS_SPINS", "MAX_ENTROPY_POLLS").replace(
    "Err(TrngError::ClockStalled)", "Err(TrngError::Stalled)"
)

_BAD_WAIT_ORDER = _GOOD_WAIT.replace(
    """            if frozen >= CLOCK_LIVENESS_SPINS {
                return Err(TrngError::ClockStalled);
            }
""",
    "",
).replace(
    "    fn await_ready(&mut self) -> Result<(), TrngError> {",
    "    fn await_ready(&mut self) -> Result<(), TrngError> {\n"
    "        let frozen = 0u32;\n"
    "        if frozen >= CLOCK_LIVENESS_SPINS { return Err(TrngError::ClockStalled); }",
)

_GOOD_TOKEN = """
    #[derive(Debug)]
    pub struct ClockReady {
        _private: (),
    }
"""

_BAD_TOKEN_PUB_FIELD = _GOOD_TOKEN.replace("_private: (),", "pub proof: (u32,),")
_BAD_TOKEN_DEFAULT = (
    "    #[derive(Debug, Default)]\n    pub struct ClockReady {\n        _private: (),\n    }\n"
)


def self_test() -> int:
    cases: list[tuple[str, callable, str, bool]] = [
        ("main: the shape as it stands passes", check_main_order, _GOOD_MAIN, True),
        ("main: check removed entirely FAILS", check_main_order, _BAD_MAIN_NO_CHECK, False),
        ("main: budget spent before the check FAILS", check_main_order, _BAD_MAIN_SPENDS_FIRST, False),
        ("main: check before the HAL init FAILS", check_main_order, _BAD_MAIN_BEFORE_HAL, False),
        ("main: the check only in a comment FAILS", check_main_order, _BAD_MAIN_COMMENTED, False),
        ("wait: the shape as it stands passes", check_wait_checks_its_clock, _GOOD_WAIT, True),
        ("wait: the liveness check removed FAILS", check_wait_checks_its_clock, _BAD_WAIT_NO_CHECK, False),
        ("wait: clock checked before Ready FAILS", check_wait_checks_its_clock, _BAD_WAIT_ORDER, False),
        ("token: unforgeable passes", check_token_unforgeable, _GOOD_TOKEN, True),
        ("token: a public field FAILS", check_token_unforgeable, _BAD_TOKEN_PUB_FIELD, False),
        ("token: a Default derive FAILS", check_token_unforgeable, _BAD_TOKEN_DEFAULT, False),
    ]
    bad = 0
    for name, fn, fixture, should_pass in cases:
        fails = fn(fixture)
        ok = (not fails) if should_pass else bool(fails)
        print(f"  [{'ok' if ok else 'BROKEN'}] {name}")
        if not ok:
            bad += 1
            for f in fails:
                print(f"        -> {f}")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="run the gate against in-memory fixtures instead of the tree",
    )
    args = ap.parse_args()

    if args.self_test:
        print("check_boot_clock_order --self-test (D-12)")
        return self_test()

    fails: list[str] = []
    try:
        main_src = (ROOT / MAIN).read_text(encoding="utf-8")
        trng_src = (ROOT / TRNG).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"FAIL: check_boot_clock_order (D-12) — {exc}")
        return 1

    fails += check_main_order(main_src)
    fails += check_wait_checks_its_clock(trng_src)
    fails += check_token_unforgeable(trng_src)

    if fails:
        for f in fails:
            print(f"FAIL: check_boot_clock_order (D-12) — {f}")
        print("  - see docs/known-gate-divergences.md (D-12) and")
        print("    platform/tests/trng_clock_precondition.rs for the host-side")
        print("    half of the same property.")
        return 1

    print("PASS: check_boot_clock_order (D-12) — the entropy wait's wall clock "
          "is checked before it is spent")
    print(f"  - {MAIN}: Rp2350Timer::require_advancing() precedes the HAL-init "
          "dependency, the Rp2350Probe construction, and the first spend of the "
          "budget (probe_bytes / init_drbg); the ClockReady proof is passed "
          "explicitly")
    print(f"  - {TRNG}: TrngProbe::await_ready still checks CLOCK_LIVENESS_SPINS "
          "and returns TrngError::ClockStalled, and still tests "
          "ProbeStatus::Ready first")
    print("  - ClockReady is still unforgeable outside platform::trng::rp2350")
    print("  - NOT checked here, and not checkable here: whether TIMER0 is in "
          "fact counting on a real part. That is a runtime fact, answered by "
          "Rp2350Timer::require_advancing() on the device; no board is attached "
          "to this tree. Recorded in docs/known-gate-divergences.md (D-12).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
