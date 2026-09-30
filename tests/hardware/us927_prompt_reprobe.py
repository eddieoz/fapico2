#!/usr/bin/env python3
"""US-927 — CCID touch-prompt visibility re-probe (operator-cued).

Re-probe for e2e-review finding 4 (hardware, 2026-09-24): the CCID touch
prompt was invisible — `window_grant` asserted the LED once at window open
and the heartbeat task + trussed Processing->Idle bracketing stomped it
within tens of ms. Fix under test: commit `a4217de` — the button task's
10 ms tick (`poll_press`) re-asserts the prompt while a presence request
is pending, so the window is signaled by a clearly faster blink (the
boot-pace cue model — idle LED never dark; pace change, not solid ON;
operator decision 2026-09-25, live-verified).

Flash `firmware/fapico2.uf2` (sha256 785b9bd0..., image >= a4217de) via
BOOTSEL MSC before running. The operator's eyes are the instrument: each
case asks you to compare the LED against the ~1 Hz idle heartbeat.

Cases:
  P1-wc-refused    refused mgmt WRITE_CONFIG -> prompt fast-blinks
                   distinctly through the whole 15 s window; heartbeat
                   cadence returns after expiry.
  P2-reset-refused refused mgmt RESET       -> same observation.
  P3-grant-clears  (optional) granted mgmt RESET -> prompt clears promptly
                   on the grant (destructive: wipes the device state).

Run: python3 tests/hardware/us927_prompt_reprobe.py [--filter P1-wc-refused] [--yes]
"""

import argparse
import sys
import time

from smartcard.System import readers

RESULTS = []

MGMT_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17]
INS_WRITE_CONFIG = 0x1C
INS_RESET = 0x1E
# The CCID consent window (`CCID_WINDOW_MS` in firmware/src/presence.rs):
# the refusal lands at 6985 with the window OPEN; it expires lazily.
WINDOW_S = 15


def apdu(con, b):
    data, sw1, sw2 = con.transmit(b)
    while sw1 == 0x61:
        r2 = con.transmit([0x00, 0xC0, 0x00, 0x00, min(0xFF, sw2)])
        data += r2[0]
        sw1, sw2 = r2[1], r2[2]
    return sw1 << 8 | sw2, bytes(data)


def mgmt_con():
    for r in readers():
        try:
            con = r.createConnection()
            con.connect()
        except Exception:
            continue
        sw, _ = apdu(con, [0x00, 0xA4, 0x04, 0x00, len(MGMT_AID)] + MGMT_AID)
        if sw == 0x9000:
            return con
        con.disconnect()
    raise SystemExit("no reader exposing the management AID")


def record(case, pass_, detail):
    RESULTS.append((case, "PASS" if pass_ else "FAIL", detail))
    print(f"  -> {'PASS' if pass_ else 'FAIL'}: {detail}\n")
    return pass_


def prompt(msg, yes):
    if not yes:
        input(f"\n>>> {msg}  [Enter when ready] ")


def ask(msg, yes):
    if yes:
        print(f"(auto-yes) {msg}")
        return True
    return input(f">>> {msg} [y/N] ").strip().lower() == "y"


def refused_case(con, case, ins, data, yes):
    """Refused destructive command: 6985 with the window open; the operator
    watches the LED fast-blink (pace change) through the window,
    heartbeat after."""
    prompt(f"{case}: watch the idle LED (~1 Hz heartbeat) now", yes)
    sw, _ = apdu(con, [0x00, ins, 0x00, 0x00] + data)
    if not record(f"{case}/sw", sw == 0x6985, f"first attempt SW={sw:04X} (expect 6985, window open)"):
        return
    ok = ask("during the WHOLE 15 s window: LED fast-blinking (pace change)?", yes)
    record(f"{case}/prompt-visible", ok, "operator: prompt fast-blink through the window")
    time.sleep(WINDOW_S + 2)
    ok = ask("window expired: heartbeat (~1 Hz blink) returned?", yes)
    record(f"{case}/expiry-restores", ok, "operator: heartbeat cadence back after expiry")


def granted_case(con, yes):
    """Granted mgmt RESET: the prompt clears promptly on the grant (destructive)."""
    prompt("P3-grant-clears: send mgmt RESET and PRESS the board when the "
           "LED lights (destructive: wipes device state)", yes)
    sw, _ = apdu(con, [0x00, INS_RESET, 0x00, 0x00])
    if not record("P3-grant-clears/sw", sw == 0x6985, f"first attempt SW={sw:04X} (window open)"):
        return
    print("    press the board NOW (window is open)")
    time.sleep(2)
    sw, _ = apdu(con, [0x00, INS_RESET, 0x00, 0x00])
    if not record("P3-grant-clears/granted", sw == 0x9000, f"retry SW={sw:04X} (press within window)"):
        return
    ok = ask("did the LED clear promptly on the grant (9000)?", yes)
    record("P3-grant-clears/clears", ok, "operator: prompt cleared on grant")


def report():
    print("\n=== US-927 CCID touch-prompt re-probe results ===")
    print("| Case | Result | Detail |")
    print("|---|---|---|")
    for case, res, detail in RESULTS:
        print(f"| {case} | {res} | {detail} |")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--filter", default="")
    ap.add_argument("--yes", action="store_true", help="no interactive pacing")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list:
        print(__doc__)
        return
    run = {c.strip() for c in args.filter.split(",") if c.strip()} or None

    def want(case):
        return run is None or case in run

    con = mgmt_con()
    if want("P1-wc-refused"):
        refused_case(con, "P1-wc-refused", INS_WRITE_CONFIG, [0x02, 0x01, 0x00], args.yes)
    if want("P2-reset-refused"):
        refused_case(con, "P2-reset-refused", INS_RESET, [], args.yes)
    if want("P3-grant-clears"):
        granted_case(con, args.yes)
    con.disconnect()
    report()


if __name__ == "__main__":
    sys.exit(main())
