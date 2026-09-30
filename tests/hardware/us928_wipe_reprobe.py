#!/usr/bin/env python3
"""US-928 — OpenPGP wipe end-state re-probe (operator-cued, destructive).

Re-probe for e2e-review finding 5 (hardware, 2026-09-24): the management
factory wipe covered the secure-store slots but not the trussed internal
filesystem, so the OpenPGP PW1 flag + retry counter SURVIVED the wipe and
the app ended locked (counter burned to 0, PW1 still set). Fix under test:
commit `e652e35` — `wipe_internal_fs()` formats + remounts the trussed
internal FS factory-fresh; a format failure aborts the RESET closed.

Flash `firmware/fapico2.uf2` (sha256 785b9bd0..., image >= e652e35) via
BOOTSEL MSC before running. You press the board once (the consent window)
and the script probes the OpenPGP end state through pcscd.

Acceptance (post-fix): after the wipe the OpenPGP app is FACTORY-FRESH —
PW1 unset (default `123456` verifies), full retry budget on `654321`
(pre-fix red state: counter burned to 0 / `63C0` and PW1 set), DOs wiped.

Cases:
  W0-pre-state   record the pre-wipe state (C4 DO + VERIFY verdicts).
  W1-reset       mgmt RESET: 6985 window -> press -> 9000.
  W2-pw1-fresh   PW1 unset (123456 -> 9000) and full budget on 654321
                 (two refusals with a fresh decreasing 63Cx).
  W3-dos-wiped   factory DO shapes (C5 keyless zeros, C7 absent).

Run: python3 tests/hardware/us928_wipe_reprobe.py [--yes]
"""

import argparse
import sys
import time

from smartcard.System import readers

RESULTS = []

MGMT_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17]
OPENPGP_AID = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
INS_RESET = 0x1E
PERSONALIZED_PIN = b"654321"
FACTORY_PIN = b"123456"


def apdu(con, b):
    data, sw1, sw2 = con.transmit(b)
    while sw1 == 0x61:
        r2 = con.transmit([0x00, 0xC0, 0x00, 0x00, min(0xFF, sw2)])
        data += r2[0]
        sw1, sw2 = r2[1], r2[2]
    return sw1 << 8 | sw2, bytes(data)


def select(con, aid):
    return apdu(con, [0x00, 0xA4, 0x04, 0x00, len(aid)] + aid)[0]


def first_reader():
    for r in readers():
        try:
            con = r.createConnection()
            con.connect()
            return con
        except Exception:
            continue
    raise SystemExit("no pcscd reader found")


def mgmt_app():
    con = first_reader()
    if select(con, MGMT_AID) != 0x9000:
        raise SystemExit("no reader exposing the management AID")
    return con


def pgp_app(con):
    con.disconnect()
    con = first_reader()
    if select(con, OPENPGP_AID) != 0x9000:
        raise SystemExit("no reader exposing the OpenPGP AID")
    return con


def record(case, pass_, detail):
    RESULTS.append((case, "PASS" if pass_ else "FAIL", detail))
    print(f"  -> {'PASS' if pass_ else 'FAIL'}: {detail}\n")
    return pass_


def prompt(msg, yes):
    if not yes:
        input(f"\n>>> {msg}  [Enter when ready] ")


def get_data(con, tag):
    # Same shape as the proven US-413 preflight probe (p7_d2_preflight.py).
    return apdu(con, [0x00, 0xCA, 0x00, tag, 0xFE])


def verify(con, pin):
    return apdu(con, [0x00, 0x20, 0x00, 0x81, len(pin)] + list(pin))[0]


def retry_of(sw):
    """The burned budget from a 63Cx refusal (0 = exhausted)."""
    return sw & 0xF if (sw & 0xFF00) == 0x6300 else None


def w0_pre_state(con, yes):
    prompt("W0-pre-state: record the board's pre-wipe OpenPGP state", yes)
    con = pgp_app(con)
    sw, c4 = get_data(con, 0xC4)
    record("W0/c4", sw == 0x9000, f"GET DATA C4 SW={sw:04X} bytes={c4.hex()}")
    sw = verify(con, PERSONALIZED_PIN)
    record("W0/pw1-personalized", (sw & 0xFF00) == 0x6300,
           f"VERIFY 654321 SW={sw:04X} (63Cx = set+budget {retry_of(sw)}; "
           "63C0-burned = the pre-fix red state)")
    con.disconnect()
    con = mgmt_app()
    return con


def w1_reset(con, yes):
    prompt("W1-reset: mgmt RESET — press the board when the LED lights "
           "(destructive: full factory wipe)", yes)
    sw, _ = apdu(con, [0x00, INS_RESET, 0x00, 0x00])
    if not record("W1/open", sw == 0x6985, f"first attempt SW={sw:04X} (window open)"):
        return False
    print("    PRESS the board NOW (consent window is open)")
    time.sleep(2)
    sw, _ = apdu(con, [0x00, INS_RESET, 0x00, 0x00])
    return record("W1/granted", sw == 0x9000, f"retry SW={sw:04X} (9000 = wipe executed)")


def w2_pw1_fresh(con, yes):
    con = pgp_app(con)
    sw = verify(con, FACTORY_PIN)
    record("W2/pw1-unset", sw == 0x9000,
           f"VERIFY 123456 SW={sw:04X} (9000 = factory default accepted, PW1 unset)")
    sw1 = verify(con, PERSONALIZED_PIN)
    sw2 = verify(con, PERSONALIZED_PIN)
    fresh = (sw1 & 0xFF00) == 0x6300 and (sw2 & 0xFF00) == 0x6300 and \
        retry_of(sw1) is not None and retry_of(sw2) == retry_of(sw1) - 1
    record("W2/budget-full", fresh,
           f"VERIFY 654321 twice: SW={sw1:04X} then {sw2:04X} "
           f"(fresh full budget walks down; pre-fix red: starts at 63C0)")
    con.disconnect()
    return mgmt_app()


def w3_dos_wiped(con, yes):
    con = pgp_app(con)
    sw, c5 = get_data(con, 0xC5)
    record("W3/c5-keyless", sw == 0x9000 and c5 == bytes(60),
           f"GET DATA C5 SW={sw:04X} len={len(c5)} (factory keyless: 60 zero bytes)")
    sw, _ = get_data(con, 0xC7)
    record("W3/c7-absent", sw == 0x6A88, f"GET DATA C7 SW={sw:04X} (6A88 = wiped)")
    con.disconnect()
    return mgmt_app()


def report():
    print("\n=== US-928 OpenPGP wipe end-state re-probe results ===")
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

    con = mgmt_app()
    if want("W0-pre-state"):
        con = w0_pre_state(con, args.yes)
    if want("W1-reset"):
        if w1_reset(con, args.yes):
            if want("W2-pw1-fresh"):
                con = w2_pw1_fresh(con, args.yes)
            if want("W3-dos-wiped"):
                con = w3_dos_wiped(con, args.yes)
    con.disconnect()
    report()


if __name__ == "__main__":
    sys.exit(main())
