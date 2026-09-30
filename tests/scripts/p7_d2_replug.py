#!/usr/bin/env python3
"""P7-D2 phase 2 — row-5 post-cycle READ_CONFIG (repin-brief WI6 phase 2).

Run AFTER the user's physical USB replug (power cycle): SELECT mgmt AID
first (a fresh session has no app selected — P7-D1 recorded a 6A82 when
READ_CONFIG was sent SELECT-less), then READ_CONFIG. PASS requires the
row-5 marker blob `07 F4 1C 0F 02 11 02 EA` verbatim.

One attempt each; on unexpected SW record verbatim and exit non-zero.

Output: docs/tasks/evidence/p7-d2/p7d2-M-readconfig-post-cycle.log
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ccid_usb import Ccid

EVID = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "..", "docs", "tasks", "evidence", "p7-d2")

MGMT_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17]
MARKER = b"\x07\xf4\x1c\x0f\x02\x11\x02\xea"

OUT = open(os.path.join(EVID, "p7d2-M-readconfig-post-cycle.log"), "w")


def out(txt=""):
    print(txt)
    OUT.write(txt + "\n")


def x(c, apdu):
    resp = c.transmit(bytes(apdu))
    return resp[:-2], (resp[-2], resp[-1])


def main():
    failed = False
    out("# P7-D2 phase 2 — row-5 post-cycle READ_CONFIG (after the user's "
        "USB replug; board re-enumerated as Device 107, %s)"
        % os.popen("date -Is").read().strip())
    out("# pre-cycle state (phase 1): WRITE_CONFIG 00 1C 00 00 08 07 F4 1C "
        "0F 02 11 02 EA -> SW 9000; pre-cycle READ_CONFIG -> "
        "07 f4 1c 0f 02 11 02 ea verbatim (p7d2-K-write-config-pre-cycle.log)")
    out("# sequence note (P7-D1 lesson): SELECT mgmt AID is sent FIRST — "
        "a fresh session has no app selected (a SELECT-less READ_CONFIG "
        "returned 6A82 in the P7-D1 cycle; sequence omission recorded there)")
    out()
    c = Ccid()
    atr = c.power_on()
    out("ATR: %s" % atr.hex(" "))
    sel = [0x00, 0xA4, 0x04, 0x00, len(MGMT_AID)] + MGMT_AID
    body, sw = x(c, sel)
    out("SELECT mgmt AID A0 00 00 05 27 47 11 17 -> SW %02X%02X, data %s"
        % (sw[0], sw[1], body.hex(" ")))
    if sw != (0x90, 0x00):
        out("STOP: unexpected SELECT SW — not retrying")
        c.close()
        return 2
    body, sw = x(c, [0x00, 0x1D, 0x00, 0x00, 0x00])
    out("post-cycle READ_CONFIG (00 1D 00 00 00) -> SW %02X%02X, data %s"
        % (sw[0], sw[1], body.hex(" ")))
    if sw != (0x90, 0x00):
        out("STOP: unexpected READ_CONFIG SW — one attempt made, recorded, "
            "NOT retried")
        c.close()
        return 2
    ok = bytes(body) == MARKER
    out("post-cycle match: %s (expected 07 F4 1C 0F 02 11 02 EA verbatim)"
        % ("YES" if ok else "NO"))
    if not ok:
        failed = True
    c.close()
    out()
    out("ROW-5 PHASE-2 %s (P7-D2)" % ("PASS" if not failed else "FAIL"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
