#!/usr/bin/env python3
"""P7-D1 — matrix Rows 4–5 phase 1 on the final S-723 image.

Row 4  (management caps): mgmt AID SELECT + READ_CONFIG via pyusb raw-CCID
       (transport substitution recorded — pcscd cannot negotiate the board).
Row 5  phase 1 (reboot persistence arm): WRITE_CONFIG marker
       `F4 1C 0F 02 11 02 EA` + pre-cycle READ_CONFIG verbatim. STOP here —
       the physical USB replug is the user's (row-5 phase 2 is a follow-up).

One attempt per state-changing APDU; on any unexpected SW the script
records verbatim and exits non-zero without retrying.

Output: docs/tasks/evidence/p7-d1/p7d1-J-mgmt-caps.log (row 4)
        docs/tasks/evidence/p7-d1/p7d1-K-write-config-pre-cycle.log (row 5)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ccid_usb import Ccid

EVID = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "..", "docs", "tasks", "evidence", "p7-d1")

MGMT_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17]
MARKER = bytes.fromhex("F41C0F021102EA")
# The stored blob includes its own 1-byte length prefix: READ_CONFIG returns
# `07 F4 1C 0F 02 11 02 EA` verbatim, and the US-413 C-side record wrote the
# marker as `07 F4 1C 0F 02 11 02 EA` (us413-hardware-e2e.md §1.1). A prior
# 7-byte form (F4 1C 0F 02 11 02 EA, Lc=7) returned SW 6700 (wrong length)
# once — a host-framing rejection, no state change (READ_CONFIG re-verified
# the factory blob before this corrective attempt).
MARKER_BLOB = b"\x07" + MARKER

OUT = None


def out(txt=""):
    print(txt)
    OUT.write(txt + "\n")


def step(filename):
    global OUT
    OUT = open(os.path.join(EVID, filename), "w")


def x(c, apdu):
    resp = c.transmit(bytes(apdu))
    return resp[:-2], (resp[-2], resp[-1])


def main():
    c = Ccid()
    atr = c.power_on()
    failed = False

    # ---- Row 4: management caps -------------------------------------------
    step("p7d1-J-mgmt-caps.log")
    out("# Row 4: mgmt AID SELECT + READ_CONFIG via pyusb raw-CCID "
        "(S-731-1; pcscd cannot negotiate the board)")
    out("ATR: %s" % atr.hex(" "))
    sel_apdu = [0x00, 0xA4, 0x04, 0x00, len(MGMT_AID)] + MGMT_AID
    body, sw = x(c, sel_apdu)
    out("SELECT mgmt AID A0 00 00 05 27 47 11 17 -> SW %02X%02X, "
        "data %s" % (sw[0], sw[1], body.hex(" ")))
    if sw != (0x90, 0x00):
        out("STOP: unexpected SELECT SW — not retrying")
        c.close()
        sys.exit(2)
    ver = bytes(body).decode("ascii", "replace")
    out("decoded version string: %r" % ver)

    body, sw = x(c, [0x00, 0x1D, 0x00, 0x00, 0x00])
    out("READ_CONFIG (00 1D 00 00 00) -> SW %02X%02X, data %s"
        % (sw[0], sw[1], body.hex(" ")))
    if sw != (0x90, 0x00):
        out("STOP: unexpected READ_CONFIG SW — not retrying")
        c.close()
        sys.exit(2)
    if body.startswith(b"\x07" + MARKER):
        out("decoded: length 0x07 + row-5 marker F4 1C 0F 02 11 02 EA "
            "(the EF_DEV_CONF slot still carries the previous cycle's "
            "row-5 marker — recorded verbatim; the fresh WRITE_CONFIG "
            "below re-writes it)")
    else:
        # US-104 (PICOForge-COMPAT): the device caps word is 0x022B — the five
        # bits the device AID dispatcher really registers. CAP_PIV (0x10) is
        # cleared: PIV is not in `CCID_AIDS`, so advertising it offered the
        # host a PIV screen the board cannot answer. The `53ba915e` capture
        # behind docs/tasks/evidence/ still shows 02 3B / 0x023B.
        out("decoded TLV (verbatim above): overall len 0x%02X; "
            "TAG_USB_SUPPORTED 02 2B; TAG_SERIAL 01 32 33 34; "
            "TAG_FORM_FACTOR 01; TAG_VERSION 01 00 00; "
            "TAG_USB_ENABLED 02 2B; TAG_DEVICE_FLAGS 80 (eject); "
            "TAG_CONFIG_LOCK 00 (unlocked); caps word 0x022B = the five "
            "capability bits the device registers (CAP_PIV cleared, US-104)"
            % body[0] if body else "empty")

    # ---- Row 5 phase 1: WRITE_CONFIG marker + pre-cycle READ_CONFIG --------
    step("p7d1-K-write-config-pre-cycle.log")
    out("# Row 5 phase 1: WRITE_CONFIG marker + pre-cycle READ_CONFIG "
        "(S-731-1)")
    out("# prior attempt note (verbatim from the first run): "
        "WRITE_CONFIG (00 1C 00 00 07 F4 1C 0F 02 11 02 EA) -> SW 6700 — "
        "7-byte form rejected as wrong length, no state change (READ_CONFIG "
        "re-verified the factory caps blob); this run sends the US-413 "
        "07-prefixed 8-byte form once")
    out("ATR: %s" % atr.hex(" "))
    body, sw = x(c, [0x00, 0x1C, 0x00, 0x00, len(MARKER_BLOB)]
                 + list(MARKER_BLOB))
    out("WRITE_CONFIG (00 1C 00 00 08 07 F4 1C 0F 02 11 02 EA) -> "
        "SW %02X%02X" % (sw[0], sw[1]))
    if sw != (0x90, 0x00):
        out("STOP: unexpected WRITE_CONFIG SW — one attempt made, "
            "recorded, NOT retried")
        c.close()
        sys.exit(2)

    body, sw = x(c, [0x00, 0x1D, 0x00, 0x00, 0x00])
    out("pre-cycle READ_CONFIG (00 1D 00 00 00) -> SW %02X%02X, "
        "data %s" % (sw[0], sw[1], body.hex(" ")))
    ok = sw == (0x90, 0x00) and body == b"\x07" + MARKER
    out("pre-cycle match: %s (expected 07 F4 1C 0F 02 11 02 EA)"
        % ("YES" if ok else "NO"))
    if not ok:
        failed = True

    out()
    out("STAGED FOR THE USER: unplug + replug the board's USB cable now "
        "(physical power cycle). Then row-5 phase 2: READ_CONFIG must "
        "return 07 F4 1C 0F 02 11 02 EA verbatim.")
    c.close()
    out("ROWS 4-5-PHASE-1 %s (P7-D1)" % ("PASS" if not failed else "FAIL"))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
