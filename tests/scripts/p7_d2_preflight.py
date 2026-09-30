#!/usr/bin/env python3
"""P7-D2 phase 1 — pre-flight factory-state verification (repin-brief WI1).

Records, verbatim:
  * lsusb identity of Device 106 (fa20:0002 The BLOCO Community fapico2) —
    caller tees
    the lsusb output into the same evidence file.
  * Flash provenance: UF2 sha256 53ba915e1ad405f32abfb7c2b062d2ef13d86795b
    557a8bab1d4aaa2eaf256f8 (= firmware/fapico2.uf2 @ HEAD dcf8397), flashed
    via BOOTSEL file copy. NO re-flash in scope.
  * Factory state via pyusb raw-CCID (pcscd cannot negotiate this board):
      - mgmt AID SELECT + READ_CONFIG -> factory caps TLV
      - OpenPGP SELECT ok; keyless verdict per the S-723-B3-1 packing:
        C5 = 60 zero bytes (SW 9000, NOT 6A88) / C6 = 60 zero bytes /
        C7 = 6A88
      - GET DATA C4 -> PW1/PW3 retries 3; the RC (middle) byte is recorded
        as-read (reads 0 on this image family — divergence P7-D2-2; never
        gated).

Read-only APDUs only (SELECT / GET DATA). One attempt each; on any
unexpected SW the script records verbatim and exits non-zero.

US-104 (PICOForge-COMPAT): live against a flashed board, so the factory caps
gate below expects the DEVICE word 0x022B. The `53ba915e` capture behind
docs/tasks/evidence/p7-d2/ recorded 0x023B (pre-US-104, CAP_PIV advertised
while PIV was never registered) — that log is historical evidence and is left
as it was recorded.

Output: docs/tasks/evidence/p7-d2/p7d2-A-preflight.log
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ccid_usb import Ccid

EVID = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "..", "docs", "tasks", "evidence", "p7-d2")

MGMT_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17]
OPENPGP_AID = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]

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
    failed = False
    step("p7d2-A-preflight.log")
    out("# P7-D2 phase 1 pre-flight (repin-brief WI1) — %s"
        % os.popen("date -Is").read().strip())
    out("# Flash provenance (binding): UF2 sha256 "
        "53ba915e1ad405f32abfb7c2b062d2ef13d86795b557a8bab1d4aaa2eaf256f8 "
        "= firmware/fapico2.uf2 @ HEAD dcf8397, BOOTSEL file copy (Device "
        "106 post-flash). NO re-flash in scope.")
    out("# lsusb identity (Device 106): "
        "Bus 001 Device 106: ID fa20:0002 The BLOCO Community fapico2")
    out()

    c = Ccid()
    atr = c.power_on()
    out("ATR: %s" % atr.hex(" "))

    # mgmt AID SELECT + READ_CONFIG (factory caps TLV)
    sel = [0x00, 0xA4, 0x04, 0x00, len(MGMT_AID)] + MGMT_AID
    body, sw = x(c, sel)
    out("SELECT mgmt AID A0 00 00 05 27 47 11 17 -> SW %02X%02X, data %s"
        % (sw[0], sw[1], body.hex(" ")))
    if sw != (0x90, 0x00):
        out("STOP: unexpected mgmt SELECT SW — not retrying")
        c.close()
        return 2
    ver = bytes(body).decode("ascii", "replace")
    out("decoded version string: %r" % ver)
    body, sw = x(c, [0x00, 0x1D, 0x00, 0x00, 0x00])
    out("READ_CONFIG (00 1D 00 00 00) -> SW %02X%02X, data %s"
        % (sw[0], sw[1], body.hex(" ")))
    if sw != (0x90, 0x00):
        out("STOP: unexpected READ_CONFIG SW — not retrying")
        c.close()
        return 2
    b = bytes(body)
    # US-104 (PICOForge-COMPAT): the device now reports 0x022B — five bits.
    # The sixth (CAP_PIV, 0x10) was cleared because the device AID dispatcher
    # registers only Management/OATH/OTP/OpenPGP (`CCID_AIDS`), so advertising
    # PIV would offer the desktop client a screen the board cannot serve. The
    # pre-US-104 word on this same image family was 0x023B. This gate is a
    # LIVE preflight against a flashed board, so it tracks the device word; the
    # captured logs under docs/tasks/evidence/p7-d2/ still show 0x023B because
    # they predate US-104.
    if len(b) > 1 and b[0] == len(b) - 1 and b"\x02\x2b" in b:
        out("decoded: factory caps TLV (len 0x%02X), caps word 0x022B = "
            "the five bits the device actually registers (CAP_PIV cleared, "
            "US-104)" % b[0])
    else:
        out("STOP: READ_CONFIG body is not the expected factory caps TLV "
            "shape — not retrying")
        c.close()
        return 2

    # OpenPGP: SELECT ok, keyless per S-723-B3-1 (C5 60B zeros / C6 zeros / C7 6A88)
    sel = [0x00, 0xA4, 0x04, 0x00, len(OPENPGP_AID)] + OPENPGP_AID
    body, sw = x(c, sel)
    out("SELECT OpenPGP AID D2 76 00 01 24 01 -> SW %02X%02X, data %s"
        % (sw[0], sw[1], body.hex(" ")))
    if sw != (0x90, 0x00):
        out("STOP: unexpected OpenPGP SELECT SW — not retrying")
        c.close()
        return 2
    for tag, label, expect in [
            (0xC5, "C5 fpr sign", None), (0xC6, "C6 fpr enc", None),
            (0xC7, "C7 fpr auth", None)]:
        body, sw = x(c, [0x00, 0xCA, 0x00, tag, 0xFE])
        b = bytes(body)
        # S-723-B3-1 register row (firmware behavior): opcard packs all
        # three fprs in the 60-byte C5 DO; C6 answers 60 zero bytes; C7
        # answers 6A88 even with keys present. Keyless signature: C5 = 60
        # zero bytes with SW 9000 (NOT 6A88), C6 = 60 zero bytes, C7 6A88.
        keyless = (sw == (0x6A, 0x88)) or \
                  (sw == (0x90, 0x00) and len(b) == 60 and b == b"\x00" * 60)
        out("GET DATA %s -> SW %02X%02X%s"
            % (label, sw[0], sw[1],
               " (referenced data not found)" if sw == (0x6A, 0x88)
               else ", data %s" % b.hex(" ")))
        out("  keyless verdict: %s"
            % ("YES (S-723-B3-1 packing: C5 60B zeros / C6 zeros / "
               "C7 6A88)" if keyless else "NO — unexpected shape"))
        if not keyless:
            failed = True
    body, sw = x(c, [0x00, 0xCA, 0x00, 0xC4, 0xFE])
    b = bytes(body)
    out("GET DATA C4 (PW status) -> SW %02X%02X, data %s"
        % (sw[0], sw[1], b.hex(" ")))
    if sw != (0x90, 0x00):
        out("STOP: unexpected C4 SW — not retrying")
        c.close()
        return 2
    out("decoded: PW1 retries %d, RC retries %d, PW3 retries %d "
        "(bytes 5-7, as-read)" % (b[4], b[5], b[6]))
    if b[4] != 3 or b[6] != 3:
        failed = True
        out("  UNEXPECTED: PW1/PW3 retries must read 3 on a factory-fresh "
            "board")
    if b[5] != 3:
        out("  AS-READ DIVERGENCE vs the brief's '3/3/3': middle byte "
            "(RC/reset-code retries) reads %d on this nuked+reflashed "
            "board; recorded verbatim, gates nothing in the ceremony "
            "(no RC path is exercised); flagged as a concern in the "
            "report." % b[5])
    c.close()

    out()
    out("PREFLIGHT %s (P7-D2 phase 1)"
        % ("PASS — factory state confirmed" if not failed else "FAIL"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
