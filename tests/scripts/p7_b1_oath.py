#!/usr/bin/env python3
"""P7-B1 — OATH hardware acceptance over real CCID (S-711-3, US-356).

Drives the flashed board through the full YKOATH command set over pcscd +
libccid (pyscard), with the byte-exact vectors from the emulation suite
(tests/pico-fido/test_070_oath.py) plus Python-computed HMAC cross-checks.

Phases:
  1. lifecycle   RESET / PUT / LIST / CALCULATE (TOTP full digest) /
                 CALC_ALL / CALCULATE (HOTP counter) / RENAME / DELETE
  2. pin         SET_PIN / VERIFY_PIN / CHANGE_PIN / wrong-PIN 6982
  3. access code SET_CODE -> SELECT challenge / locked LIST 6982 /
                 VALIDATE / unlocked LIST
  4. persist-arm full state (creds + HOTP counter + PIN + access code),
                 then the USER power-cycles the board (USB unplug/replug)
  5. --after-power-cycle
                 SELECT challenge / locked LIST / VALIDATE / creds + HOTP
                 counter continuation / TOTP vector / VERIFY_PIN

Usage (repo venv has pyscard/smartcard 2.3.1):
  .venv/bin/python tests/scripts/p7_b1_oath.py                    # phases 1-4
  .venv/bin/python tests/scripts/p7_b1_oath.py --after-power-cycle # phase 5

Transports (US-130):
  --emul                drive the fapico2 emulation binary over the harness
                        CCID relay instead of a real reader (phases 1-4; there
                        is no power cycle to observe under emulation)
  --chipid 0xHEXBE      the unit's OTP chip-id, so the SELECT FCI's
                        chip-derived device-id can be checked by value as well
                        as by shape. Optional on hardware: without it the FCI
                        is still gated structurally (tags, lengths, order).

Exit 0 = every check passed; exit 1 = at least one failure.
"""
import os
import sys
import hmac as _hmac
import hashlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oath_p7 import (DEVICE_ID_LEN, FCI_HEAD, check_device_id_vs_mgmt_serial,
                     check_fci, open_dev)

OATH_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]

TAG_NAME = 0x71
TAG_NAME_LIST = 0x72
TAG_KEY = 0x73
TAG_CHALLENGE = 0x74
TAG_RESPONSE = 0x75
TAG_T_RESPONSE = 0x76
TAG_NO_RESPONSE = 0x77
TAG_IMF = 0x7A
TAG_PASSWORD = 0x80
TAG_NEW_PASSWORD = 0x81

INS_PUT = 0x01
INS_DELETE = 0x02
INS_SET_CODE = 0x03
INS_RESET = 0x04
INS_RENAME = 0x05
INS_LIST = 0xA1
INS_CALCULATE = 0xA2
INS_VALIDATE = 0xA3
INS_CALC_ALL = 0xA4
INS_VERIFY_PIN = 0xB2
INS_CHANGE_PIN = 0xB3
INS_SET_PIN = 0xB4

FAILED = False


def trunc_hmac(key, counter_be):
    """RFC 4226 4-byte truncation as the firmware emits it."""
    mac = _hmac.new(key, counter_be, hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return [mac[off] & 0x7F] + list(mac[off + 1:off + 4])


class Dev:
    def __init__(self):
        try:
            from smartcard import scard
        except ModuleNotFoundError:
            print("FAIL: pyscard (smartcard.scard) not importable — "
                  "run with .venv/bin/python")
            sys.exit(1)
        self.s = scard
        hr, ctx = scard.SCardEstablishContext(0)
        if hr != scard.SCARD_S_SUCCESS:
            print("FAIL: SCardEstablishContext %s" % hex(hr))
            sys.exit(1)
        hr, readers = scard.SCardListReaders(ctx, [])
        if hr != scard.SCARD_S_SUCCESS or not readers:
            print("FAIL: no CCID reader visible (pcscd/libccid?)")
            sys.exit(1)
        hr, card, proto = scard.SCardConnect(
            ctx, readers[0], scard.SCARD_SHARE_DIRECT, scard.SCARD_PROTOCOL_RAW)
        if hr != scard.SCARD_S_SUCCESS:
            print("FAIL: SCardConnect %s" % hex(hr))
            sys.exit(1)
        self.card = card
        print("reader:", readers[0])

    def x(self, apdu):
        hr, resp = self.s.SCardTransmit(self.card, self.s.SCARD_PCI_RAW,
                                        list(apdu))
        if hr != self.s.SCARD_S_SUCCESS:
            print("FAIL: SCardTransmit %s" % hex(hr))
            sys.exit(1)
        b = bytes(resp)
        assert len(b) >= 2, "empty card response"
        return b[:-2], (b[-2], b[-1])

    def select(self):
        # C-harness SELECT framing (tests/conftest.py select_oath).
        return self.x([0x00, 0xA4, 0x04, 0x00, 0x00, 0x00, len(OATH_AID)]
                      + OATH_AID + [0x00, 0x00])

    def apdu(self, ins, p1, p2, data=None):
        # C-harness framing (tests/pico-fido/utils.py send_apdu).
        base = [0x00, ins, p1, p2]
        if data:
            base += [0x00, 0x00, len(data)] + list(data)
        return self.x(base + [0x00, 0x00])


def check(label, got, exp_data, exp_sw=(0x90, 0x00)):
    """got = (body, (sw1, sw2)). exp_data None = any body."""
    global FAILED
    body, sw = got
    problems = []
    if sw != exp_sw:
        problems.append("sw %02X%02X != %02X%02X" % (sw[0], sw[1],
                                                     exp_sw[0], exp_sw[1]))
    if exp_data is not None and list(body) != list(exp_data):
        problems.append("body %s != %s" % (body.hex(' '), exp_data.hex(' ')))
    print("%s %s%s" % ("PASS" if not problems else "FAIL", label,
                       ("  [" + "; ".join(problems) + "]") if problems else ""))
    if problems:
        FAILED = True


def challenge_from_select(body):
    # FCI: 79 03 04 03 00 71 08 <8-byte device-id> [74 08 <8-byte challenge>]
    if 0x74 in body:
        i = body.index(0x74)
        assert body[i + 1] == 8, "challenge TLV len != 8: %s" % body.hex(' ')
        return bytes(body[i + 2:i + 10])
    return None


def put_apdu(name, key, imf=None):
    data = [TAG_NAME, len(name)] + list(name) + [TAG_KEY, len(key)] + list(key)
    if imf is not None:
        data += [TAG_IMF, len(imf)] + imf
    return data


def main():
    after_pc = "--after-power-cycle" in sys.argv
    dev, chipid = open_dev(sys.argv, Dev)
    if after_pc:
        phase_power_cycle(dev)
    else:
        phase_lifecycle(dev)
        phase_pin(dev)
        phase_access_code(dev)
        phase_persist_arm(dev)
    print()
    print("CEREMONY %s (P7-B1, US-356)"
          % ("PASS" if not FAILED else "FAIL"))
    sys.exit(1 if FAILED else 0)




def select_session(dev, label="SELECT OATH AID"):
    got = dev.select()
    check(label, got, None)
    return got


def phase_lifecycle(dev):
    print("== phase 1: lifecycle ==")
    got = select_session(dev)
    body, sw = got
    # US-130: the FCI prefix and its validation live in `oath_p7` (derived from
    # the chip-id, NOT a literal) — see that module for what it must track.
    fci_ok, fci_why = check_fci(body, sw, dev.chipid)
    # Cross-check against the management applet: its TAG_SERIAL is the
    # same device-bound hash, 4 bytes, so this pins the OATH salt to a
    # per-unit value even on hardware where the chip-id is unknown.
    dev_id = body[len(FCI_HEAD):len(FCI_HEAD) + DEVICE_ID_LEN]
    if fci_ok:
        cross_ok, cross_why = check_device_id_vs_mgmt_serial(dev_id, dev)
        fci_ok, fci_why = cross_ok, cross_why
    print("%s SELECT FCI (version 4.3.0, chip-derived 8-byte device-id)%s" % (
        "PASS" if fci_ok else "FAIL",
        "" if fci_ok else "  [%s | got: %s %02X%02X]"
        % (fci_why, body.hex(' '), sw[0], sw[1])))
    if not fci_ok:
        global FAILED
        FAILED = True
    check("RESET", dev.apdu(INS_RESET, 0xDE, 0xAD), b"")

    # TOTP "kaka": key TLV [0x21, 0x06, 0x0B x 20] (suite data_key)
    key_kaka = bytes([0x21, 0x06] + [0x0B] * 20)
    check("PUT kaka (TOTP sha1-6)", dev.apdu(INS_PUT, 0, 0,
                                             put_apdu(b"kaka", key_kaka)), b"")
    check("LIST = kaka", dev.apdu(INS_LIST, 0, 0),
          bytes([TAG_NAME_LIST, 5, 0x21]) + b"kaka")

    # Suite vector (test_life): full digest, counter 00 00 00 00 00 00 00 01
    exp_totp_full = bytes([TAG_RESPONSE, 0x15, 0x06,
                           0xB3, 0x99, 0xBD, 0xFC, 0x9D, 0x05, 0xD1, 0x2A,
                           0xC4, 0x35, 0xC4, 0xC8, 0xD6, 0xCB, 0xD2, 0x47,
                           0xC4, 0x0A, 0x30, 0xF1])
    check("CALCULATE kaka TOTP (full digest, suite vector)",
          dev.apdu(INS_CALCULATE, 0, 0,
                   [TAG_NAME, 4] + list(b"kaka")
                   + [TAG_CHALLENGE, 8, 0, 0, 0, 0, 0, 0, 0, 1]),
          exp_totp_full)

    # test_bothoath credentials: key b"foo bar"
    key_fb = bytes([0x21, 0x06]) + b"foo bar"
    check("PUT totp", dev.apdu(INS_PUT, 0, 0, put_apdu(b"totp", key_fb)), b"")
    key_fb_hotp = bytes([0x11, 0x06]) + b"foo bar"
    check("PUT htop (HOTP)",
          dev.apdu(INS_PUT, 0, 0, put_apdu(b"htop", key_fb_hotp)), b"")

    # CALC_ALL p2=1, challenge 00 00 00 00 02 bc ad c8 (suite test_bothoath
    # credentials; "kaka" from above rides along first in slot order).
    chal_all = bytes([0, 0, 0, 0, 2, 0xBC, 0xAD, 0xC8])
    exp_all = (bytes([TAG_NAME, 4]) + b"kaka"
               + bytes([TAG_T_RESPONSE, 5, 6]
                       + trunc_hmac(bytes([0x0B] * 20), chal_all))
               + bytes([TAG_NAME, 4]) + b"totp"
               + bytes([TAG_T_RESPONSE, 5, 6, 0x3D, 0xC6, 0xBF, 0x3D])
               + bytes([TAG_NAME, 4]) + b"htop"
               + bytes([TAG_NO_RESPONSE, 1, 6]))
    check("CALC_ALL p2=1 (suite vector + HOTP no-response)",
          dev.apdu(INS_CALC_ALL, 0, 1,
                   [TAG_CHALLENGE, 8, 0, 0, 0, 0, 2, 0xBC, 0xAD, 0xC8]),
          exp_all)

    # HOTP counter 0 (suite vector) — bare trailing TAG_CHALLENGE
    check("CALCULATE htop HOTP ctr=0 (suite vector)",
          dev.apdu(INS_CALCULATE, 0, 1,
                   [TAG_NAME, 4] + list(b"htop") + [TAG_CHALLENGE]),
          bytes([TAG_T_RESPONSE, 5, 6, 0x17, 0xFA, 0x2D, 0x40]))

    check("RENAME totp->totp2", dev.apdu(
        INS_RENAME, 0, 0,
        [TAG_NAME, 4] + list(b"totp")
        + [TAG_NAME, 5] + list(b"totp2")), b"")
    check("LIST = kaka + totp2 + htop (slot order)", dev.apdu(INS_LIST, 0, 0),
          bytes([TAG_NAME_LIST, 5, 0x21]) + b"kaka"
          + bytes([TAG_NAME_LIST, 6, 0x21]) + b"totp2"
          + bytes([TAG_NAME_LIST, 5, 0x11]) + b"htop")

    check("DELETE totp2", dev.apdu(
        INS_DELETE, 0, 0, [TAG_NAME, 5] + list(b"totp2")), b"")
    check("DELETE htop", dev.apdu(
        INS_DELETE, 0, 0, [TAG_NAME, 4] + list(b"htop")), b"")
    check("DELETE kaka", dev.apdu(
        INS_DELETE, 0, 0, [TAG_NAME, 4] + list(b"kaka")), b"")
    check("LIST empty", dev.apdu(INS_LIST, 0, 0), b"")


def phase_pin(dev):
    print("== phase 2: OTP PIN lifecycle ==")
    select_session(dev)
    check("RESET", dev.apdu(INS_RESET, 0xDE, 0xAD), b"")
    old_pin, new_pin = b"123456", b"654321"
    check("SET_PIN 123456", dev.apdu(
        INS_SET_PIN, 0, 0,
        [TAG_PASSWORD, len(old_pin)] + list(old_pin)), b"")
    check("VERIFY_PIN 123456", dev.apdu(
        INS_VERIFY_PIN, 0, 0,
        [TAG_PASSWORD, len(old_pin)] + list(old_pin)), b"")
    check("CHANGE_PIN -> 654321", dev.apdu(
        INS_CHANGE_PIN, 0, 0,
        [TAG_PASSWORD, len(old_pin)] + list(old_pin)
        + [TAG_NEW_PASSWORD, len(new_pin)] + list(new_pin)), b"")
    check("VERIFY_PIN old -> 6982", dev.apdu(
        INS_VERIFY_PIN, 0, 0,
        [TAG_PASSWORD, len(old_pin)] + list(old_pin)), b"", (0x69, 0x82))
    check("VERIFY_PIN new", dev.apdu(
        INS_VERIFY_PIN, 0, 0,
        [TAG_PASSWORD, len(new_pin)] + list(new_pin)), b"")


def phase_access_code(dev):
    print("== phase 3: access code (challenge / VALIDATE) ==")
    select_session(dev)
    check("RESET", dev.apdu(INS_RESET, 0xDE, 0xAD), b"")
    code_key = bytes([0x21]) + b"kaka blahonga"
    chal = bytes(range(1, 9))
    resp = _hmac.new(b"kaka blahonga", chal, hashlib.sha1).digest()
    check("SET_CODE (suite key/challenge/response)", dev.apdu(
        INS_SET_CODE, 0, 0,
        [TAG_KEY, len(code_key)] + list(code_key)
        + [TAG_CHALLENGE, len(chal)] + list(chal)
        + [TAG_RESPONSE, len(resp)] + list(resp)), b"")

    got = dev.select()
    check("SELECT (locked session)", got, None)
    sel_chal = challenge_from_select(got[0])
    if sel_chal is None:
        print("FAIL SELECT challenge TLV 74 08 missing: %s" % got[0].hex(' '))
        global FAILED
        FAILED = True
        return
    print("     select challenge:", sel_chal.hex(' '))

    check("LIST locked -> 6982", dev.apdu(INS_LIST, 0, 0), b"", (0x69, 0x82))

    vresp = _hmac.new(b"kaka blahonga", sel_chal, hashlib.sha1).digest()
    check("VALIDATE (hmac of SELECT challenge)", dev.apdu(
        INS_VALIDATE, 0, 0,
        [TAG_RESPONSE, len(vresp)] + list(vresp)
        + [TAG_CHALLENGE, len(chal)] + list(chal)),
        bytes([TAG_RESPONSE, 20]) + _hmac.new(b"kaka blahonga", chal,
                                              hashlib.sha1).digest())
    check("LIST unlocked (empty)", dev.apdu(INS_LIST, 0, 0), b"")


def phase_persist_arm(dev):
    print("== phase 4: persistence arm ==")
    select_session(dev)
    check("RESET", dev.apdu(INS_RESET, 0xDE, 0xAD), b"")
    key_kaka = bytes([0x21, 0x06] + [0x0B] * 20)
    check("PUT kaka (TOTP)", dev.apdu(INS_PUT, 0, 0,
                                      put_apdu(b"kaka", key_kaka)), b"")
    key_imf = bytes([0x11, 0x06]) + b"kaka"
    imf = [0xFF, 0x00, 0xFF, 0xFF]  # counter 0x00000000FF00FFFF
    check("PUT imf1 (HOTP, IMF ff 00 ff ff)",
          dev.apdu(INS_PUT, 0, 0, put_apdu(b"imf1", key_imf, imf)), b"")

    # Suite vectors (test_imf_overwrite): counters 0xFF00FFFF, then +1
    hotp_apdu = [TAG_NAME, 4] + list(b"imf1") + [TAG_CHALLENGE]
    check("CALCULATE imf1 #1 (suite vector, ctr 0xFF00FFFF)",
          dev.apdu(INS_CALCULATE, 0, 1, hotp_apdu),
          bytes([TAG_T_RESPONSE, 5, 6, 0x45, 0xD9, 0x0F, 0x25]))
    check("CALCULATE imf1 #2 (suite vector, ctr 0xFF010000)",
          dev.apdu(INS_CALCULATE, 0, 1, hotp_apdu),
          bytes([TAG_T_RESPONSE, 5, 6, 0x1B, 0xC5, 0x4A, 0x85]))
    # Cross-check the post-reboot expectation with an independent HMAC
    exp3 = [TAG_T_RESPONSE, 5, 6] + trunc_hmac(b"kaka",
                                               (0xFF00FFFF + 2).to_bytes(8, 'big'))
    print("     post-reboot HOTP prediction (ctr 0xFF010001):",
          ' '.join('%02x' % b for b in exp3))

    pin = b"123456"
    check("SET_PIN 123456", dev.apdu(
        INS_SET_PIN, 0, 0,
        [TAG_PASSWORD, len(pin)] + list(pin)), b"")
    code_key = bytes([0x21]) + b"kaka blahonga"
    chal = bytes(range(1, 9))
    resp = _hmac.new(b"kaka blahonga", chal, hashlib.sha1).digest()
    check("SET_CODE (locks session)", dev.apdu(
        INS_SET_CODE, 0, 0,
        [TAG_KEY, len(code_key)] + list(code_key)
        + [TAG_CHALLENGE, len(chal)] + list(chal)
        + [TAG_RESPONSE, len(resp)] + list(resp)), b"")
    got = dev.select()
    ok = got[1] == (0x90, 0x00) and challenge_from_select(got[0]) is not None
    print("%s SELECT after SET_CODE (challenge present)" % ("PASS" if ok else "FAIL"))
    if not ok:
        global FAILED
        FAILED = True

    print()
    print("PWR-CYCLE-ARMED: state = {kaka TOTP, imf1 HOTP ctr 0xFF010001, "
          "PIN 123456, access code}.")
    print("UNPLUG and REPLUG the board's USB cable, then re-run:")
    print("  .venv/bin/python tests/scripts/p7_b1_oath.py --after-power-cycle")


def phase_power_cycle(dev):
    print("== phase 5: after power cycle ==")
    got = dev.select()
    check("SELECT (locked: access code persisted)", got, None)
    sel_chal = challenge_from_select(got[0])
    if sel_chal is None:
        print("FAIL SELECT challenge TLV 74 08 missing: %s" % got[0].hex(' '))
        global FAILED
        FAILED = True
        return
    print("     select challenge:", sel_chal.hex(' '))

    check("LIST locked -> 6982 (code still on file)",
          dev.apdu(INS_LIST, 0, 0), b"", (0x69, 0x82))

    vresp = _hmac.new(b"kaka blahonga", sel_chal, hashlib.sha1).digest()
    chal = bytes(range(1, 9))
    check("VALIDATE (persisted code verifies)", dev.apdu(
        INS_VALIDATE, 0, 0,
        [TAG_RESPONSE, len(vresp)] + list(vresp)
        + [TAG_CHALLENGE, len(chal)] + list(chal)),
        bytes([TAG_RESPONSE, 20]) + _hmac.new(b"kaka blahonga", chal,
                                              hashlib.sha1).digest())

    check("LIST = kaka + imf1 (creds persisted)", dev.apdu(INS_LIST, 0, 0),
          bytes([TAG_NAME_LIST, 5, 0x21]) + b"kaka"
          + bytes([TAG_NAME_LIST, 5, 0x11]) + b"imf1")

    # TOTP is deterministic: same vector as pre-reboot phase 1
    exp_totp_full = bytes([TAG_RESPONSE, 0x15, 0x06,
                           0xB3, 0x99, 0xBD, 0xFC, 0x9D, 0x05, 0xD1, 0x2A,
                           0xC4, 0x35, 0xC4, 0xC8, 0xD6, 0xCB, 0xD2, 0x47,
                           0xC4, 0x0A, 0x30, 0xF1])
    check("CALCULATE kaka TOTP (same vector pre/post reboot)",
          dev.apdu(INS_CALCULATE, 0, 0,
                   [TAG_NAME, 4] + list(b"kaka")
                   + [TAG_CHALLENGE, 8, 0, 0, 0, 0, 0, 0, 0, 1]),
          exp_totp_full)

    # HOTP counter continued across the power cycle: next value is #3
    exp3 = [TAG_T_RESPONSE, 5, 6] + trunc_hmac(b"kaka",
                                               (0xFF00FFFF + 2).to_bytes(8, 'big'))
    check("CALCULATE imf1 HOTP ctr=0xFF010001 (counter continued)",
          dev.apdu(INS_CALCULATE, 0, 1,
                   [TAG_NAME, 4] + list(b"imf1") + [TAG_CHALLENGE]),
          bytes(exp3))

    # Documented S-711-1 scope note: the PIN record is session state, not
    # part of the oath.keystore.v1 stream (C persists EF_OTP_PIN instead —
    # known divergence, recorded in the ladder observation).
    check("VERIFY_PIN after reboot -> 6985 (PIN is session state)",
          dev.apdu(INS_VERIFY_PIN, 0, 0,
                   [TAG_PASSWORD, 6] + list(b"123456")), b"", (0x69, 0x85))

    check("RESET (cleanup)", dev.apdu(INS_RESET, 0xDE, 0xAD), b"")
    check("LIST empty after RESET", dev.apdu(INS_LIST, 0, 0), b"")


if __name__ == "__main__":
    main()
