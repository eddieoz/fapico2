#!/usr/bin/env python3
"""US-914 hardware BDD: PSO touch-to-sign presence gate on the live RP2350.

Drives the OpenPGP applet of an attached fapico2 board over pcscd (the
on-device CCID reader, `fa20:0002`). SETUP MUTATES THE CARD: it
personalizes PW1/PW3 away from the factory defaults (US-912 gate) and
GENERATEs fresh Ed25519/X25519 keys into slots B6/B8/A4 — run only on a
test device.

BDD cases (EPIC US-914 + US-926's device consent rule):

  C1  PSO:SIGN, PW1-sign verified, NO touch   -> 6982 after the 10 s window, no signature
  C2  PSO:SIGN, touch inside the window      -> 9000 + Ed25519 signature (verified)
  C3  INT-AUTH, PW1-other verified, NO touch  -> 6982 (US-926 consent rule)
  C4  INT-AUTH, touch inside the window      -> 9000 + signature (verified)
  C5  press BEFORE the command, none during   -> 6982 (anti-harvest: a press that
      predates the pending request is not consent)
  C6  GET DATA 0xC4, no touch                -> 9000 (gate selectivity; also
      reads back the US-913 secure PW-status on hardware)
  C7  PSO:DECIPHER, PW1-other verified, NO touch -> 6982
  C8  PSO:DECIPHER, touch inside the window  -> 9000 + X25519 shared secret (verified)

Usage:
  python3 tests/hardware/pso_touch_bdd.py                  # interactive, all cases
  python3 tests/hardware/pso_touch_bdd.py --filter C1,C3   # subset
  python3 tests/hardware/pso_touch_bdd.py --yes            # no input() pacing
  python3 tests/hardware/pso_touch_bdd.py --skip-setup     # card already set up

Prints a PASS/FAIL table with per-case timings — append it to
docs/tasks/security-hardware-bdd.md as the US-914 evidence.
"""
import argparse
import hashlib
import sys
import time

from smartcard.System import readers

PGP_AID = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
FACTORY_PW1 = list(b"123456")
FACTORY_PW3 = list(b"12345678")
BDD_PW1 = list(b"654321")
BDD_PW3 = list(b"87654321")
DIGEST = hashlib.sha256(b"US-914 hardware BDD digest").digest()

RESULTS = []


def apdu(con, b):
    data, sw1, sw2 = con.transmit(b)
    while sw1 == 0x61:
        r2 = con.transmit([0x00, 0xC0, 0x00, 0x00, min(0xFF, sw2)])
        data += r2[0]
        sw1, sw2 = r2[1], r2[2]
    return sw1 << 8 | sw2, bytes(data)


def select(con):
    sw, _ = apdu(con, [0x00, 0xA4, 0x04, 0x00, len(PGP_AID)] + PGP_AID)
    if sw != 0x9000:
        sys.exit("SELECT OPENPGP failed: SW=%04X (is the fapico2 reader up?)" % sw)


def verify(con, p2, pin):
    return apdu(con, [0x00, 0x20, 0x00, p2, len(pin)] + pin)[0]


def change_ref(con, p2, old, new):
    return apdu(con, [0x00, 0x24, 0x00, p2, len(old) + len(new)] + old + new)[0]


def generate(con, slot):
    # GENERATE ASYMMETRIC KEY PAIR (CRT <slot> 00), case-4 with Le=0.
    return apdu(con, [0x00, 0x47, 0x80, 0x00, 0x02, slot, 0x00, 0x00])


def setup(con, assume_yes):
    """Personalize PINs + generate the three keys; idempotent re-runs."""
    select(con)
    sw = verify(con, 0x83, FACTORY_PW3)
    if sw == 0x9000:
        print("setup: factory PW3 verifies — personalizing PINs "
              "(PW1->654321, PW3->87654321)")
        if not assume_yes and input("     proceed? [y/N] ").strip().lower() != "y":
            sys.exit("aborted")
        sw = change_ref(con, 0x81, FACTORY_PW1, BDD_PW1)
        if sw != 0x9000:
            sys.exit("CHANGE REF PW1 failed: SW=%04X" % sw)
        sw = change_ref(con, 0x83, FACTORY_PW3, BDD_PW3)
        if sw != 0x9000:
            sys.exit("CHANGE REF PW3 failed: SW=%04X" % sw)
    else:
        sw = verify(con, 0x83, BDD_PW3)
        if sw != 0x9000:
            sys.exit("PW3 is neither factory default nor the BDD value "
                     "(SW=%04X) — refusing to guess" % sw)
        print("setup: card already personalized with the BDD PINs")
    sw = verify(con, 0x83, BDD_PW3)
    if sw != 0x9000:
        sys.exit("VERIFY PW3 failed after personalization: SW=%04X" % sw)
    # Pin the key algorithms to Ed25519 / Cv25519 (US-914 BDD key shape,
    # mirroring apps/openpgp/tests/device_pso.rs): legacy cards may carry
    # P256 attributes from earlier waves, which would verify as ECDSA.
    ED = [0x16, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01]
    CV = [0x12, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]
    for tag, alg in [(0xC1, ED), (0xC2, CV), (0xC3, ED)]:
        sw = apdu(con, [0x00, 0xDA, 0x00, tag, len(alg)] + alg)[0]
        if sw != 0x9000:
            sys.exit("PUT DATA algorithm %02X failed: SW=%04X" % (tag, sw))
    keys = {}
    for slot, name in [(0xB6, "sign"), (0xA4, "auth"), (0xB8, "dec")]:
        sw, pub = generate(con, slot)
        if sw != 0x9000 or len(pub) < 37 or pub[:5] != bytes([0x7F, 0x49, 0x22, 0x86, 0x20]):
            sys.exit("GENERATE %s failed: SW=%04X len=%d" % (name, sw, len(pub)))
        keys[slot] = pub[5:37]
        print("setup: GENERATE %s (slot %02X) -> %s" % (name, slot, keys[slot].hex()))
    return keys


def run_case(con, cid, keys, assume_yes):
    if cid == "C1":
        verify(con, 0x81, BDD_PW1)
        return gated(con, cid, "PSO:SIGN, NO touch — do not press for 10 s",
                     [0x00, 0x2A, 0x9E, 0x9A, len(DIGEST)] + list(DIGEST),
                     expect_sw=0x6982)
    if cid == "C2":
        return touch_sign(con, cid, keys)
    if cid == "C3":
        verify(con, 0x82, BDD_PW1)
        return gated(con, cid, "INT-AUTH, NO touch — do not press for 10 s",
                     [0x00, 0x88, 0x00, 0x00, len(DIGEST)] + list(DIGEST),
                     expect_sw=0x6982)
    if cid == "C4":
        return touch_intauth(con, cid, keys)
    if cid == "C5":
        return harvested(con, cid)
    if cid == "C6":
        return gated(con, cid, "GET DATA 0xC4 (non-gated) — no touch needed",
                     [0x00, 0xCA, 0x00, 0xC4, 0x00], expect_sw=0x9000)
    if cid == "C7":
        data = decipher_payload()
        verify(con, 0x82, BDD_PW1)
        return gated(con, cid, "PSO:DECIPHER, NO touch — do not press for 10 s",
                     [0x00, 0x2A, 0x80, 0x86, len(data)] + list(data),
                     expect_sw=0x6982)
    if cid == "C8":
        return touch_decipher(con, cid, keys)
    sys.exit("unknown case %s" % cid)


# X25519 ephemeral for the DECIPHER cases: a per-run key (the shared
# secret is checked against the device's reply).
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

X25519_EPHEMERAL = X25519PrivateKey.generate()


def decipher_payload():
    pub = X25519_EPHEMERAL.public_key().public_bytes_raw()
    return bytes([0xA6, 0x25, 0x7F, 0x49, 0x22, 0x86, 0x20]) + pub


def expected_shared(dec_pub):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    peer = X25519PublicKey.from_public_bytes(dec_pub)
    return X25519_EPHEMERAL.exchange(peer)


def gated(con, cid, instructions, bytes_, expect_sw):
    """A device-side case with no physical interaction during the exchange."""
    print("\n=== %s ===" % cid)
    print("    %s" % instructions)
    print("    sending...")
    t0 = time.monotonic()
    sw, data = apdu(con, bytes_)
    elapsed = time.monotonic() - t0
    ok = sw == expect_sw
    note = "SW=%04X len=%d elapsed=%.1fs" % (sw, len(data), elapsed)
    if cid == "C6" and ok:
        note += " pw-status=%s" % data.hex()
    if cid in ("C1", "C3", "C7") and ok:
        ok = len(data) == 0
        note += " body-empty=%s" % (len(data) == 0)
    RESULTS.append((cid, ok, note))
    print("    %s: %s" % ("PASS" if ok else "FAIL", note))
    return ok


def touch_case(con, cid, instructions, bytes_, check, action_label, attempts=6):
    """One touch case: up to `attempts` consecutive 10 s device windows; a
    refused attempt (no press landed) is retried after a short pause, so
    a ~1 Hz pressing rhythm reliably lands an edge inside one window."""
    print("\n=== %s (TOUCH CASE) ===" % cid)
    print("    %s" % instructions)
    for attempt in range(1, attempts + 1):
        if attempt > 1:
            print("    (attempt %d/%d — keep pressing)" % (attempt, attempts))
        print("    >>> WINDOW OPEN — PRESS AND RELEASE BOOTSEL NOW <<<")
        t0 = time.monotonic()
        try:
            sw, data = apdu(con, bytes_)
        except Exception as e:
            print("    transport error: %s" % str(e)[:60])
            time.sleep(2)
            continue
        elapsed = time.monotonic() - t0
        note = "SW=%04X len=%d elapsed=%.1fs" % (sw, len(data), elapsed)
        try:
            ok = sw == 0x9000 and check(data)
            note += " %s=verified (attempt %d)" % (action_label, attempt)
        except Exception as e:
            ok = False
            note += " %s=INVALID (%s)" % (action_label, e)
        if ok or sw != 0x6982:
            RESULTS.append((cid, ok, note))
            print("    %s: %s" % ("PASS" if ok else "FAIL", note))
            return ok
        print("    no press landed (attempt %d/%d): %s" % (attempt, attempts, note))
        time.sleep(2)
    RESULTS.append((cid, False, "no press landed in %d attempts" % attempts))
    print("    FAIL: no press landed in %d attempts" % attempts)
    return False


def touch_sign(con, cid, keys):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    verify(con, 0x81, BDD_PW1)
    pk = Ed25519PublicKey.from_public_bytes(keys[0xB6])
    return touch_case(
        con, cid,
        "PSO:SIGN — press BOOTSEL once inside the 10 s window after ENTER",
        [0x00, 0x2A, 0x9E, 0x9A, len(DIGEST)] + list(DIGEST),
        lambda sig: len(sig) == 64 and pk.verify(sig, DIGEST) is None,
        "ed25519-signature",
    )


def touch_intauth(con, cid, keys):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    verify(con, 0x82, BDD_PW1)
    pk = Ed25519PublicKey.from_public_bytes(keys[0xA4])
    return touch_case(
        con, cid,
        "INT-AUTH (US-926) — press BOOTSEL once inside the 10 s window after ENTER",
        [0x00, 0x88, 0x00, 0x00, len(DIGEST)] + list(DIGEST),
        lambda sig: len(sig) == 64 and pk.verify(sig, DIGEST) is None,
        "ed25519-signature",
    )


def touch_decipher(con, cid, keys):
    verify(con, 0x82, BDD_PW1)
    expected = expected_shared(keys[0xB8])
    payload = decipher_payload()
    return touch_case(
        con, cid,
        "PSO:DECIPHER — press BOOTSEL once inside the 10 s window after ENTER",
        [0x00, 0x2A, 0x80, 0x86, len(payload)] + list(payload),
        lambda shared: bytes(shared) == expected,
        "x25519-shared-secret",
    )


def harvested(con, cid):
    """C5: press BEFORE the command — the press predates the pending
    request, so the anti-harvest discipline must NOT turn it into a
    grant."""
    print("\n=== %s (ANTI-HARVEST) ===" % cid)
    print("    Press and RELEASE BOOTSEL now (once), then STOP pressing. "
          "The command opens right away.")
    verify(con, 0x81, BDD_PW1)
    print("    sending PSO:SIGN with no press pending...")
    t0 = time.monotonic()
    sw, data = apdu(con, [0x00, 0x2A, 0x9E, 0x9A, len(DIGEST)] + list(DIGEST))
    elapsed = time.monotonic() - t0
    ok = sw == 0x6982 and len(data) == 0
    note = "SW=%04X len=%d elapsed=%.1fs body-empty=%s" % (
        sw, len(data), elapsed, len(data) == 0)
    RESULTS.append((cid, ok, note))
    print("    %s: %s" % ("PASS" if ok else "FAIL", note))
    return ok


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--filter", default=",".join("C%d" % i for i in range(1, 9)))
    p.add_argument("--yes", action="store_true", help="skip setup confirmation")
    args = p.parse_args()
    cases = [c.strip().upper() for c in args.filter.split(",") if c.strip()]

    rs = [r for r in readers()]
    if not rs:
        sys.exit("no pcsc readers — restart pcscd and check the libccid allowlist")
    print("reader: %s" % rs[0])
    con = rs[0].createConnection()
    con.connect()

    # setup auto-detects: PIN personalization only while factory PW3
    # verifies; fresh keys are (re)GENERATED and captured every run.
    keys = setup(con, args.yes)

    passed = 0
    for cid in cases:
        print()
        if run_case(con, cid, keys, args.yes):
            passed += 1

    print("\n=== US-914 hardware BDD summary ===")
    for cid, ok, note in RESULTS:
        print("  %-3s %s  %s" % (cid, "PASS" if ok else "FAIL", note))
    total = len(RESULTS)
    print("  %d/%d cases passed" % (passed, total))
    con.disconnect()
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
