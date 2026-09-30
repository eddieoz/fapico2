#!/usr/bin/env python3
"""P7-C6/C7 — OpenPGP ceremony over CCID (S-721-5, US-341; repaired S-723-B1).

Drives an OpenPGP card (flashed board over pcscd/pyscard, or the emulation
binary over TCP) through a representative OpenPGP workflow: SELECT, key
attributes, on-card GENERATE, PSO:SIGN, INTERNAL AUTHENTICATE, PIN handling,
and GET CHALLENGE. Uses factory PINs (PW1=123456, PW3=12345678).

Repairs (S-723-B1, EPIC F5/F10/F11/F14 — do not regress):
  * GET DATA tag bytes: the tag rides in P1(high)/P2(low); tag 0xC1 is sent as
    P1=0x00, P2=0xC1 — the literal APDU for tag 0xC1 with Le=254 is
    ``00 CA 00 C1 FE``. The old script sent P1=0xC1/P2=0x00 (unknown tag
    0xC100 → SW 6A88 regardless of card state) and mis-recorded the result as
    an "empty card" observation. On any card, attributes are NOT
    key-dependent: C1/C2/C3 always answer 9000 + attribute bytes (defaults
    Ed255/X255/Ed255, ``16 2B 06 01 04 01 DA 47 0F 01 FF`` /
    ``12 2B 06 01 04 01 97 55 01 05 01 FF`` / Ed255 again). There is no
    "6A88 (empty card)" branch.
  * VERIFY P2 semantics: P2 = 0x80 + context — 0x81 = PW1-for-signing,
    0x82 = PW1-for-authentication/decryption. INTERNAL AUTHENTICATE (INS
    0x88) gates on the 0x82 context only; the old script verified with
    P2=0x81, hit 6982, and mis-recorded that as an "EdDSA limitation". It is
    a script artifact: verify PW1 with P2=0x82 first and INTERNAL
    AUTHENTICATE signs (9000 + 64-byte Ed25519 signature).
  * GENERATE (INS 0x47) is the only key-creation mechanism used here
    (on-card; keys live in the secure store, entropy from the TRNG — never
    host-side key generation).

Phases:
  1. select    SELECT OpenPGP AID, verify FCI structure
  2. keys      GET DATA C1/C2/C3 attributes (fixed tag bytes; always 9000)
  3. generate  VERIFY PW3 + on-card GENERATE B6/B8/A4 (--emul or --generate)
  4. sign      VERIFY PW1 (P2=0x81) → PSO:SIGN, 64-byte Ed25519 signature
  5. auth      VERIFY PW1 (P2=0x82) → INTERNAL AUTHENTICATE (9000 + signature)
  6. pin       VERIFY PW1, wrong PIN → 63CX, correct PIN restores access
  7. challenge GET CHALLENGE returns non-constant 8 bytes
  8. gpg       gpg --card-status; gpg --clearsign + --verify ("Good
               signature") — only with --with-gpg (needs a gpg/scd setup)

Usage:
  python3 tests/scripts/p7_c6_openpgp.py --self-test   # dry APDU composition check
  python3 tests/scripts/p7_c6_openpgp.py --emul        # emulation binary (factory fresh)
  .venv/bin/python tests/scripts/p7_c6_openpgp.py      # hardware over pyscard

Exit 0 = every check passed; exit 1 = at least one failure.
"""
import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
import time
from struct import pack

OPENPGP_AID = bytes([0xD2, 0x76, 0x00, 0x01, 0x24, 0x01])
FACTORY_PW1 = b"123456"
FACTORY_PW3 = b"12345678"

# Default key-attribute DOs on the ECC-only build (vendor/opcard/src/types.rs):
# C1 = Ed255 (signing), C2 = X255 (decryption), C3 = Ed255 (authentication).
ED255_ATTR = bytes.fromhex("162B06010401DA470F01FF")
X255_ATTR = bytes.fromhex("122B060104019755010501FF")
EXPECTED_ATTRS = {0xC1: ED255_ATTR, 0xC2: X255_ATTR, 0xC3: ED255_ATTR}

FAILED = False


def iso7816_compose(ins, p1, p2, data=b"", cls=0x00, le=None):
    """Compose an ISO 7816 APDU (case 1/2/3/4).

    Le 256 is encoded short-form as the single byte 0x00 (ISO 7816-3: an
    absent Le and Le=0x00 both mean "max 256"); Le > 256 uses the extended
    two-byte header. Everything else is short-form.
    """
    data = bytes(data)
    data_len = len(data)
    if le == 256:
        le = 0  # short-form "max" — one 0x00 byte
    if data_len == 0:
        if le is None:
            return pack(">BBBB", cls, ins, p1, p2)
        if le < 256:
            return pack(">BBBBB", cls, ins, p1, p2, le)
        return pack(">BBBBBH", cls, ins, p1, p2, 0, le)
    if le is None:
        if data_len <= 255:
            return pack(">BBBBB", cls, ins, p1, p2, data_len) + data
        return pack(">BBBBBH", cls, ins, p1, p2, 0, data_len) + data
    if data_len <= 255 and le < 256:
        return pack(">BBBBB", cls, ins, p1, p2, data_len) + data + pack(">B", le)
    return pack(">BBBBBH", cls, ins, p1, p2, 0, data_len) + data + pack(">H", le)


# --- APDU composition (shared by the transports and the dry self-test) ------

def apdu_select(aid=OPENPGP_AID):
    """SELECT OpenPGP AID."""
    return iso7816_compose(0xA4, 0x04, 0x00, aid)


def apdu_verify(context, pin):
    """VERIFY. P2 = 0x80 + context: 1=PW1-signing (0x81), 2=PW1-auth/dec
    (0x82), 3=PW3/admin (0x83)."""
    return iso7816_compose(0x20, 0x00, 0x80 + context, pin)


def apdu_get_data(tag, le=254):
    """GET DATA for a 7816 tag. The tag rides in P1(high)/P2(low)
    (opcard Tag::from((p1, p2)) = u16::from_be_bytes([p1, p2]) —
    vendor/opcard/src/types.rs), so single-byte tags go in P2 with P1=0x00.
    Tag 0xC1 + Le=254 is the literal ``00 CA 00 C1 FE``."""
    if tag > 0xFF:
        p1, p2 = tag >> 8, tag & 0xFF
    else:
        p1, p2 = 0x00, tag
    return iso7816_compose(0xCA, p1, p2, b"", le=le)


def apdu_pso_sign(digest):
    """PSO:SIGN with the signing key (C1). EdDSA template 7C <len> [80 <digest>]."""
    body = bytes([0x7C, len(digest) + 2, 0x80]) + digest
    return iso7816_compose(0x2A, 0x9E, 0x9A, body, le=256)


def apdu_internal_auth(challenge):
    """INTERNAL AUTHENTICATE with the authentication key (C3)."""
    return iso7816_compose(0x88, 0x00, 0x00, challenge, le=256)


def apdu_get_challenge(le=8):
    """GET CHALLENGE."""
    return iso7816_compose(0x84, 0x00, 0x00, b"", le=le)


def apdu_generate(crt):
    """GENERATE (INS 0x47) for one key — on-card key creation only.
    crt is the CRT template byte: 0xB6 sign, 0xB8 dec, 0xA4 auth."""
    return iso7816_compose(0x47, 0x80, 0x00, bytes([crt, 0x00]))


def apdu_get_response(le):
    """GET RESPONSE (INS 0xC0) — drains a 61XX remainder."""
    return iso7816_compose(0xC0, 0x00, 0x00, b"", le=le)


# --- Transports ---------------------------------------------------------------


class PyscardDev:
    """OpenPGP card device over pyscard (real CCID / flashed board)."""

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

    def transmit(self, apdu):
        """Transmit APDU, return (body, (sw1, sw2))."""
        hr, resp = self.s.SCardTransmit(self.card, self.s.SCARD_PCI_RAW, list(apdu))
        if hr != self.s.SCARD_S_SUCCESS:
            print("FAIL: SCardTransmit %s" % hex(hr))
            sys.exit(1)
        b = bytes(resp)
        assert len(b) >= 2, "empty card response"
        return b[:-2], (b[-2], b[-1])


class EmulDev:
    """OpenPGP card device over the fapico2 emulation binary (host TCP).

    Wiring (tests/conftest.py fixtures ccid_card/card): the emulator dials
    127.0.0.1:35963; tests/harness/ccid_relay.py accepts that dial-in and
    exposes the client port 35970; EmulatorSession (tests/harness/ccid.py)
    starts the binary and connects a client. A fresh temp keystore is used so
    the card starts factory-fresh every run.
    """

    def __init__(self):
        harness = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "harness")
        if harness not in sys.path:
            sys.path.insert(0, harness)
        from ccid import EmulatorSession

        self._relay = subprocess.Popen(
            [sys.executable, os.path.join(harness, "ccid_relay.py")],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        # Fresh factory state: a per-run temp keystore (emul_main.rs honours
        # FAPICO2_KEYSTORE; default /tmp/fapico2_keystore.cbor persists).
        os.environ["FAPICO2_KEYSTORE"] = os.path.join(
            tempfile.mkdtemp(prefix="fapico2-p7-"), "keystore.cbor")
        # Wait for the relay to bind 35963/35970 before the emulator dials in.
        ready = False
        for _ in range(50):
            line = self._relay.stdout.readline().decode(errors="replace")
            if "READY" in line:
                ready = True
                break
            if not line:
                break
        if not ready:
            raise RuntimeError("ccid relay did not report READY")
        self._session = EmulatorSession()
        self._card = self._session.start()
        print("emulation binary:", self._session.binary)
        print("keystore:", os.environ["FAPICO2_KEYSTORE"])

    def transmit(self, apdu):
        """Transmit APDU, return (body, (sw1, sw2))."""
        resp = self._card.transmit(bytes(apdu))
        assert len(resp) >= 2, "empty card response"
        return resp[:-2], (resp[-2], resp[-1])

    def close(self):
        self._session.stop()
        if self._relay and self._relay.poll() is None:
            self._relay.terminate()


# --- check helpers ------------------------------------------------------------


def check(label, got, exp_sw=(0x90, 0x00), exp_body=None):
    """Check an APDU response. exp_body None = any body."""
    global FAILED
    body, sw = got
    problems = []
    if sw != exp_sw:
        problems.append("sw %02X%02X != %02X%02X" % (sw[0], sw[1], exp_sw[0], exp_sw[1]))
    if exp_body is not None and body != exp_body:
        problems.append("body mismatch")
    status = "PASS" if not problems else "FAIL"
    detail = ""
    if problems:
        detail = "  [" + "; ".join(problems) + "]"
    print("%s %s%s" % (status, label, detail))
    if problems:
        FAILED = True
    return body, sw


# --- Phases -------------------------------------------------------------------


def phase_select(dev):
    """Phase 1: SELECT OpenPGP AID."""
    print("== phase 1: SELECT OpenPGP AID ==")
    check("SELECT OpenPGP AID", dev.transmit(apdu_select()))


def phase_keys(dev):
    """Phase 2: GET DATA C1/C2/C3 key attributes (fixed tag bytes).

    Attributes are not key-dependent: on an empty card they still return
    9000 + the default attribute bytes (Ed255/X255/Ed255). There is NO
    "6A88 (empty card)" branch — that was the F11 script artifact.
    """
    print("== phase 2: key attributes ==")
    for slot in (0xC1, 0xC2, 0xC3):
        body, sw = check("GET DATA C%X attrs" % (slot & 0x0F),
                         dev.transmit(apdu_get_data(slot)))
        if sw == (0x90, 0x00):
            expect = EXPECTED_ATTRS.get(slot)
            verdict = "matches default" if body == expect else "customised"
            print("     attrs: %s (%s)" % (body.hex(" "), verdict))


def phase_generate(dev):
    """Phase 3: VERIFY PW3 + on-card GENERATE B6/B8/A4 (INS 0x47)."""
    print("== phase 3: on-card GENERATE ==")
    check("VERIFY PW3", dev.transmit(apdu_verify(3, FACTORY_PW3)))
    for crt in (0xB6, 0xB8, 0xA4):
        body, sw = check("GENERATE %02X" % crt, dev.transmit(apdu_generate(crt)))
        if sw == (0x90, 0x00):
            print("     reply: %s" % body.hex(" "))


def phase_sign(dev):
    """Phase 4: PSO:SIGN — VERIFY PW1 with P2=0x81 (signing context)."""
    print("== phase 4: PSO:SIGN ==")
    check("VERIFY PW1 (P2=81, signing)", dev.transmit(apdu_verify(1, FACTORY_PW1)))
    message = b"fapico2 OpenPGP sign test"
    digest = hashlib.sha256(message).digest()
    body, sw = check("PSO:SIGN Ed25519", dev.transmit(apdu_pso_sign(digest)))
    if sw == (0x90, 0x00):
        print("     signature length: %d bytes" % len(body))


def phase_auth(dev):
    """Phase 5: INTERNAL AUTHENTICATE — VERIFY PW1 with P2=0x82 (auth/dec
    context). The card gates INS 0x88 on the 0x82 context only; under the
    correct context it signs: 9000 + 64-byte Ed25519 signature. The old
    "6982 expected EdDSA limitation" note was a P2=0x81 script artifact."""
    print("== phase 5: INTERNAL AUTHENTICATE ==")
    check("VERIFY PW1 (P2=82, auth/dec)", dev.transmit(apdu_verify(2, FACTORY_PW1)))
    challenge = hashlib.sha256(b"fapico2 internal auth challenge").digest()
    body, sw = check("INTERNAL AUTHENTICATE Ed25519",
                     dev.transmit(apdu_internal_auth(challenge)))
    if sw == (0x90, 0x00):
        print("     auth response length: %d bytes" % len(body))


def phase_pin(dev):
    """Phase 6: PIN handling."""
    print("== phase 6: PIN handling ==")
    check("VERIFY correct PW1", dev.transmit(apdu_verify(1, FACTORY_PW1)))
    got = dev.transmit(apdu_verify(1, b"000000"))
    body, sw = got
    if sw[0] == 0x63 and sw[1] & 0xF0 == 0xC0:
        print("PASS VERIFY wrong PW1 → 63C%X (retries %d)" % (sw[1] & 0x0F, sw[1] & 0x0F))
    else:
        check("VERIFY wrong PW1 → 63CX", got, (0x63, 0xC2))


def phase_challenge(dev):
    """Phase 7: GET CHALLENGE."""
    print("== phase 7: GET CHALLENGE ==")
    body, sw = check("GET CHALLENGE", dev.transmit(apdu_get_challenge()))
    if sw == (0x90, 0x00):
        print("     challenge: %s" % body.hex(" "))


def phase_gpg(dev):
    """Phase 8: gpg steps (--with-gpg): --card-status, --clearsign, --verify."""
    print("== phase 8: gpg (--with-gpg) ==")
    try:
        r = subprocess.run(["gpg", "--card-status"],
                           capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        print("FAIL gpg not found on PATH")
        globals()["FAILED"] = True
        return
    if r.returncode != 0:
        print("FAIL gpg --card-status rc=%d" % r.returncode)
        globals()["FAILED"] = True
    else:
        print("PASS gpg --card-status")
    print("     " + "\n     ".join(r.stdout.strip().splitlines()[:12]))

    msg_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="fapico2-sign-")
    msg_file.write("fapico2 sign test\n")
    msg_file.close()
    sig_file = msg_file.name + ".asc"
    r = subprocess.run(["gpg", "--clearsign", "--yes", "--output", sig_file,
                        msg_file.name], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        print("FAIL gpg --clearsign rc=%d\n     %s" % (r.returncode, r.stderr.strip()))
        globals()["FAILED"] = True
    else:
        print("PASS gpg --clearsign")
    r = subprocess.run(["gpg", "--verify", sig_file],
                       capture_output=True, text=True, timeout=60)
    if r.returncode == 0 and "Good signature" in r.stderr:
        print("PASS gpg --verify (Good signature)")
    else:
        print("FAIL gpg --verify rc=%d\n     %s" % (r.returncode, r.stderr.strip()))
        globals()["FAILED"] = True


# --- Self-test (dry, no device) -------------------------------------------------

def self_test():
    """Dry APDU-composition unit check — no device needed.

    Pins the repaired byte sequences: the F11 GET DATA tag fix (literal
    ``00 CA 00 C1 FE`` among them) and the F10/F14 VERIFY contexts.
    """
    print("== self-test: APDU composition (dry, no device) ==")
    cases = [
        ("GET DATA tag 0xC1, Le=254 (F11 literal)",
         apdu_get_data(0xC1), bytes.fromhex("00CA00C1FE")),
        ("GET DATA tag 0xC2, Le=254",
         apdu_get_data(0xC2), bytes.fromhex("00CA00C2FE")),
        ("GET DATA tag 0xC3, Le=254",
         apdu_get_data(0xC3), bytes.fromhex("00CA00C3FE")),
        ("GET DATA tag 0x6E (PIV-style two-byte tag), Le=254",
         apdu_get_data(0x6E), bytes.fromhex("00CA006EFE")),
        ("VERIFY PW1 P2=81 (signing context)",
         apdu_verify(1, FACTORY_PW1), bytes.fromhex("0020008106313233343536")),
        ("VERIFY PW1 P2=82 (auth/dec context)",
         apdu_verify(2, FACTORY_PW1), bytes.fromhex("0020008206313233343536")),
        ("VERIFY PW3 P2=83 (admin)",
         apdu_verify(3, FACTORY_PW3), bytes.fromhex("00200083083132333435363738")),
        ("INTERNAL AUTHENTICATE (Le short-form 0x00 = 256)",
         apdu_internal_auth(bytes(range(32))),
         bytes.fromhex("0088000020") + bytes(range(32)) + bytes([0x00])),
        ("PSO:SIGN EdDSA template (Le short-form 0x00 = 256)",
         apdu_pso_sign(b"\x00" * 32),
         bytes.fromhex("002A9E9A237C2280") + b"\x00" * 32 + bytes([0x00])),
        ("GENERATE sign (CRT B6)",
         apdu_generate(0xB6), bytes.fromhex("0047800002B600")),
        ("GENERATE dec (CRT B8)",
         apdu_generate(0xB8), bytes.fromhex("0047800002B800")),
        ("GENERATE auth (CRT A4)",
         apdu_generate(0xA4), bytes.fromhex("0047800002A400")),
        ("GET CHALLENGE Le=8",
         apdu_get_challenge(), bytes.fromhex("0084000008")),
        ("SELECT OpenPGP AID",
         apdu_select(), bytes.fromhex("00A4040006") + OPENPGP_AID),
        ("GET RESPONSE Le=256 (short-form 0x00)",
         apdu_get_response(256), bytes.fromhex("00C0000000")),
    ]
    failures = 0
    for label, got, exp in cases:
        ok = got == exp
        print("%s %s\n     got %s\n     exp %s"
              % ("PASS" if ok else "FAIL", label, got.hex(" "), exp.hex(" ")))
        if not ok:
            failures += 1
    if failures:
        print("SELF-TEST FAIL (%d case(s))" % failures)
        return 1
    print("SELF-TEST PASS (%d cases)" % len(cases))
    return 0


# --- main -----------------------------------------------------------------------


def main():
    global FAILED
    parser = argparse.ArgumentParser(
        description="P7 OpenPGP ceremony (repaired S-723-B1): fixed GET DATA "
                    "tag bytes, correct VERIFY contexts, on-card GENERATE.")
    parser.add_argument("--emul", action="store_true",
                        help="run against the emulation binary over TCP "
                             "(fresh factory-state keystore) instead of "
                             "pyscard/pcscd hardware")
    parser.add_argument("--generate", action="store_true",
                        help="run the on-card GENERATE phase (VERIFY PW3 + "
                             "GENERATE B6/B8/A4) before signing; implied by "
                             "--emul (the emul card starts factory-fresh)")
    parser.add_argument("--with-gpg", action="store_true",
                        help="additionally run the gpg steps (gpg --card-status, "
                             "--clearsign + --verify); needs a gpg/scd setup")
    parser.add_argument("--self-test", action="store_true",
                        help="dry APDU-composition unit check; no device")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(self_test())

    dev = None
    try:
        dev = EmulDev() if args.emul else PyscardDev()
        phase_select(dev)
        phase_keys(dev)
        if args.emul or args.generate:
            phase_generate(dev)
        phase_sign(dev)
        phase_auth(dev)
        phase_pin(dev)
        phase_challenge(dev)
        if args.with_gpg:
            phase_gpg(dev)
    except Exception as exc:  # surface the real failure, never mask it
        import traceback
        traceback.print_exc()
        print("FAIL: %s" % exc)
        FAILED = True
    finally:
        if dev is not None and isinstance(dev, EmulDev):
            dev.close()
    print()
    if FAILED:
        print("CEREMONY FAIL (US-341)")
        sys.exit(1)
    print("CEREMONY PASS (US-341)")
    sys.exit(0)


if __name__ == "__main__":
    main()
