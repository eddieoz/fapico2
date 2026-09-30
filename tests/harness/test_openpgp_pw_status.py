"""US-913: PW-status ships secure defaults — verification required.

The PW-status DO (0xC4) must ship "PW1 required for both" defaults and the
dispatch must honor the flag for PW1-sign vs PW1-other sessions:

- A fresh card reads byte0 == 0x00 — this firmware's encoding of
  "PW1 valid once for PSO:CDS" (openpgp-card parses 0x00 as
  ``pw1_cds_valid_once``), i.e. verification required, per PSO:SIGN.
- PSO:SIGN is refused without a PW1-sign session (0x6982); a PW1-other
  session does not unlock signing (no shortcut bypass); the strict default
  clears the sign session after every PSO:SIGN.
- INTERNAL AUTHENTICATE stays gated on a PW1-other session.
- Relaxing the flag (PUT DATA 0xC4) requires PW3: it is refused with no
  session and with a PW1-only session. Once relaxed, the sign session
  persists across PSO:SIGN.

Reboot persistence of the flag is covered by the host-level remount test
``apps/openpgp/tests/pw_status_resume.rs``: the emulation binary keeps the
OpenPGP secure partition in RAM, so a process restart starts from factory
state and cannot exercise durability.

The emulator and relay are private to this test (own keystore/partition),
like test_openpgp_pin_gate.py. pytest does not rebuild the emulator —
rebuild ``cargo build -p fapico2-firmware --bin fapico2-emulation
--no-default-features --features emulation --target x86_64-unknown-linux-gnu``
before running.
"""

import hashlib
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

from harness.test_restart import Emu

REPO = Path(__file__).resolve().parents[2]
# DEDICATED relay ports (dial-in / client), disjoint from the shared
# run_tests.sh pair (35963/35970) and from the sibling suites — see the
# port map in tests/harness/ccid_relay.py.
RELAY_CCID_PORT = 35977  # the emulator dials in here (FAPICO2_CCID_PORT)
RELAY_CLIENT_PORT = 35985  # this test connects here

OPENPGP_AID = bytes.fromhex("D27600012401")

PW1_FACTORY = b"123456"
PW3_FACTORY = b"12345678"
PW1_NEW = b"246813"
PW3_NEW = b"86429753"

DIGEST = hashlib.sha256(b"us-913 pw status").digest()
# key attributes DO (0xC1): Ed25519 — GENKEY with the RSA default is slow.
KEY_ATTR_ED25519 = b"\x16\x2b\x06\x01\x04\x01\xda\x47\x0f\x01"
# PUT PW-status: flag byte 0x01 ("PW1 valid for multiple use") + the three
# max-length bytes the card requires unchanged (0x7F).
RELAXED_PW_STATUS = b"\x01\x7f\x7f\x7f"


def _apdu(ins, p1, p2, data=b"", le=None):
    """Short/extended APDU (mirrors openpgp_card.iso7816_compose)."""
    if not data:
        if le is None:
            return bytes([0x00, ins, p1, p2])
        if le < 256:
            return bytes([0x00, ins, p1, p2, le])
        return bytes([0x00, ins, p1, p2, 0x00]) + le.to_bytes(2, "big")
    if le is None:
        return bytes([0x00, ins, p1, p2, len(data)]) + data
    if le < 256:
        return bytes([0x00, ins, p1, p2, len(data)]) + data + bytes([le])
    return bytes([0x00, ins, p1, p2, 0x00]) + len(data).to_bytes(2, "big") \
        + data + le.to_bytes(2, "big")


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("CCID connection closed")
        buf += chunk
    return bytes(buf)


def _ccid(sock, apdu):
    """One [u16 BE length] framed APDU exchange; returns body + SW bytes."""
    sock.sendall(struct.pack(">H", len(apdu)) + apdu)
    (length,) = struct.unpack(">H", _recv_exact(sock, 2))
    return _recv_exact(sock, length)


def _sw(resp):
    return (resp[-2] << 8) | resp[-1]


class _Card:
    """Raw-APDU OpenPGP card over the relayed CCID connection."""

    def __init__(self, sock):
        self.sock = sock

    def select(self):
        assert _sw(_ccid(self.sock, _apdu(0xA4, 0x04, 0x00, OPENPGP_AID))) == 0x9000

    def verify(self, who, pin):
        return _sw(_ccid(self.sock, _apdu(0x20, 0x00, 0x80 + who, pin)))

    def reset_sessions(self):
        """VERIFY RESET (P1=0xFF) clears each volatile session."""
        for p2 in (0x81, 0x82, 0x83):
            assert _sw(_ccid(self.sock, _apdu(0x20, 0xFF, p2))) == 0x9000

    def change_pw(self, who, old, new):
        return _sw(_ccid(self.sock, _apdu(0x24, 0x00, 0x80 + who, old + new)))

    def pso_sign(self, digest):
        return _sw(_ccid(self.sock, _apdu(0x2A, 0x9E, 0x9A, digest, le=256)))

    def internal_auth(self, digest):
        return _sw(_ccid(self.sock, _apdu(0x88, 0x00, 0x00, digest, le=256)))

    def genkey(self):
        resp = _ccid(self.sock, _apdu(0x47, 0x80, 0x00, b"\xb6\x00", le=512))
        sw = _sw(resp)
        if (sw >> 8) == 0x61:  # more data: GET RESPONSE
            sw = _sw(_ccid(self.sock, _apdu(0xC0, 0x00, 0x00, le=sw & 0xFF)))
        return sw

    def put_data(self, tagh, tagl, data):
        return _sw(_ccid(self.sock, _apdu(0xDA, tagh, tagl, data)))

    def get_c4(self):
        resp = _ccid(self.sock, _apdu(0xCA, 0x00, 0xC4))
        assert _sw(resp) == 0x9000
        return resp[:-2]


def _wait_relay_line(proc, needle, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        if needle in line:
            return
    raise AssertionError(f"ccid relay did not report {needle!r} within {timeout}s")


class _Relay:
    """CCID relay on the suite's dedicated ports for the private emulator."""

    def __init__(self):
        self.proc = subprocess.Popen(
            [sys.executable, str(REPO / "tests" / "harness" / "ccid_relay.py"),
             "--ccid-port", str(RELAY_CCID_PORT),
             "--client-port", str(RELAY_CLIENT_PORT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        _wait_relay_line(self.proc, "READY", timeout=10)

    def stop(self):
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        self.proc = None


def test_pw_status_secure_defaults(tmp_path, monkeypatch):
    monkeypatch.setenv("FAPICO2_KEYSTORE", str(tmp_path / "pw_keystore.cbor"))
    monkeypatch.setenv("FAPICO2_SECURE_PARTITION", str(tmp_path / "pw_partition.bin"))
    monkeypatch.setenv("FAPICO2_PIV_KEYSTORE", str(tmp_path / "pw_piv.cbor"))
    # Dedicated CCID dial-in (Emu.start copies os.environ): the private
    # relay holds RELAY_CCID_PORT, not the shared harness dial-in 35963.
    monkeypatch.setenv("FAPICO2_CCID_PORT", str(RELAY_CCID_PORT))

    relay = _Relay()
    client = None
    emu = Emu(tmp_path / "pw_keystore.cbor", hid_port=35967)
    try:
        emu.start()
        relay.proc.stdout.readline()  # emulator connected line
        client = socket.create_connection(("127.0.0.1", RELAY_CLIENT_PORT), timeout=3)
        client.settimeout(15)
        _wait_relay_line(relay.proc, "[client] test client connected", 15)
        card = _Card(client)

        # --- Fresh card ships "PW1 required for both" ---------------------
        card.select()
        c4 = card.get_c4()
        assert len(c4) == 7
        # Byte0 == 0x00: PW1 valid once for PSO:CDS (verification required).
        # (0x01 would advertise the relaxed "valid for multiple use" flag.)
        assert c4[0] == 0x00, "fresh card must ship PW1-required-for-sign"

        # Personalize (US-912 gate) and generate the sign key.
        assert card.change_pw(1, PW1_FACTORY, PW1_NEW) == 0x9000
        assert card.change_pw(3, PW3_FACTORY, PW3_NEW) == 0x9000
        assert card.verify(3, PW3_NEW) == 0x9000
        assert card.put_data(0x00, 0xC1, KEY_ATTR_ED25519) == 0x9000
        assert card.put_data(0x00, 0xC3, KEY_ATTR_ED25519) == 0x9000
        assert card.genkey() == 0x9000  # sign key (0xB6)
        resp = _ccid(client, _apdu(0x47, 0x80, 0x00, b"\xa4\x00", le=512))
        sw = _sw(resp)
        if (sw >> 8) == 0x61:
            sw = _sw(_ccid(client, _apdu(0xC0, 0x00, 0x00, le=sw & 0xFF)))
        assert sw == 0x9000  # auth key (0xA4)

        # --- Strict default honored: sign needs a PW1-sign session --------
        # No session: PSO:SIGN and INTERNAL AUTHENTICATE refused.
        assert card.pso_sign(DIGEST) == 0x6982, \
            "PSO:SIGN must require PW1 verification"
        assert card.internal_auth(DIGEST) == 0x6982, \
            "INTERNAL AUTHENTICATE must require a PW1-other session"
        # PW1-other session does NOT unlock signing (no shortcut bypass).
        assert card.verify(2, PW1_NEW) == 0x9000
        assert card.pso_sign(DIGEST) == 0x6982, \
            "PW1-other session must not unlock PSO:SIGN"
        # ...but it does unlock "other" operations.
        assert card.internal_auth(DIGEST) == 0x9000
        # PW1-sign session unlocks one PSO:SIGN; the strict default then
        # clears the session — the next PSO:SIGN needs a fresh VERIFY.
        assert card.verify(1, PW1_NEW) == 0x9000
        assert card.pso_sign(DIGEST) == 0x9000
        assert card.pso_sign(DIGEST) == 0x6982, \
            "strict default: sign session cleared after each PSO:SIGN"

        # --- Relaxing the flag requires PW3 -------------------------------
        # Start from a clean slate: VERIFY RESET clears every session.
        card.reset_sessions()
        assert card.put_data(0x00, 0xC4, RELAXED_PW_STATUS) == 0x6982, \
            "PUT PW-status must require PW3"
        # A PW1 session is not enough.
        assert card.verify(1, PW1_NEW) == 0x9000
        # Admin session authorizes the relaxation.
        assert card.verify(3, PW3_NEW) == 0x9000
        assert card.put_data(0x00, 0xC4, RELAXED_PW_STATUS) == 0x9000
        assert card.get_c4()[0] == 0x01, "relaxed flag must read back"

        # --- Relaxed flag honored, PW1 still gates each session -----------
        # Sessions do not survive a RESET: without PW1 the PSO is refused
        # even though the flag is now relaxed.
        card.reset_sessions()
        assert card.pso_sign(DIGEST) == 0x6982
        # With PW1-sign verified once, the relaxed flag keeps the session
        # alive across PSO:SIGN.
        assert card.verify(1, PW1_NEW) == 0x9000
        assert card.pso_sign(DIGEST) == 0x9000
        assert card.pso_sign(DIGEST) == 0x9000, \
            "relaxed flag: sign session must persist"
    finally:
        emu.stop()
        if client is not None:
            client.close()
        relay.stop()
