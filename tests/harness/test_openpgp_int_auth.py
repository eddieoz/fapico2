"""US-926: InternalAuthenticate (INS 0x88) requires a verified PW1-other
session, and is refused outright while the factory-default PINs are in
force (US-912 flag).

Own relay + emulator instance on the suite's dedicated ports with a
private secure partition, like test_openpgp_pin_gate.py.

RED (pre-US-926): a fresh, never-verified session gets a 64-byte signature
over an attacker-chosen challenge (SW=9000) from the AUTH key — the AUTH
path had no PW1 gate; the factory-defaults gate was likewise absent.
"""

import hashlib
import signal
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
RELAY_CCID_PORT = 35976  # the emulator dials in here (FAPICO2_CCID_PORT)
RELAY_CLIENT_PORT = 35984  # this test connects here

OPENPGP_AID = bytes.fromhex("D27600012401")

PW1_FACTORY = b"123456"
PW3_FACTORY = b"12345678"
PW1_NEW = b"246813"
PW3_NEW = b"86429753"

DIGEST = hashlib.sha256(b"us-926 int-auth gate").digest()
# key attributes DOs (0xC1 sign / 0xC3 aut): Ed25519 — GENKEY with the RSA
# default is slow.
KEY_ATTR_ED25519 = b"\x16\x2b\x06\x01\x04\x01\xda\x47\x0f\x01"


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

    def change_pw(self, who, old, new):
        return _sw(_ccid(self.sock, _apdu(0x24, 0x00, 0x80 + who, old + new)))

    def put_data(self, tagh, tagl, data):
        return _sw(_ccid(self.sock, _apdu(0xDA, tagh, tagl, data)))

    def genkey_aut(self):
        # CRT 0xA4 = AUT (0xB8 is DEC in this opcard).
        resp = _ccid(self.sock, _apdu(0x47, 0x80, 0x00, b"\xa4\x00", le=512))
        sw = _sw(resp)
        if (sw >> 8) == 0x61:  # more data: GET RESPONSE
            sw = _sw(_ccid(self.sock, _apdu(0xC0, 0x00, 0x00, le=sw & 0xFF)))
        return sw

    def int_auth(self, challenge):
        return _sw(_ccid(self.sock, _apdu(0x88, 0x00, 0x00, challenge, le=256)))


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


def test_int_auth_session_gate(tmp_path, monkeypatch):
    monkeypatch.setenv("FAPICO2_KEYSTORE", str(tmp_path / "ia_keystore.cbor"))
    monkeypatch.setenv("FAPICO2_SECURE_PARTITION", str(tmp_path / "ia_partition.bin"))
    monkeypatch.setenv("FAPICO2_PIV_KEYSTORE", str(tmp_path / "ia_piv.cbor"))
    # Dedicated CCID dial-in (Emu.start copies os.environ): the private
    # relay holds RELAY_CCID_PORT, not the shared harness dial-in 35963.
    monkeypatch.setenv("FAPICO2_CCID_PORT", str(RELAY_CCID_PORT))

    relay = _Relay()
    client = None
    emu = Emu(tmp_path / "ia_keystore.cbor", hid_port=35966)
    try:
        emu.start()
        relay.proc.stdout.readline()  # emulator connected line
        client = socket.create_connection(("127.0.0.1", RELAY_CLIENT_PORT), timeout=3)
        client.settimeout(15)
        _wait_relay_line(relay.proc, "[client] test client connected", 15)
        card = _Card(client)

        # --- Phase A: fresh factory card, never verified ------------------
        card.select()
        # RED (pre-US-926): INT-AUTH served a signature unverified.
        # On a factory card the US-912 factory-defaults gate (6985) fires
        # before the PW1 session gate (6982) — both are refusals.
        sw = card.int_auth(DIGEST)
        assert sw in (0x6982, 0x6985), \
            f"INT-AUTH must be refused in a fresh, unverified session (got {sw:04X})"

        # --- Phase B: provision an AUTH key with changed PINs -------------
        assert card.verify(3, PW3_FACTORY) == 0x9000
        assert card.put_data(0x00, 0xC3, KEY_ATTR_ED25519) == 0x9000
        assert card.change_pw(1, PW1_FACTORY, PW1_NEW) == 0x9000
        assert card.change_pw(3, PW3_FACTORY, PW3_NEW) == 0x9000
        assert card.genkey_aut() == 0x9000

        # --- Phase B2: provisioned but still unverified session -----------
        # PW3 verification does not arm the PW1-other session: the volatile
        # PW1 gate must refuse with 6982 on its own.
        assert card.int_auth(DIGEST) == 0x6982, \
            "INT-AUTH must be refused without a verified PW1-other session"

        # --- Phase C: verified PW1-other session -> signature -------------
        # who=2 -> P2 0x82: PW1 verification for "other" (authentication).
        assert card.verify(2, PW1_NEW) == 0x9000
        sw = card.int_auth(DIGEST)
        assert sw == 0x9000, \
            f"INT-AUTH must succeed after VERIFY PW1 mode=0x82 (got {sw:04X})"

        # --- Phase D: factory defaults in force -> refused even verified ---
        # Reverting PW1 to the shipped default re-arms the US-912 gate; the
        # default PIN would re-arm INT-AUTH trivially, so refuse outright.
        assert card.change_pw(1, PW1_NEW, PW1_FACTORY) == 0x9000
        assert card.verify(2, PW1_FACTORY) == 0x9000
        assert card.int_auth(DIGEST) == 0x6985, \
            "factory-default PW1 in force: INT-AUTH must be refused even verified"
    finally:
        emu.stop(signal.SIGTERM)
        if client is not None:
            client.close()
        relay.stop()
