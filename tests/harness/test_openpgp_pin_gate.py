"""US-912: factory-default PIN gate — PSO/GENKEY/TERMINATE DF refused until
PW1 *and* PW3 have been changed away from the shipped defaults.

Own relay + emulator instance on the suite's dedicated ports with a
private secure partition, like test_boot_refuse.py. The durable
"factory-defaults-in-force" flag must survive an emulator restart while it
is still armed, clear only after BOTH PINs changed (changing one keeps the
gate armed), and GENERATE/PSO must work once the flag is gone.

RED (pre-US-912): on a factory card the default PINs verify and
PSO:SIGN / GENKEY / TERMINATE DF are served instead of 0x6985.
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
RELAY_CCID_PORT = 35978  # the emulator dials in here (FAPICO2_CCID_PORT)
RELAY_CLIENT_PORT = 35986  # this test connects here

OPENPGP_AID = bytes.fromhex("D27600012401")

PW1_FACTORY = b"123456"
PW3_FACTORY = b"12345678"
PW1_NEW = b"246813"
PW3_NEW = b"86429753"

DIGEST = hashlib.sha256(b"us-912 pin gate").digest()
# key attributes DO (0xC1): Ed25519 — GENKEY with the RSA default is slow.
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

    def pso_sign(self, digest):
        return _sw(_ccid(self.sock, _apdu(0x2A, 0x9E, 0x9A, digest, le=256)))

    def genkey(self):
        resp = _ccid(self.sock, _apdu(0x47, 0x80, 0x00, b"\xb6\x00", le=512))
        sw = _sw(resp)
        if (sw >> 8) == 0x61:  # more data: GET RESPONSE
            sw = _sw(_ccid(self.sock, _apdu(0xC0, 0x00, 0x00, le=sw & 0xFF)))
        return sw

    def terminate_df(self):
        return _sw(_ccid(self.sock, _apdu(0xE6, 0x00, 0x00)))

    def put_data(self, tagh, tagl, data):
        return _sw(_ccid(self.sock, _apdu(0xDA, tagh, tagl, data)))


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


def test_factory_pin_gate(tmp_path, monkeypatch):
    monkeypatch.setenv("FAPICO2_KEYSTORE", str(tmp_path / "gate_keystore.cbor"))
    monkeypatch.setenv("FAPICO2_SECURE_PARTITION", str(tmp_path / "gate_partition.bin"))
    monkeypatch.setenv("FAPICO2_PIV_KEYSTORE", str(tmp_path / "gate_piv.cbor"))
    # Dedicated CCID dial-in (Emu.start copies os.environ; both emulator
    # starts in this test inherit it): the private relay holds
    # RELAY_CCID_PORT, not the shared harness dial-in 35963.
    monkeypatch.setenv("FAPICO2_CCID_PORT", str(RELAY_CCID_PORT))

    relay = _Relay()
    client = None
    emu = Emu(tmp_path / "gate_keystore.cbor", hid_port=35966)
    try:
        emu.start()
        relay.proc.stdout.readline()  # emulator connected line
        client = socket.create_connection(("127.0.0.1", RELAY_CLIENT_PORT), timeout=3)
        client.settimeout(15)
        _wait_relay_line(relay.proc, "[client] test client connected", 15)
        card = _Card(client)

        # --- Phase A: fresh factory card, gate in force ------------------
        card.select()
        assert card.verify(3, PW3_FACTORY) == 0x9000
        assert card.verify(1, PW1_FACTORY) == 0x9000

        # PSO:SIGN refused while the factory defaults are in force.
        assert card.pso_sign(DIGEST) == 0x6985
        # GENERATE (INS 0x47) refused as well.
        assert card.genkey() == 0x6985
        # TERMINATE DF refused as well.
        assert card.terminate_df() == 0x6985

        # --- Phase B: the flag is durable — restart the emulator ---------
        emu.stop(signal.SIGTERM)
        emu = Emu(tmp_path / "gate_keystore.cbor", hid_port=35966)
        emu.start()
        relay.proc.stdout.readline()  # emulator connected line
        card.select()
        assert card.verify(3, PW3_FACTORY) == 0x9000
        assert card.genkey() == 0x6985, "gate must persist across restart"

        # --- Phase C: changing PW1 alone keeps the gate armed ------------
        assert card.change_pw(1, PW1_FACTORY, PW1_NEW) == 0x9000
        assert card.genkey() == 0x6985, "PW3 still factory: gate stays armed"

        # --- Phase D: changing PW3 too clears the gate --------------------
        assert card.change_pw(3, PW3_FACTORY, PW3_NEW) == 0x9000
        assert card.verify(3, PW3_NEW) == 0x9000
        # Fresh GENERATE flow works once the factory defaults are gone.
        assert card.put_data(0x00, 0xC1, KEY_ATTR_ED25519) == 0x9000
        assert card.genkey() == 0x9000
        # PSO:SIGN proceeds with the new PW1.
        assert card.verify(1, PW1_NEW) == 0x9000
        sig_sw = card.pso_sign(DIGEST)
        assert sig_sw == 0x9000, "PSO:SIGN must proceed once the gate is cleared"

        # --- Phase E: reverting to the factory PIN re-arms the gate -------
        # The flag is an assignment derived from the stored PIN, so changing
        # a PIN back to its shipped default re-arms the gate (no |=).
        assert card.change_pw(1, PW1_NEW, PW1_FACTORY) == 0x9000
        assert card.genkey() == 0x6985, "PW1 reverted: gate must be armed again"
        assert card.verify(1, PW1_FACTORY) == 0x9000
        assert card.pso_sign(DIGEST) == 0x6985, \
            "factory PW1 in force: PSO:SIGN must be refused again"
        # Re-change both: the gate lifts again and key ops work.
        assert card.change_pw(1, PW1_FACTORY, PW1_NEW) == 0x9000
        assert card.change_pw(3, PW3_NEW, PW3_FACTORY) == 0x9000
        assert card.genkey() == 0x6985, "PW3 factory: gate stays armed"
        assert card.change_pw(3, PW3_FACTORY, PW3_NEW) == 0x9000
        assert card.verify(3, PW3_NEW) == 0x9000
        assert card.verify(1, PW1_NEW) == 0x9000
        assert card.genkey() == 0x9000, "gate must lift again after both re-changed"
    finally:
        emu.stop(signal.SIGTERM)
        if client is not None:
            client.close()
        relay.stop()
