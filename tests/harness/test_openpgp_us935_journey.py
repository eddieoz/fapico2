"""US-935: gpg terminal-mode PIN journey — regression guard (no firmware fix).

US-933's device capture closed the epic's hypothesis split: the reported
``gpg --edit-card → passwd`` failure (``Error changing the PIN``) was NOT a
firmware defect. The captured failing exchange
(``CRD 0x24 0x81 123456‖123123`` → ``6300``,
docs/tasks/evidence/us933-device-trace-migration.txt) came from
non-factory card state — an earlier capture script had left PW1 at
``123123`` while gpg sent the factory PW1 as ``old`` — and gpg renders the
card's spec-correct bare ``6300`` (VerificationFailed, no retry info) as a
generic ``Card error``. Therefore the epic's "red test from capture" clause
is satisfied VACUOUSLY: the capture demonstrated no firmware red state to
reproduce, and US-935 ships this journey lock instead of a fix.

This test locks the ALL-GREEN journey captured on the device at HEAD
(docs/tasks/evidence/us933-device-trace-journey.txt, §6b of
docs/tasks/openpgp-pw3-change-rootcause.md). The byte-for-byte-in-shape
claim covers only the FOUR captured journey APDUs below — select plus the
three PIN-change steps; nothing in the trace beyond them is asserted:

  select → CRD(0x24, 0x81, 123456‖246813) → 9000        (passwd 1)
         → CRD(0x24, 0x83, 12345678‖13572468) → 9000    (passwd 3 — the
           previously "failing" APDU)
         → VERIFY(0x20, 0x83, 13572468) → 9000          (new Admin PIN)

The GENERATE slice around it intentionally follows the US-912 pin-gate
SHORT-FORM contract (GENKEY P1=0x80 → 6985 while the gate is armed, 9000
once both PINs left their factory defaults), NOT the device trace's
extended-form GENKEY rows (which answered 6A88 on a factory card with no
key material) — the pin-gate test owns the gate contract; this test only
re-asserts the journey's slice.

Own relay + emulator instance on dedicated ports with a private secure
partition, like test_openpgp_pin_gate.py. pytest does not rebuild the
emulator — rebuild ``cargo build -p fapico2-firmware --bin
fapico2-emulation --no-default-features --features emulation --target
x86_64-unknown-linux-gnu`` before running.
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
# run_tests.sh pair (35963/35970), from test_socket_transport.py's
# dial-in-only 35979, and from the sibling suites — see the port map in
# tests/harness/ccid_relay.py.
RELAY_CCID_PORT = 35980  # the emulator dials in here (FAPICO2_CCID_PORT)
RELAY_CLIENT_PORT = 35987  # this test connects here

OPENPGP_AID = bytes.fromhex("D27600012401")

# The captured journey's PIN values (us933-device-trace-journey.txt):
# PW1 123456 → 246813, PW3 12345678 → 13572468.
PW1_FACTORY = b"123456"
PW3_FACTORY = b"12345678"
PW1_NEW = b"246813"
PW3_NEW = b"13572468"

DIGEST = hashlib.sha256(b"us-935 gpg terminal journey").digest()
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

    def genkey(self):
        resp = _ccid(self.sock, _apdu(0x47, 0x80, 0x00, b"\xb6\x00", le=512))
        sw = _sw(resp)
        if (sw >> 8) == 0x61:  # more data: GET RESPONSE
            sw = _sw(_ccid(self.sock, _apdu(0xC0, 0x00, 0x00, le=sw & 0xFF)))
        return sw

    def pso_sign(self, digest):
        return _sw(_ccid(self.sock, _apdu(0x2A, 0x9E, 0x9A, digest, le=256)))

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


def test_us935_journey_gpg_terminal_flow_is_green(tmp_path, monkeypatch):
    monkeypatch.setenv("FAPICO2_KEYSTORE", str(tmp_path / "journey_keystore.cbor"))
    monkeypatch.setenv("FAPICO2_SECURE_PARTITION", str(tmp_path / "journey_partition.bin"))
    monkeypatch.setenv("FAPICO2_PIV_KEYSTORE", str(tmp_path / "journey_piv.cbor"))
    # Dedicated CCID dial-in (Emu.start copies os.environ; the private relay
    # holds RELAY_CCID_PORT, not the shared harness dial-in 35963).
    monkeypatch.setenv("FAPICO2_CCID_PORT", str(RELAY_CCID_PORT))

    relay = _Relay()
    client = None
    # Private HID port, disjoint from test_restart.py's MATRIX_HID_PORT
    # (35965) and every other suite in the map.
    emu = Emu(tmp_path / "journey_keystore.cbor", hid_port=35960)
    try:
        emu.start()
        relay.proc.stdout.readline()  # emulator connected line
        client = socket.create_connection(("127.0.0.1", RELAY_CLIENT_PORT), timeout=3)
        client.settimeout(15)
        _wait_relay_line(relay.proc, "[client] test client connected", 15)
        card = _Card(client)

        # --- Gate context (US-912): factory card refuses key operations --
        card.select()
        assert card.verify(3, PW3_FACTORY) == 0x9000
        assert card.genkey() == 0x6985, \
            "factory defaults in force: GENERATE must be refused"

        # --- Captured journey step 1: passwd 1 (PW1 change) --------------
        # CRD(0x24, 0x81, 123456‖246813) → 9000
        assert card.change_pw(1, PW1_FACTORY, PW1_NEW) == 0x9000
        # Gate contract: PW1 alone changed, PW3 still factory → refused.
        assert card.genkey() == 0x6985, \
            "PW3 still factory: gate must stay armed after passwd 1"

        # --- Captured journey step 2: passwd 3 (PW3 change) --------------
        # CRD(0x24, 0x83, 12345678‖13572468) → 9000 — the APDU the original
        # report blamed; the US-933 capture showed it answering 9000 on the
        # device and emulator at HEAD (the captured 6300 was operator state).
        assert card.change_pw(3, PW3_FACTORY, PW3_NEW) == 0x9000

        # --- Captured journey step 3: VERIFY with the new Admin PIN ------
        # VERIFY(0x20, 0x83, 13572468) → 9000
        assert card.verify(3, PW3_NEW) == 0x9000

        # --- Gate lifted: GENERATE allowed (journey end state) -----------
        assert card.put_data(0x00, 0xC1, KEY_ATTR_ED25519) == 0x9000
        assert card.genkey() == 0x9000, \
            "gate must clear once both PINs left the factory defaults"
        # And the PW1 change from step 1 is still in force for signing.
        assert card.verify(1, PW1_NEW) == 0x9000
        assert card.pso_sign(DIGEST) == 0x9000, \
            "PSO:SIGN must proceed with the journey's changed PW1"
    finally:
        emu.stop(signal.SIGTERM)
        if client is not None:
            client.close()
        relay.stop()
