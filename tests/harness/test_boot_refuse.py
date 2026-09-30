"""US-427: boot Refuse parity — the emulator refuses a corrupt secure partition.

The device parks in ``fatal_boot`` when neither flash slot holds a valid
partition image; the emulator must have the same parity (EPIC
SECURE-PERSIST, US-427): when ``FAPICO2_SECURE_PARTITION`` exists but
``partition_image_is_valid`` fails, it must ``exit(2)`` BEFORE the
OATH/OTP/mgmt boots — the same refuse the keystore loads already perform
(FX-409). A missing/empty file is Fresh (today's behavior).

RED today (pre-US-427): a corrupt partition file is silently treated as
fresh — the emulator starts empty and serves (exit 0), so the refusal
assertions below fail. GREEN: both corruptions produce exit code 2.

Durable operation (per the US-427 restart-matrix APDU table): management
``WRITE_CONFIG`` over CCID — the mgmt app persists its config blob through
the platform gate into the shared secure partition, so after the APDU the
partition file holds a valid sealed format-v3 image (US-915). (The
emulation's FIDO app keeps its keystore in its own file and never dirties
the shared store, so the durable op must ride a CCID app.) The CCID path
needs the relay (``ccid_relay.py``) BEFORE the emulator — the emulator
dials the suite's dedicated CCID dial-in (RELAY_CCID_PORT below, pointed
at the relay via ``FAPICO2_CCID_PORT``) at start-up.

The two corruptions are the tamper shapes the sealed ``boot_decision``
tests cover: (1) one flipped byte — under the v3 encrypt-then-MAC format
any flipped byte breaks the entry/image tag; (2) the file truncated to
~60 % (the torn-write shape). Both must Refuse, and a lone legacy v2 slot
(the red-team forged shape) is likewise never loaded or migrated in
emulation.
"""

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
RELAY_CCID_PORT = 35975  # the emulator dials in here (FAPICO2_CCID_PORT)
RELAY_CLIENT_PORT = 35983  # this test connects here

MGMT_AID = bytes.fromhex("A000000527471117")
# SELECT AID (short form, 8-byte AID): CLA 00 INS A4 P1 04 Lc 08, raw AID in
# data (the restart-matrix APDU table's "data" column is Lc ‖ AID).
SELECT_MGMT = bytes([0x00, 0xA4, 0x04, 0x00, 0x08]) + MGMT_AID
# WRITE_CONFIG: data[0] = config len 04; config TLV 03 02 00 21
# (TAG_USB_ENABLED caps 0x0021) — no admin gating in factory state.
WRITE_CONFIG = bytes([0x00, 0x1C, 0x00, 0x00, 0x05, 0x04, 0x03, 0x02, 0x00, 0x21])


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("CCID connection closed")
        buf += chunk
    return bytes(buf)


def _ccid_frame(sock: socket.socket, payload: bytes) -> bytes:
    """One [u16 BE length] + body frame, both directions."""
    sock.sendall(struct.pack(">H", len(payload)) + payload)
    (length,) = struct.unpack(">H", _recv_exact(sock, 2))
    return _recv_exact(sock, length)


def _wait_relay_line(proc: subprocess.Popen, needle: str, timeout: float) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        if needle in line:
            return
    raise AssertionError(f"ccid relay did not report {needle!r} within {timeout}s")


class _Relay:
    """The harness CCID relay on the suite's dedicated ports for one emulator."""

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

    def expect_emulator(self, timeout: float = 15) -> None:
        _wait_relay_line(self.proc, "[ccid] emulator connected", timeout=timeout)

    def expect_client(self, timeout: float = 15) -> None:
        _wait_relay_line(self.proc, "[client] test client connected", timeout=timeout)

    def stop(self):
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        self.proc = None


def _expect_refusal(keystore: Path) -> None:
    """Boot the emulator against the (corrupt) partition file and require the
    FX-409-style refusal: the process must die with exit code 2 instead of
    serving. (No relay needed — the emulator tolerates a missing relay and
    dies at the partition check before it would matter. Emu.start defaults
    the CCID dial to the dead port test_restart.DEAD_CCID_PORT, so the
    one-shot startup dial never lands on the shared run_tests.sh relay.)"""
    emu = Emu(keystore)
    try:
        emu.start()
    except (RuntimeError, OSError):
        pass  # expected: the emulator refused to come up
    else:
        # It answered the INIT handshake: the emulator served from a corrupt
        # partition (the US-427 gap). Tear it down before failing so the next
        # case can bind the private HID port.
        emu.stop(signal.SIGTERM)
        raise AssertionError(
            "emulator served from a corrupt secure partition (no refusal)"
        )
    rc = emu.proc.returncode if emu.proc is not None else None
    emu.stop()  # closes any half-open socket; the process is already dead
    assert rc == 2, f"corrupt secure partition must produce exit code 2, got {rc}"


def test_boot_refuses_corrupt_secure_partition(tmp_path, monkeypatch):
    keystore = tmp_path / "boot_refuse_keystore.cbor"
    partition = tmp_path / "boot_refuse_partition.bin"
    piv = tmp_path / "boot_refuse_piv.cbor"
    # Private durable paths: Emu carries only FAPICO2_KEYSTORE/FAPICO2_HID_PORT
    # itself, so the partition + PIV paths ride on the inherited environment.
    monkeypatch.setenv("FAPICO2_SECURE_PARTITION", str(partition))
    monkeypatch.setenv("FAPICO2_PIV_KEYSTORE", str(piv))

    # 1) Build a valid partition image: start the relay BEFORE the emulator,
    #    perform one durable CCID operation (mgmt WRITE_CONFIG), SIGTERM.
    #    The emulator dials the suite's dedicated relay (not the shared
    #    harness dial-in 35963; Emu.start copies os.environ).
    monkeypatch.setenv("FAPICO2_CCID_PORT", str(RELAY_CCID_PORT))
    relay = _Relay()
    client = None
    emu = Emu(keystore)
    try:
        emu.start()
        relay.expect_emulator()
        client = socket.create_connection(("127.0.0.1", RELAY_CLIENT_PORT), timeout=3)
        client.settimeout(15)
        relay.expect_client()
        atr = _ccid_frame(client, b"\x04")
        # Power-on must answer with the device ATR — the OpenPGP-parity
        # bytes in firmware/src/emul_main.rs (C parity: atr_openpgp,
        # openpgp.c:294, T=1). The suite's original `3b 00` expectation
        # predates US-331, which switched the emulation to this ATR.
        assert atr == bytes.fromhex(
            "3bda18ff81b1fe751f030031f573c001600090001c"
        ), f"unexpected ATR: {atr.hex()}"
        resp = _ccid_frame(client, SELECT_MGMT)
        assert resp[-2:] == b"\x90\x00", f"SELECT mgmt failed: {resp.hex()}"
        resp = _ccid_frame(client, WRITE_CONFIG)
        assert resp[-2:] == b"\x90\x00", f"WRITE_CONFIG failed: {resp.hex()}"
    finally:
        emu.stop(signal.SIGTERM)
        if client is not None:
            client.close()
        relay.stop()

    data = partition.read_bytes()
    assert data[:4] == b"PS3F", (
        "the partition file must hold a sealed format-v3 image after a "
        "durable op (US-915)"
    )

    # 2) Corrupt it in place — case (1): flip the first key byte (offset 12:
    #    under the v3 format every byte is inside the tag-verified image).
    flipped = bytearray(data)
    flipped[12] ^= 0xFF
    partition.write_bytes(bytes(flipped))
    _expect_refusal(keystore)

    # 3) Corrupt it in place — case (2): truncate the file to ~60 % (torn
    #    write), re-corrupting from the original valid bytes.
    partition.write_bytes(data[: max(12, len(data) * 6 // 10)])
    _expect_refusal(keystore)
