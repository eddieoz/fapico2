"""Shared CCID plumbing for the Nostr applet suites (EPIC NOSTR-APPLET,
US-1651).

The shape is `rescue_ccid.py`'s: one private relay + one emulation binary per
suite, durable files per instance, APDU transcriptions in one place.

**Every APDU here is transcribed from the design's wire table**
(`docs/tasks/nostr-applet-design.md` §2.2), because the client this applet is
built for — the OpenXrypt extension — does not exist on the wire yet (its
signer seam is US-1668+). When it does, the transcriptions are cross-checked
against its encoder and this docstring loses its caveat; until then the file
carries the design's bytes, and the Rust side's wire.rs holds the same
constants under test.

Nothing here imports the firmware.
"""

from __future__ import annotations

import os
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# Dedicated relay ports, disjoint from every other entry in the port map in
# `tests/harness/ccid_relay.py` (updated in the same change).
PORTS = {
    "select": (36013, 36014),
    "keymgmt": (36015, 36016),
    # The presence-deny emulator (FAPICO2_NOSTR_PRESENCE=deny) is a separate
    # process from the auto-ack one, so it needs its own relay pair.
    "deny": (36017, 36018),
}

#: `NOSTR_AID` (design §2.1) — `F0 00 00 00 02`, vendor-private, mirroring the
#: vendor_led AID's shape and sharing no prefix with any registered AID.
NOSTR_AID = bytes.fromhex("F000000002")

#: The SELECT: `00 A4 04 04 <len> <AID>` — P1 = 0x04 (select by DF name),
#: P2 = 0x04 (return FCI), no Le. `is_select_apdu` checks the first three
#: bytes and nothing else, so this arrives as an ordinary SELECT.
SELECT_NOSTR = bytes([0x00, 0xA4, 0x04, 0x04, len(NOSTR_AID)]) + NOSTR_AID

#: §2.2 INS map. All commands are CLA `0x00` (design §2.2), P2 = 0.
INS_GET_INFO = 0x10
INS_LIST_KEYS = 0x11
INS_GET_PUBKEY = 0x12
INS_GENERATE_KEY = 0x13
INS_IMPORT_KEY = 0x14
INS_SIGN = 0x15
INS_SET_LABEL = 0x18
INS_DELETE_KEY = 0x19
INS_EXPORT_KEY = 0x1A  # retired by US-1699 — refused 6D00 on every channel
#: The PIN custody dialect (US-1691..1694, US-1702). Touch-free by design:
#: the PIN is the consent.
INS_VERIFY_PIN = 0x1B
INS_SET_PIN = 0x1C  # P1 0 = SET, P1 1 = CHANGE
INS_LOCK = 0x1D

#: §2.2.0 status words — the vocabulary the host renders.
SW_OK = 0x9000
SW_WRONG_DATA = 0x6A80
SW_NO_SUCH_IDENTITY = 0x6A82
SW_WRONG_P1_P2 = 0x6A86
SW_INDEX_OCCUPIED = 0x6A84
SW_KEY_SET_FULL = 0x6A88
SW_TOUCH_REQUIRED = 0x6985
SW_INS_NOT_SUPPORTED = 0x6D00
#: The PIN custody vocabulary (US-1691). SW_PIN_NOT_SET and
#: SW_PIN_ALREADY_SET share 6A82 (the file-not-found state word);
#: SW_PIN_SESSION_REQUIRED is 6982, OpenPGP's CHV-not-verified; the wrong-
#: PIN rows are 63C0|remaining and 63C0 itself is the lockout.
SW_PIN_NOT_SET = 0x6A82
SW_PIN_SESSION_REQUIRED = 0x6982
SW_PIN_LOCKED = 0x63C0

# GET_INFO flags (US-1714): bit 2 is the migration-pending state — PIN set,
# the ceremony marker absent.
FLAG_MIGRATION_PENDING = 0x04


def apdu(ins: int, p1: int = 0, p2: int = 0, data: bytes = b"") -> bytes:
    """One short-form command APDU: `CLA INS P1 P2 [Lc data]`, no Le."""
    out = bytearray([0x00, ins, p1, p2])
    if data:
        assert len(data) <= 255, "short form only"
        out.append(len(data))
        out += data
    return bytes(out)


def split(resp: bytes) -> tuple[bytes, int]:
    """Split an APDU response into `(data, sw)`, the SW as a single int."""
    assert len(resp) >= 2, f"response must carry a status word: {resp.hex()}"
    return resp[:-2], (resp[-2] << 8) | resp[-1]


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("CCID connection closed")
        buf += chunk
    return bytes(buf)


def frame(sock: socket.socket, payload: bytes) -> bytes:
    """One `[u16 BE length] + body` frame, both directions."""
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


class NostrEmu:
    """A private CCID relay + one emulation binary, driven over ISO 7816-4.

    `presence="deny"` starts the emulator with `FAPICO2_NOSTR_PRESENCE=deny`
    (US-1646's hook, the OATH hook's shape): the touch-gated commands then
    answer `6985`, which is the only way that refusal is exercisable over
    CCID — the host build's default presence auto-acks.

    The durable files (keystore, partition, PIV, and the Nostr region) are
    all private per instance, so a write in one test is not visible to the
    next.
    """

    def __init__(
        self,
        key: str,
        tmp_path: Path,
        log_path: Path | None = None,
        presence: str = "auto",
        binary: Path | None = None,
    ):
        # `binary` overrides the repo's current build — the cross-generation
        # matrix (US-1708) drives the v0.2.0 image the same harness.
        self.binary = binary
        if key not in PORTS:
            raise ValueError(
                f"no ports reserved for {key!r}; add them to PORTS "
                f"and to the port map in tests/harness/ccid_relay.py"
            )
        if presence not in ("auto", "deny"):
            raise ValueError(f"presence must be 'auto' or 'deny', got {presence!r}")
        self.dial_port, self.client_port = PORTS[key]
        self.tmp_path = tmp_path
        self.log_path = log_path
        self.presence = presence
        self.relay = None
        self.emulator = None
        self.client = None
        self._log = None

    # -- lifecycle ---------------------------------------------------

    def __enter__(self) -> "NostrEmu":
        keystore = self.tmp_path / "nostr_keystore.cbor"
        partition = self.tmp_path / "nostr_partition.bin"
        piv = self.tmp_path / "nostr_piv.cbor"
        nostr_region = self.tmp_path / "nostr_region.bin"

        self.relay = subprocess.Popen(
            [
                sys.executable,
                str(REPO / "tests" / "harness" / "ccid_relay.py"),
                "--ccid-port",
                str(self.dial_port),
                "--client-port",
                str(self.client_port),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        _wait_relay_line(self.relay, "READY", timeout=10)

        env = dict(os.environ)
        env["FAPICO2_KEYSTORE"] = str(keystore)
        env["FAPICO2_SECURE_PARTITION"] = str(partition)
        env["FAPICO2_PIV_KEYSTORE"] = str(piv)
        env["FAPICO2_NOSTR_REGION"] = str(nostr_region)
        env["FAPICO2_CCID_PORT"] = str(self.dial_port)
        # A private HID port so a Nostr test can never displace the shared
        # run_tests.sh HID listener (the port map's reason for 35988).
        env["FAPICO2_HID_PORT"] = str(self.dial_port + 100)
        if self.presence == "deny":
            env["FAPICO2_NOSTR_PRESENCE"] = "deny"

        if self.log_path is not None:
            self._log = self.log_path.open("w+")
            stdout = stderr = self._log
        else:
            stdout = stderr = subprocess.DEVNULL
        self.emulator = subprocess.Popen(
            [
                str(
                    self.binary
                    or (
                        REPO
                        / "target"
                        / "x86_64-unknown-linux-gnu"
                        / "debug"
                        / "fapico2-emulation"
                    )
                )
            ],
            env=env,
            stdout=stdout,
            stderr=stderr,
        )
        self._wait("emulator connected", proc=self.relay)
        self.client = socket.create_connection(
            ("127.0.0.1", self.client_port), timeout=3
        )
        self.client.settimeout(20)
        self._wait("[client] test client connected", proc=self.relay)
        # Power-on must answer with the device ATR before an XfrBlock is
        # served; the bytes themselves are asserted by test_boot_refuse.py, so
        # this only checks the handshake happened.
        atr = frame(self.client, b"\x04")
        assert atr[:1] == b"\x3b", f"unexpected ATR: {atr.hex()}"
        return self

    def __exit__(self, *exc) -> None:
        if self.client is not None:
            self.client.close()
            self.client = None
        if self.emulator is not None and self.emulator.poll() is None:
            self.emulator.send_signal(signal.SIGTERM)
            try:
                self.emulator.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.emulator.kill()
                self.emulator.wait(timeout=5)
        self.emulator = None
        if self.relay is not None:
            try:
                self.relay.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.relay.kill()
                self.relay.wait(timeout=5)
            self.relay = None
        if self._log is not None:
            self._log.close()
            self._log = None

    def _wait(self, needle: str, proc: subprocess.Popen, timeout: float = 15) -> None:
        _wait_relay_line(proc, needle, timeout=timeout)

    # -- card operations ---------------------------------------------

    def send(self, apdu_bytes: bytes) -> tuple[bytes, int]:
        """Transmit one APDU and return `(data, sw)`."""
        data, sw = split(frame(self.client, apdu_bytes))
        return data, sw

    def select(self) -> tuple[bytes, int]:
        return self.send(SELECT_NOSTR)

    def log(self) -> str:
        """The emulator's stderr/stdout, for the tests that assert on it."""
        if self._log is None:
            return ""
        self._log.flush()
        self._log.seek(0)
        return self._log.read()
