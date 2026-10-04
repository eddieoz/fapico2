"""Shared CCID plumbing for the US-161/162/163 (PICOForge-COMPAT) Rescue tests.

Four EPIC-named test files drive the Rescue applet over CCID against the
emulation binary. They share one relay+emulator harness and one set of APDU
transcriptions, because a byte that is transcribed four times is a byte that
can be wrong four ways.

**Every APDU here is transcribed from the PicoForge client**, not from the
firmware (``picoforge/src/hal/rescue/ops.rs``), and the file:line is on each
one. That is deliberate: a test built from the applet's own constants cannot
fail when the applet and the client disagree, which is the only failure mode
that matters for a compatibility surface with a single consumer.

Nothing here imports the firmware. The tests are the evidence that the wire
the client speaks is the wire the device answers.
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

# Dedicated relay ports per test file, disjoint from every other entry in the
# port map in `tests/harness/ccid_relay.py` (which must be updated when these
# are added or moved). Dial-in is the port the emulator connects to; client is
# the port the test connects to.
PORTS = {
    "select": (36001, 36002),
    "read": (36003, 36004),
    "write": (36005, 36006),
    "reboot": (36007, 36008),
}

#: `RESCUE_AID` (`picoforge/src/hal/rescue/constants.rs:106`).
RESCUE_AID = bytes.fromhex("A0583FC19B7E4F21")

#: `APDU_CLA_PROPRIETARY` (`constants.rs:68`). Every non-SELECT Rescue command
#: is CLA 0x80; the vendor applets on this firmware use 0x00.
CLA = 0x80

#: The SELECT, byte for byte (`picoforge/src/hal/transport/pcsc.rs:53-61`):
#: `00 A4 04 04 08 <AID>` — CLA 0x00, INS 0xA4, P1 0x04 (select by DF name),
#: P2 0x04 (return FCI), Lc 0x08, and **no Le**.
#:
#: P2 = 0x04 does not constrain the dispatcher's AID path —
#: `platform::dispatch::is_select_apdu` checks `CLA=0x00, INS=0xA4, P1=0x04` and
#: nothing else — so this arrives as an ordinary SELECT. That is why the applet
#: needs no special casing to be selectable.
SELECT_RESCUE = bytes([0x00, 0xA4, 0x04, 0x04, len(RESCUE_AID)]) + RESCUE_AID

#: `READ` FlashInfo — `80 1E 02 00 00` (`ops.rs:275-279`).
READ_FLASH_INFO = bytes([CLA, 0x1E, 0x02, 0x00, 0x00])
#: `READ` SecureBootStatus — `80 1E 03 00 00` (`ops.rs:288-292`).
READ_SECURE_BOOT = bytes([CLA, 0x1E, 0x03, 0x00, 0x00])
#: `READ` PhyConfig — `80 1E 01 01 00` (`ops.rs:292-296`).
#:
#: **P2 = 0x01 here**, unlike the other two reads. The device accepts 0x00 here
#: too (the client writes with P2 = 0x00), and this file asserts both.
READ_PHY_P2_ONE = bytes([CLA, 0x1E, 0x01, 0x01, 0x00])
READ_PHY_P2_ZERO = bytes([CLA, 0x1E, 0x01, 0x00, 0x00])
#: A P2 the protocol does not define for this read. Must be refused.
READ_PHY_P2_BOGUS = bytes([CLA, 0x1E, 0x01, 0x02, 0x00])

#: The PHY TLV tags this firmware has a field for, in ascending order. A tag
#: outside this list — one of the protocol's other five — is **skipped**, not
#: refused: both references do that, and refusing the whole blob broke every
#: configuration save from picoforge.
TAG_VIDPID = 0x00
TAG_LED_GPIO = 0x04
TAG_LED_BRIGHTNESS = 0x05
TAG_OPTIONS = 0x06
TAG_ENABLED_USB_ITF = 0x0B
#: The seven with no field in the persisted record
#: (`docs/tasks/rescue-threat-model.md` §0.2).
# The PHY tags with no field in the persisted record, and therefore refused
# whole by a WRITE. It was **seven** until 2026-09-28, when `0x09` (product)
# and `0x0F` (manufacturer) were given fields — a write of a NUL-terminated
# name to either is now accepted and read back through `READ PhyConfig`.
# Kept as a named tuple rather than recomputed from the codec so that a tag
# quietly gaining or losing a field shows up here, in a diff, instead of
# silently changing what the sweep below tests.
TAGS_UNDESTINED = (0x08, 0x0A, 0x0C, 0x0D, 0x0E)

#: `USB_ITF_CCID` (`platform/src/phy_tlv.rs:105`) — the bit tag `0x0B` must never
#: lose, because CCID is the Rescue applet's own transport.
USB_ITF_CCID = 0x01
USB_ITF_WCID = 0x02
USB_ITF_HID = 0x04


def tlv(*records: tuple[int, bytes]) -> bytes:
    """Encode `TAG LEN VALUE` records — one-byte tag, one-byte length, no
    header, no terminator (`platform/src/phy_tlv.rs`)."""
    out = bytearray()
    for tag, value in records:
        out += bytes([tag, len(value)]) + value
    return bytes(out)


def write_phy(data: bytes) -> bytes:
    """`WRITE` PhyConfig — `80 1C 01 00 <Lc> <TLV>`, no Le (`ops.rs:601-609`).

    P1 = 0x01 is `WriteParam::PhyConfig` (`constants.rs:171`) and P2 = 0x00 is
    `P2_UNUSED` — the mirror image of the read's P2.
    """
    return bytes([CLA, 0x1C, 0x01, 0x00, len(data)]) + data


def reboot(mode: int) -> bytes:
    """`REBOOT` — `80 1F <mode> 00 00`, **mode in P1** (`ops.rs:646-652`).

    The client's own `RescueInstruction::Reboot` doc comment says P2
    (`constants.rs:143-145`); the code says P1 and three other call sites
    agree with the code.
    """
    return bytes([CLA, 0x1F, mode, 0x00, 0x00])


def secure(lock: int, key_index: int = 0x00) -> bytes:
    """`SECURE` — `80 1D 00 <lock> 00`, **lock byte in P2** (`ops.rs:691-696`).

    P1 is the boot-key index; the client only ever sends 0
    (`ops.rs:694`, `// Boot Key Index (0 = Default)`).
    """
    return bytes([CLA, 0x1D, key_index, lock, 0x00])


def split(resp: bytes) -> tuple[bytes, int]:
    """Split an APDU response into `(data, sw)`, the SW as a single int."""
    assert len(resp) >= 2, f"response must carry a status word: {resp.hex()}"
    return resp[:-2], (resp[-2] << 8) | resp[-1]


def parse_phy(blob: bytes) -> dict[int, bytes]:
    """Decode a PHY TLV blob into `{tag: value}`.

    The client's own reader is a flat `while offset < data.len()` walk
    (`ops.rs:307-315`) that stops on the first short read, so this is
    deliberately the same shape rather than a stricter one: a blob this parses
    is a blob the client parses.
    """
    out: dict[int, bytes] = {}
    i = 0
    while i < len(blob):
        if i + 2 > len(blob):
            break
        tag, length = blob[i], blob[i + 1]
        i += 2
        if i + length > len(blob):
            break
        out[tag] = blob[i : i + length]
        i += length
    return out


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


class RescueEmu:
    """A private CCID relay + one emulation binary, driven over ISO 7816-4.

    Each test file gets its own ports from [`PORTS`] so a run under bare
    ``./run_tests.sh`` cannot have one suite's emulator steal another's relay
    slot — the same discipline the port map in ``ccid_relay.py`` exists to
    enforce.

    The durable files (keystore, partition, PIV, and the Rescue PHY record) are
    all private per instance, so a write in one test is not visible to the next.
    """

    def __init__(self, key: str, tmp_path: Path, log_path: Path | None = None):
        if key not in PORTS:
            raise ValueError(f"no ports reserved for {key!r}; add them to PORTS "
                             f"and to the port map in tests/harness/ccid_relay.py")
        self.dial_port, self.client_port = PORTS[key]
        self.tmp_path = tmp_path
        self.log_path = log_path
        self.relay = None
        self.emulator = None
        self.client = None
        self._log = None

    # -- lifecycle ---------------------------------------------------

    def __enter__(self) -> "RescueEmu":
        keystore = self.tmp_path / "rescue_keystore.cbor"
        partition = self.tmp_path / "rescue_partition.bin"
        piv = self.tmp_path / "rescue_piv.cbor"
        phy = self.tmp_path / "rescue_phy.bin"

        self.relay = subprocess.Popen(
            [sys.executable, str(REPO / "tests" / "harness" / "ccid_relay.py"),
             "--ccid-port", str(self.dial_port),
             "--client-port", str(self.client_port)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        _wait_relay_line(self.relay, "READY", timeout=10)

        env = dict(os.environ)
        env["FAPICO2_KEYSTORE"] = str(keystore)
        env["FAPICO2_SECURE_PARTITION"] = str(partition)
        env["FAPICO2_PIV_KEYSTORE"] = str(piv)
        env["FAPICO2_RESCUE_PHY"] = str(phy)
        env["FAPICO2_CCID_PORT"] = str(self.dial_port)
        # A private HID port so a Rescue test can never displace the shared
        # run_tests.sh HID listener (the port map's reason for 35988).
        env["FAPICO2_HID_PORT"] = str(self.dial_port + 100)

        if self.log_path is not None:
            self._log = self.log_path.open("w+")
            stdout = stderr = self._log
        else:
            stdout = stderr = subprocess.DEVNULL
        self.emulator = subprocess.Popen(
            [str(REPO / "target" / "x86_64-unknown-linux-gnu" / "debug" / "fapico2-emulation")],
            env=env, stdout=stdout, stderr=stderr,
        )
        self._wait("emulator connected", proc=self.relay)
        self.client = socket.create_connection(("127.0.0.1", self.client_port), timeout=3)
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

    def send(self, apdu: bytes) -> tuple[bytes, int]:
        """Transmit one APDU and return `(data, sw)`."""
        data, sw = split(frame(self.client, apdu))
        return data, sw

    def select(self) -> tuple[bytes, int]:
        return self.send(SELECT_RESCUE)

    def log(self) -> str:
        """The emulator's stderr/stdout, for the tests that assert on it."""
        if self._log is None:
            return ""
        self._log.flush()
        self._log.seek(0)
        return self._log.read()
