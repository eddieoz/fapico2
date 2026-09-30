"""US-921 harness check: the emulation's consent-window parity.

The emulation mirrors the device's keepalive-driven cross-call window
(firmware/src/emul_main.rs, tasks.rs parity comments) over the shared
presence runtime, but its FIDO app AUTO-ACKS presence — so the windowed
retry loop completes on iteration 1 and the observable reply sequence is
the device's happy path:

  - makeCredential/getAssertion: exactly ONE CTAPHID keepalive
    (0x3B, status 0x02) BEFORE the CBOR reply (FX-402), then the 0x90
    frame — the window must not add spurious frames.
  - U2F register: a direct MSG reply (SW 0x9000), no keepalive.

Runs against a private HID port (default 35966) with its own emulator
process, like test_restart.py.
"""

import os
import socket
import subprocess
import time
from pathlib import Path

import pytest
from fido2.cbor import encode as cbor_encode

REPO = Path(__file__).resolve().parents[2]
DEFAULT_BIN = REPO / "target/x86_64-unknown-linux-gnu/debug/fapico2-emulation"
HOST = "127.0.0.1"
REPORT_SIZE = 64


def _bin() -> Path:
    return Path(os.environ.get("FAPICO2_EMULATION_BIN", DEFAULT_BIN))


def _port() -> int:
    return int(os.environ.get("FAPICO2_WINDOW_HID_PORT", "35966"))


class RawEmu:
    """One emulation process + a raw CTAPHID client that DOES NOT skip
    keepalives — the point of this suite is to observe every frame."""

    def __init__(self, keystore_path: Path):
        self.keystore_path = keystore_path
        self.proc = None
        self.sock = None
        self.cid = b"\xff\xff\xff\xff"

    def start(self):
        env = dict(os.environ)
        env["FAPICO2_KEYSTORE"] = str(self.keystore_path)
        env["FAPICO2_HID_PORT"] = str(_port())
        # HID-only suite: keep the one-shot CCID dial off the shared relay.
        env.setdefault("FAPICO2_CCID_PORT", "35973")
        self.proc = subprocess.Popen(
            [str(_bin())],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                self.sock = socket.create_connection((HOST, _port()), timeout=1)
                # The connect timeout leaks into recv; frames arrive on the
                # emulator's own schedule, so reads get a dedicated budget.
                self.sock.settimeout(10)
                break
            except OSError:
                if self.proc.poll() is not None:
                    raise RuntimeError(f"emulator exited early: {self.proc.returncode}")
                time.sleep(0.1)
        else:
            raise RuntimeError("emulator did not come up in time")
        self._init_handshake()

    def stop(self):
        if self.sock:
            self.sock.close()
            self.sock = None
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        self.proc = None

    def _send_frame(self, frame: bytes):
        self.sock.sendall(len(frame).to_bytes(2, "big") + frame)

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise OSError("connection closed by emulator")
            buf += chunk
        return bytes(buf)

    def _recv_frame(self) -> bytes:
        size = int.from_bytes(self._recv_exact(2), "big")
        return self._recv_exact(size)

    def _init_handshake(self):
        nonce = b"\x22" * 8
        payload = nonce
        self._send_frame(
            self.cid + bytes([0x86]) + len(payload).to_bytes(2, "big")
            + payload.ljust(REPORT_SIZE - 7, b"\x00")
        )
        resp = self._recv_frame()
        assert resp[4] == 0x86, "INIT response expected"
        self.cid = resp[15:19]

    def send_cbor(self, cmd: int, body: bytes):
        payload = bytes([cmd]) + body
        out = bytearray()
        out += self.cid + bytes([0x90 | 0x10]) + len(payload).to_bytes(2, "big")
        out += payload[:57].ljust(REPORT_SIZE - 7, b"\x00")
        self._send_frame(bytes(out))
        offset = 57
        seq = 0
        while offset < len(payload):
            chunk = payload[offset : offset + 59]
            self._send_frame(self.cid + bytes([seq]) + chunk.ljust(REPORT_SIZE - 5, b"\x00"))
            offset += 59
            seq += 1

    def recv_frame(self) -> bytes:
        return self._recv_frame()

    def recv_cbor(self, first: bytes) -> bytes:
        assert first[4] == 0x90, f"expected CBOR response, got {first[4]:02x}"
        total = int.from_bytes(first[5:7], "big")
        data = bytes(first[7:])
        while len(data) < total:
            cont = self._recv_frame()
            data += cont[5:]
        return data[:total]

    def send_msg(self, apdu: bytes):
        out = bytearray()
        # First-packet command bytes carry the CTAPHID type bit (0x80|cmd);
        # without it the assembler treats the frame as a continuation.
        out += self.cid + bytes([0x80 | 0x03]) + len(apdu).to_bytes(2, "big")
        out += apdu[:57].ljust(REPORT_SIZE - 7, b"\x00")
        self._send_frame(bytes(out))
        offset = 57
        seq = 0
        while offset < len(apdu):
            chunk = apdu[offset : offset + 59]
            self._send_frame(self.cid + bytes([seq]) + chunk.ljust(REPORT_SIZE - 5, b"\x00"))
            offset += 59
            seq += 1


@pytest.fixture()
def emu(tmp_path):
    e = RawEmu(tmp_path / "window_keystore.cbor")
    e.start()
    try:
        yield e
    finally:
        e.stop()


def test_mc_replies_keepalive_then_cbor_and_never_repeats(emu):
    """makeCredential: exactly one keepalive (0x3B/0x02), then the CBOR
    success — the auto-ack window loop must not add frames."""
    req = cbor_encode(
        {
            1: os.urandom(32),
            2: {"id": "window.test", "name": "Window RP"},
            3: {"id": b"user_id", "name": "A. User"},
            4: [{"type": "public-key", "alg": -7}],
        }
    )
    emu.send_cbor(0x01, req)
    first = emu.recv_frame()
    # Reply command bytes carry the CTAPHID type bit (0x80|cmd).
    assert first[4] == 0x80 | 0x3B, (
        f"expected CTAPHID keepalive first, got {first[4]:02x}"
    )
    assert first[7] == 0x02, f"keepalive must report UP NEEDED (0x02), got {first[7]:02x}"
    # No second keepalive: the auto-ack app grants on the (virtual) retry.
    second = emu.recv_frame()
    resp = emu.recv_cbor(second)
    assert resp[0] == 0x00, f"makeCredential failed: {resp[0]:02x}"


def test_u2f_register_replies_directly_without_keepalive(emu):
    """U2F register over MSG: the auto-ack app never refuses UP, so the
    window loop is never entered and the reply is a single MSG frame."""
    # U2F REGISTER, short-form Lc=0x40: client_param(32) || app_param(32).
    apdu = bytes([0x00, 0x01, 0x03, 0x00, 0x40]) + os.urandom(32) + os.urandom(32)
    emu.send_msg(apdu)
    frame = emu.recv_frame()
    assert frame[4] == 0x80 | 0x03, (
        f"expected direct MSG reply, got {frame[4]:02x}"
    )
    total = int.from_bytes(frame[5:7], "big")
    data = bytes(frame[7:])
    while len(data) < total:
        cont = emu.recv_frame()
        data += cont[5:]
    data = data[:total]
    assert data[-2:] == b"\x90\x00", f"register SW: {data[-2:].hex()}"
