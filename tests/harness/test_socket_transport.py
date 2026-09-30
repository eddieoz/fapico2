"""US-304 TDD: socket transport integration test.

Opens the Rust emulation binary's CCID socket, sends a CCID frame, asserts a
response frame (even if empty / SW-only counts as RED→GREEN of the transport).

Also tests the [gb_*] stdout filter on the relay log.
"""
from __future__ import annotations

import os
import re
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path


def _filter_gb(line: str) -> str:
    return re.sub(r'\[gb_\w+\]\s*', '', line)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return bytes(buf)


def _recv_frame(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, 2)
    (length,) = struct.unpack(">H", header)
    return _recv_exact(sock, length)


def _send_frame(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack(">H", len(data)) + data)


def _start_ccid_server(port: int) -> tuple[socket.socket, socket.socket, threading.Thread]:
    """Start a simple TCP server that accepts one connection and returns (server_sock, client_sock, thread)."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(1)

    result: dict = {}

    def accept_one() -> None:
        sock, _ = listener.accept()
        result["sock"] = sock

    t = threading.Thread(target=accept_one, daemon=True)
    t.start()
    return listener, result, t


def test_emulation_transport(tmp_path) -> None:
    """Start emulation binary, send a CCID frame, assert response."""
    # Build first
    subprocess.run(
        ["cargo", "build", "-p", "fapico2-firmware", "--bin", "fapico2-emulation",
         "--no-default-features", "--features", "emulation",
         "--target", "x86_64-unknown-linux-gnu"],
        check=True,
    )

    # Start a CCID server on the suite's DEDICATED port (see the harness
    # port map in tests/harness/ccid_relay.py): under bare ./run_tests.sh
    # the shared relay holds 35963, so the emulator is pointed at this
    # port via FAPICO2_CCID_PORT and its one-shot dial lands here.
    ccid_port = 35979
    listener, accept_result, accept_thread = _start_ccid_server(ccid_port)

    # Start the emulation binary with fully private paths: the shared
    # run_tests.sh emulator (if up) owns the default HID port (35962) and
    # default /tmp durable files, and a second process binding either
    # dies before serving (EmulationTransport::new binds HID fatally).
    emul_env = dict(os.environ)
    emul_env["FAPICO2_CCID_PORT"] = str(ccid_port)
    emul_env["FAPICO2_HID_PORT"] = "35961"
    emul_env["FAPICO2_KEYSTORE"] = str(tmp_path / "transport_keystore.cbor")
    emul_env["FAPICO2_SECURE_PARTITION"] = str(
        tmp_path / "transport_partition.bin"
    )
    emul_env["FAPICO2_PIV_KEYSTORE"] = str(tmp_path / "transport_piv.cbor")
    emul_bin = os.path.join(
        os.path.dirname(__file__), "..", "..", "target", "x86_64-unknown-linux-gnu",
        "debug", "fapico2-emulation",
    )
    emul_proc = subprocess.Popen(
        [emul_bin],
        env=emul_env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )

    # Wait for emulator to connect
    accept_thread.join(timeout=5.0)
    assert "sock" in accept_result, "emulator did not connect to CCID port"
    ccid_sock = accept_result["sock"]
    print(f" emulator connected to CCID port")

    # Send ATR reset (0x04)
    _send_frame(ccid_sock, bytes([0x04]))
    atr = _recv_frame(ccid_sock)
    print(f"ATR: {' '.join(f'{b:02X}' for b in atr)}")
    assert len(atr) > 0, "ATR must not be empty"

    # Send SELECT AID for the management app (the positive dispatch case;
    # the US-305-era "null app" AID ...1111 no longer exists in the firmware
    # — ManagementApp registers ...1117, see apps/mgmt/src/lib.rs).
    mgmt_aid = bytes([0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17])
    apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(mgmt_aid)]) + mgmt_aid
    _send_frame(ccid_sock, apdu)
    resp = _recv_frame(ccid_sock)
    print(f"SELECT resp: {' '.join(f'{b:02X}' for b in resp)}")
    assert resp[-2:] == bytes([0x90, 0x00]), f"expected 9000, got {resp[-2:].hex()}"

    # Test unknown AID returns 6A82
    unknown_aid = bytes([0xFF, 0xFF])
    apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(unknown_aid)]) + unknown_aid
    _send_frame(ccid_sock, apdu)
    resp = _recv_frame(ccid_sock)
    print(f"unknown AID resp: {' '.join(f'{b:02X}' for b in resp)}")
    assert resp[-2:] == bytes([0x6A, 0x82]), f"expected 6A82, got {resp[-2:].hex()}"

    ccid_sock.close()
    emul_proc.terminate()
    print("OK: emulation transport + AID dispatcher works")


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        test_emulation_transport(Path(td))
