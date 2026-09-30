"""ISO7816 client for the fapico2 emulation CCID interface.

Adapted from pico-fido2/tests/harness/ccid.py — simplified for the Rust
emulation binary which speaks the same length-prefixed wire protocol.

Wire protocol (simplified CCID, both directions are [u16 BE length] framed):
* Power on / reset: sending a single byte 0x04 makes the emulator answer with the ATR.
* Every other command is the raw 7816-4 APDU bytes; the reply is the response
  data followed by SW1 SW2.

[gb_*] GreenBoost telemetry lines are filtered from stdout when parsing
subprocess output.
"""
from __future__ import annotations

import os
import socket
import struct
import subprocess
import tempfile

CCID_PORT = 35970  # relay's client port (emulator dials 35963)


def _filter_gb(line: str) -> str:
    """Filter out GreenBoost [gb_*] telemetry lines from subprocess output."""
    import re
    return re.sub(r'\[gb_\w+\]\s*', '', line)


def resolve_emulator_binary(explicit: str | None = None) -> str:
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    cwd = os.getcwd()
    candidates += [
        os.path.join(cwd, "build", "pico_fido2"),
        os.path.expanduser("~/Projects/git/pico/pico-fido2/build/pico_fido2"),
    ]
    # Rust emulation binary
    candidates += [
        os.path.join(cwd, "target", "x86_64-unknown-linux-gnu", "debug", "fapico2-emulation"),
    ]
    for path in candidates:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    raise FileNotFoundError(f"could not locate emulation binary (tried {candidates})")


_RESET = bytes([0x04])


class EmulatedCard:
    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._atr: bytes | None = None

    def _send(self, payload: bytes) -> None:
        self._sock.sendall(struct.pack(">H", len(payload)) + payload)

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("CCID connection closed")
            buf += chunk
        return bytes(buf)

    def _recv_frame(self) -> bytes:
        (length,) = struct.unpack(">H", self._recv_exact(2))
        return self._recv_exact(length)

    def power_on(self) -> bytes:
        self._send(_RESET)
        self._atr = self._recv_frame()
        return self._atr

    @property
    def atr(self) -> bytes | None:
        return self._atr

    def transmit(self, command: bytes) -> bytes:
        self._send(command)
        return self._recv_frame()

    def send_apdu(
        self,
        cla: int,
        ins: int,
        p1: int = 0,
        p2: int = 0,
        data: bytes | None = None,
        le: int | None = None,
    ) -> tuple[bytes, int, int]:
        data = data or b""
        apdu = bytearray([cla, ins, p1 & 0xFF, p2 & 0xFF, len(data)])
        apdu += data
        if le is not None:
            apdu.append(le & 0xFF)
        response = self.transmit(bytes(apdu))
        sw1, sw2 = response[-2], response[-1]
        return response[:-2], sw1, sw2

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


class EmulatorSession:
    def __init__(self, binary: str | None = None, port: int = CCID_PORT) -> None:
        self.binary = resolve_emulator_binary(binary)
        self.port = port
        self.proc: subprocess.Popen | None = None
        self.card: EmulatedCard | None = None

    def start(self) -> EmulatedCard:
        self.proc = subprocess.Popen(
            [self.binary],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )
        # Wait for the emulator to be ready by reading its output
        import time
        time.sleep(1.0)  # simple wait for the binary to start
        self.card = EmulatedCard(socket.create_connection(("127.0.0.1", self.port)))
        return self.card

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.card:
            self.card.close()

    def __enter__(self) -> EmulatedCard:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
