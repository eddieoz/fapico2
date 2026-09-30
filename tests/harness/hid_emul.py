"""python-fido2 HID bridge to the merged firmware emulation server.

The merged emulation binary *listens* on ``0.0.0.0:35962`` (CCID port minus one)
and expects CTAP-HID reports framed as ``[u16 BE length]`` — see
``emulation.c``.  This module teaches python-fido2 about that socket by providing
socket-backed ``list_descriptors`` / ``open_connection`` / ``get_descriptor`` that
a conftest installs over the platform backend before any device is opened.

Adapted from pico-fido's ``tests/docker/fido2/emulation.py``.
"""

from __future__ import annotations

import socket

from fido2.hid.base import CtapHidConnection, HidDescriptor

HOST = "127.0.0.1"
PORT = 35962

_REPORT_SIZE = 64  # Pico CTAP-HID report size


def _recv_exact(handle: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = handle.recv(n - len(buf))
        if not chunk:
            raise OSError("read_packet: connection closed by emulator")
        buf += chunk
    return bytes(buf)


class EmulationCtapHidConnection(CtapHidConnection):
    def __init__(self, descriptor: HidDescriptor) -> None:
        self.descriptor = descriptor
        self.handle = socket.create_connection((HOST, PORT))

    def write_packet(self, packet: bytes) -> None:
        self.handle.sendall(len(packet).to_bytes(2, "big") + packet)

    def read_packet(self) -> bytes:
        size = int.from_bytes(_recv_exact(self.handle, 2), "big")
        data = _recv_exact(self.handle, size)
        if len(data) != size:
            raise OSError("read_packet: short read")
        return data

    def close(self) -> None:
        self.handle.close()


def get_descriptor(_):
    # Don't open a connection here - open_connection() will do that.
    # Just return a descriptor with the metadata python-fido2 needs.
    return HidDescriptor(None, 0x00, 0x00, _REPORT_SIZE, _REPORT_SIZE, "Pico-Fido", "AAAAAA")


def open_connection(descriptor):
    return EmulationCtapHidConnection(descriptor)


def list_descriptors():
    return [get_descriptor(None)]
