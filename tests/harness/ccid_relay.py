#!/usr/bin/env python3
"""CCID relay for the fapico2 emulation transport.

The fapico2 emulation binary dials out to 127.0.0.1:35963 at start-up (same as the C
emulation binary). This relay binds that port first, accepts the emulator's connection,
and exposes a second port (35970) for test clients to connect to.

The wire protocol in both directions is the same length-prefixed frame the C harness
expects: [u16 BE length] + body.

Adapted from pico-fido2/tests/harness/ccid_relay.py.
"""
from __future__ import annotations

import argparse
import socket
import struct
import sys
import threading
import time

CCID_PORT = 35963  # shared relay: emulator dials in here
CLIENT_PORT = 35970  # shared relay: tests connect here

# Harness CCID port map (keep every entry disjoint so private relays never
# fight the shared run_tests.sh pair under bare ./run_tests.sh discovery):
#   35963/35970     shared relay started by run_tests.sh (the defaults here)
#   35964/35972     test_redteam.py private relay
#   35974/35982     test_restart.py CcidEmu private relay
#   35975/35983     test_boot_refuse.py private relay
#   35976/35984     test_openpgp_int_auth.py private relay
#   35977/35985     test_openpgp_pw_status.py private relay
#   35978/35986     test_openpgp_pin_gate.py private relay
#   35979           test_socket_transport.py private CCID server (dial-in only)
#   35980/35987     test_openpgp_us935_journey.py private relay
#   35988           us933_replay.py private HID port
#   36001/36002     test_rescue_select.py private relay (US-161a)
#   36003/36004     test_rescue_read.py private relay (US-161a/161b)
#   36005/36006     test_rescue_write.py private relay (US-162)
#   36007/36008     test_rescue_reboot.py private relay (US-163)
#   36009/36010     test_paging.py private relay (US-180)
#   36109           test_paging.py private HID port (US-180)
#   36011/36012     test_openpgp_chaining.py private relay (US-181)
#   36111           test_openpgp_chaining.py private HID port (US-181)
#   35973           dead dial port for direct-spawn FIDO-only emulators
# Every private relay is spawned with explicit --ccid-port/--client-port and
# its emulator is pointed at the private dial-in via FAPICO2_CCID_PORT.


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("CCID connection closed")
        buf += chunk
    return bytes(buf)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ccid-port", type=int, default=CCID_PORT)
    parser.add_argument("--client-port", type=int, default=CLIENT_PORT)
    args = parser.parse_args()

    # Bind the CCID port for the emulator to dial into
    ccid_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ccid_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ccid_listener.bind(("127.0.0.1", args.ccid_port))
    ccid_listener.listen(8)

    # Bind the client port for tests to connect to
    client_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client_listener.bind(("127.0.0.1", args.client_port))
    client_listener.listen(1)

    print(f"READY: ccid={args.ccid_port} client={args.client_port}", flush=True)

    # One test client, many emulator dials: run_tests.sh starts a shared
    # emulator AND suites like tests/harness/test_restart.py spawn private
    # emulator instances that each dial this port (EmulationTransport::new
    # connects once, no retry). The relay therefore accepts every emulator
    # dial and relays frames to/from the most recent dial — a stale dial
    # from an exited emulator must never wedge the next one.
    state = {"client": None, "ccid": None}
    lock = threading.Lock()

    def _relay_from_client(csock: socket.socket) -> None:
        while True:
            try:
                header = _recv_exact(csock, 2)
                (length,) = struct.unpack(">H", header)
                body = _recv_exact(csock, length)
                # The client may speak before the emulator's dial is
                # accepted (CcidEmu.start connects the client right after
                # spawning the emulator) — wait for the peer rather than
                # dropping the frame.
                dst = None
                for _ in range(500):
                    with lock:
                        dst = state["ccid"]
                    if dst is not None:
                        break
                    time.sleep(0.02)
                if dst is not None:
                    dst.sendall(header + body)
            except (ConnectionError, OSError):
                return

    def _relay_to_client(eso: socket.socket) -> None:
        while True:
            try:
                header = _recv_exact(eso, 2)
                (length,) = struct.unpack(">H", header)
                body = _recv_exact(eso, length)
                with lock:
                    dst = state["client"]
                if dst is not None:
                    dst.sendall(header + body)
            except (ConnectionError, OSError):
                return

    def _accept_clients() -> None:
        while True:
            csock, client_addr = client_listener.accept()
            print(f"[client] test client connected from {client_addr}", flush=True)
            with lock:
                old = state["client"]
                state["client"] = csock
            if old is not None:
                try:
                    old.close()
                except OSError:
                    pass
            threading.Thread(target=_relay_from_client, args=(csock,), daemon=True).start()

    threading.Thread(target=_accept_clients, daemon=True).start()

    while True:
        eso, ccid_addr = ccid_listener.accept()
        print(f"[ccid] emulator connected from {ccid_addr}", flush=True)
        with lock:
            old = state["ccid"]
            state["ccid"] = eso
        if old is not None:
            try:
                old.close()
            except OSError:
                pass
        threading.Thread(target=_relay_to_client, args=(eso,), daemon=True).start()


if __name__ == "__main__":
    main()
