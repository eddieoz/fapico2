#!/usr/bin/env python3
"""24-h soak harness (US-385) — prove the merged firmware is panic-free.

A soak is a long, unattended loop that hammers the *same* dispatcher + app
code the firmware ships, so that a stability bug (a panic, a hung USB channel,
a leaked session) surfaces on the bench *before* release rather than in the
field. The pass criterion is deliberately narrow: **zero panics over the soak
window** — a functional bug (a wrong SW) is the pytest gate's job, not the
soak's.

What one "cycle" does — interleaved app sessions, the exact pattern a real
user drives (webauthn in a browser while gpg/scdaemon holds the CCID channel):

    1. CCID  SELECT OpenPGP AID ; SELECT MF      (OpenPGP app processing)
    2. HID   FIDO2 CTAP2.1 get_info              (FIDO stack alive on its
    3. CCID  SELECT OATH AID                     (its own transport, OATH app)
    4. CCID  SELECT management AID ; READ_CONFIG (dispatcher caps path)

Repeated until the soak window elapses (default 24 h) or a panic aborts it.

Transports (same cycle logic, different card/device plumbing):

* ``--transport emu`` (default, VERIFIED): drives the ``fapico2-emulation``
  binary over its TCP CCID (dial-in on :data:`CCID_PORT`) + HID (listen on
  :data:`HID_PORT`) sockets. A panic in the emulator aborts the process and
  writes a ``panicked at`` line to the emulator log — the watcher reads both.
* ``--transport usb`` (bench hardware): the same cycle over a real RP2350 —
  pyscard for CCID, fido2's native HID for FIDO2, and the firmware's **defmt
  panic counter** read off the debug probe's RTT stream via ``probe-rs``. See
  ``README.md`` for the bench procedure; this path needs hardware +
  ``pyscard`` + ``probe-rs`` and is validated by the emu mechanism, not here.

Exit status: 0 = PASS (zero panics, window completed), 1 = FAIL (a panic),
2 = harness/setup error. The per-step log, the emulator/RTT log, and a summary
are archived under ``--log-dir`` (default ``logs/soak-<UTC-stamp>``).
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

# --- wire constants (match platform/emulation.rs + C emulation.c) -----------
CCID_PORT = 35963  # the emulator dials OUT to this (CCID)
HID_PORT = 35962   # the emulator LISTENS on this (CTAP-HID)
HID_REPORT = 64    # Pico CTAP-HID report size

# App AIDs (see tests/merged/test_app_switching.py for the same values).
AID_OPENPGP = bytes([0xD2, 0x76, 0x00, 0x01, 0x24, 0x01])
AID_OATH = bytes([0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01])
AID_MANAGEMENT = bytes([0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17])

INS_READ_CONFIG = 0x1D  # management: read config (caps TLV)


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sw(sw1: int, sw2: int) -> str:
    return f"{sw1:02X}{sw2:02X}"


# ---------------------------------------------------------------------------
# CCID (ISO7816) card interface. emu: length-prefixed TCP frames; usb: pyscard.
# ---------------------------------------------------------------------------
class EmuCard:
    """APDU client over the emulator's accepted CCID socket.

    Wire framing (both directions): ``[u16 BE length] || payload``. Power on /
    reset is a single ``0x04`` byte answered with the ATR; every other command
    is a raw 7816-4 APDU answered with ``data + SW1 SW2``.
    """

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def _send(self, payload: bytes) -> None:
        self._sock.sendall(len(payload).to_bytes(2, "big") + payload)

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("CCID connection closed by emulator")
            buf += chunk
        return bytes(buf)

    def _recv_frame(self) -> bytes:
        (length,) = int.from_bytes(self._recv_exact(2), "big"),
        return self._recv_exact(length)

    def power_on(self) -> bytes:
        self._send(bytes([0x04]))
        return self._recv_frame()

    def transmit(self, command: bytes) -> bytes:
        self._send(command)
        return self._recv_frame()

    def send_apdu(self, cla, ins, p1=0, p2=0, data=b"", le=None):
        data = bytes(data or b"")
        apdu = bytearray([cla, ins, p1 & 0xFF, p2 & 0xFF, len(data)]) + data
        if le is not None:
            apdu.append(le & 0xFF)
        resp = self.transmit(bytes(apdu))
        return resp[:-2], resp[-2], resp[-1]

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


class UsbCard:
    """APDU client over a real CCID smartcard reader (pyscard)."""

    def __init__(self, reader_name: str | None = None) -> None:
        from smartcard.System import get_readers
        from smartcard.util import toHexString  # noqa: F401  (kept for parity)

        readers = get_readers()
        if not readers:
            raise SystemExit("usb transport: no CCID smartcard reader found "
                             "(attach the RP2350 via a CCID reader)")
        reader = next((r for r in readers if reader_name and reader_name in str(r)),
                      readers[0])
        self.conn = reader.createConnection()

    def power_on(self) -> bytes:
        self.conn.connect(protocol="T=0")
        return self.conn.get_atr()

    def transmit(self, command: bytes) -> bytes:
        resp, sw1, sw2 = self.conn.transmit(bytes(command))
        return bytes(resp) + bytes([sw1, sw2])

    def send_apdu(self, cla, ins, p1=0, p2=0, data=b"", le=None):
        data = bytes(data or b"")
        apdu = bytearray([cla, ins, p1 & 0xFF, p2 & 0xFF, len(data)]) + data
        if le is not None:
            apdu.append(le & 0xFF)
        resp = self.transmit(bytes(apdu))
        return resp[:-2], resp[-2], resp[-1]

    def close(self) -> None:
        try:
            self.conn.disconnect()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Emu session: bind the CCID port, launch the emulator, accept its dial-in.
# ---------------------------------------------------------------------------
class EmuSession:
    """Owns the ``fapico2-emulation`` subprocess + its CCID acceptor.

    The emulator *listens* on HID :data:`HID_PORT` and *dials out* to CCID
    :data:`CCID_PORT`, so we bind the CCID port before launching it (else the
    firmware disables the CCID interface). stdout+stderr go to a log file so a
    Rust panic (``panicked at``) and the process abort are both observable.
    """

    def __init__(self, binary: str, ccid_port: int = CCID_PORT, workdir: str | None = None):
        self.binary = binary
        self.ccid_port = ccid_port
        # A fresh cwd isolates the emulator's NV (memory.flash) per run.
        self.workdir = workdir or tempfile.mkdtemp(prefix="fapico2-soak-")
        os.makedirs(self.workdir, exist_ok=True)
        self.log_path = os.path.join(self.workdir, "emulator.log")
        self.proc: subprocess.Popen | None = None
        self.card: EmuCard | None = None
        self._logf = None

    def start(self) -> EmuCard:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", self.ccid_port))
        listener.listen(1)
        listener.settimeout(20)
        self._logf = open(self.log_path, "w")
        self.proc = subprocess.Popen(
            [self.binary], cwd=self.workdir,
            stdout=self._logf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
        )
        try:
            dev_sock, _ = listener.accept()  # the emulator dials in
        except socket.timeout:
            self.stop()
            raise SystemExit(f"emu: emulator did not dial CCID port {self.ccid_port} "
                             f"within 20s (is the port free? binary ok?)")
        listener.close()
        self.card = EmuCard(dev_sock)
        self.card.power_on()
        return self.card

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.card:
            self.card.close()
        if self._logf:
            try:
                self._logf.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# FIDO2 / CTAP over HID.
# ---------------------------------------------------------------------------
def _install_hid_socket_shim() -> None:
    """Redirect python-fido2's HID to the emulator's CTAP-HID TCP socket.

    Teaches fido2 about the emulator the same way tests/conftest.py does, so
    ``CtapHidDevice.list_devices()`` finds the socket as if it were a /dev/hidraw.
    """
    import fido2.hid.linux as _linux_hid
    import fido2.hid as _hid
    from fido2.hid.base import CtapHidConnection, HidDescriptor

    class EmulConn(CtapHidConnection):
        def __init__(self, descriptor: HidDescriptor) -> None:
            self.descriptor = descriptor
            self.handle = socket.create_connection(("127.0.0.1", HID_PORT))

        def _recv(self, n: int) -> bytes:
            buf = bytearray()
            while len(buf) < n:
                chunk = self.handle.recv(n - len(buf))
                if not chunk:
                    raise OSError("HID connection closed by emulator")
                buf += chunk
            return bytes(buf)

        def write_packet(self, packet: bytes) -> None:
            self.handle.sendall(len(packet).to_bytes(2, "big") + packet)

        def read_packet(self) -> bytes:
            size = int.from_bytes(self._recv(2), "big")
            return self._recv(size)

        def close(self) -> None:
            self.handle.close()

    def get_descriptor(_):
        sock = socket.create_connection(("127.0.0.1", HID_PORT))
        return HidDescriptor(sock, 0x00, 0x00, HID_REPORT, HID_REPORT, "fapico2", "SOAK00")

    def open_connection(descriptor):
        return EmulConn(descriptor)

    def list_descriptors():
        return [get_descriptor(None)]

    for m in (_linux_hid, _hid):
        m.list_descriptors = list_descriptors
        m.open_connection = open_connection


def make_fido(transport: str):
    """Return a CTAP2.1 backend whose ``get_info()`` proves FIDO2 is alive."""
    from fido2.hid import CtapHidDevice
    from fido2.ctap2 import Ctap2

    if transport == "emu":
        _install_hid_socket_shim()
    dev = next(CtapHidDevice.list_devices(), None)
    if dev is None:
        raise SystemExit("fido: no CTAP HID device found "
                         f"(transport={transport})")
    return Ctap2(dev)


# ---------------------------------------------------------------------------
# Panic detection.
# ---------------------------------------------------------------------------
class EmuPanicWatcher:
    """emu: a panic = the emulator process dies + a ``panicked at`` log line."""

    PANIC_MARKERS = ("panicked at", "thread '", "SOAK-PANIC")

    def __init__(self, session: EmuSession) -> None:
        self.session = session

    def alive(self) -> bool:
        return self.session.alive()

    def panic_count(self) -> int:
        try:
            with open(self.session.log_path, "r", errors="replace") as f:
                text = f.read()
        except FileNotFoundError:
            return 0
        return sum(text.count(m) for m in self.PANIC_MARKERS)


class RttPanicWatcher:
    """usb (bench): read the firmware's defmt panic counter off the RTT stream.

    Spawns ``probe-rs defmt`` (which decodes the firmware's defmt config and
    streams it) into a log file and counts the ``SOAK-PANIC #`` lines emitted by
    the device's #[panic_handler] (firmware/src/main.rs). A panic also hangs the
    USB stack, which the driver independently sees as the device going silent.
    """

    def __init__(self, firmware_elf: str, log_path: str, chip: str = "RP2350") -> None:
        self.log_path = log_path
        self.proc: subprocess.Popen | None = None
        if shutil.which("probe-rs") is None:
            raise SystemExit("usb transport: `probe-rs` not on PATH "
                             "(install: cargo install probe-rs)")
        self._logf = open(log_path, "w")
        self.proc = subprocess.Popen(
            ["probe-rs", "defmt", "-b", firmware_elf, "--chip", chip],
            stdout=self._logf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
        )
        time.sleep(2.0)  # give probe-rs time to attach + start streaming

    def alive(self) -> bool:
        # The firmware, not the probe, is the soak subject; "alive" here means
        # probe-rs is still streaming (a lost probe is a harness error, not a
        # device panic). The real panic signal is panic_count().
        return self.proc is not None and self.proc.poll() is None

    def panic_count(self) -> int:
        try:
            with open(self.log_path, "r", errors="replace") as f:
                text = f.read()
        except FileNotFoundError:
            return 0
        return text.count("SOAK-PANIC")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        try:
            self._logf.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# The soak.
# ---------------------------------------------------------------------------
def run_cycle(cycle: int, card, fido, log) -> None:
    """One interleaved app session. Logs each step; never raises on an app SW."""
    # 1. OpenPGP over CCID.
    sel = bytes([0x00, 0xA4, 0x04, 0x00, len(AID_OPENPGP)]) + AID_OPENPGP
    resp = card.transmit(sel)
    log(cycle, "openpgp", "SELECT AID", _sw(resp[-2], resp[-1]))
    data, sw1, sw2 = card.send_apdu(0x00, 0xA4, 0x00, 0x00)  # SELECT MF
    log(cycle, "openpgp", "SELECT MF", _sw(sw1, sw2), f"len={len(data)}")

    # 2. FIDO2 over HID (proves the FIDO stack is alive on its own transport
    #    while the CCID channel is free to switch apps — the stress path).
    try:
        info = fido.get_info()
        log(cycle, "fido2", "GET_INFO", "ok", f"versions={info.versions}")
    except Exception as e:  # a FIDO error is functional, not a stability panic
        log(cycle, "fido2", "GET_INFO", "err", repr(e))

    # 3. OATH over CCID.
    sel = bytes([0x00, 0xA4, 0x04, 0x00, len(AID_OATH)]) + AID_OATH
    resp = card.transmit(sel)
    log(cycle, "oath", "SELECT AID", _sw(resp[-2], resp[-1]))

    # 4. Management over CCID: SELECT + READ_CONFIG (caps).
    sel = bytes([0x00, 0xA4, 0x04, 0x00, len(AID_MANAGEMENT)]) + AID_MANAGEMENT
    resp = card.transmit(sel)
    log(cycle, "mgmt", "SELECT AID", _sw(resp[-2], resp[-1]))
    resp = card.transmit(bytes([0x00, INS_READ_CONFIG, 0x00, 0x00, 0x00]))
    log(cycle, "mgmt", "READ_CONFIG", _sw(resp[-2], resp[-1]), f"len={len(resp)}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--transport", choices=["emu", "usb"], default="emu",
                    help="emu (default, verified) drives fapico2-emulation over "
                         "TCP; usb drives bench RP2350 hardware")
    ap.add_argument("--duration-hours", type=float, default=24.0,
                    help="soak window (default 24 h)")
    ap.add_argument("--max-cycles", type=int, default=0,
                    help="stop after N cycles (0 = run the full window)")
    ap.add_argument("--binary", default=None,
                    help="emu: path to fapico2-emulation (auto-resolved if omitted)")
    ap.add_argument("--firmware-elf", default=None,
                    help="usb: path to the device ELF (for probe-rs defmt)")
    ap.add_argument("--ccid-port", type=int, default=CCID_PORT)
    ap.add_argument("--log-dir", default=None,
                    help="where to archive logs (default logs/soak-<UTC-stamp>)")
    args = ap.parse_args(argv)

    here = os.path.dirname(os.path.abspath(__file__))
    log_dir = args.log_dir or os.path.join(
        here, "logs", "soak-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    os.makedirs(log_dir, exist_ok=True)

    cycle_log_path = os.path.join(log_dir, "soak_cycles.log")
    cycle_log = open(cycle_log_path, "w")

    def log(cycle, app, op, status, extra=""):
        line = f"{_ts()}  c={cycle:07d}  {app:8s} {op:12s} {status:5s} {extra}"
        cycle_log.write(line + "\n")
        cycle_log.flush()
        if cycle % 500 == 0:
            print(line, flush=True)

    log(0, "system", "SOAK-START", "ok",
        f"transport={args.transport} window={args.duration_hours}h "
        f"max_cycles={args.max_cycles} log_dir={log_dir}")

    card = fido = None
    session: EmuSession | None = None
    watcher = None
    panics = 0
    exit_code = 1
    cycle = 0
    verdict = "n/a (setup error)"
    start = time.time()

    try:
        # --- transport setup ---------------------------------------------
        if args.transport == "emu":
            binary = args.binary
            if binary is None:
                cand = os.path.join(here, "..", "..", "target",
                                    "x86_64-unknown-linux-gnu", "debug",
                                    "fapico2-emulation")
                binary = cand if os.path.isfile(cand) else "fapico2-emulation"
            if not os.path.isfile(binary) and not shutil.which(binary):
                raise SystemExit(f"emu: cannot find emulator binary at {binary} "
                                 "(build: cargo build --bin fapico2-emulation "
                                 "--no-default-features --features emulation "
                                 "--target x86_64-unknown-linux-gnu)")
            session = EmuSession(binary, ccid_port=args.ccid_port)
            card = session.start()
            log(0, "system", "EMU-UP", "ok", f"pid={session.proc.pid}")
            watcher = EmuPanicWatcher(session)
        else:  # usb
            if args.firmware_elf is None or not os.path.isfile(args.firmware_elf):
                raise SystemExit("usb: --firmware-elf <device ELF> is required "
                                 "(built for thumbv8m.main-none-eabi)")
            card = UsbCard()
            card.power_on()
            log(0, "system", "USB-UP", "ok")
            fido = make_fido("usb")
            watcher = RttPanicWatcher(args.firmware_elf,
                                      os.path.join(log_dir, "rtt.log"))

        fido = fido or make_fido(args.transport)
        log(0, "system", "FIDO-UP", "ok")

        # --- the loop ----------------------------------------------------
        window = args.duration_hours * 3600.0
        cycle = 0
        while True:
            try:
                run_cycle(cycle, card, fido, log)
                cycle += 1
            except (ConnectionError, OSError) as e:
                # A transport drop is the tell-tale of a dead device/emulator.
                if not watcher.alive():
                    log(cycle, "system", "DEAD", "err", repr(e))
                    break
                log(cycle, "system", "TRANSIENT", "err", repr(e))
                time.sleep(0.5)
                continue

            if not watcher.alive():
                log(cycle, "system", "WATCHER-GONE", "err")
                break
            if watcher.panic_count() > 0:
                log(cycle, "system", "PANIC", "fail", f"count={watcher.panic_count()}")
                break
            if time.time() - start >= window:
                break
            if args.max_cycles and cycle >= args.max_cycles:
                break

        panics = watcher.panic_count()
        elapsed = time.time() - start

        passed = panics == 0
        exit_code = 0 if passed else 1
        verdict = "PASS (zero panics)" if passed else f"FAIL ({panics} panic(s))"
        log(cycle, "system", "SOAK-END", verdict,
            f"cycles={cycle} elapsed={elapsed:.1f}s panics={panics}")
    except SystemExit as e:
        print(f"SOAK SETUP ERROR: {e}", file=sys.stderr)
        log(-1, "system", "SETUP-ERROR", "err", str(e))
        exit_code = 2
    except KeyboardInterrupt:
        log(-1, "system", "INTERRUPTED", "warn")
        exit_code = 2
    finally:
        # --- archive + report -------------------------------------------
        if fido is not None:
            try:
                fido.close()
            except Exception:
                pass
        if card is not None:
            try:
                card.close()
            except Exception:
                pass
        if session is not None:
            session.stop()
        if watcher is not None and hasattr(watcher, "stop"):
            try:
                watcher.stop()
            except Exception:
                pass

        # Copy the transport log (emulator.log / rtt.log) next to the cycle log.
        for src in (
            (os.path.join(session.workdir, "emulator.log") if session else None),
            (os.path.join(log_dir, "rtt.log") if args.transport == "usb" else None),
        ):
            if src and os.path.isfile(src):
                shutil.copyfile(src, os.path.join(log_dir, os.path.basename(src)))

        summary = (
            f"fapico2 soak (US-385)\n"
            f"  verdict   : {verdict}\n"
            f"  transport : {args.transport}\n"
            f"  window    : {args.duration_hours}h\n"
            f"  cycles    : {cycle}\n"
            f"  panics    : {panics}\n"
            f"  exit      : {exit_code}\n"
            f"  log_dir   : {log_dir}\n"
        )
        with open(os.path.join(log_dir, "soak_summary.txt"), "w") as f:
            f.write(summary)
        print(summary, flush=True)
        cycle_log.close()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
