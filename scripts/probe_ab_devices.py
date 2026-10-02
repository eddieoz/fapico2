#!/usr/bin/env python3
"""A/B probe: our Rust fapico2 firmware vs the pico-fido2 C reference firmware.

Two boards are plugged into the same machine. Both enumerate as 1050:0407 and
differ only in their USB identity strings, so this script identifies them by
reading the descriptors -- never by hidraw node number, which can move across
replugs.

READ-ONLY. This script never sets, changes or clears a PIN, never creates or
deletes a credential, and never sends a management or reset command. The only
non-idempotent call it makes is a MakeCredential sent to a throwaway RP id
(`ab-probe.invalid`) that is deliberately never completed.

Usage:
    PYTHON=/path/to/fido2-venv/bin/python scripts/probe_ab_devices.py

The fido2 2.2.1 virtualenv lives in the main checkout, not in this worktree:
    /home/eddieoz/Projects/git/pico/pico-fido2/.test-venv

Evidence discipline: every value this script prints was observed on the wire in
this run. Fields that could not be observed are printed as UNAVAILABLE with the
reason, never defaulted from spec knowledge.
"""

from __future__ import annotations

import json
import os
import re
import select
import signal
import struct
import subprocess
import sys
import threading
import time

BROADCAST_CID = 0xFFFFFFFF

# ---------------------------------------------------------------------------
# Global watchdog.
#
# AUDIT FIX (US-1521). The inherited version guarded every READ with
# select(), but every WRITE went straight to connection.write_packet() with no
# bound. On Linux a hidraw interrupt-OUT write blocks in the kernel until the
# device drains the endpoint -- and US-1501 measured exactly that behaviour on
# our board: it stops reading the OUT endpoint during the user-presence window
# and the host's writes block to ETIMEDOUT. So the very defect under
# investigation was also an unbounded-hang path in the probe harness: one
# unlucky write and the script would sit there forever instead of recording a
# timeout.
#
# Every probe step therefore runs under a hard SIGALRM deadline. A blocked
# write cannot outrun it; it is interrupted, the exception propagates, and the
# step is recorded as TIMED OUT. Nothing is left half-sent that mutates state:
# the worst case is a frame the device ignores.
# ---------------------------------------------------------------------------


def _alarm_handler(signum, frame):
    raise Timeout(f"hard watchdog: step exceeded its {WATCHDOG_S}s budget")


def set_watchdog(seconds):
    """Arm the hard per-step deadline. No-op off the main thread."""
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(int(seconds))


def clear_watchdog():
    if threading.current_thread() is threading.main_thread():
        signal.alarm(0)


WATCHDOG_S = 45

# Per-step hard budgets. A step is allowed a generous ceiling because it
# contains several bounded sub-operations (e.g. the consent-window step can
# legitimately spend 35s on WINK + 30s of PING probes + 25s multiplexed
# MakeCredential). The per-read `select()` timeouts inside those sub-operations
# remain the real bound; this outer alarm is only a backstop against a WRITE
# that blocks in the kernel, which no inner timeout can interrupt.
STEP_BUDGET_DEFAULT = 60
STEP_BUDGETS = {
    "assertion_a": 70, "assertion_b": 70,
    "pin_a": 130, "pin_b": 130,
    "window_a": 140, "window_b": 140,
    "presence_a": 80, "presence_b": 80,
}
TYPE_INIT = 0x80
CTAPHID_PING = 0x01
CTAPHID_INIT = 0x06
CTAPHID_WINK = 0x08
CTAPHID_CBOR = 0x10
CTAPHID_CANCEL = 0x11
CTAPHID_KEEPALIVE = 0x3B
CTAPHID_ERROR_FRAME = TYPE_INIT | 0x3F

# fido2 2.2.1 dialect opcodes (NOT the CTAP 2.1 spec values -- see AGENTS.md 2).
CTAP2_GET_INFO = 0x04
CTAP2_CLIENT_PIN = 0x06
CTAP2_MAKE_CREDENTIAL = 0x01
CTAP2_GET_NEXT_ASSERTION = 0x02
CTAP2_AUTH_SELECTION = 0x0B

READ_TIMEOUT = 5.0
PING_TIMEOUT = 5.0
LONG_TIMEOUT = 35.0

# The two firmwares we are comparing, keyed by iManufacturer.
DEVICE_A_MANUFACTURER = "EddieOz"  # our Rust firmware
DEVICE_B_MANUFACTURER = "Pol Henarejos"  # ../pico-fido2 C reference

throwaway_rp = "ab-probe.invalid"

cbor = None  # set in main()


# --------------------------------------------------------------------------
# raw CTAPHID framing
# --------------------------------------------------------------------------


class Timeout(Exception):
    pass


class RawCtap:
    """Minimal CTAPHID framer giving byte-level access and explicit timeouts.

    Deliberately does not use fido2's CtapHidDevice.call(), because that helper
    parses the reply for us and would hide the raw bytes that are the evidence.
    """

    def __init__(self, descriptor, connection):
        self.desc = descriptor
        self.conn = connection
        self.fd = connection.handle
        self.packet_size = descriptor.report_size_out
        self._cid = BROADCAST_CID
        self._last_keepalives = []

    @classmethod
    def open(cls, descriptor):
        from fido2.hid import open_connection

        return cls(descriptor, open_connection(descriptor))

    def close(self):
        try:
            self.conn.close()
        except OSError:
            pass

    def _write(self, packet):
        # IMPORTANT: on Linux the hidraw WRITE path requires the leading report
        # id byte. fido2's LinuxCtapHidConnection.write_packet prepends b"\0";
        # a raw os.write() without it sends a frame the device mis-frames. The
        # first run of this script made that mistake and it produced a column
        # of bogus timeouts on one device and clean results on the other, so
        # the write path goes through the connection object, not os.write().
        self.conn.write_packet(packet)

    def selftest(self, label):
        """Prove the framer works on THIS device before trusting any reading.

        INIT alone is not a sufficient test: a frame written without the
        hidraw report-id byte still gets a correct-looking INIT reply on the
        broadcast channel, because the first cid byte is consumed as the report
        id. Only a PING on the assigned, non-broadcast channel proves the
        framing.
        """
        init, _, _ = self.call(CTAPHID_INIT, os.urandom(8), cid=BROADCAST_CID)
        if init is None or len(init) < 17:
            raise Timeout("self-test: INIT did not return a 17-byte reply")
        self._cid = struct.unpack_from(">I", init, 8)[0]
        probe = b"FRAMING-SELFTEST"
        try:
            echo, _, _ = self.call(CTAPHID_PING, probe, cid=self._cid, timeout=PING_TIMEOUT)
        except (Timeout, CtapHidError, OSError) as e:
            raise Timeout(
                f"self-test FAILED on {label}: PING on cid 0x{self._cid:08x} did not "
                f"echo ({type(e).__name__}: {e}). The framer is not talking to this "
                f"device correctly; DISCARDING every reading from it."
            ) from e
        if echo != probe:
            raise Timeout(
                f"self-test FAILED on {label}: PING echo mismatch "
                f"(sent {probe.hex()}, got {echo.hex()})"
            )
        return self._cid

    def _read(self, timeout):
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            raise Timeout(f"no packet within {timeout}s")
        return os.read(self.fd, self.desc.report_size_in)

    def send_only(self, cmd, data=b"", cid=BROADCAST_CID):
        """Write the packets for one command without reading the reply.

        Used to interleave commands on a single channel, which is what CTAPHID
        multiplexing is for and what a browser does.
        """
        trace = []
        header = struct.pack(">IBH", cid, TYPE_INIT | cmd, len(data))
        remaining, seq = data, 0
        while remaining or seq == 0:
            size = min(len(remaining), self.packet_size - len(header))
            body, remaining = remaining[:size], remaining[size:]
            packet = (header + body).ljust(self.packet_size, b"\0")
            trace.append(("SEND", packet.hex()))
            self._write(packet)
            header = struct.pack(">IB", cid, 0x7F & seq)
            seq += 1
        return trace

    def read_message(self, cmd, cid, timeout, trace=None):
        """Read one CTAPHID message, skipping KEEPALIVE frames.

        Returns (payload, trace). Raises CtapHidError / Timeout.
        """
        seq, r_len, response = 0, 0, b""
        while True:
            recv = self._read(timeout)
            if trace is not None:
                trace.append(("RECV", recv.hex()))
            if struct.unpack_from(">I", recv)[0] != cid:
                raise Timeout(
                    f"wrong channel 0x{struct.unpack_from('>I', recv)[0]:08x}"
                    f" (waiting on 0x{cid:08x})"
                )
            recv = recv[4:]
            if not response:
                r_cmd, r_len = struct.unpack_from(">BH", recv)
                recv = recv[3:]
                if r_cmd == TYPE_INIT | cmd:
                    pass
                elif r_cmd == TYPE_INIT | 0x3B:  # KEEPALIVE
                    if trace is not None:
                        trace.append(("KEEPALIVE", "status=0x%02x" % recv[0]))
                    self._last_keepalives.append(recv[0])
                    continue
                elif r_cmd == TYPE_INIT | 0x3F:  # CTAPHID ERROR
                    raise CtapHidError(struct.unpack_from(">B", recv)[0],
                                       trace or [])
                else:
                    raise CtapHidError(0x7F, trace or [])
            else:
                r_seq = recv[0]
                recv = recv[1:]
                if r_seq != seq & 0x7F:
                    raise Timeout("bad sequence number")
                seq += 1
            response += recv
            if len(response) >= r_len:
                return response[:r_len], trace or []

    def call(self, cmd, data=b"", cid=BROADCAST_CID, timeout=READ_TIMEOUT):
        """Send one CTAPHID command. Returns (payload, packet_hex_list, elapsed)."""
        self._last_keepalives = []
        t0 = time.monotonic()
        trace = self.send_only(cmd, data, cid)
        payload, _ = self.read_message(cmd, cid, timeout, trace)
        return payload, trace, time.monotonic() - t0

    def read_frame(self, cid, timeout):
        """Read ONE CTAPHID message from `cid` and return (frame_cmd, payload).

        frame_cmd is the response byte with TYPE_INIT still set, so
        TYPE_INIT | cmd identifies which outstanding request the message answers.
        That is what makes interleaved multiplexing unambiguous: while a long
        command is outstanding, a PING reply and a KEEPALIVE frame can be told
        apart without guessing.
        """
        seq, r_len, response = 0, 0, b""
        frame_cmd = None
        while True:
            recv = self._read(timeout)
            if struct.unpack_from(">I", recv)[0] != cid:
                raise Timeout(
                    f"wrong channel 0x{struct.unpack_from('>I', recv)[0]:08x} "
                    f"(waiting on 0x{cid:08x})"
                )
            recv = recv[4:]
            if frame_cmd is None:
                frame_cmd, r_len = struct.unpack_from(">BH", recv)
                recv = recv[3:]
            else:
                r_seq = recv[0]
                recv = recv[1:]
                if r_seq != seq & 0x7F:
                    raise Timeout("bad sequence number")
                seq += 1
            response += recv
            if len(response) >= r_len:
                return frame_cmd, response[:r_len]

    def multiplex(self, long_cmd, long_data, pings=4, ping_timeout=PING_TIMEOUT,
                  total_budget=20.0):
        """Send a long-running command and PING it on the SAME channel, interleaved.

        This is the only correct way to ask "does the authenticator still answer
        while a user-presence window is open?" from a single process against a
        single hidraw node.

        Opening a SECOND file descriptor on the same /dev/hidrawN looks like the
        obvious approach and is wrong: both fds share one USB interrupt endpoint,
        so a write on one blocks behind the other's pending read and the kernel
        eventually returns ETIMEDOUT -- on BOTH devices, identically. Two threads
        on one fd are worse: they steal each other's packets.

        Responses are attributed by their frame-command byte, which is exactly
        what that byte is for.
        """
        cid = self._cid
        t0 = time.monotonic()
        self._last_keepalives = []
        self.send_only(long_cmd, long_data, cid)
        result = {"outcome": "long command still outstanding at end of probe",
                  "payload_hex": None, "status": None, "long_error": None,
                  "pings": []}
        long_done = False
        for i in range(pings + 1):
            if time.monotonic() - t0 > total_budget or long_done:
                break
            self.send_only(CTAPHID_PING, b"inwindow", cid)
            ping_t = time.monotonic()
            while True:
                try:
                    r_cmd, payload = self.read_frame(cid, ping_timeout)
                except Timeout:
                    result["pings"].append({"i": i, "timeout": True})
                    break
                except CtapHidError:
                    raise
                if r_cmd == TYPE_INIT | 0x3B:  # KEEPALIVE
                    self._last_keepalives.append(payload[0])
                    continue
                if r_cmd == TYPE_INIT | long_cmd:
                    long_done = True
                    result["payload_hex"] = payload.hex()
                    result["status"] = f"0x{payload[0]:02x}" if payload else None
                    result["outcome"] = "replied"
                    continue
                if r_cmd == CTAPHID_ERROR_FRAME:
                    # AUDIT FIX (US-1521): the inherited version tested
                    # `r_cmd == TYPE_INIT | 0x3F` INSIDE the
                    # `r_cmd == TYPE_INIT | long_cmd` branch. That is dead
                    # code: 0xBF != 0x90 for a CBOR command, so a CTAPHID
                    # ERROR answering the long command never matched and fell
                    # through to the generic "unexpected frame command"
                    # Timeout below -- reporting a framing fault for what is
                    # actually a device reply. Checked before the keepalive and
                    # ping branches because 0xBF is neither of those.
                    long_done = True
                    result["long_error"] = (
                        f"CTAPHID_ERROR frame 0x{payload[0]:02x} "
                        f"(ERR on channel, not a CTAP2 status)"
                        if payload else "CTAPHID_ERROR frame, empty payload")
                    result["outcome"] = result["long_error"]
                    continue
                if r_cmd == TYPE_INIT | CTAPHID_PING:
                    result["pings"].append({
                        "i": i,
                        "latency_ms": round((time.monotonic() - ping_t) * 1000, 1),
                        "echo_ok": payload == b"inwindow",
                    })
                    break
                raise Timeout(
                    f"unexpected frame command 0x{r_cmd:02x} while waiting for "
                    f"0x{(TYPE_INIT | long_cmd):02x} / 0x{(TYPE_INIT | CTAPHID_PING):02x}"
                )
        if not long_done:
            result["outcome"] = "STILL PARKED when the probe budget ran out"
        result["keepalive_statuses"] = sorted(set(self._last_keepalives))
        result["keepalive_frames"] = len(self._last_keepalives)
        result["elapsed_ms"] = round((time.monotonic() - t0) * 1000, 1)
        result["any_ping_timeout"] = any(p.get("timeout") for p in result["pings"])
        return result

    def ping(self, msg=b"Hello FIDO", timeout=PING_TIMEOUT):
        return self.call(CTAPHID_PING, msg, cid=self.cid, timeout=timeout)

    def cancel(self):
        """Send CTAPHID_CANCEL (0x11) on the current channel.

        Required to leave a device that is parked in a user-presence wait in a
        clean state. Read-only: it aborts nothing that was created.
        """
        try:
            self.call(CTAPHID_CANCEL, b"", cid=self._cid, timeout=5.0)
            return True
        except (Timeout, CtapHidError, OSError) as e:
            return f"{type(e).__name__}: {e}"

    @property
    def cid(self):
        return self._cid


class CtapHidError(Exception):
    def __init__(self, code, trace=None):
        super().__init__(f"CTAPHID error 0x{code:02x}")
        self.code = code
        self.trace = trace or []


# --------------------------------------------------------------------------
# device identification -- never by hidraw node number
# --------------------------------------------------------------------------


def usb_strings(bus, dev):
    """Read iManufacturer/iProduct/iSerial/bcdDevice from lsusb -v."""
    out = {}
    try:
        raw = subprocess.run(
            ["lsusb", "-v", "-s", f"{bus}:{dev}", "-d", "1050:0407"],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return out
    for key in ("iManufacturer", "iProduct", "iSerial"):
        m = re.search(rf"^\s+{key}\s+\d+\s+(.*)$", raw, re.M)
        if m:
            out[key] = m.group(1).strip()
    # AUDIT FIX (US-1521): the inherited regex was `(0x[0-9a-f]+)`, which only
    # matched a bcdDevice printed in hex. lsusb prints bcdDevice in DECIMAL
    # ("9.00"), so the column silently came back None for the C reference even
    # though the descriptor carried it. Accept both, and keep the raw text so
    # nothing is inferred.
    m = re.search(r"^\s+bcdDevice\s+(\S+)\s*$", raw, re.M)
    if m:
        rawval = m.group(1)
        try:
            if rawval.lower().startswith("0x"):
                major = int(rawval[2:4], 16)
                minor = int(rawval[4:6], 16) if len(rawval) >= 6 else 0
            else:
                whole, _, frac = rawval.partition(".")
                major, minor = int(whole), int(frac or 0)
            out["bcdDevice"] = f"{major}.{minor} (raw {rawval})"
        except ValueError:
            out["bcdDevice"] = f"UNPARSED (raw {rawval})"
    return out


def hidraw_usb_address(path):
    """hidrawN -> (bus, dev) by walking sysfs up to the usb_device node.

    The usb_device directory (e.g. /sys/bus/usb/devices/1-1:1.1) exposes busnum
    and devnum, which is exactly what `lsusb -s` wants.
    """
    node = os.path.basename(path)
    real = os.path.realpath(f"/sys/class/hidraw/{node}/device")
    d = real
    for _ in range(6):
        d = os.path.dirname(d)
        try:
            with open(os.path.join(d, "busnum")) as f:
                bus = f.read().strip()
            with open(os.path.join(d, "devnum")) as f:
                dev = f.read().strip()
        except OSError:
            continue
        return (bus, f"{int(dev):03d}")
    return None


def enumerate_devices():
    """Every FIDO CTAPHID device, with a positive identity from descriptors."""
    from fido2.hid import get_descriptor
    import glob

    found = []
    for path in sorted(glob.glob("/dev/hidraw*"), key=lambda p: int(re.sub(r"\D", "", p))):
        try:
            desc = get_descriptor(path)
        except Exception:
            continue
        if (desc.vid, desc.pid) != (0x1050, 0x0407):
            continue
        addr = hidraw_usb_address(path)
        strings = usb_strings(*addr) if addr else {}
        found.append(
            {
                "path": path,
                "usb_addr": addr,
                "manufacturer": strings.get("iManufacturer"),
                "product": strings.get("iProduct"),
                "serial": strings.get("iSerial"),
                "bcdDevice": strings.get("bcdDevice"),
                "hid_product_name": desc.product_name,
                "hid_serial": desc.serial_number,
                "descriptor": desc,
            }
        )
    return found


def pick(inventory, manufacturer, label):
    """Select exactly one device by iManufacturer, or fail loudly."""
    matches = [d for d in inventory if d["manufacturer"] == manufacturer]
    if len(matches) != 1:
        raise SystemExit(
            f"FATAL: expected exactly 1 device with iManufacturer={manufacturer!r} "
            f"({label}), found {len(matches)}. Refusing to guess."
        )
    d = matches[0]
    print(
        f"  {label}: iManufacturer={d['manufacturer']!r} iProduct={d['product']!r} "
        f"iSerial={d['serial']!r} bcdDevice={d['bcdDevice']} "
        f"-> {d['path']} (usb {d['usb_addr']})"
    )
    return d


def self_check(dev, expected_manufacturer):
    """Re-verify identity immediately before trusting a reading."""
    if dev["manufacturer"] != expected_manufacturer:
        raise SystemExit(
            f"FATAL: identity mismatch on {dev['path']}: expected "
            f"iManufacturer={expected_manufacturer!r}, got {dev['manufacturer']!r}. "
            f"Discarding reading."
        )


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def hx(b):
    return b.hex() if isinstance(b, (bytes, bytearray)) else str(b)


def show_trace(trace):
    for direction, data in trace:
        print(f"      {direction} {data}")


def decode_capflags(v):
    """Decode one capFlags byte under BOTH live conventions.

    AUDIT FIX (US-1521). The inherited version HARDCODED the de-facto column
    {0x01: WINK, 0x02: "(LOCK, unused)", 0x04: CBOR, 0x08: NMSG} while its own
    docstring claimed the column "reads fido2 2.2.1's own
    fido2/hid/__init__.py CAPABILITY IntFlag". The claim was false: nothing read
    the library. The hardcoded copy happened to agree with the installed
    library, but a hardcoded copy is exactly the "fill the gap from spec
    knowledge" failure mode this probe exists to avoid -- if the venv ever
    moved to a different fido2, the column would silently keep asserting the
    old one. It is now read from the installed package at run time and the
    source is printed, so the evidence is anchored to the artefact.

    spec convention (CTAP 2.1 sec 11.2.1.1) has no machine-readable form in the
    installed package, so that column stays a literal transcription and says so.
    """
    spec = {0x01: "CBOR", 0x02: "NMSG", 0x04: "WINK"}  # literal CTAP 2.1 11.2.1.1
    defacto, defacto_src = _defacto_capability_map()
    s = [f"{spec[b]}(0x{b:02x})" for b in (0x01, 0x02, 0x04, 0x08) if v & b and b in spec]
    f = [f"{defacto[b]}(0x{b:02x})" for b in sorted(defacto) if v & b]
    unknown = v & ~0x0F
    if unknown:
        s.append(f"UNASSIGNED(0x{unknown:02x})")
        f.append(f"UNASSIGNED(0x{unknown:02x})")
    print(f"         de-facto column source: {defacto_src}")
    return s, f


_DEFACTO_SRC = None


def _defacto_capability_map():
    """Read the de-facto capFlags bits from the INSTALLED fido2 package."""
    global _DEFACTO_SRC
    if _DEFACTO_SRC is not None:
        return _DEFACTO_SRC
    try:
        import fido2.hid

        cap = fido2.hid.CAPABILITY
        m = {int(v): n for n, v in cap.__members__.items()}
        src = (f"fido2.hid.CAPABILITY in {fido2.hid.__file__} "
               f"-> { {n: hex(int(v)) for n, v in cap.__members__.items()} }")
    except Exception as e:  # never fall back to a hardcoded guess
        m = {}
        src = f"UNAVAILABLE: could not read fido2.hid.CAPABILITY ({type(e).__name__}: {e})"
    _DEFACTO_SRC = (m, src)
    return _DEFACTO_SRC


def options_report(options):
    """Render the options map with key TYPES preserved. Never guesses."""
    if options is None:
        return "options map NOT PRESENT in the reply (unobserved)"
    if not isinstance(options, dict):
        return f"options is {type(options).__name__}, not a map: {options!r}"
    lines = [f"{k!r} (key type={type(k).__name__}) = {v!r}" for k, v in options.items()]
    return "; ".join(lines) if lines else "options map present but EMPTY"


# GetInfo TOP-LEVEL members as (name, spec integer key). A device may key this
# map either by text name or by integer id; every lookup below reports which
# form it actually found and prints UNAVAILABLE when neither is present. It
# never substitutes a default.
GETINFO_MEMBERS = [
    ("versions", 0x01),
    ("extensions", 0x02),
    ("aaguid", 0x03),
    ("options", 0x04),
    ("maxMsgSize", 0x05),
    ("pinUvAuthProtocols", 0x06),
    ("maxCredentialCountInList", 0x07),
    ("maxCredentialIdLength", 0x08),
    ("transports", 0x09),
    ("algorithms", 0x0A),
    ("maxSerializedLargeBlobArray", 0x0B),
    ("forcePINChange", 0x0C),
    ("minPINLength", 0x0D),
    ("firmwareVersion", 0x0E),
    ("maxCredBlobLength", 0x0F),
    ("maxRPIDsForSetMinPINLength", 0x10),
    ("preferredPlatformUvAttempts", 0x11),
    ("uvModality", 0x12),
    ("certifications", 0x13),
    ("remainingDiscoverableCredentials", 0x14),
    ("vendorPrototypeConfigCommands", 0x15),
    ("attestationFormats", 0x19),
    ("uvCountSinceLastPinEntry", 0x1B),
    ("longTouchForReset", 0x1D),
    ("encIdentifier", 0x1E),
    ("transportsForReset", 0x1F),
]

# Options-MAP members: (name, spec integer option id). These live INSIDE the
# `options` member, and a device may key that map by text or by integer.
OPTION_MEMBERS = [
    ("rk", 0x02),
    ("up", 0x03),
    ("uv", 0x04),
    ("plat", 0x05),
    ("clientPin", 0x06),
    ("credMgmt", 0x07),
    ("bioEnroll", 0x08),
    ("pinUvAuthToken", 0x09),
    ("noMcGaPermissionsWithClientPin", 0x0A),
    ("largeBlobs", 0x0B),
    ("ep", 0x0D),
    ("authnrCfg", 0x0E),
    ("uvBioEnroll", 0x0F),
    ("uvToken", 0x14),
    ("alwaysUv", 0x15),
    ("makeCredUvNotRqd", 0x16),
]


def dual_lookup(mapping, name, int_key):
    """Find `name` under either key form. Returns (found, value, how)."""
    if not isinstance(mapping, dict):
        return False, None, None
    if name in mapping:
        return True, mapping[name], f"text key {name!r}"
    if int_key is not None and int_key in mapping:
        return True, mapping[int_key], f"integer key {int_key} (0x{int_key:02x})"
    return False, None, None


def parse_ctap2(payload):
    """Split the CTAP2 status byte, then decode the CBOR map. Raw hex kept."""
    if not payload:
        return None, None, "empty payload"
    status = payload[0]
    rest = payload[1:]
    if not rest:
        return status, None, "no CBOR body after status byte"
    try:
        return status, cbor.loads(rest), None
    except Exception as e:  # loud anomaly, not a silent default
        return status, None, f"CBOR DECODE FAILED: {type(e).__name__}: {e}"


CTAP2_STATUS = {
    0x00: "CTAP2_OK",
    0x01: "CTAP1_ERR_INVALID_COMMAND",
    0x02: "CTAP1_ERR_INVALID_PARAMETER",
    0x03: "CTAP1_ERR_INVALID_LENGTH",
    0x04: "CTAP1_ERR_INVALID_SEQ",
    0x05: "CTAP1_ERR_TIMEOUT",
    0x06: "CTAP1_ERR_CHANNEL_BUSY",
    0x0A: "CTAP1_ERR_LOCK_REQUIRED",
    0x0B: "CTAP1_ERR_INVALID_CHANNEL",
    0x11: "CTAP2_ERR_CBOR_UNEXPECTED_TYPE",
    0x12: "CTAP2_ERR_INVALID_CBOR",
    0x14: "CTAP2_ERR_MISSING_PARAMETER",
    0x15: "CTAP2_ERR_LIMIT_EXCEEDED",
    0x16: "CTAP2_ERR_UNSUPPORTED_EXTENSION",
    0x19: "CTAP2_ERR_CREDENTIAL_EXCLUDED",
    0x21: "CTAP2_ERR_PROCESSING",
    0x22: "CTAP2_ERR_INVALID_CREDENTIAL",
    0x23: "CTAP2_ERR_USER_ACTION_PENDING",
    0x24: "CTAP2_ERR_OPERATION_PENDING",
    0x25: "CTAP2_ERR_NO_OPERATIONS",
    0x26: "CTAP2_ERR_UNSUPPORTED_ALGORITHM",
    0x27: "CTAP2_ERR_OPERATION_DENIED",
    0x28: "CTAP2_ERR_KEY_STORE_FULL",
    0x2B: "CTAP1_ERR_APPLICATION_ERROR (0x2B)",
    0x2C: "CTAP1_ERR_APPLICATION_ERROR (0x2C)",
    0x2D: "CTAP1_ERR_APPLICATION_ERROR (0x2D)",
    0x2E: "CTAP1_ERR_APPLICATION_ERROR (0x2E)",
    0x2F: "CTAP1_ERR_APPLICATION_ERROR (0x2F)",
    0x30: "CTAP2_ERR_PIN_REQUIRED",
    0x31: "CTAP2_ERR_PIN_INVALID",
    0x32: "CTAP2_ERR_PIN_AUTH_INVALID",
    0x33: "CTAP2_ERR_PIN_AUTH_BLOCKED",
    0x34: "CTAP2_ERR_PIN_NOT_SET",
    0x35: "CTAP2_ERR_PUAT_REQUIRED",
    0x36: "CTAP2_ERR_PIN_POLICY_VIOLATION",
    0x37: "CTAP2_ERR_PIN_TOKEN_EXPIRED (reserved)",
    0x38: "CTAP2_ERR_REQUEST_TOO_LARGE",
    0x39: "CTAP2_ERR_ACTION_TIMEOUT",
    0x3A: "CTAP2_ERR_UP_REQUIRED",
    0x3B: "CTAP2_ERR_UV_BLOCKED",
    0x3C: "CTAP2_ERR_INTEGRITY_FAILURE",
    0x3D: "CTAP2_ERR_INVALID_SUBCOMMAND",
    0x3E: "CTAP2_ERR_UV_INVALID",
    0x3F: "CTAP2_ERR_UNAUTHORIZED_PERMISSION",
    0x7F: "CTAP1_ERR_OTHER",
    0xDF: "CTAP2_ERR_UP_DISABLED",
}


def status_name(code):
    return CTAP2_STATUS.get(code, "NOT IN MY TABLE -- meaning UNOBSERVED, not guessed")


def hdr(title):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


# --------------------------------------------------------------------------
# probes
# --------------------------------------------------------------------------


def probe_selftest(dev, manufacturer, label):
    """Prove the framer works on this device before any reading is trusted."""
    self_check(dev, manufacturer)
    raw = RawCtap.open(dev["descriptor"])
    try:
        cid = raw.selftest(label)
        print(f"  [{label}] framer self-test PASSED on {dev['path']} "
              f"(iManufacturer={dev['manufacturer']!r}): INIT ok, PING echoed on "
              f"cid 0x{cid:08x}")
        return {"path": dev["path"], "manufacturer": dev["manufacturer"],
                "selftest": "PASS", "cid": f"0x{cid:08x}"}
    except Timeout as e:
        print(f"  [{label}] framer self-test FAILED on {dev['path']}: {e}")
        return {"path": dev["path"], "manufacturer": dev["manufacturer"],
                "selftest": "FAIL", "error": str(e)}
    finally:
        raw.close()


def probe_init(dev, manufacturer, label, nonce):
    """Probe 1: CTAPHID_INIT (0x06) on the broadcast channel."""
    self_check(dev, manufacturer)
    raw = RawCtap.open(dev["descriptor"])
    try:
        payload, trace, elapsed = raw.call(CTAPHID_INIT, nonce, cid=BROADCAST_CID)
        # CTAPHID_INIT reply layout, 17 bytes total:
        #   [0:8]  nonce echo
        #   [8:12] newly assigned channel id (big endian)
        #   [12]   CTAPHID protocol version
        #   [13]   device firmware version major
        #   [14]   device firmware version minor
        #   [15]   device firmware version build
        #   [16]   capability flags   <-- the contested byte
        if len(payload) < 17:
            raise Timeout(f"INIT reply too short: {len(payload)} bytes, expected 17")
        assigned = struct.unpack_from(">I", payload, 8)[0]
        version_interface = payload[12]
        fw = (payload[13], payload[14], payload[15])
        caps = payload[16]
        raw._cid = assigned
        spec_names, defacto_names = decode_capflags(caps)
        print(f"\n  [{label}] CTAPHID_INIT reply in {elapsed * 1000:.1f} ms")
        print(f"      nonce sent      : {hx(nonce)}")
        print(f"      full payload hex: {hx(payload)}  ({len(payload)} bytes)")
        show_trace(trace)
        print(f"      echo nonce      : {hx(payload[:8])}  match={payload[:8] == nonce}")
        print(f"      byte 8  cid     : 0x{assigned:08x}")
        print(f"      byte 12 verIf   : {version_interface}  (CTAPHID protocol version)")
        print(
            f"      bytes 13..15 fw : {fw[0]}.{fw[1]}.{fw[2]}  "
            f"(YubiKey firmware version field, NOT a CTAP version)"
        )
        print(f"      BYTE 16 capFlags: 0x{caps:02x}")
        print(f"         spec CTAP 2.1 : {' + '.join(spec_names) or 'none'}")
        print(f"         de-facto sdk  : {' + '.join(defacto_names) or 'none'}")
        print(f"         -> spec convention (CTAP 2.1) concludes CBOR supported? "
              f"{'YES' if caps & 0x01 else 'NO'}  (tests bit 0x01)")
        print(f"         -> de-facto convention (pico-keys-sdk/fido2) concludes CBOR "
              f"supported? {'YES' if caps & 0x04 else 'NO'}  (tests bit 0x04)")
        return {
            "label": label,
            "path": dev["path"],
            "manufacturer": dev["manufacturer"],
            "serial": dev["serial"],
            "latency_ms": round(elapsed * 1000, 1),
            "payload_hex": hx(payload),
            "echo_ok": payload[:8] == nonce,
            "cid": f"0x{assigned:08x}",
            "version_interface": version_interface,
            "firmware_version": ".".join(map(str, fw)),
            "cap_flags": f"0x{caps:02x}",
            "cap_flags_int": caps,
            "cap_flags_spec": spec_names,
            "cap_flags_defacto": defacto_names,
            "spec_says_cbor": bool(caps & 0x01),
            "defacto_says_cbor": bool(caps & 0x04),
        }
    except (Timeout, CtapHidError, OSError) as e:
        print(f"      [{label}] CTAPHID_INIT FAILED: {type(e).__name__}: {e}")
        return {"label": label, "path": dev["path"], "error": f"{type(e).__name__}: {e}"}
    finally:
        raw.close()


def probe_init_random(dev, manufacturer, label):
    """Second INIT with a random nonce, to confirm the echo is not a constant."""
    self_check(dev, manufacturer)
    nonce = os.urandom(8)
    raw = RawCtap.open(dev["descriptor"])
    try:
        payload, _, _ = raw.call(CTAPHID_INIT, nonce, cid=BROADCAST_CID)
        return {"nonce": hx(nonce), "echo": hx(payload[:8]), "match": payload[:8] == nonce}
    finally:
        raw.close()


def probe_getinfo(dev, manufacturer, label, attempts=3, timeout=10.0):
    """Probe 2: authenticatorGetInfo, opcode 0x04 in the fido2 2.2.1 dialect.

    Retried a bounded number of times with an explicit timeout so that a
    timeout is recorded AS a timeout rather than silently becoming an absence.
    """
    self_check(dev, manufacturer)
    raw = RawCtap.open(dev["descriptor"])
    try:
        raw.selftest(label)
        payload = trace = elapsed = None
        failures = []
        for attempt in range(1, attempts + 1):
            try:
                payload, trace, elapsed = raw.call(
                    CTAPHID_CBOR, bytes([CTAP2_GET_INFO]), cid=raw.cid, timeout=timeout
                )
                break
            except (Timeout, CtapHidError, OSError) as e:
                failures.append(f"attempt {attempt}: {type(e).__name__}: {e}")
                print(f"      [{label}] GetInfo attempt {attempt}/{attempts} FAILED: "
                      f"{type(e).__name__}: {e}  (timeout {timeout}s)")
        if payload is None:
            print(f"      [{label}] authenticatorGetInfo: NO REPLY after {attempts} "
                  f"attempts. Detail: {failures}")
            print(f"      !! ANOMALY: GetInfo never answered. This is a recorded failure, "
                  f"NOT an absence of fields.")
            return {"label": label, "attempts": attempts, "timeout_s": timeout,
                    "failures": failures, "getinfo_answered": False}
        print(f"      (GetInfo answered on the last of {attempts} attempts after "
              f"{len(failures)} failure(s); failures: {failures})")
        status, info, err = parse_ctap2(payload)
        print(f"\n  [{label}] authenticatorGetInfo (opcode 0x04, fido2 dialect) "
              f"in {elapsed*1000:.1f} ms")
        print(f"      full payload hex: {hx(payload)}  ({len(payload)} bytes)")
        show_trace(trace)
        print(f"      status byte     : 0x{status:02x}")
        if err:
            print(f"      !! {err}")
            return {"label": label, "status": f"0x{status:02x}", "error": err,
                    "payload_hex": hx(payload)}
        if not isinstance(info, dict):
            print(f"      !! ANOMALY: decoded body is {type(info).__name__}, not a map: "
                  f"{info!r}")
            return {"label": label, "status": f"0x{status:02x}",
                    "error": f"not a map: {info!r}", "payload_hex": hx(payload)}

        key_types = sorted({type(k).__name__ for k in info})
        print(f"      CBOR decoded OK: {len(info)} top-level keys, "
              f"key type(s) present = {key_types}")
        print(f"      RAW DECODED TOP-LEVEL MAP (every key, key type shown):")
        for k, v in info.items():
            print(f"        {k!r:>10}  (key type={type(k).__name__:>5})  = {v!r}")
        print()
        print("      TOP-LEVEL MEMBER LOOKUP (text key first, then spec integer key; "
              "UNAVAILABLE = genuinely absent from the reply):")
        top = {}
        for name, int_key in GETINFO_MEMBERS:
            found, value, how = dual_lookup(info, name, int_key)
            if found:
                print(f"        {name:34s} = {value!r}   [via {how}]")
                top[name] = {"value": value, "via": how, "present": True}
            else:
                print(f"        {name:34s} = UNAVAILABLE (neither {name!r} nor integer "
                      f"key 0x{int_key:02x} present)")
                top[name] = {"value": "UNAVAILABLE", "via": None, "present": False}

        opts_found, opts_value, opts_how = dual_lookup(info, "options", 0x04)
        print()
        print(f"      OPTIONS MAP (member present={opts_found}, found via {opts_how}):")
        if not opts_found:
            print("        !! ANOMALY: no `options` member under either key form. "
                  f"Top-level keys actually seen: "
                  f"{[(k, type(k).__name__) for k in info]!r}")
            opts = None
        else:
            opts = opts_value
            if not isinstance(opts, dict):
                print(f"        !! ANOMALY: `options` decoded as {type(opts).__name__}, "
                      f"not a map: {opts!r}")
                opts = None
            else:
                opt_key_types = sorted({type(k).__name__ for k in opts})
                print(f"        options key type(s) present = {opt_key_types}")
                print(f"        RAW OPTIONS MAP (every key, key type shown):")
                for k, v in opts.items():
                    print(f"          {k!r:>10}  (key type={type(k).__name__:>5})  = {v!r}")

        print()
        print("      OPTION-MEMBER LOOKUP (inside the options map; text key first, "
              "then spec integer option id):")
        optvals = {}
        if opts is None:
            for name, int_key in OPTION_MEMBERS:
                print(f"        {name:28s} = UNAVAILABLE (no options map to read)")
                optvals[name] = {"value": "UNAVAILABLE", "present": False, "via": None}
        else:
            for name, int_key in OPTION_MEMBERS:
                found, value, how = dual_lookup(opts, name, int_key)
                if found:
                    print(f"        {name:28s} = {value!r}   [via {how}]")
                    optvals[name] = {"value": value, "present": True, "via": how}
                else:
                    print(f"        {name:28s} = UNAVAILABLE (neither {name!r} nor "
                          f"integer option id 0x{int_key:02x} present)")
                    optvals[name] = {"value": "UNAVAILABLE", "present": False, "via": None}

        print()
        print("      THE THREE QUESTIONS THE BRIEF ASKS DIRECTLY:")
        print(f"        clientPin      = {optvals['clientPin']['value']!r}  "
              f"(True means SUPPORTS a PIN, not that one is set)")
        print(f"        pinUvAuthToken = {optvals['pinUvAuthToken']['value']!r}")
        both = (optvals['clientPin']['value'] is False
                and optvals['pinUvAuthToken']['value'] is True)
        print(f"        -> pinUvAuthToken:true ALONGSIDE clientPin:false ? "
              f"{'YES' if both else 'NO (per the observed values above; UNAVAILABLE does not count)'}")
        print(f"        uv             = {optvals['uv']['value']!r}   "
              f"<-- built-in UV advertised?")
        print(f"        up             = {optvals['up']['value']!r}")
        print(f"        rk             = {optvals['rk']['value']!r}")
        print(f"        credMgmt       = {optvals['credMgmt']['value']!r}")
        print(f"        largeBlobs     = {optvals['largeBlobs']['value']!r}")
        print(f"        top-level `transports` (0x09) = "
              f"{top['transports']['value']!r}  "
              f"[via {top['transports']['via']}]")

        out = {
            "label": label,
            "status": f"0x{status:02x}",
            "payload_hex": hx(payload),
            "payload_len": len(payload),
            "latency_ms": round(elapsed * 1000, 1),
            "top_level_key_types": key_types,
            "top_level_keys": [repr(k) for k in info],
            "raw_map": {repr(k): repr(v) for k, v in info.items()},
            "top_level_resolved": {
                k: {"value": repr(v["value"]), "via": v["via"], "present": v["present"]}
                for k, v in top.items()
            },
            "options_present": opts_found,
            "options_via": opts_how,
            "options_key_types": (
                sorted({type(k).__name__ for k in opts}) if isinstance(opts, dict) else None
            ),
            "options_raw": ({repr(k): repr(v) for k, v in opts.items()}
                            if isinstance(opts, dict) else None),
            "options_resolved": {
                k: {"value": repr(v["value"]), "via": v["via"], "present": v["present"]}
                for k, v in optvals.items()
            },
            "advertises_puat_with_clientpin_false": both,
        }
        return out
    except (Timeout, CtapHidError, OSError) as e:
        print(f"      [{label}] GetInfo FAILED: {type(e).__name__}: {e}")
        return {"label": label, "error": f"{type(e).__name__}: {e}",
                "getinfo_answered": False}
    finally:
        raw.close()


def probe_get_info_highlevel(dev, manufacturer, label):
    """Cross-check probe 2 using fido2's OWN client stack, unmodified.

    Uses fido2.hid.CtapHidDevice.list_devices() (so fido2's own framing and
    its own INIT) and fido2.client.Ctap2.get_info(). If our raw probe and
    fido2's stack disagree, the raw probe is wrong.
    """
    self_check(dev, manufacturer)
    from fido2.hid import CtapHidDevice, CTAPHID
    from fido2.client import Ctap2

    target = None
    rejected = []
    for d in CtapHidDevice.list_devices():
        # AUDIT FIX (US-1521): the inherited version took the FIRST device whose
        # product_name and serial_number matched, comparing only those two
        # fields and falling through to a "not matched" failure if none did.
        # Both boards in this A/B present the SAME iProduct string ("Fapico2"),
        # so product_name is not a discriminator at all -- if the two HID
        # serial strings ever collided, or one board reported no serial, this
        # could have silently cross-checked board A against board B's readings.
        # The path here was itself established from the descriptor-identified
        # device in probe 0, and the descriptor strings are re-asserted as a
        # cross-check rather than used to pick.
        if d.descriptor.path != dev["path"]:
            continue
        if d.serial_number != dev["hid_serial"]:
            rejected.append(
                f"{d.descriptor.path}: HID serial {d.serial_number!r} != "
                f"probe-0 HID serial {dev['hid_serial']!r}")
            continue
        target = d
        break
    if rejected:
        for r in rejected:
            print(f"      [{label}] REJECTED candidate {r}")
    if target is None:
        print(f"\n  [{label}] CROSS-CHECK: fido2 did not enumerate a device at "
              f"{dev['path']} whose HID serial matched {dev['hid_serial']!r}. "
              f"Discarding rather than guessing.")
        return {"ok": False, "error": "identity not matched in fido2 enumeration",
                "rejected": rejected}

    print(f"\n  [{label}] CROSS-CHECK with fido2's own stack, on "
          f"{target.descriptor.path} product_name={target.product_name!r} "
          f"serial={target.serial_number!r}")
    print(f"      fido2 parsed this device as: device_version="
          f"{target.device_version} capabilities=0x{target.capabilities:02x}")
    # fido2's own CBOR call, its own INIT, its own framing.
    raw_payload = target.call(CTAPHID.CBOR, b"\x04")
    print(f"      fido2 CtapHidDevice.call(CBOR, 0x04) raw hex: {raw_payload.hex()}")
    try:
        info = Ctap2(target).get_info()
        print(f"      fido2 Ctap2.get_info() OK")
        print(f"        info.__repr__ = {info!r}")
        print(f"        info.versions = {getattr(info, 'versions', 'UNAVAILABLE')!r}")
        return {"ok": True,
                "fido2_parsed_device_version": str(target.device_version),
                "fido2_parsed_capabilities": f"0x{target.capabilities:02x}",
                "fido2_raw_payload_hex": raw_payload.hex(),
                "fido2_info_repr": repr(info),
                "fido2_versions": str(getattr(info, "versions", "UNAVAILABLE"))}
    except Exception as e:
        print(f"      fido2 Ctap2.get_info() FAILED: {type(e).__name__}: {e}")
        return {"ok": False, "error": f"{type(e).__name__}: {e}",
                "fido2_parsed_device_version": str(target.device_version),
                "fido2_parsed_capabilities": f"0x{target.capabilities:02x}",
                "fido2_raw_payload_hex": raw_payload.hex()}


def probe_auth_selection(dev, manufacturer, label):
    """Probe 3: authenticatorSelection, opcode 0x0B, up=false uv=false."""
    self_check(dev, manufacturer)
    raw = RawCtap.open(dev["descriptor"])
    try:
        raw.selftest(label)
        params = cbor.dumps({"up": False, "uv": False})
        body = bytes([CTAP2_AUTH_SELECTION]) + params
        payload, trace, elapsed = raw.call(CTAPHID_CBOR, body, cid=raw.cid)
        print(f"\n  [{label}] authenticatorSelection (opcode 0x0B) in {elapsed*1000:.1f} ms")
        print(f"      sent payload hex : {hx(body)}")
        print(f"      reply payload hex: {hx(payload)}  ({len(payload)} bytes)")
        show_trace(trace)
        status = payload[0] if payload else None
        ok = status == 0x00
        print(f"      status byte      : 0x{status:02x}  "
              f"({'CTAP2_OK' if ok else 'NOT CTAP2_OK'} / {status_name(status)})")
        return {"label": label, "status": f"0x{status:02x}",
                "status_name": status_name(status),
                "ctap2_ok": ok, "payload_hex": hx(payload),
                "latency_ms": round(elapsed * 1000, 1)}
    except (Timeout, CtapHidError, OSError) as e:
        print(f"      [{label}] authenticatorSelection FAILED: "
              f"{type(e).__name__}: {e}")
        return {"label": label, "error": f"{type(e).__name__}: {e}"}
    finally:
        raw.close()


def probe_client_pin_uv_with_permissions(dev, manufacturer, label):
    """Probe 4: authenticatorClientPIN 0x06 / sub-command 0x06.

    getPinUvAuthTokenUsingUvWithPermissions -- a read-only query. It asks the
    device to hand back a token; a device with no UV-capable PIN returns an
    error status rather than a token. No PIN state is changed. No
    setPIN/changePIN/getKeyAgreement sub-command is ever sent.

    AUDIT FIX (US-1521). The inherited version sent
        {1: 1, 2: b"\\x00" * 32, 3: throwaway_rp}
    i.e. permissions=1, rpId=<32 raw bytes>, uv=<a string>. Those keys are
    wrong in a way that makes the probe nearly information-free: on either
    board it would come back MISSING_PARAMETER / INVALID_TYPE for reasons that
    have nothing to do with the board, and an A/B difference in the error code
    would have been read as a firmware difference. The three keys are
        0x01 permissions (array), 0x02 rpId (text), 0x03 uv (bool)
    and both boards are now asked with correctly-typed values.

    Two variants, because they answer different questions:
      uv=False -- cannot park the authenticator in a user-presence wait, so it
                  always returns promptly. Tests whether the sub-command is
                  implemented at all.
      uv=True  -- the real browser path. Guarded by multiplex() and followed by
                  an unconditional CTAPHID_CANCEL so nothing is left parked.
    """
    self_check(dev, manufacturer)
    results = {}
    for variant, uv in (("uv_false", False), ("uv_true", True)):
        raw = RawCtap.open(dev["descriptor"])
        try:
            set_watchdog(WATCHDOG_S)
            raw.selftest(label)
            params = cbor.dumps(
                {"permissions": [], "rpId": throwaway_rp, "uv": uv}
            )
            body = bytes([CTAP2_CLIENT_PIN, 0x06]) + params
            print(f"\n  [{label}] clientPIN subCmd 0x06 "
                  f"(getPinUvAuthTokenUsingUvWithPermissions) variant={variant}")
            print(f"      sent payload hex : {hx(body)}")
            print(f"      sent CBOR params : "
                  f"permissions={[]!r} rpId={throwaway_rp!r} uv={uv!r}")
            t0 = time.monotonic()
            try:
                payload, trace, _ = raw.call(
                    CTAPHID_CBOR, body, cid=raw.cid, timeout=LONG_TIMEOUT
                )
                elapsed = time.monotonic() - t0
                print(f"      replied in {elapsed*1000:.1f} ms")
                show_trace(trace)
                status = payload[0] if payload else None
                print(f"      status byte      : 0x{status:02x}  ({status_name(status)})")
                results[variant] = {
                    "status": f"0x{status:02x}",
                    "status_name": status_name(status),
                    "payload_hex": hx(payload),
                    "sent_payload_hex": hx(body),
                    "latency_ms": round(elapsed * 1000, 1),
                }
            except Timeout:
                elapsed = time.monotonic() - t0
                ka = raw._last_keepalives
                print(f"      NO REPLY within {LONG_TIMEOUT}s ({elapsed:.1f}s). "
                      f"{len(ka)} KEEPALIVE frame(s), statuses {sorted(set(ka))}.")
                print(f"      This is a RECORDED TIMEOUT, not an absent field.")
                results[variant] = {"timed_out": True, "timeout_s": LONG_TIMEOUT,
                                    "keepalive_frames": len(ka),
                                    "keepalive_statuses": sorted(set(ka)),
                                    "sent_payload_hex": hx(body)}
            finally:
                cancelled = raw.cancel()
                print(f"      CTAPHID_CANCEL sent: {cancelled}")
                results[variant]["cancelled"] = str(cancelled)
        except (Timeout, CtapHidError, OSError) as e:
            print(f"      [{label}] clientPIN {variant} FAILED: "
                  f"{type(e).__name__}: {e}")
            results[variant] = {"error": f"{type(e).__name__}: {e}"}
        finally:
            clear_watchdog()
            raw.close()
    return results


def probe_consent_window(dev, manufacturer, label):
    """Probe 5: CTAPHID_WINK, then a MakeCredential to a throwaway RP id.

    Read-only in both cases: WINK needs no PIN and mints nothing, and the
    MakeCredential is never confirmed and never completed. After each, PING
    latency is measured on the SAME channel (single fd, no second descriptor --
    see RawCtap.multiplex for why a second fd is invalid here).
    """
    self_check(dev, manufacturer)
    results = {}

    # (a) CTAPHID_WINK on the assigned channel -- no PIN required, creates nothing.
    raw = RawCtap.open(dev["descriptor"])
    try:
        raw.selftest(label)
        t0 = time.monotonic()
        payload, trace, _ = raw.call(CTAPHID_WINK, b"", cid=raw.cid, timeout=LONG_TIMEOUT)
        wink_ms = (time.monotonic() - t0) * 1000
        print(f"\n  [{label}] CTAPHID_WINK replied in {wink_ms:.1f} ms")
        print(f"      reply payload hex: {hx(payload)!r}  (empty payload = success)")
        show_trace(trace)
        pings = []
        for i in range(6):
            t = time.monotonic()
            try:
                p, _, _ = raw.call(CTAPHID_PING, b"probe", cid=raw.cid, timeout=PING_TIMEOUT)
                dt = (time.monotonic() - t) * 1000
                pings.append({"i": i, "latency_ms": round(dt, 1), "echo_ok": p == b"probe"})
                print(f"      PING after WINK #{i}: {dt:.1f} ms, echo_ok={p == b'probe'}")
            except Timeout:
                pings.append({"i": i, "timeout": True})
                print(f"      PING after WINK #{i}: TIMEOUT after {PING_TIMEOUT}s  <-- BLOCKED")
            except (CtapHidError, OSError) as e:
                pings.append({"i": i, "error": f"{type(e).__name__}: {e}"})
                print(f"      PING after WINK #{i}: {type(e).__name__}: {e}")
        results["wink"] = {
            "reply_hex": hx(payload),
            "wink_latency_ms": round(wink_ms, 1),
            "pings": pings,
            "any_ping_timeout": any(p.get("timeout") for p in pings),
        }
    except (Timeout, CtapHidError, OSError) as e:
        print(f"      [{label}] WINK FAILED: {type(e).__name__}: {e}")
        results["wink"] = {"error": f"{type(e).__name__}: {e}"}
    finally:
        raw.close()

    # (b) MakeCredential to a throwaway RP id, PINGed on the same channel.
    raw = RawCtap.open(dev["descriptor"])
    try:
        raw.selftest(label)
        params = cbor.dumps(
            {
                1: {"id": throwaway_rp, "name": "ab-probe.invalid"},
                2: {"type": "public-key", "alg": -7},
                3: [{"type": "public-key", "alg": -7}],
                4: [{"type": "public-key", "alg": -7}],
                5: b"\x00" * 32,  # clientDataHash -- deliberately not a real challenge
                6: {},
                7: {},
            }
        )
        body = bytes([CTAP2_MAKE_CREDENTIAL]) + params
        print(f"\n  [{label}] MakeCredential to throwaway RP id {throwaway_rp!r} "
              f"(never confirmed, never completed)")
        print(f"      sent payload hex : {hx(body)}  ({len(body)} bytes)")
        mc = raw.multiplex(CTAPHID_CBOR, body, pings=4, total_budget=15.0)
        print(f"      outcome          : {mc['outcome']}")
        print(f"      reply payload hex: {mc['payload_hex']}")
        if mc.get("status"):
            print(f"      status byte      : {mc['status']} "
                  f"({status_name(int(mc['status'], 16))})")
        for p in mc["pings"]:
            if p.get("timeout"):
                print(f"      PING #{p['i']}: TIMEOUT after {PING_TIMEOUT}s  <-- BLOCKED")
            elif "latency_ms" in p:
                print(f"      PING #{p['i']}: {p['latency_ms']} ms, echo_ok={p['echo_ok']}")
        print(f"      keepalive frames   : {mc['keepalive_frames']}, "
              f"statuses {mc['keepalive_statuses']}")
        # AUDIT FIX (US-1521): the inherited version closed the fd without ever
        # sending CTAPHID_CANCEL here, leaving a device that had parked in a
        # user-presence wait parked until its own 30 s timer expired -- which
        # is long enough to make the NEXT probe on that board measure the
        # previous probe's window. Cancel unconditionally.
        cancelled = raw.cancel()
        print(f"      CTAPHID_CANCEL sent: {cancelled}")
        try:
            echo, _, ms = raw.ping(b"AFTER-MC", timeout=PING_TIMEOUT)
            print(f"      PING after cancel  : echo_ok={echo == b'AFTER-MC'} "
                  f"in {ms*1000:.1f} ms")
            mc["ping_after_cancel"] = {"ok": echo == b"AFTER-MC",
                                       "latency_ms": round(ms * 1000, 1)}
        except Timeout:
            print(f"      PING after cancel  : TIMEOUT  <-- device did NOT recover")
            mc["ping_after_cancel"] = {"ok": False, "timeout": True}
        mc["cancelled"] = str(cancelled)
        results["make_credential"] = {"sent_payload_hex": hx(body), **mc}
    except (Timeout, CtapHidError, OSError) as e:
        print(f"      [{label}] MakeCredential probe FAILED: {type(e).__name__}: {e}")
        results["make_credential"] = {"error": f"{type(e).__name__}: {e}"}
    finally:
        raw.close()
    return results



def probe_presence_window(dev, manufacturer, label):
    """Probe 5c: a REAL user-presence window, and whether the channel survives it.

    Probe 5's MakeCredential is rejected at the CBOR layer on both devices, so it
    never parks the authenticator. An authenticatorGetNextAssertion to a
    throwaway RP id does park it: the authenticator goes into the "waiting for
    user presence" state and streams CTAPHID_KEEPALIVE frames until it is
    satisfied or times out. Nothing is confirmed, nothing is created.

    While the window is open we PING the SAME channel from the SAME fd, which is
    what CTAPHID multiplexing is for. Opening a second file descriptor on the
    same /dev/hidrawN is invalid: both share one USB interrupt endpoint, a write
    on one blocks behind the other's pending read, and the kernel returns
    ETIMEDOUT -- on BOTH devices, identically, which is why that variant was
    discarded.

    This is the direct test of the epic's earlier claim that our device "goes
    blind for the full 30.11 s and subsequent writes block to ETIMEDOUT".
    """
    self_check(dev, manufacturer)
    raw = RawCtap.open(dev["descriptor"])
    try:
        raw.selftest(label)
        body = bytes([CTAP2_GET_NEXT_ASSERTION]) + cbor.dumps(
            {1: throwaway_rp, 2: b"\x00" * 32}
        )  # rpId + clientDataHash (zeros; never a real challenge)
        print(f"\n  [{label}] opening a REAL user-presence window with an "
              f"authenticatorGetNextAssertion to {throwaway_rp!r}")
        print(f"      sent payload hex : {hx(body)}  ({len(body)} bytes)")
        res = raw.multiplex(CTAPHID_CBOR, body, pings=4, total_budget=25.0)
        print(f"      outcome            : {res['outcome']}")
        print(f"      reply payload hex  : {res['payload_hex']}")
        if res.get("status"):
            print(f"      status byte        : {res['status']} "
                  f"({status_name(int(res['status'], 16))})")
        print(f"      keepalive frames   : {res['keepalive_frames']}, "
              f"statuses {res['keepalive_statuses']} "
              f"(0x02 = CTAP2_UP_REQUIRED = waiting for a touch)")
        for p in res["pings"]:
            if p.get("timeout"):
                print(f"      PING during window #{p['i']}: TIMEOUT after {PING_TIMEOUT}s"
                      f"   <-- CHANNEL BLOCKED while the window is open")
            elif "latency_ms" not in p:
                print(f"      PING during window #{p['i']}: {p}")
            else:
                print(f"      PING during window #{p['i']}: {p['latency_ms']} ms, "
                      f"echo_ok={p['echo_ok']}")
        print(f"      elapsed            : {res['elapsed_ms']} ms")
        cancelled = raw.cancel()
        print(f"      CTAPHID_CANCEL sent: {cancelled}")
        res["cancel"] = str(cancelled)
        try:
            echo, _, ms = raw.ping(b"AFTER-CANCEL", timeout=PING_TIMEOUT)
            print(f"      PING after cancel  : echo_ok={echo == b'AFTER-CANCEL'} "
                  f"in {ms*1000:.1f} ms")
            res["ping_after_cancel"] = {"ok": echo == b"AFTER-CANCEL",
                                        "latency_ms": round(ms * 1000, 1)}
        except Timeout:
            print(f"      PING after cancel  : TIMEOUT  <-- device did NOT recover")
            res["ping_after_cancel"] = {"ok": False, "timeout": True}
        return res
    except (Timeout, CtapHidError, OSError) as e:
        print(f"      [{label}] presence-window probe FAILED: {type(e).__name__}: {e}")
        return {"error": f"{type(e).__name__}: {e}"}
    finally:
        raw.close()



def probe_get_assertion(dev, manufacturer, label):
    """Probe 2c: authenticatorGetNextAssertion (0x08).

    Sent to a throwaway RP id with no allowList and no pinUvAuthToken. Depending
    on the device this either fails outright or parks the authenticator in the
    user-presence wait, streaming KEEPALIVE 0x02. Either way nothing is
    confirmed and nothing is created, and the operation is CANCELled if it
    parks.
    """
    self_check(dev, manufacturer)
    raw = RawCtap.open(dev["descriptor"])
    try:
        raw.selftest(label)
        body = bytes([CTAP2_GET_NEXT_ASSERTION]) + cbor.dumps({1: throwaway_rp})
        print(f"\n  [{label}] authenticatorGetNextAssertion (opcode 0x08), "
              f"timeout {LONG_TIMEOUT}s")
        print(f"      sent payload hex : {hx(body)}  ({len(body)} bytes)")
        try:
            payload, trace, _ = raw.call(CTAPHID_CBOR, body, cid=raw.cid,
                                         timeout=LONG_TIMEOUT)
        except Timeout:
            ka = raw._last_keepalives
            print(f"      NO REPLY within {LONG_TIMEOUT}s. The device parked in the "
                  f"user-presence wait and streamed {len(ka)} CTAPHID_KEEPALIVE "
                  f"frame(s), statuses {sorted(set(ka))} "
                  f"(0x02 = CTAP2_UP_REQUIRED).")
            print(f"      This is a RECORDED TIMEOUT, not an absent field.")
            cancelled = raw.cancel()
            print(f"      CTAPHID_CANCEL sent: {cancelled}")
            return {"label": label, "timed_out": True, "timeout_s": LONG_TIMEOUT,
                    "keepalive_frames": len(ka),
                    "keepalive_statuses": sorted(set(ka)),
                    "cancelled": str(cancelled)}
        print(f"      reply payload hex: {hx(payload)}  ({len(payload)} bytes)")
        show_trace(trace)
        status = payload[0] if payload else None
        print(f"      status byte      : 0x{status:02x}  ({status_name(status)})")
        return {"label": label, "status": f"0x{status:02x}",
                "status_name": status_name(status), "payload_hex": hx(payload)}
    except (Timeout, CtapHidError, OSError) as e:
        print(f"      [{label}] getAssertion FAILED: {type(e).__name__}: {e}")
        return {"label": label, "error": f"{type(e).__name__}: {e}"}
    finally:
        raw.close()


def final_liveness(dev, manufacturer, label):
    """Leave the device in a normal answerable state and prove it."""
    self_check(dev, manufacturer)
    raw = RawCtap.open(dev["descriptor"])
    try:
        raw.selftest(label)
        echo, _, ping_ms = raw.ping(b"FINAL-LIVENESS", timeout=PING_TIMEOUT)
        print(f"\n  [{label}] FINAL INIT+PING: INIT ok (cid 0x{raw.cid:08x}), "
              f"PING echo_ok={echo == b'FINAL-LIVENESS'} in {ping_ms*1000:.1f} ms")
        return {"init_ok": True, "ping_echo_ok": echo == b"FINAL-LIVENESS",
                "ping_ms": round(ping_ms * 1000, 1)}
    except (Timeout, CtapHidError, OSError) as e:
        print(f"\n  [{label}] FINAL LIVENESS CHECK FAILED: {type(e).__name__}: {e}")
        return {"init_ok": False, "error": f"{type(e).__name__}: {e}"}
    finally:
        raw.close()


# --------------------------------------------------------------------------


def main():
    global cbor
    import types

    # fido2 2.2.1 ships its own CBOR codec exposing encode/decode, not
    # dumps/loads. Wrap it so the rest of this script can use one spelling.
    from fido2 import cbor as _fido_cbor

    cbor = types.SimpleNamespace(
        dumps=_fido_cbor.encode,
        loads=_fido_cbor.decode,
        raw=_fido_cbor,
    )

    print(f"python  : {sys.version.split()[0]}")
    print(f"fido2   : ", end="")
    try:
        import importlib.metadata as md

        print(md.version("fido2"))
    except Exception as e:
        print(f"UNAVAILABLE ({e})")

    hdr("PROBE 0 — device inventory and positive identification")
    inventory = enumerate_devices()
    print(f"  {len(inventory)} FIDO CTAPHID device(s) with 1050:0407 found.")
    for d in inventory:
        print(f"    {d['path']}: iManufacturer={d['manufacturer']!r} "
              f"iProduct={d['product']!r} iSerial={d['serial']!r} bcdDevice={d['bcdDevice']} "
              f"hidName={d['hid_product_name']!r} hidUniq={d['hid_serial']!r}")
    dev_a = pick(inventory, DEVICE_A_MANUFACTURER, "DEVICE A (our Rust firmware)")
    dev_b = pick(inventory, DEVICE_B_MANUFACTURER, "DEVICE B (pico-fido2 C reference)")
    print("  Identified by USB iManufacturer, NOT by hidraw node number.")

    hdr("PROBE 0b — framer self-test on each device (before any reading is trusted)")
    print("  A CTAPHID frame written to /dev/hidrawN WITHOUT the leading hidraw report-id")
    print("  byte still produces a plausible INIT reply on the broadcast channel, because")
    print("  the first channel-id byte gets consumed as the report id. Only a PING on the")
    print("  assigned non-broadcast channel proves the framer. An earlier revision of this")
    print("  script got this wrong and reported a column of bogus timeouts.")

    nonce = bytes.fromhex("0102030405060708")

    # AUDIT FIX (US-1521): every step below runs under a hard SIGALRM watchdog
    # (see set_watchdog). The inherited version ran these as bare calls, so a
    # blocked hidraw WRITE -- precisely the US-1501 symptom under
    # investigation -- would have hung the whole probe indefinitely instead of
    # being recorded as a timeout.
    STEPS = [
        (("selftest_a",), probe_selftest, (dev_a, DEVICE_A_MANUFACTURER, "A")),
        (("selftest_b",), probe_selftest, (dev_b, DEVICE_B_MANUFACTURER, "B")),
        (("init_a",), probe_init,
         (dev_a, DEVICE_A_MANUFACTURER, "A", nonce)),
        (("init_b",), probe_init,
         (dev_b, DEVICE_B_MANUFACTURER, "B", nonce)),
        (("init_random_a",), probe_init_random,
         (dev_a, DEVICE_A_MANUFACTURER, "A")),
        (("init_random_b",), probe_init_random,
         (dev_b, DEVICE_B_MANUFACTURER, "B")),
        (("getinfo_a",), probe_getinfo, (dev_a, DEVICE_A_MANUFACTURER, "A")),
        (("getinfo_b",), probe_getinfo, (dev_b, DEVICE_B_MANUFACTURER, "B")),
        (("getinfo_hl_a",), probe_get_info_highlevel,
         (dev_a, DEVICE_A_MANUFACTURER, "A")),
        (("getinfo_hl_b",), probe_get_info_highlevel,
         (dev_b, DEVICE_B_MANUFACTURER, "B")),
        (("assertion_a",), probe_get_assertion, (dev_a, DEVICE_A_MANUFACTURER, "A")),
        (("assertion_b",), probe_get_assertion, (dev_b, DEVICE_B_MANUFACTURER, "B")),
        (("authsel_a",), probe_auth_selection, (dev_a, DEVICE_A_MANUFACTURER, "A")),
        (("authsel_b",), probe_auth_selection, (dev_b, DEVICE_B_MANUFACTURER, "B")),
        (("pin_a",), probe_client_pin_uv_with_permissions,
         (dev_a, DEVICE_A_MANUFACTURER, "A")),
        (("pin_b",), probe_client_pin_uv_with_permissions,
         (dev_b, DEVICE_B_MANUFACTURER, "B")),
        (("window_a",), probe_consent_window, (dev_a, DEVICE_A_MANUFACTURER, "A")),
        (("window_b",), probe_consent_window, (dev_b, DEVICE_B_MANUFACTURER, "B")),
        (("presence_a",), probe_presence_window, (dev_a, DEVICE_A_MANUFACTURER, "A")),
        (("presence_b",), probe_presence_window, (dev_b, DEVICE_B_MANUFACTURER, "B")),
        (("final_a",), final_liveness, (dev_a, DEVICE_A_MANUFACTURER, "A")),
        (("final_b",), final_liveness, (dev_b, DEVICE_B_MANUFACTURER, "B")),
    ]

    out = {"inventory": [{k: str(v) for k, v in d.items() if k != "descriptor"}
                         for d in inventory]}

    # Section headings, printed just before the step that opens each section.
    HEADINGS = {
        "init_a": "PROBE 1 — CTAPHID_INIT (0x06), broadcast channel, fixed 8-byte nonce",
        "getinfo_a": "PROBE 2 — authenticatorGetInfo (opcode 0x04, fido2 dialect)",
        "getinfo_hl_a": "PROBE 2b — cross-check with fido2's own high-level client",
        "assertion_a": "PROBE 2c — authenticatorGetNextAssertion (opcode 0x08)",
        "authsel_a": "PROBE 3 — authenticatorSelection (opcode 0x0B)",
        "pin_a": "PROBE 4 — authenticatorClientPIN 0x06 sub-command 0x06 "
                 "(getPinUvAuthTokenUsingUvWithPermissions)",
        "window_a": "PROBE 5 — user-presence window; does the channel stay answerable?",
        "presence_a": "PROBE 5c — REAL user-presence window (GetAssertion); "
                      "does the channel stay open?",
        "final_a": "FINAL — leave both devices in a normal, answerable state",
    }

    for step, fn, args in STEPS:
        name = step[0]
        budget = STEP_BUDGETS.get(name, STEP_BUDGET_DEFAULT)
        if name in HEADINGS:
            hdr(HEADINGS[name])
            if name == "init_a":
                print("  Random-nonce re-check (confirms the echo tracks the request):")
            if name == "init_random_a":
                print(f"      A: {out.get('init_random_a')}")
            if name == "init_random_b":
                print(f"      B: {out.get('init_random_b')}")
        print()
        set_watchdog(budget)
        t0 = time.monotonic()
        try:
            out[step[0]] = fn(*args)
        except (Timeout, CtapHidError, OSError, Exception) as e:
            # AUDIT FIX (US-1521): a step that blows the hard watchdog or dies
            # unexpectedly is RECORDED as a failure and the run continues, so
            # one misbehaving board cannot silently truncate the A/B table --
            # and so a timeout is never mistaken for an absent field.
            print(f"\n  !! STEP {step[0]!r} ABORTED after "
                  f"{time.monotonic() - t0:.1f}s: {type(e).__name__}: {e}")
            out[step[0]] = {"aborted": True, "error": f"{type(e).__name__}: {e}"}
        finally:
            clear_watchdog()

    hdr("MACHINE-READABLE RESULTS")
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()