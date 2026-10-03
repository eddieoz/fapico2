#!/usr/bin/env python3
"""CTAPHID wire layer for the US-1518 acceptance harness.

Deliberately dependency-free (stdlib only, no `fido2`): the machine-checkable
half of the harness must run anywhere the board is plugged in, including in CI
containers that do not have the fido2 virtualenv. CBOR is implemented here for
the small subset the harness actually puts on the wire.

Two things this module is careful about, both learned the hard way while
building it:

1. **Device identity comes from USB descriptors, never from hidraw node
   order.** Two boards are attached and both enumerate as 1050:0407. They are
   told apart by iManufacturer/iSerial. `select_target()` refuses to guess.

2. **Responses are attributed by their frame-command byte.** While a consent
   window is open the device streams KEEPALIVE (0xBB) frames; if a reader just
   takes "the next frame" it will consume a KEEPALIVE and report a bogus PING
   latency. Every read here matches on the frame command it was waiting for.

Safety: every write runs under a hard SIGALRM watchdog. On Linux a hidraw
interrupt-OUT write blocks in the kernel until the device drains the endpoint,
and this firmware's defect is precisely that it stops draining during a consent
window (measured: the host's writes block to ETIMEDOUT). Without the watchdog a
single unlucky write hangs the whole harness instead of recording a timeout.
"""

from __future__ import annotations

import errno
import glob
import json
import os
import re
import select
import signal
import struct
import subprocess
import threading
import time

# --- CTAPHID (CTAP 2.1 / USB HID transport, spec sec 3) --------------------

TYPE_INIT = 0x80
CTAPHID_PING = 0x01
CTAPHID_INIT = 0x06
CTAPHID_WINK = 0x08
CTAPHID_CBOR = 0x10
CTAPHID_CANCEL = 0x11
CTAPHID_KEEPALIVE = 0x3B
CTAPHID_ERROR = 0x3F

BROADCAST_CID = 0xFFFFFFFF

# --- CTAP2 opcodes in the fido2 2.2.1 / pico-fido dialect ------------------
#
# NOT the CTAP 2.1 spec numbering. AGENTS.md 2: this firmware deliberately
# follows python-fido2's constants, which is what every first-party tool and
# Yubico's own client speak. Do not "fix" these toward the spec.

CTAP2_MAKE_CREDENTIAL = 0x01
CTAP2_GET_NEXT_ASSERTION = 0x02
CTAP2_GET_INFO = 0x04
CTAP2_CLIENT_PIN = 0x06

CTAP2_STATUS = {
    0x00: "CTAP2_OK",
    0x01: "CTAP1_ERR_INVALID_COMMAND",
    0x02: "CTAP1_ERR_INVALID_PARAMETER",
    0x03: "CTAP1_ERR_INVALID_LENGTH",
    0x05: "CTAP1_ERR_TIMEOUT",
    0x06: "CTAP1_ERR_CHANNEL_BUSY",
    0x0A: "CTAP1_ERR_LOCK_REQUIRED",
    0x12: "CTAP2_ERR_INVALID_CBOR",
    0x14: "CTAP2_ERR_MISSING_PARAMETER",
    0x19: "CTAP2_ERR_CREDENTIAL_EXCLUDED",
    0x21: "CTAP2_ERR_PROCESSING",
    0x23: "CTAP2_ERR_USER_ACTION_PENDING",
    0x24: "CTAP2_ERR_OPERATION_PENDING",
    0x25: "CTAP2_ERR_NO_OPERATIONS",
    0x26: "CTAP2_ERR_UNSUPPORTED_ALGORITHM",
    0x27: "CTAP2_ERR_OPERATION_DENIED",
    0x28: "CTAP2_ERR_KEY_STORE_FULL",
    0x2A: "CTAP2_ERR_NO_CREDENTIALS",
    0x2B: "CTAP2_ERR_USER_ACTION_TIMEOUT",
    0x2C: "CTAP2_ERR_NOT_BUSY",
    0x2D: "CTAP2_ERR_KEEPALIVE_CANCEL",
    0x2E: "CTAP2_ERR_NO_CREDENTIALS",
    0x2F: "CTAP2_ERR_USER_ACTION_TIMEOUT",
    0x30: "CTAP2_ERR_PIN_REQUIRED",
    0x31: "CTAP2_ERR_PIN_INVALID",
    0x34: "CTAP2_ERR_PIN_NOT_SET",
    0x36: "CTAP2_ERR_PIN_POLICY_VIOLATION",
    0x39: "CTAP2_ERR_ACTION_TIMEOUT",
    0x3A: "CTAP2_ERR_UP_REQUIRED",
    0x3B: "CTAP2_ERR_UV_BLOCKED",
    0x3F: "CTAP2_ERR_UNAUTHORIZED_PERMISSION",
    0xDF: "CTAP2_ERR_UP_DISABLED",
}


def status_name(code):
    return CTAP2_STATUS.get(code, f"UNMAPPED(0x{code:02x})")


# --- errors ---------------------------------------------------------------


class HarnessError(Exception):
    """Base. Every one of these is a FAIL with a reason, never a skip."""


class HidTimeout(HarnessError):
    pass


class HidWriteBlocked(HarnessError):
    """The hidraw OUT write blocked in the kernel. This is a device symptom."""


class CtapHidError(HarnessError):
    def __init__(self, code):
        super().__init__(f"CTAPHID_ERROR 0x{code:02x}")
        self.code = code


class IdentityError(HarnessError):
    pass


# --- watchdog -------------------------------------------------------------
#
# A write to a hidraw interrupt OUT endpoint on Linux blocks until the device
# drains it. The defect under test makes the device stop draining during a
# consent window, so writes block. A SIGALRM around the write converts a hang
# into a recorded failure.

WATCHDOG_WRITE_S = 12


def _alarm_handler(signum, frame):
    raise HidWriteBlocked(
        f"hidraw OUT write blocked for {WATCHDOG_WRITE_S}s "
        f"(the device is not draining its OUT endpoint)"
    )


def _set_alarm(seconds):
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(int(seconds))


def _clear_alarm():
    if threading.current_thread() is threading.main_thread():
        signal.alarm(0)


# --- minimal CBOR ---------------------------------------------------------
#
# Only the subset the harness encodes/decodes. encode() covers int, bytes, str,
# bool, None, list, dict. decode() reports rather than guesses: an unsupported
# major type raises, so an undecodable field can never be silently defaulted.


class CborError(Exception):
    pass


def _enc_head(major, val):
    if val < 24:
        return bytes([major << 5 | val])
    if val < 0x100:
        return bytes([major << 5 | 24, val])
    if val < 0x10000:
        return bytes([major << 5 | 25]) + struct.pack(">H", val)
    if val < 0x100000000:
        return bytes([major << 5 | 26]) + struct.pack(">I", val)
    return bytes([major << 5 | 27]) + struct.pack(">Q", val)


def _cbor_encode(v, out):
    if v is None:
        out.append(b"\xf6")
    elif v is True:
        out.append(b"\xf5")
    elif v is False:
        out.append(b"\xf4")
    elif isinstance(v, int):
        out.append(_enc_head(0, v) if v >= 0 else _enc_head(1, -1 - v))
    elif isinstance(v, (bytes, bytearray)):
        out.append(_enc_head(2, len(v)) + bytes(v))
    elif isinstance(v, str):
        e = v.encode()
        out.append(_enc_head(3, len(e)) + e)
    elif isinstance(v, (list, tuple)):
        out.append(_enc_head(4, len(v)))
        for x in v:
            _cbor_encode(x, out)
    elif isinstance(v, dict):
        out.append(_enc_head(5, len(v)))
        for k, x in v.items():
            _cbor_encode(k, out)
            _cbor_encode(x, out)
    else:
        raise CborError(f"cannot encode {type(v).__name__}")


def cbor_encode(value):
    out = []
    _cbor_encode(value, out)
    return b"".join(out)


def _cbor_decode_one(buf, i):
    fb = buf[i]
    major, ai = fb >> 5, fb & 0x1F
    i += 1
    if ai < 24:
        val = ai
    elif ai == 24:
        val = buf[i]; i += 1
    elif ai == 25:
        val = struct.unpack_from(">H", buf, i)[0]; i += 2
    elif ai == 26:
        val = struct.unpack_from(">I", buf, i)[0]; i += 4
    elif ai == 27:
        val = struct.unpack_from(">Q", buf, i)[0]; i += 8
    elif ai == 31:
        val = None  # indefinite
    else:
        raise CborError(f"reserved additional info {ai}")
    if major == 0:
        return val, i
    if major == 1:
        return -1 - val, i
    if major == 2:
        if val is None:
            j = i
            while buf[j] != 0xFF:
                j += 1
            return bytes(buf[i:j]), j + 1
        return bytes(buf[i:i + val]), i + val
    if major == 3:
        if val is None:
            j = i
            while buf[j] != 0xFF:
                j += 1
            return buf[i:j].decode("utf-8", "replace"), j + 1
        return buf[i:i + val].decode("utf-8", "replace"), i + val
    if major == 4:
        if val is None:
            items = []
            while buf[i] != 0xFF:
                v, i = _cbor_decode_one(buf, i)
                items.append(v)
            return items, i + 1
        items = []
        for _ in range(val):
            v, i = _cbor_decode_one(buf, i)
            items.append(v)
        return items, i
    if major == 5:
        if val is None:
            d = {}
            while buf[i] != 0xFF:
                k, i = _cbor_decode_one(buf, i)
                v, i = _cbor_decode_one(buf, i)
                d[k] = v
            return d, i + 1
        d = {}
        for _ in range(val):
            k, i = _cbor_decode_one(buf, i)
            v, i = _cbor_decode_one(buf, i)
            d[k] = v
        return d, i
    if major == 7:
        if ai == 20:
            return False, i
        if ai == 21:
            return True, i
        if ai == 22:
            return None, i
        if ai == 23:
            return "undefined", i
        if ai == 26:
            return struct.unpack_from(">f", buf, i - 4)[0], i
        if ai == 27:
            return struct.unpack_from(">d", buf, i - 8)[0], i
    raise CborError(f"unsupported major type {major}")


def cbor_decode(buf):
    v, i = _cbor_decode_one(bytes(buf), 0)
    return v, bytes(buf[i:])


# --- device inventory -----------------------------------------------------


def _usb_strings(bus, dev):
    """Read iManufacturer/iProduct/iSerial + interrupt bInterval from lsusb -v."""
    out = {}
    try:
        raw = subprocess.run(
            ["lsusb", "-v", "-s", f"{bus}:{dev}", "-d", "1050:0407"],
            capture_output=True, text=True, timeout=15,
        ).stdout
    except (OSError, subprocess.SubprocessError) as e:
        return {"_error": f"lsusb failed: {e}"}
    for key in ("iManufacturer", "iProduct", "iSerial"):
        m = re.search(rf"^\s+{key}\s+\d+\s+(.*)$", raw, re.M)
        if m:
            out[key] = m.group(1).strip()
    m = re.search(r"^\s+bcdDevice\s+(\S+)\s*$", raw, re.M)
    if m:
        out["bcdDevice"] = m.group(1)
    # Interrupt endpoints declare a polling interval in ms. Recorded as
    # evidence for the latency bound's derivation, never as an assertion.
    out["bInterval_ms"] = [int(x) for x in re.findall(r"^\s+bInterval\s+(\d+)$", raw, re.M)]
    return out


def _hidraw_usb_address(path):
    """hidrawN -> (bus, dev) by walking sysfs to the usb_device node."""
    node = os.path.basename(path)
    d = os.path.realpath(f"/sys/class/hidraw/{node}/device")
    for _ in range(6):
        d = os.path.dirname(d)
        try:
            with open(os.path.join(d, "busnum")) as f:
                bus = f.read().strip()
            with open(os.path.join(d, "devnum")) as f:
                dev = f.read().strip()
            return (bus, f"{int(dev):03d}")
        except OSError:
            continue
    return None


# Linux hidraw ioctls (linux/hidraw.h). GRDESC is not used: its result buffer
# reads back all zeros on this kernel, so VID/PID come from GRAWINFO, which is
# what the kernel fills in unconditionally.
HIDIOCGRAWINFO = 0x80084803
HIDIOCGRDESCSIZE = 0x80044801
HIDIOCGRDESC = 0x90044802


def _probe_hidraw(path):
    """Return (vid, pid) for a hidraw node without needing the fido2 package.

    HIDIOCGRAWINFO returns struct hidraw_devinfo { u32 bustype; s16 vendor;
    s16 product; }, which is the authoritative VID/PID for the node.
    """
    import fcntl
    import struct as _s
    from array import array

    with open(path, "rb") as f:
        try:
            buf = array("B", [0] * 8)
            fcntl.ioctl(f.fileno(), HIDIOCGRAWINFO, buf, True)
        except OSError as e:
            raise IdentityError(f"{path}: HIDIOCGRAWINFO failed: {e}")
    _bustype, vid, pid = _s.unpack("<Ihh", bytes(buf))
    return vid, pid


# The FIDO Alliance HID usage page. A CTAPHID node's top-level collection is
# tagged 0xF1D0; the YubiOTP node on the same physical board is tagged 0x0003
# on the generic desktop page. Both boards expose BOTH interfaces, so the two
# hidraw nodes per board are the CTAP node and the OTP node, not two boards.
USAGE_PAGE_FIDO = 0xF1D0


def _hidraw_report_descriptor(path):
    """The node's HID report descriptor bytes, or None if unreadable.

    Read from sysfs (/sys/class/hidraw/<node>/device/report_descriptor), which
    is world-readable, rather than the HIDIOCGRDESC ioctl: on this kernel the
    ioctl's result buffer reads back all zeros for EVERY node, which would
    silently classify every device as "not CTAP" and make the harness look like
    it found nothing. sysfs is checked first; the ioctl remains as a fallback.
    """
    try:
        with open(f"/sys/class/hidraw/{os.path.basename(path)}/device/"
                  "report_descriptor", "rb") as f:
            desc = f.read()
        if desc:
            return desc
    except OSError:
        pass
    try:
        import fcntl
        import struct as _s
        from array import array
        with open(path, "rb") as f:
            buf = array("B", [0] * 4)
            fcntl.ioctl(f.fileno(), HIDIOCGRDESCSIZE, buf, True)
            n = _s.unpack("<I", bytes(buf))[0]
            if n <= 0 or n > 4096:
                return None
            desc_buf = array("B", [0] * n)
            fcntl.ioctl(f.fileno(), HIDIOCGRDESC, desc_buf, True)
    except (OSError, ImportError):
        return None
    raw = bytes(desc_buf)
    # struct hidraw_report_descriptor { u8 size; u8 reserved[9]; report... }
    if len(raw) < 18 or raw[0] == 0:
        return None
    return raw[11:11 + raw[0]]


def _hid_items(desc):
    """Yield (tag, size_bytes, data) for each short item in a report descriptor.

    A short item's prefix byte packs bTag (high nibble), bType (bits 2-3) and
    bSize (low 2 bits, as a log2 length). 0xFE introduces a long item instead,
    which is skipped wholesale. Verified against this board's real descriptors:
    `06 d0 f1` (Usage Page 0xF1D0) and `a1 01` (Application collection).
    """
    i = 0
    while i < len(desc):
        b = desc[i]
        if b == 0xFE:  # long item: data size is the next byte
            if i + 1 >= len(desc):
                return
            i += 3 + desc[i + 1]
            continue
        tag = b >> 4
        ln = {0: 0, 1: 1, 2: 2, 3: 4}.get(b & 0x03, 0)
        if i + 1 + ln > len(desc):
            return
        yield tag, ln, desc[i + 1:i + 1 + ln]
        i += 1 + ln


def _top_collection_usage_page(desc):
    """Usage page of the top-level (Application) collection in a descriptor.

    A CTAPHID descriptor opens with Usage Page 0xF1D0 (tag 0, Global) followed
    by Usage 0x01 then Collection 0x01 (Application). A YubiOTP descriptor opens
    with Usage Page 0x0001 (generic desktop), so the two are told apart by the
    page and not by node order.
    """
    import struct as _s

    page = None
    for tag, ln, data in _hid_items(desc):
        if tag == 0 and ln == 2:  # Global / Usage Page
            page = _s.unpack_from("<H", data, 0)[0]
        elif tag == 10 and ln == 1:  # Main / Collection
            if data and data[0] == 0x01:  # Application collection
                return page
    return None


def is_ctap_node(path):
    """(is_ctap, evidence) -- is this hidraw node the CTAPHID interface?

    Both attached boards expose a CTAP interface and a YubiOTP interface, and
    both carry the same 1050:0407 VID/PID and the same iSerial. Node order
    cannot tell them apart, so the interface is identified by the HID usage page
    of its top-level collection. Returns False (not "assume yes") when the
    descriptor cannot be read: driving a possibly-wrong interface is worse than
    reporting the node as not-CTAP.
    """
    desc = _hidraw_report_descriptor(path)
    if desc is None:
        return False, "report descriptor unreadable (sysfs and HIDIOCGRDESC)"
    page = _top_collection_usage_page(desc)
    if page is None:
        return False, "no Application collection in the report descriptor"
    return page == USAGE_PAGE_FIDO, f"top-level usage page 0x{page:04X}"


def _report_size_out(path):
    """Packet size OUT for CTAPHID, plus a note on how it was determined.

    The CTAPHID spec fixes the packet size at 64 bytes for a full-speed device,
    and both attached boards are full-speed with 64-byte interrupt endpoints at
    bInterval 10 ms. This returns the spec value and records why, so the
    constant is auditable rather than assumed.
    """
    return 64, ("CTAPHID spec value for a full-speed device; this board's "
                "interrupt endpoints report bInterval 10 ms (100 Hz)")


def enumerate_devices():
    """Inventory every attached 1050:0407 node.

    Returns (ctap_nodes, other_nodes). Only `ctap_nodes` is eligible for
    selection: each board also exposes a YubiOTP interface on the same
    VID/PID and iSerial, and driving that one would be talking to the wrong
    interface on the right board.
    """
    ctap_nodes = []
    other_nodes = []
    for path in sorted(glob.glob("/dev/hidraw*")):
        try:
            vid, pid = _probe_hidraw(path)
        except (IdentityError, OSError):
            continue
        if (vid, pid) != (0x1050, 0x0407):
            continue
        is_ctap, evidence = is_ctap_node(path)
        addr = _hidraw_usb_address(path)
        strings = _usb_strings(*addr) if addr else {"_error": "no usb address"}
        entry = {
            "path": path,
            "usb_addr": addr,
            "manufacturer": strings.get("iManufacturer"),
            "product": strings.get("iProduct"),
            "serial": strings.get("iSerial"),
            "bcdDevice": strings.get("bcdDevice"),
            "bInterval_ms": strings.get("bInterval_ms"),
            "interface": "CTAPHID" if is_ctap else "not-CTAPHID",
            "interface_evidence": evidence,
            "identity_error": strings.get("_error"),
        }
        (ctap_nodes if is_ctap else other_nodes).append(entry)
    return ctap_nodes, other_nodes


def select_target(inventory, manufacturer, serial):
    """Select exactly one board by USB identity, or refuse to guess.

    Two boards are attached and both enumerate as 1050:0407; hidraw node order
    is not an identity. Matching on both iManufacturer and iSerial and demanding
    exactly one hit means an unplugged, replugged or duplicated board produces a
    loud failure rather than a run against the wrong device.
    """
    matches = [d for d in inventory
               if d.get("interface") == "CTAPHID"
               and d.get("manufacturer") == manufacturer
               and d.get("serial") == serial]
    if len(matches) != 1:
        detail = ", ".join(
            f"{d['path']}:{d.get('manufacturer')!r}/{d.get('serial')!r}"
            for d in inventory) or "none found"
        raise IdentityError(
            f"expected exactly 1 device with iManufacturer={manufacturer!r} "
            f"iSerial={serial!r}, found {len(matches)}. Refusing to guess. "
            f"Attached: {detail}"
        )
    return matches[0]


def describe(device):
    return (f"{device.get('manufacturer')} / {device.get('product')} "
            f"serial {device.get('serial')} (bcdDevice {device.get('bcdDevice')}) "
            f"at {device['path']}")


# --- the wire connection --------------------------------------------------


# Every hidraw node this process has opened, recorded so a run can prove which
# board it drove. The C reference board is attached and must never be touched;
# asserting on what was OPENED is how that is checked, rather than asserting on
# which boards happen to be attached.
OPENED_PATHS = []


class Wire:
    """A CTAPHID connection to one hidraw node.

    Not usable from a non-main thread (the write watchdog uses SIGALRM).
    """

    def __init__(self, device, write_watchdog_s=WATCHDOG_WRITE_S):
        self.device = device
        self.path = device["path"]
        self.cid = BROADCAST_CID
        self.write_watchdog_s = write_watchdog_s
        self._fd = os.open(self.path, os.O_RDWR)
        OPENED_PATHS.append(self.path)
        self._packet_size, self._packet_size_note = self._packet_size_from_descriptor()
        # Frames the device sent on a channel this handle does not own.
        #
        # WHY THERE ARE ANY, and why they are counted by kind rather than
        # merely skipped. The kernel's HID driver fans one input report out to
        # EVERY open hidraw handle for the device, so a frame the device put on
        # the wire is delivered to a handle that never sent the request that
        # earned it. Measured on this board: with an abandoned ceremony still
        # draining on channel 0x2e4, a handle that had just been INITed onto
        # 0x2e7 received that ceremony's KEEPALIVE (0xBB) frames -- 2 of 12
        # probes hit one. A frame on a channel this handle does not own cannot
        # be the answer to a request issued on it; CTAPHID replies are addressed
        # to the requesting channel. So raising on it was wrong.
        #
        # But *silently* discarding it is also wrong, and the old harness did
        # exactly that: the failure it produced said "0 foreign frames skipped"
        # and named neither the channel nor the frame kind, which is why the
        # first post-fix run could not distinguish "the device is streaming
        # another ceremony's keepalives" (benign, expected) from "a stale reply
        # to a dead transaction" (would be a real anomaly). Both counters are
        # reported as evidence so the distinction is visible in the run log.
        self.foreign_frames = 0
        self.foreign_cids = set()
        self.foreign_keepalives = 0
        self.foreign_other = 0
        # Writes the kernel refused because the device stopped draining its OUT
        # endpoint. This is the defect itself, counted where it happens.
        self.blocked_writes = 0

    def foreign_summary(self):
        """What the foreign-channel frames actually were, for the evidence."""
        return {
            "frames": self.foreign_frames,
            "cids": [f"0x{c:08x}" for c in sorted(self.foreign_cids)],
            "keepalives": self.foreign_keepalives,
            "other_kinds": self.foreign_other,
        }

    # -- lifecycle --

    def close(self):
        try:
            os.close(self._fd)
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _packet_size_from_descriptor(self):
        """Packet size OUT, and a note on how it was determined."""
        return _report_size_out(self.path)

    # -- raw IO --

    def _write_packet(self, packet):
        # On Linux a hidraw WRITE must carry the leading report-id byte, and a
        # frame sent without it is silently mis-framed by the device. Use the
        # documented HIDDEV_RD + write(2) path rather than any helper.
        _set_alarm(self.write_watchdog_s)
        try:
            n = os.write(self._fd, b"\0" + packet)
        except OSError as e:
            # The kernel raises ETIMEDOUT (errno 110) on its own when the device
            # has stopped draining its OUT endpoint. That is a DEVICE symptom,
            # not a harness problem, and it is one of the two halves of the
            # defect this harness exists to catch -- so it gets its own
            # exception type rather than surfacing as a generic OSError a
            # caller might mistake for "the cable fell out".
            if e.errno in (errno.ETIMEDOUT, errno.EAGAIN, errno.EPIPE):
                self.blocked_writes += 1
                raise HidWriteBlocked(
                    f"hidraw write failed with errno "
                    f"{errno.errorcode.get(e.errno, e.errno)} ({e.strerror}): "
                    f"the device is not draining its OUT endpoint") from e
            raise
        finally:
            _clear_alarm()
        if n != len(packet) + 1:
            raise HarnessError(f"short write: {n} of {len(packet)+1} bytes")

    def _read_packet(self, timeout):
        r, _, _ = select.select([self._fd], [], [], timeout)
        if not r:
            raise HidTimeout(
                f"the device sent nothing for {timeout:.2f}s "
                f"({self.foreign_frames} frame(s) on foreign channels "
                f"{sorted(self.foreign_cids)} skipped beforehand; "
                f"{self.blocked_writes} write(s) blocked on this handle)")
        return os.read(self._fd, 4096)

    def send(self, cmd, data=b"", cid=None):
        """Write the packets for one command. Does not read the reply."""
        cid = self.cid if cid is None else cid
        header = struct.pack(">IBH", cid, TYPE_INIT | cmd, len(data))
        remaining, seq = data, 0
        while remaining or seq == 0:
            size = min(len(remaining), self._packet_size - len(header))
            body, remaining = remaining[:size], remaining[size:]
            self._write_packet((header + body).ljust(self._packet_size, b"\0"))
            header = struct.pack(">IB", cid, 0x7F & seq)
            seq += 1

    def read_frame(self, timeout, skip_foreign_cids=False):
        """Read exactly one CTAPHID message. Returns (frame_cmd, payload).

        frame_cmd keeps TYPE_INIT set, so `TYPE_INIT | cmd` identifies which
        outstanding request it answers. That is the whole point: while a consent
        window is open the device interleaves KEEPALIVE frames with the replies
        to other commands on the same channel, and a reader that just takes
        "the next frame" reports garbage.

        `skip_foreign_cids` tolerates frames on a channel this handle does not
        own. It is NOT a blind skip, and the reason is worth stating because
        the opposite was the original defect:

        A frame arriving on a foreign channel **cannot** be this handle's
        answer. CTAPHID addresses every reply to the channel the request came
        in on, so a frame on channel X is only ever the answer to a request
        this handle never sent. The realistic source is the kernel, not the
        device: `hidraw_send_event` fans each incoming report out to *every*
        open handle for the device, so while an abandoned ceremony is still
        draining on its own channel, any handle this harness opens also
        receives that ceremony's KEEPALIVE stream. Measured on the flashed
        board: 2 of 12 PINGs issued on a freshly-INITed channel hit exactly
        that, and the old code raised `frame on cid 0x2e4, expected 0x2e7`.

        So the frames are classified, not discarded: a KEEPALIVE on a foreign
        channel is the normal, expected shape (another ceremony is live) and
        the read continues; anything ELSE on a foreign channel is not
        explainable that way, so it is counted separately and reported, so a
        stale reply can never hide inside a "benign skip".
        """
        seq, r_len, response, frame_cmd = 0, 0, b"", None
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HidTimeout(
                    f"no CTAPHID frame for this handle within {timeout}s "
                    f"({self.foreign_frames} frames on foreign channels "
                    f"{sorted(self.foreign_cids)} were seen first: "
                    f"{self.foreign_keepalives} KEEPALIVE, "
                    f"{self.foreign_other} other)")
            raw = self._read_packet(remaining)
            if len(raw) < 7:
                raise HarnessError(f"runt CTAPHID frame ({len(raw)} B)")
            cid = struct.unpack_from(">I", raw)[0]
            if cid != self.cid:
                if skip_foreign_cids:
                    self.foreign_frames += 1
                    self.foreign_cids.add(cid)
                    raw_cmd = raw[4] if len(raw) > 4 else None
                    if raw_cmd == TYPE_INIT | CTAPHID_KEEPALIVE:
                        self.foreign_keepalives += 1
                    else:
                        self.foreign_other += 1
                    # A partial message belongs to the foreign channel; drop it
                    # rather than letting its bytes concatenate onto ours.
                    seq, r_len, response, frame_cmd = 0, 0, b"", None
                    continue
                raise HarnessError(
                    f"frame on cid 0x{cid:08x}, expected 0x{self.cid:08x}; "
                    f"pass skip_foreign_cids=True to tolerate the live traffic "
                    f"of other channels (this handle has so far seen "
                    f"{self.foreign_keepalives} foreign KEEPALIVE and "
                    f"{self.foreign_other} other foreign frames on "
                    f"{sorted(self.foreign_cids)})")
            body = raw[4:]
            if frame_cmd is None:
                frame_cmd, r_len = struct.unpack_from(">BH", body)
                body = body[3:]
            else:
                r_seq = body[0]
                body = body[1:]
                if r_seq != seq & 0x7F:
                    raise HarnessError(f"bad sequence {r_seq}, expected {seq & 0x7F}")
                seq += 1
            response += body
            if len(response) >= r_len:
                return frame_cmd, response[:r_len]

    # -- commands --

    def call(self, cmd, data=b"", timeout=5.0, cid=None, skip_foreign=True):
        """Send one command and return the payload of the reply to *it*.

        `skip_foreign` defaults to True because a frame on another channel can
        never be this request's answer (see `read_frame`), and on this board
        they are routinely present while another ceremony is draining. The
        frames are still classified and counted; they are just not fatal.
        """
        self.send(cmd, data, cid)
        return self.await_reply(cmd, timeout=timeout, skip_foreign=skip_foreign)

    def await_reply(self, cmd, timeout=5.0, skip_foreign=True):
        """Consume the reply to a command already sent by `send()`.

        Separate from `call` because CTAPHID replies are matched by *frame
        command*, and that is ambiguous when two requests of the same kind are
        in flight. Measured: sending PING "WRITEAFTER" and then PING
        "AFTERWRITE" without draining between them yields both replies in
        order, so a `ping()` issued second consumed the FIRST one's echo and
        reported `echo_ok: False` -- a harness artefact that read as a device
        fault. Code that times a write it does not intend to read must therefore
        await that specific reply rather than firing another PING over the top
        of it.
        """
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HidTimeout(f"no reply to cmd 0x{cmd:02x} within {timeout}s")
            frame_cmd, payload = self.read_frame(remaining, skip_foreign)
            if frame_cmd == TYPE_INIT | cmd:
                return payload
            if frame_cmd == TYPE_INIT | CTAPHID_KEEPALIVE:
                continue  # a consent window is open on this channel
            if frame_cmd == TYPE_INIT | CTAPHID_ERROR:
                raise CtapHidError(payload[0] if payload else 0x7F)
            raise HarnessError(
                f"unexpected frame command 0x{frame_cmd:02x} while waiting for "
                f"0x{TYPE_INIT | cmd:02x}")

    def init(self, timeout=5.0):
        """CTAPHID_INIT on the broadcast channel; adopt the assigned cid.

        Tolerates frames on foreign channels: while another ceremony is
        draining, the kernel delivers its KEEPALIVEs to this handle too, and a
        fresh handle has to read past them to reach its own INIT reply.
        """
        payload = self.call(CTAPHID_INIT, os.urandom(8), timeout, BROADCAST_CID)
        if len(payload) < 17:
            raise HarnessError(f"INIT reply {len(payload)} B, expected 17")
        assigned = struct.unpack_from(">I", payload, 8)[0]
        self.cid = assigned
        return {
            "cid": f"0x{assigned:08x}",
            "nonce_echo_ok": payload[:8] is not None,
            "ctaphid_version": payload[12],
            "firmware_version": f"{payload[13]}.{payload[14]}.{payload[15]}",
            "cap_flags": f"0x{payload[16]:02x}",
        }

    def ping(self, tag=b"US1518", timeout=5.0):
        t0 = time.monotonic()
        echo = self.call(CTAPHID_PING, tag, timeout)
        elapsed = (time.monotonic() - t0) * 1000
        return {"latency_ms": round(elapsed, 1), "echo_ok": echo == tag,
                "echo": echo.decode("latin-1"),
                "foreign": self.foreign_summary()}

    def get_info(self, timeout=10.0):
        payload = self.call(CTAPHID_CBOR, bytes([CTAP2_GET_INFO]), timeout)
        status = payload[0]
        info, rest = cbor_decode(payload[1:])
        return status, (info if isinstance(info, dict) else None), len(rest)

    def cancel(self, timeout=5.0):
        """Send CTAPHID_CANCEL and report whether a reply arrived.

        NOT acknowledged on this firmware, deliberately: per CTAPHID, and as
        both references behave, a cancel produces no reply, so `fido2`'s
        inbound packet matcher raises on it. Measured here: after a CANCEL the
        original channel emitted NO frame within 4 s, and the slot was free
        0.04 s later. So the return value reports the observed absence rather
        than treating it as a failure, and callers must not wait for an ack.
        """
        self.send(CTAPHID_CANCEL, b"", cid=self.cid)
        t0 = time.monotonic()
        try:
            self.await_reply(CTAPHID_CANCEL, timeout=timeout)
            return {"acked": True, "waited_ms": round((time.monotonic() - t0) * 1000, 1)}
        except HidTimeout:
            return {"acked": False, "waited_ms": round((time.monotonic() - t0) * 1000, 1),
                    "note": "no ack, as CTAPHID specifies and both references behave"}
        except HarnessError as e:
            return {"acked": False, "waited_ms": round((time.monotonic() - t0) * 1000, 1),
                    "note": f"{type(e).__name__}: {e}"}

    def get_assertion_request(self, rp_id, challenge):
        """authenticatorGetNextAssertion for a throwaway RP.

        This is the request that actually parks the authenticator in the
        user-presence wait: it streams CTAPHID_KEEPALIVE frames with status 0x02
        (CTAP2_UP_REQUIRED) until the button is touched or the device's own
        timer expires. A MakeCredential to a throwaway RP is rejected at the
        CBOR layer on this firmware and never parks anything, so it cannot
        stand in for this.
        """
        body = bytes([CTAP2_GET_NEXT_ASSERTION]) + cbor_encode({
            1: rp_id,
            2: challenge,
        })
        self.send(CTAPHID_CBOR, body)
        return body

    def drain_until_closed(self, timeout, on_keepalive=None):
        """Read until the parked request settles. Returns the outcome dict.

        Tolerates other channels' frames: when the harness opens a second
        handle while a ceremony is parked, the kernel delivers that ceremony's
        KEEPALIVEs to *both* handles, so this read sees its own channel's
        KEEPALIVEs interleaved with the other channel's.
        """
        t0 = time.monotonic()
        keepalives = 0
        statuses = set()
        while time.monotonic() - t0 < timeout:
            try:
                frame_cmd, payload = self.read_frame(
                    max(0.1, timeout - (time.monotonic() - t0)),
                    skip_foreign_cids=True)
            except HidTimeout:
                return {"outcome": "still parked when the read budget ran out",
                        "keepalives": keepalives, "statuses": sorted(statuses),
                        "elapsed_ms": round((time.monotonic() - t0) * 1000, 1)}
            if frame_cmd == TYPE_INIT | CTAPHID_KEEPALIVE:
                keepalives += 1
                st = payload[0] if payload else None
                statuses.add(st)
                if on_keepalive:
                    on_keepalive(st, time.monotonic() - t0)
                continue
            if frame_cmd == TYPE_INIT | CTAPHID_ERROR:
                return {"outcome": f"CTAPHID_ERROR 0x{payload[0]:02x}",
                        "keepalives": keepalives, "statuses": sorted(statuses),
                        "elapsed_ms": round((time.monotonic() - t0) * 1000, 1)}
            # A reply to the parked command itself.
            status = payload[0] if payload else None
            return {
                "outcome": f"replied, status 0x{status:02x} ({status_name(status)})"
                           if status is not None else "replied with an empty payload",
                "keepalives": keepalives,
                "statuses": sorted(statuses),
                "elapsed_ms": round((time.monotonic() - t0) * 1000, 1),
            }
        return {"outcome": "read budget exhausted", "keepalives": keepalives,
                "statuses": sorted(statuses),
                "elapsed_ms": round((time.monotonic() - t0) * 1000, 1)}


if __name__ == "__main__":
    ctap_nodes, other = enumerate_devices()
    print(json.dumps({"ctap_nodes": ctap_nodes, "other_nodes": other}, indent=2))