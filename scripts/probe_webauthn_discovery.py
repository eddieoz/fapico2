#!/usr/bin/env python3
"""US-1501 — baseline FIDO/WebAuthn discovery probe for fapico2 on RP2350.

Read-and-CBOR only against the CTAP FIDO interface. It does NOT reflash, does
NOT send a management factory reset, does NOT enter BOOTSEL, does NOT attach a
SWD debugger, and never requires a button press for parts (a), (b), (c).

Why raw framing instead of the high-level ``fido2.ctap2.Ctap2`` client: this
probe has to observe frames that are *never answered* and time them, and the
high-level client turns an unanswered frame into an unbounded blocking read or
an exception. So the CTAPHID framing is done here against the same descriptor
the library would pick, and the library itself is used (a) to select the
hidraw node, (b) to encode/decode CBOR, and (c) in part (a) as an independent
cross-check that the hand-rolled framing agrees with ``CtapHidDevice``.

Dialect note (AGENTS.md §2): this firmware deliberately speaks the
``python-fido2`` 2.2.1 dialect, so ``authenticatorGetInfo`` is CTAP2 opcode
**0x04**, not the CTAP 2.1 spec's 0x03. Probing 0x03 returns
INVALID_COMMAND and would wrongly look like a broken device.

Usage:
    python3 scripts/probe_webauthn_discovery.py
    python3 scripts/probe_webauthn_discovery.py --unanswered-observe 3.0

Exit codes:
    0  every part completed and the device was left answering
    2  a part could not be run at all (device missing, unanswered INIT, ...)
    3  the final INIT+PING round-trip failed — the board was not left answerable
    4  every part ran, but one of the measurements the brief asks for could not
       be read (currently: every requested getInfo option came back absent).
       That is a probe defect being reported, not a device finding.
"""

from __future__ import annotations

import argparse
import os
import select
import struct
import sys
import threading
import time
import uuid

from fido2 import cbor
from fido2.hid import CTAPHID, TYPE_INIT, CtapHidDevice, get_descriptor, list_descriptors, open_connection
from fido2.hid.linux import LinuxCtapHidConnection

# --- CTAPHID frame commands (fido2/hid/__init__.py) ------------------------
PING = int(CTAPHID.PING)
INIT = int(CTAPHID.INIT)
WINK = int(CTAPHID.WINK)
CBOR = int(CTAPHID.CBOR)
CANCEL = int(CTAPHID.CANCEL)
ERROR = int(CTAPHID.ERROR)
KEEPALIVE = int(CTAPHID.KEEPALIVE)

BROADCAST = b"\xff\xff\xff\xff"

# --- CTAP2 opcodes, fido2-2.2.1 dialect (NOT the CTAP 2.1 spec numbers) ----
CTAP2_MAKE_CREDENTIAL = 0x01
CTAP2_GET_INFO = 0x04  # AGENTS.md §2 — spec would say 0x03. Do not "fix".
FRAME_CBOR = TYPE_INIT | CBOR  # 0x90

# CTAP2 status bytes this firmware actually returns (apps/fido/src/ctap2.rs
# `Ctap2Response`). Names come from the firmware, not a generic CTAP table: this
# board answers 0x36 to a MakeCredential carrying no pinUvAuthParam (a PIN is
# set on it), and 0x3B when the consent window expires with no press.
CTAP2_STATUS_NAMES = {
    0x00: "SUCCESS", 0x01: "INVALID_COMMAND", 0x02: "INVALID_PARAMETER",
    0x03: "INVALID_LENGTH", 0x11: "CBOR_UNEXPECTED_TYPE", 0x12: "INVALID_CBOR",
    0x14: "MISSING_PARAMETER", 0x15: "LIMIT_EXCEEDED", 0x19: "CREDENTIAL_EXCLUDED",
    0x21: "PROCESSING", 0x22: "INVALID_CREDENTIAL", 0x23: "USER_ACTION_PENDING",
    0x24: "OPERATION_PENDING", 0x26: "UNSUPPORTED_ALGORITHM",
    0x27: "OPERATION_DENIED", 0x28: "KEY_STORE_FULL", 0x2A: "UNSUPPORTED_OPTION",
    0x2B: "INVALID_OPTION", 0x2C: "KEEPALIVE_CANCEL", 0x2E: "NO_CREDENTIALS",
    0x2F: "USER_ACTION_TIMEOUT", 0x30: "NOT_ALLOWED", 0x31: "PIN_INVALID",
    0x33: "PIN_AUTH_INVALID", 0x34: "PIN_AUTH_BLOCKED", 0x35: "PIN_NOT_SET",
    0x36: "PUAT_REQUIRED", 0x37: "PIN_POLICY_VIOLATION", 0x38: "PIN_TOKEN_EXPIRED",
    0x39: "REQUEST_TOO_LARGE", 0x3A: "ACTION_TIMEOUT", 0x3B: "UP_REQUIRED",
    0x3C: "UV_BLOCKED", 0x3D: "INTEGRITY_FAILURE", 0x3E: "INVALID_SUBCOMMAND",
    0x3F: "UV_INVALID", 0x40: "UNAUTHORIZED_PERMISSION", 0x7F: "OTHER",
}

# Frame-command matching key. `_drain_one` logs the command with the TYPE_INIT
# bit masked off (CTAPHID.CBOR == 0x10, not the 0x90 that goes on the wire), so
# matches are made against the masked value. Getting this backwards makes a
# perfectly good reply look unanswered.
MATCH_CBOR = CBOR

CTAP_ERROR_NAMES = {
    0x01: "INVALID_CMD",
    0x02: "INVALID_PAR",
    0x03: "INVALID_LEN",
    0x04: "INVALID_SEQ",
    0x05: "MSG_TIMEOUT",
    0x06: "CHANNEL_BUSY",
    0x0A: "LOCK_REQUIRED",
    0x0B: "INVALID_CHANNEL",
    0x7F: "OTHER",
}

# The firmware's consent window (firmware/src/presence.rs:CTAP_TOUCH_WINDOW_MS).
# Used only to decide how long to *observe*; the actual deadline is observed,
# never assumed.
WINDOW_HINT_S = 30.0
OBSERVE_SLACK_S = 15.0

THROWAWAY_RP = "baseline-probe.invalid"  # noqa: S105 - not a secret, an RP id

OUT = []


def say(line: str = "") -> None:
    print(line, flush=True)
    OUT.append(line)


def hx(b: bytes) -> str:
    return b.hex() if b else "(empty)"


def find_fido_node(vid: int, pid: int):
    """Pick the CTAP-FIDO hidraw node for this VID:PID (not the YubiOTP one)."""
    for d in list_descriptors():
        if d.vid == vid and d.pid == pid:
            return d
    return None


class RawHid:
    """CTAPHID framing with explicit, bounded reads.

    Mirrors ``fido2.hid.CtapHidDevice._do_call`` byte for byte (same header
    layout, same continuation sequencing, same 0x7F continuation command byte)
    but every read is bounded by a wall-clock deadline, and every frame —
    including keepalives, error frames and frames nobody is waiting for — is
    written to a timestamped event log.
    """

    def __init__(self, conn, report_size_out: int, report_size_in: int):
        self.conn = conn
        self.fd = conn.handle
        self.size_out = report_size_out
        self.size_in = report_size_in
        self.log: list[dict] = []
        self._pending: dict | None = None  # multi-packet response accumulator
        # Linux prepends a report ID to every OUT write; other backends do not.
        # Set from the connection class so the report ID is added exactly once.
        self._prepend_report_id = isinstance(conn, LinuxCtapHidConnection)
        self.write_stalls = 0
        os.set_blocking(self.fd, False)

    # -- wire -------------------------------------------------------------
    @staticmethod
    def _cid_int(cid: bytes) -> int:
        """Channel as a big-endian int. Callers hold it as 4 raw bytes, because
        that is the form the INIT reply and the frame log use."""
        return int.from_bytes(cid, "big")

    def send(self, cid: bytes, cmd: int, payload: bytes = b"",
             write_timeout: float = 3.0) -> float:
        """Write one request frame. Returns how long the write took.

        A CTAPHID request is an interrupt-OUT write on /dev/hidraw. When the
        device is inside its consent window it is not draining that endpoint,
        the kernel's HID output buffer fills, and a *blocking* write stalls
        with ETIMEDOUT. That stall is itself a measurement, not a bug to hide,
        so writes are non-blocking and bounded here and the elapsed time is
        reported: a request the device never even reads shows up as a write
        that blocks, distinctly from one that is written and then ignored.
        """
        cid_i = self._cid_int(cid)
        remaining = payload
        seq = 0
        header = struct.pack(">IBH", cid_i, TYPE_INIT | cmd, len(payload))
        t0 = time.monotonic()
        while remaining or seq == 0:
            size = min(len(remaining), self.size_out - len(header))
            body, remaining = remaining[:size], remaining[size:]
            packet = (header + body).ljust(self.size_out, b"\0")
            header = struct.pack(">IB", cid_i, 0x7F & seq)
            seq += 1
            # Linux prepends the report ID; go through the library's own writer
            # so the report ID is added exactly once.
            framed = b"\0" + packet if self._prepend_report_id else packet
            self._write_bounded(framed, write_timeout)
        return time.monotonic() - t0

    def _write_bounded(self, data: bytes, timeout: float) -> None:
        view = memoryview(data)
        deadline = time.monotonic() + timeout
        while view:
            try:
                n = os.write(self.fd, view)
                view = view[n:]
            except BlockingIOError:
                # Output buffer full — the device is not reading. Wait for
                # room, bounded, and record that we had to.
                #
                # This clause is the whole handler: `BlockingIOError` *is*
                # `OSError(errno.EAGAIN)`, so a separate `except OSError` arm
                # keyed on EAGAIN is unreachable behind it. An earlier draft
                # had one, and it was worse than dead — its `continue` skipped
                # the deadline check below, turning a bounded wait into an
                # unbounded spin. There is no other OSError worth special-casing
                # here, so the rest propagate.
                self.write_stalls += 1
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        f"hidraw OUT endpoint not drained after {timeout:.1f}s "
                        f"({self.write_stalls} stalls) — device is not reading"
                    ) from None
                select.select([], [self.fd], [], min(remaining, 0.05))

    def _drain_one(self) -> bool:
        """Read one report if one is available. False if nothing was ready."""
        r, _, _ = select.select([self.fd], [], [], 0)
        if not r:
            return False
        try:
            pkt = os.read(self.fd, self.size_in)
        except BlockingIOError:
            return False
        if len(pkt) < 5:
            self.log.append({"t": time.monotonic(), "kind": "short", "raw": hx(pkt)})
            return True
        cid = pkt[0:4]
        cmd_byte = pkt[4]
        if cmd_byte & TYPE_INIT:
            cmd = cmd_byte & 0x7F
            length = struct.unpack_from(">H", pkt, 5)[0]
            body = pkt[7:]
            if length <= len(body):
                self._emit(cid, cmd, body[:length], pkt)
            else:
                self._pending = {"cid": cid, "cmd": cmd, "length": length, "buf": bytearray(body), "raw": bytearray(pkt)}
        else:
            if self._pending is not None:
                self._pending["buf"] += pkt[5:]
                if len(self._pending["buf"]) >= self._pending["length"]:
                    p = self._pending
                    self._pending = None
                    self._emit(p["cid"], p["cmd"], bytes(p["buf"][: p["length"]]), bytes(p["raw"]))
            else:
                self.log.append({"t": time.monotonic(), "kind": "stray_cont", "cid": cid.hex(), "raw": hx(pkt)})
        return True

    def _emit(self, cid: bytes, cmd: int, body: bytes, raw: bytes) -> None:
        ev = {
            "t": time.monotonic(),
            "kind": "frame",
            "cid": cid.hex(),
            "cmd": cmd,
            "len": len(body),
            "body": body,
            "raw": hx(raw),
        }
        if cmd == KEEPALIVE and body:
            ev["status"] = body[0]
        if cmd == ERROR and body:
            ev["err"] = body[0]
        self.log.append(ev)

    # -- bounded receive --------------------------------------------------
    def wait_for(self, cid_hex: str, cmd: int, timeout: float) -> dict | None:
        """Wait for one frame matching (cid, cmd). Logs and consumes the rest."""
        deadline = time.monotonic() + timeout
        while True:
            for ev in self.log:
                if ev.get("_consumed"):
                    continue
                if ev.get("kind") == "frame" and ev["cid"] == cid_hex and ev["cmd"] == cmd:
                    ev["_consumed"] = True
                    ev["waited_s"] = time.monotonic() - ev["t"]
                    return ev
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self._drain_one()

    def wait_for_any_on(self, cid_hex: str, timeout: float) -> dict | None:
        """Return the first unconsumed frame on this channel, whatever its command.

        Used for CANCEL, whose spec-correct answer is a zero-length 0x11 frame:
        matching on the command would assume the answer and could not report a
        device that answers something else, which is exactly what part (c) is
        here to find out.
        """
        deadline = time.monotonic() + timeout
        while True:
            for ev in self.log:
                if ev.get("_consumed") or ev.get("kind") != "frame":
                    continue
                if ev["cid"] == cid_hex:
                    ev["_consumed"] = True
                    ev["waited_s"] = time.monotonic() - ev["t"]
                    return ev
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self._drain_one()

    def settle(self, quiet_s: float = 0.4, hard_s: float = 3.0) -> None:
        """Read until the device has been silent for `quiet_s` (or `hard_s` elapses)."""
        hard = time.monotonic() + hard_s
        while True:
            now = time.monotonic()
            if now >= hard:
                return
            if self._drain_one():
                continue
            if self.log and now - self.log[-1]["t"] > quiet_s:
                return
            time.sleep(0.005)

    # -- bookkeeping ------------------------------------------------------
    def since(self, mark: float) -> list[dict]:
        return [e for e in self.log if e.get("kind") == "frame" and e["t"] >= mark]

    def find(self, cid_hex: str, cmd: int, since: float | None = None) -> dict | None:
        """First frame matching (cid, cmd). Non-consuming, so classification
        never swallows a KEEPALIVE that a later lookup still needs."""
        for e in self.log:
            if e.get("kind") != "frame" or e.get("_consumed"):
                continue
            if e["cid"] == cid_hex and e["cmd"] == cmd:
                if since is not None and e["t"] < since:
                    continue
                return e
        return None

    def find_other(self, cid_hex: str, since: float, exclude: tuple[int, ...]) -> list[dict]:
        """Every frame on this channel that is not a keepalive or an excluded
        command — i.e. everything the device volunteered beyond the keepalive
        stream. Reported rather than filtered away."""
        return [e for e in self.log
                if e.get("kind") == "frame" and e["t"] >= since
                and e["cid"] == cid_hex and e["cmd"] not in exclude]

    def mark_all_consumed(self) -> None:
        for e in self.log:
            e["_consumed"] = True

    def count_since(self, mark: float, cid_hex: str, cmd: int) -> int:
        return len([e for e in self.log if e.get("kind") == "frame" and e["t"] >= mark
                    and e["cid"] == cid_hex and e["cmd"] == cmd])


class Session:
    """One open channel plus the event log it shares with the blacked-out device."""

    def __init__(self, hid: RawHid, cid: bytes, init_ev: dict):
        self.hid = hid
        self.cid = cid
        self.cid_hex = cid.hex()
        self.init_ev = init_ev

    def broadcast_init(self, timeout: float = 5.0) -> tuple[dict | None, float]:
        """CTAPHID_INIT on [FF FF FF FF] with a fresh 8-byte nonce."""
        nonce = os.urandom(8)
        t0 = time.monotonic()
        self.hid.send(BROADCAST, INIT, nonce)
        ev = self.hid.wait_for(BROADCAST.hex(), INIT, timeout)
        if ev is not None:
            ev["nonce"] = nonce.hex()
        # Latency is measured from the frame's own arrival timestamp, not from
        # how long `wait_for` happened to be on the stack. The two differ
        # whenever a reply frame was already sitting in the event log, and the
        # difference can be large enough to make a real reply look instant.
        return ev, (ev["t"] - t0) * 1000.0 if ev is not None else float("nan")

    def ping(self, data: bytes = b"US-1501", timeout: float = 3.0) -> tuple[dict | None, float]:
        t0 = time.monotonic()
        self.hid.send(self.cid, PING, data)
        ev = self.hid.wait_for(self.cid_hex, PING, timeout)
        return ev, (ev["t"] - t0) * 1000.0 if ev is not None else float("nan")

    def cbor_call(self, opcode: int, params: dict | None, timeout: float) -> tuple[dict | None, float]:
        payload = bytes([opcode]) + cbor.encode(params or {})
        t0 = time.monotonic()
        self.hid.send(self.cid, FRAME_CBOR, payload)
        ev = self.hid.wait_for(self.cid_hex, MATCH_CBOR, timeout)
        return ev, (ev["t"] - t0) * 1000.0 if ev is not None else float("nan")

    def cancel(self, timeout: float = 3.0) -> tuple[dict | None, float]:
        t0 = time.monotonic()
        self.hid.send(self.cid, TYPE_INIT | CANCEL)
        ev = self.hid.wait_for_any_on(self.cid_hex, timeout)
        return ev, (ev["t"] - t0) * 1000.0 if ev is not None else float("nan")


def describe_capflags(b: int) -> tuple[str, bool]:
    """Decode capFlags under BOTH live bit conventions.

    Spec (CTAP 2.1 §11.2.1.1): 0x01=CBOR, 0x02=NMSG, 0x04=WINK.
    De-facto (pico-keys-sdk / Yubico fido2 CAPABILITY): 0x01=WINK, 0x04=CBOR.
    Returns (text, does-this-convention-conclude-CBOR-supported).
    """
    spec_cbor = bool(b & 0x01)
    spec_nmsg = bool(b & 0x02)
    spec_wink = bool(b & 0x04)
    df_wink = bool(b & 0x01)
    df_lock = bool(b & 0x02)
    df_cbor = bool(b & 0x04)
    df_nmsg = bool(b & 0x08)
    text = (
        f"capFlags=0x{b:02X} -> "
        f"SPEC: CBOR={'yes' if spec_cbor else 'NO'}, NMSG={'yes' if spec_nmsg else 'no'}, "
        f"WINK={'yes' if spec_wink else 'no'} | "
        f"DE-FACTO: WINK={'yes' if df_wink else 'no'}, LOCK={'yes' if df_lock else 'no'}, "
        f"CBOR={'yes' if df_cbor else 'NO'}, NMSG={'yes' if df_nmsg else 'no'}"
    )
    return text, spec_cbor and df_cbor


def mc_payload() -> bytes:
    """MakeCredential for a throwaway RP, built to the CTAP2 request map.

    The keys are the spec ones, and the order of the earlier draft of this
    probe was wrong in a way that mattered: 1 is `clientDataHash` (a 32-byte
    bstr), 2 is `rp` (a *map* with an "id" key), 3 is `user` (a map), 4 is
    `pubKeyCredParams`, 5 is `excludeList`, 7 is `options`. Putting the RP id
    under key 1 makes the firmware answer 0x12 INVALID_CBOR before it ever
    reaches the presence gate, which silently turns part (b) into a measurement
    of nothing.

    `options: {uv: false}` is required on THIS board: a PIN is set, so
    `make_credential_inner` answers 0x36 PUAT_REQUIRED to any MakeCredential
    without a pinUvAuthParam, and again never opens a window. With `uv:false`
    the request reaches the `user_present` gate and the 30 s consent window
    opens. No PIN is needed and none is known to this probe.

    `rk: true` is a non-issue: the window is never granted here (nobody presses
    the button), so no credential is ever minted and nothing is persisted.
    """
    params = {
        1: os.urandom(32),                                          # clientDataHash
        2: {"id": THROWAWAY_RP, "name": "US-1501 baseline probe"},   # rp
        3: {"id": os.urandom(32),                                    # user
            "name": "probe@" + THROWAWAY_RP,
            "displayName": "US-1501 baseline probe"},
        4: [{"alg": -7, "type": "public-key"}],                      # pubKeyCredParams
        5: [],                                                       # excludeList
        7: {"uv": False},                                            # options
    }
    return bytes([CTAP2_MAKE_CREDENTIAL]) + cbor.encode(params)


def part_a(hid: RawHid, desc, observe: float) -> tuple[Session, bool]:
    """Cold-boot INIT + getInfo. Returns (session, options_anomaly).

    `options_anomaly` is True when every option the brief asked for came back
    absent, which is this probe having looked in the wrong place rather than
    the device having said something. It is a nonzero exit, not a device
    finding — see the ANOMALY block printed at the point it is detected.
    """
    say("=" * 78)
    say("PART (a) — cold-boot CTAPHID_INIT + authenticatorGetInfo latency")
    say("=" * 78)
    say(f"firmware identity via /sys + lsusb and the hidraw node: "
        f"vid=0x{desc.vid:04X} pid=0x{desc.pid:04X} product={desc.product_name!r} "
        f"serial={desc.serial_number!r} node={desc.path}")

    nonce = os.urandom(8)
    t0 = time.monotonic()
    hid.send(BROADCAST, INIT, nonce)
    init_ev = hid.wait_for(BROADCAST.hex(), INIT, 5.0)
    init_ms = (init_ev["t"] - t0) * 1000.0 if init_ev is not None else float("nan")
    if init_ev is None:
        say("  FATAL: broadcast INIT was not answered within 5.0 s")
        sys.exit(2)
    body = init_ev["body"]
    say(f"  (a1) CTAPHID_INIT frame cmd 0x06 on [FF FF FF FF], 8-byte nonce")
    say(f"       nonce sent   = {nonce.hex()}")
    say(f"       reply payload (17 B) = {hx(body)}")
    say(f"       LATENCY = {init_ms:.1f} ms   (send -> first byte of reply frame)")
    if body[:8] != nonce:
        say(f"  FATAL: nonce mismatch: got {body[:8].hex()}")
        sys.exit(2)
    say(f"       nonce echoed  = {body[0:8].hex()}  MATCH")
    cid = body[8:12]
    iface, major, minor, build, capflags = body[12], body[13], body[14], body[15], body[16]
    say(f"       byte 12 versionInterface = 0x{iface:02X} (CTAP HID protocol version)")
    say(f"       bytes 13..15 YubiKey firmware version = {major}.{minor}.{build}")
    say(f"       byte 16 capFlags = 0x{capflags:02X}")
    text, cbor_under_both = describe_capflags(capflags)
    say(f"       {text}")
    say(f"       -> SPEC convention concludes CBOR supported: "
        f"{'YES' if bool(capflags & 0x01) else 'NO'}")
    say(f"       -> DE-FACTO convention concludes CBOR supported: "
        f"{'YES' if bool(capflags & 0x04) else 'NO'}")
    say(f"       -> CBOR supported under BOTH conventions: {'YES' if cbor_under_both else 'NO'}")

    sess = Session(hid, cid, init_ev)

    # Cross-check that the hand-rolled framing agrees with the real library.
    lib_dev = CtapHidDevice(desc, open_connection(desc))
    say(f"       library cross-check: fido2.hid.CtapHidDevice version="
        f"{lib_dev.version} capabilities=0x{lib_dev.capabilities:02X} "
        f"device_version={lib_dev.device_version} cid={lib_dev._channel_id:#010x} "
        f"(agrees with raw framing: {lib_dev.capabilities == capflags})")
    # `close()` is the public API (`CtapHidDevice.close`, fido2/hid/__init__.py
    # — it just forwards to the connection), so there is no reason to reach
    # into `_connection`. `_channel_id` above has no public accessor in 2.2.1
    # and is only printed for the record.
    lib_dev.close()
    hid.mark_all_consumed()

    # Repeat INIT a few times so the number is not a single sample.
    samples = [init_ms]
    for _ in range(4):
        _, ms = sess.broadcast_init(5.0)
        samples.append(ms)
    samples_sorted = sorted(samples)
    say(f"       repeat INIT latencies (ms, n={len(samples)}): "
        f"{', '.join(f'{s:.1f}' for s in samples)}")
    say(f"       min={samples_sorted[0]:.1f}  median="
        f"{samples_sorted[len(samples_sorted)//2]:.1f}  max={samples_sorted[-1]:.1f}")
    hid.mark_all_consumed()
    hid.settle()

    say("")
    say(f"  (a2) authenticatorGetInfo — CTAP2 opcode 0x{CTAP2_GET_INFO:02X} "
        f"as first CBOR byte (fido2 2.2.1 dialect), frame cmd 0x{FRAME_CBOR:02X}")
    gi_ev, gi_ms = sess.cbor_call(CTAP2_GET_INFO, None, 5.0)
    if gi_ev is None:
        say("  FATAL: getInfo not answered within 5.0 s")
        sys.exit(2)
    say(f"       reply raw (first packet) = {gi_ev['raw']}")
    say(f"       LATENCY = {gi_ms:.1f} ms")
    say(f"       getInfo reply body = {len(gi_ev['body'])} bytes (multi-packet CBOR)")
    # A CTAP2 response body is a leading status byte followed by the CBOR item.
    # Decoding the body as CBOR from offset 0 silently yields a wrong map,
    # because 0x00 is itself a valid CBOR integer (and 0xa0, the next byte
    # here, is a valid empty map) — so the status byte must be stripped first.
    gi_status = gi_ev["body"][0]
    say(f"       CTAP2 status byte = 0x{gi_status:02X} "
        f"({CTAP2_STATUS_NAMES.get(gi_status, 'UNKNOWN')})")
    if gi_status != 0x00:
        say("  FATAL: getInfo returned a non-success status; not decoding further")
        sys.exit(2)
    try:
        info = cbor.decode_from(gi_ev["body"][1:])[0]
    except Exception as exc:  # pragma: no cover
        say(f"  FATAL: getInfo body is not CBOR after the status byte: {exc}")
        sys.exit(2)
    # getInfo key 4 is the options map, and this device spells it with **text
    # keys**: `{"rk": True, "clientPin": True, ...}`. The integer option ids
    # (0x01 rk, 0x03 alwaysUv, 0x06 clientPin, 0x0C pinUvAuthToken, 0x07
    # largeBlobs, 0x0E makeCredUvNotRqd) are the *other* dialect's spelling —
    # picoforge/Yubico's own. Indexing this map with them yields `<absent>` for
    # every key, which is exactly what the first draft of this probe did, and
    # a row of seven `<absent>` reads like "the device supports none of these"
    # rather than "the probe looked in the wrong place".
    #
    # So: print the keys the device actually sent, look the brief's options up
    # BY NAME, and treat an all-absent result as an anomaly to shout about
    # rather than print (it returns nonzero at the end of the run).
    opts = info.get(4, {}) if isinstance(info, dict) else {}
    key_type = type(next(iter(opts), None)).__name__
    say(f"       getInfo options map (key 0x04) = {opts!r}")
    say(f"       options map key type as received = {key_type!r} "
        f"(observed keys are {sorted(opts, key=str)!r})")
    requested = ("clientPin", "pinUvAuthToken", "alwaysUv", "makeCredUvNotRqd", "rk")
    say("       the options the brief asks about, looked up BY NAME:")
    missing = [name for name in requested if name not in opts]
    for name in requested:
        if name in opts:
            say(f"         options[{name!r}] = {opts[name]!r}")
        else:
            say(f"         options[{name!r}] = '<absent>'  ** not in the observed key set **")
    say(f"       (CTAP2's options map has no 'uv' and no 'up' key: alwaysUv "
        f"and makeCredUvNotRqd are what a MakeCredential's UV requirement is "
        f"governed by, and user presence is implied rather than optional)")
    options_anomaly = False
    if missing and len(missing) == len(requested):
        options_anomaly = True
        say("")
        say("  !!! ANOMALY — EVERY requested option came back absent !!!")
        say("  !!! This is a probe defect, not a device finding. An all-absent")
        say("  !!! result is what an integer-option-id lookup produces against a")
        say("  !!! text-keyed map, and it looks exactly like 'the device")
        say("  !!! advertises none of these options'. Do not record it as one.")
        say("  !!! The keys the device DID send are printed above; re-derive the")
        say("  !!! lookup from those before any of this is written down.")
        say("  !!! (The run exits 4.)")
        say("")
    elif missing:
        say(f"  NOTE: absent from the observed key set: {missing!r} "
            f"— reported as observed, not as an id miss.")
    say(f"       full getInfo map keys = {sorted(info.keys()) if isinstance(info, dict) else 'n/a'}")
    say(f"       versions (key 1) = {info.get(1) if isinstance(info, dict) else 'n/a'}")
    say(f"       maxMsgSize (key 5) = {info.get(5) if isinstance(info, dict) else 'n/a'}")
    say("")
    return sess, options_anomaly


def consent_round(hid: RawHid, sess: Session, label: str, observe: float,
                  send_cancel: bool) -> dict:
    """One MakeCredential + concurrent INIT/PING (+ optional CANCEL) blackout run."""
    say("-" * 78)
    say(f"  {label}: MakeCredential for RP id {THROWAWAY_RP!r} — BUTTON NOT TOUCHED")
    say("-" * 78)
    hid.mark_all_consumed()
    cid_hex = sess.cid_hex

    mc = mc_payload()
    t_mc = time.monotonic()
    hid.send(sess.cid, FRAME_CBOR, mc)
    say(f"    sent MC: frame cmd 0x{FRAME_CBOR:02X}, CTAP2 opcode 0x01, "
        f"{len(mc)} payload bytes, on channel {cid_hex}")

    # The device answers an initial KEEPALIVE (status UP_NEEDED=0x02) for a
    # 0x01/0x02 request before it opens the window. Record it, do not treat it
    # as the MC answer.
    ka = hid.wait_for(cid_hex, KEEPALIVE, 2.0)
    if ka is not None:
        say(f"    +{ (ka['t']-t_mc)*1000:.1f} ms  KEEPALIVE status=0x{ka.get('status',0):02X}"
            f" (UP_NEEDED) — consent window opening")

    # Immediately, without touching the button: broadcast INIT and open-channel PING.
    #
    # These are written on background threads so the main loop keeps draining
    # the IN endpoint (where the keepalives are) while a write is pending.
    #
    # A blocking write is a distinct outcome from a write that succeeds and
    # goes unanswered: the first means the device is not draining the OUT
    # endpoint at all, the second means it read the frame and chose not to
    # reply. On this board the device is single-tasked inside its
    # consent-window loop, which only writes keepalives and never reads, so
    # the OUT buffer fills and the host write stalls.
    #
    # Writes are serialised by `write_lock`: two threads interleaving 64-byte
    # reports on one fd would splice two frames into one and produce a
    # measurement of the probe's own bug. Each write gets its own bounded
    # deadline, so a stalled write cannot stop the next probe from being
    # attempted — and all attempts still land inside the consent window.
    write_lock = threading.Lock()

    def bg_send(name: str, cid: bytes, cmd: int, payload: bytes):
        box: dict = {}

        def run():
            t = time.monotonic()
            try:
                with write_lock:
                    box["ms"] = hid.send(cid, cmd, payload,
                                         write_timeout=observe) * 1000
                box["ok"] = True
            except TimeoutError as exc:
                box["ok"] = False
                box["err"] = str(exc)
            box["t"] = t
        th = threading.Thread(target=run, daemon=True)
        th.start()
        box["name"] = name
        box["thread"] = th
        return box

    t_init_send = time.monotonic()
    nonce2 = os.urandom(8)
    boxes = [bg_send("broadcast INIT", BROADCAST, INIT, nonce2)]

    t_ping_send = time.monotonic()
    ping_payload = b"US-1501-ping"
    boxes.append(bg_send("open-channel PING", sess.cid, PING, ping_payload))

    if send_cancel:
        t_cancel_send = time.monotonic()
        boxes.append(bg_send("CTAPHID_CANCEL", sess.cid, TYPE_INIT | CANCEL, b""))

    # Bounded observation of the blackout. The loop runs the FULL window, not
    # just the short `--unanswered-observe` interval, so the reported
    # "unanswered for N s" is bounded by the window actually expiring rather
    # than by when the probe stopped looking. The short interval is still used:
    # it is the point at which the probe declares a frame unanswered-if-silent.
    say(f"    ... observing the full window (up to "
        f"{WINDOW_HINT_S + OBSERVE_SLACK_S:.0f} s), NO button press. "
        f"Declaring 'unanswered' at {observe:.1f} s of silence ...")
    hard = t_mc + WINDOW_HINT_S + OBSERVE_SLACK_S
    while time.monotonic() < hard:
        # Stop as soon as the MC has its final answer AND every concurrent
        # probe write has resolved — there is nothing further to learn.
        if hid.find(cid_hex, MATCH_CBOR, since=t_mc) is not None and (
                time.monotonic() - t_mc) > observe:
            if all(not b["thread"].is_alive() for b in boxes):
                break
        hid._drain_one()
        time.sleep(0.002)
    # Any write still outstanding gets the remainder of its deadline.
    for b in boxes:
        b["thread"].join(timeout=WINDOW_HINT_S + OBSERVE_SLACK_S)

    init_ans = hid.find(BROADCAST.hex(), INIT, since=t_init_send)
    ping_ans = hid.find(cid_hex, PING, since=t_ping_send)
    cancel_ans = (hid.find(cid_hex, CANCEL, since=t_cancel_send)
                  or hid.find(cid_hex, ERROR, since=t_cancel_send)) if send_cancel else None
    ka_during = hid.count_since(t_mc, cid_hex, KEEPALIVE)
    # Anything else the device volunteered on the open channel during the
    # blackout, beyond the keepalive stream. Reported, never filtered away.
    others = hid.find_other(cid_hex, t_mc, exclude=(KEEPALIVE, CANCEL, ERROR, PING, MATCH_CBOR))
    for o in others:
        say(f"      (unexpected) extra frame on open channel: cmd=0x{o['cmd']:02X} "
            f"len={o['len']} raw={o['raw']} at +{(o['t']-t_mc)*1000:.1f} ms")

    observed_s = time.monotonic() - t_mc
    say(f"    observation ran {observed_s:.2f} s after the MC "
        f"({ka_during} keepalives on the open channel meanwhile)")
    say(f"    write outcome of the concurrent probes "
        f"(each write deadline {observe:.1f} s, serialised on the fd):")
    write_report = {}
    for b in boxes:
        b["thread"].join(timeout=1.0)
        if b.get("ok"):
            write_report[b["name"]] = {"written": True, "ms": b["ms"]}
            say(f"      {b['name']:<18} WRITTEN to the OUT endpoint in {b['ms']:.1f} ms "
                f"(+{(b['t']-t_mc)*1000:.1f} ms after the MC)")
        else:
            write_report[b["name"]] = {"written": False, "err": b.get("err")}
            say(f"      {b['name']:<18} NEVER WRITTEN — the write blocked and gave up "
                f"after its {observe:.1f} s deadline: {b.get('err')}")
    say(f"    verdict at the {observe:.1f} s mark and at the end of observation:")
    for what, ev, t_send, expect in (
            ("broadcast INIT  ", init_ans, t_init_send, "INIT reply"),
            ("open-channel PING", ping_ans, t_ping_send, "PING echo"),
    ):
        if ev is None:
            say(f"      (b) {what}: NOT ANSWERED — unanswered for the whole "
                f"{observed_s:.2f} s observation")
        else:
            lat = (ev["t"] - t_send) * 1000
            within = "WITHIN the blackout" if lat <= observe * 1000 else "LATE (after the window)"
            say(f"      (b) {what}: answered, +{lat:.1f} ms after send "
                f"({(ev['t']-t_mc)*1000:.1f} ms after the MC) — {within}")
            if expect == "INIT reply":
                say(f"           INIT reply payload = {hx(ev['body'])}")
            else:
                say(f"           PING echo = {hx(ev['body'])} "
                    f"(echo matches sent: {ev['body'] == ping_payload})")
    if send_cancel:
        if cancel_ans is None:
            say(f"      (c) CTAPHID_CANCEL : NOT ANSWERED — unanswered for the whole "
                f"{observed_s:.2f} s observation")
        else:
            lat = (cancel_ans["t"] - t_cancel_send) * 1000
            say(f"      (c) CTAPHID_CANCEL : answered, +{lat:.1f} ms after send "
                f"({(cancel_ans['t']-t_mc)*1000:.1f} ms after the MC) — "
                f"cmd=0x{cancel_ans['cmd']:02X} len={cancel_ans['len']} "
                f"raw={cancel_ans['raw']}")
            if cancel_ans["cmd"] == ERROR and cancel_ans["body"]:
                say(f"          CTAPHID_ERROR code 0x{cancel_ans['body'][0]:02X} = "
                    f"{CTAP_ERROR_NAMES.get(cancel_ans['body'][0], '?')}")

    # The observation loop above already ran to the window's deadline, so the
    # MC's final answer should be in the log. Wait only as a fallback.
    mc_ev = hid.find(cid_hex, MATCH_CBOR, since=t_mc)
    if mc_ev is None:
        say(f"    ... MC still unanswered after {observed_s:.1f} s, waiting up to "
            f"{WINDOW_HINT_S + OBSERVE_SLACK_S:.0f} s more ...")
        mc_ev = hid.wait_for(cid_hex, MATCH_CBOR, WINDOW_HINT_S + OBSERVE_SLACK_S)
    t_end = time.monotonic()
    total_s = (mc_ev["t"] - t_mc) if mc_ev is not None else (t_end - t_mc)

    result = {"label": label, "total_s": total_s, "observe_s": observe,
              "observed_s": observed_s,
              "init_answered": init_ans is not None,
              "ping_answered": ping_ans is not None,
              "cancel_answered": (cancel_ans is not None) if send_cancel else None,
              "keepalives_during_observe": ka_during,
              "write_report": write_report,
              "mc": None, "init_late": None, "ping_late": None, "cancel_late": None}

    if mc_ev is None:
        say(f"    (b) MakeCredential: NO final CBOR reply within "
            f"{WINDOW_HINT_S + OBSERVE_SLACK_S:.0f} s")
        result["mc"] = {"answered": False}
    else:
        status = mc_ev["body"][0] if mc_ev["body"] else None
        mc_name = CTAP2_STATUS_NAMES.get(status, "UNKNOWN")
        say(f"    (b) MakeCredential final reply: +{total_s*1000:.1f} ms wall, "
            f"cmd=0x{mc_ev['cmd']:02X} len={mc_ev['len']} raw={mc_ev['raw']}")
        say(f"        CTAP2 status byte = 0x{status:02X} = {mc_name}")
        result["mc"] = {"answered": True, "status": status, "name": mc_name,
                        "total_s": total_s, "raw": mc_ev["raw"]}

    # Late answers to the blacked-out probes, if the device got to them. The
    # device serves one command at a time, so its queued frames are answered
    # only after the window closes — drain a bounded moment, then classify.
    hid.settle(quiet_s=0.5, hard_s=3.0)
    late_init = init_ans or hid.find(BROADCAST.hex(), INIT, since=t_init_send)
    late_ping = ping_ans or hid.find(cid_hex, PING, since=t_ping_send)
    late_cancel = None
    if send_cancel:
        late_cancel = cancel_ans or hid.find(cid_hex, CANCEL, since=t_cancel_send) \
            or hid.find(cid_hex, ERROR, since=t_cancel_send)
    if late_init is not None and init_ans is None:
        say(f"    (b) broadcast INIT answered LATE, "
            f"+{(late_init['t']-t_init_send)*1000:.1f} ms after send "
            f"({(late_init['t']-t_mc)*1000:.1f} ms after MC) — payload "
            f"{hx(late_init['body'])}")
        result["init_late"] = {"ms_after_send": (late_init["t"] - t_init_send) * 1000,
                               "ms_after_mc": (late_init["t"] - t_mc) * 1000,
                               "body": late_init["body"].hex()}
    if late_ping is not None and ping_ans is None:
        say(f"    (b) open-channel PING answered LATE, "
            f"+{(late_ping['t']-t_ping_send)*1000:.1f} ms after send "
            f"({(late_ping['t']-t_mc)*1000:.1f} ms after MC) — echo="
            f"{hx(late_ping['body'])} (matches sent: {late_ping['body'] == ping_payload})")
        result["ping_late"] = {"ms_after_send": (late_ping["t"] - t_ping_send) * 1000,
                               "ms_after_mc": (late_ping["t"] - t_mc) * 1000,
                               "echo_ok": late_ping["body"] == ping_payload}
    if send_cancel:
        if late_cancel is not None and cancel_ans is None:
            say(f"    (c) CTAPHID_CANCEL answered LATE, "
                f"+{(late_cancel['t']-t_cancel_send)*1000:.1f} ms after send "
                f"({(late_cancel['t']-t_mc)*1000:.1f} ms after MC) — "
                f"cmd=0x{late_cancel['cmd']:02X} len={late_cancel['len']} "
                f"raw={late_cancel['raw']}")
            if late_cancel["cmd"] == ERROR and late_cancel["body"]:
                say(f"        CTAPHID_ERROR code 0x{late_cancel['body'][0]:02X} = "
                    f"{CTAP_ERROR_NAMES.get(late_cancel['body'][0], '?')}")
            result["cancel_late"] = {"cmd": late_cancel["cmd"], "len": late_cancel["len"],
                                     "raw": late_cancel["raw"],
                                     "ms_after_send": (late_cancel["t"] - t_cancel_send) * 1000}

    say("")
    hid.settle()
    hid.mark_all_consumed()
    return result


def part_b_and_c(hid: RawHid, sess: Session, observe: float) -> dict:
    say("=" * 78)
    say(f"PART (c1) — CTAPHID_CANCEL (0x{CANCEL:02X}) with NO consent window open")
    say("=" * 78)
    hid.settle()
    hid.mark_all_consumed()
    ev, ms = sess.cancel(3.0)
    if ev is None:
        say(f"  CTAPHID_CANCEL: NOT ANSWERED after 3000 ms")
        c1 = {"answered": False}
    else:
        verdict = (f"zero-length 0x{CANCEL:02X} frame — CTAPHID §11.2.9 CORRECT"
                   if ev["cmd"] == CANCEL and ev["len"] == 0 else
                   f"NOT the zero-length 0x{CANCEL:02X} frame §11.2.9 requires")
        say(f"  sent CTAPHID_CANCEL frame cmd 0x{CANCEL:02X} on channel "
            f"{sess.cid_hex}, 0-byte payload")
        say(f"  reply: cmd=0x{ev['cmd']:02X} len={ev['len']} raw={ev['raw']} "
            f"latency={ms:.1f} ms")
        if ev["cmd"] == ERROR and ev["body"]:
            say(f"        CTAPHID_ERROR code 0x{ev['body'][0]:02X} = "
                f"{CTAP_ERROR_NAMES.get(ev['body'][0], '?')}")
        say(f"  VERDICT: {verdict}")
        c1 = {"answered": True, "cmd": ev["cmd"], "len": ev["len"], "raw": ev["raw"],
              "ms": ms,
              "error_code": ev["body"][0] if ev["cmd"] == ERROR and ev["body"] else None}
    say("")

    say("=" * 78)
    say("PART (b) — the consent-window blackout, measured twice for reproducibility")
    say("=" * 78)
    r1 = consent_round(hid, sess, "RUN 1", observe, send_cancel=False)
    r2 = consent_round(hid, sess, "RUN 2 (repeat — variance)", observe, send_cancel=True)
    say("  Reproducibility summary:")
    for r in (r1, r2):
        mc = r["mc"] or {}
        say(f"    {r['label']:<26} observed={r['observed_s']:.2f}s "
            f"init_answered={r['init_answered']!s:<5} "
            f"ping_answered={r['ping_answered']!s:<5} "
            f"cancel_answered={r['cancel_answered']!s:<5} "
            f"keepalives={r['keepalives_during_observe']:<4} "
            f"MC_wall={mc.get('total_s', float('nan')):.2f}s "
            f"MC_status={('%s/0x%02X' % (mc.get('name'), mc['status'])) if mc.get('answered') else 'none'}")
    say("")

    say("=" * 78)
    say("PART (d) — deliberate BOOTSEL / touch press")
    say("=" * 78)
    say("  NOT MEASURED — requires human.")
    say("  This probe cannot press the physical button and must not simulate it.")
    say("  The exact human procedure is written in "
        "docs/webauthn-discovery-baseline.md, part (d).")
    say("")
    return {"c_no_window": c1, "run1": r1, "run2": r2}


def final_state_check(hid: RawHid, observe: float) -> bool:
    say("=" * 78)
    say("FINAL STATE CHECK — device must be left in a normal answerable state")
    say("=" * 78)
    hid.settle(quiet_s=0.5, hard_s=5.0)
    hid.mark_all_consumed()
    ok = True

    nonce = os.urandom(8)
    t0 = time.monotonic()
    hid.send(BROADCAST, INIT, nonce)
    ev = hid.wait_for(BROADCAST.hex(), INIT, 5.0)
    ms = (ev["t"] - t0) * 1000 if ev is not None else float("nan")
    if ev is None:
        say(f"  broadcast INIT: NOT ANSWERED after 5000 ms  ** NOT LEFT ANSWERABLE **")
        return False
    body = ev["body"]
    say(f"  broadcast INIT: answered in {ms:.1f} ms, payload {hx(body)}")
    say(f"      nonce match={body[:8] == nonce}  capFlags=0x{body[16]:02X}  "
        f"fw={body[13]}.{body[14]}.{body[15]}")
    cid = body[8:12]
    sess = Session(hid, cid, ev)
    pid = b"US-1501-final"
    t0 = time.monotonic()
    hid.send(cid, PING, pid)
    pev = hid.wait_for(cid.hex(), PING, 5.0)
    pms = (pev["t"] - t0) * 1000 if pev is not None else float("nan")
    if pev is None:
        say(f"  PING on the fresh channel: NOT ANSWERED after 5000 ms")
        ok = False
    else:
        say(f"  PING on the fresh channel: answered in {pms:.1f} ms, echo {hx(pev['body'])} "
            f"(matches: {pev['body'] == pid})")
        ok = ok and pev["body"] == pid
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--vid", type=lambda x: int(x, 0), default=0x1050)
    ap.add_argument("--pid", type=lambda x: int(x, 0), default=0x0407)
    ap.add_argument("--unanswered-observe", type=float, default=3.0,
                    help="seconds to observe the blackout before calling a probe unanswered")
    ap.add_argument("--dump-log", default=None, help="write the raw frame log here")
    args = ap.parse_args()

    say("US-1501 baseline discovery probe")
    say(f"run id {uuid.uuid4()}  started {time.strftime('%Y-%m-%dT%H:%M:%S%z')}")
    say(f"python {sys.version.split()[0]}  fido2 {__import__('fido2').__file__}")
    say(f"observe window for an unanswered frame: {args.unanswered_observe:.1f} s")
    say("")

    desc = find_fido_node(args.vid, args.pid)
    if desc is None:
        say(f"FATAL: no CTAP-FIDO hidraw node for {args.vid:04X}:{args.pid:04X}")
        return 2
    conn = open_connection(desc)
    hid = RawHid(conn, desc.report_size_out, desc.report_size_in)

    rc = 0
    try:
        sess, options_anomaly = part_a(hid, desc, args.unanswered_observe)
        res = part_b_and_c(hid, sess, args.unanswered_observe)
        ok = final_state_check(hid, args.unanswered_observe)
        say("")
        say("=" * 78)
        say("RAW FRAME LOG (all frames, in arrival order)")
        say("=" * 78)
        t0 = hid.log[0]["t"] if hid.log else 0.0
        # The keepalive stream runs at 10 Hz for the whole 30 s window, so ~260
        # identical frames would bury everything else. Collapse a run of
        # same-command frames into first/last/count.
        frames = [e for e in hid.log if e.get("kind") == "frame"]
        i = 0
        while i < len(frames):
            j = i
            while (j + 1 < len(frames) and frames[j + 1]["cmd"] == frames[i]["cmd"]
                   and frames[j + 1]["cid"] == frames[i]["cid"]):
                j += 1
            e = frames[i]
            extra = ""
            if e["cmd"] == KEEPALIVE:
                extra = f" status=0x{e.get('status',0):02X}"
            elif e["cmd"] == ERROR:
                extra = f" error=0x{e.get('err',0):02X}"
            if j > i:
                span = (frames[j]["t"] - e["t"]) * 1000
                say(f"  [{e['t']-t0:8.3f}s .. {frames[j]['t']-t0:8.3f}s] "
                    f"cid={e['cid']} cmd=0x{e['cmd']:02X} x{j-i+1} over {span:.0f} ms"
                    f"{extra} body={hx(e['body'])}")
            else:
                say(f"  [{e['t']-t0:8.3f}s] cid={e['cid']} cmd=0x{e['cmd']:02X} "
                    f"len={e['len']}{extra} body={hx(e['body'])}")
            i = j + 1
        for e in hid.log:
            if e.get("kind") not in ("frame",):
                say(f"  [{e['t']-t0:8.3f}s] {e.get('kind')}: {e.get('raw','')}")
        if not ok:
            rc = 3
        elif options_anomaly:
            # The run completed and every frame was measured, but one of the
            # measurements the brief asked for could not be read (see the
            # ANOMALY block in part (a)). Nonzero, so a caller scripting this
            # cannot mistake the run for a clean one.
            rc = 4
    finally:
        try:
            conn.close()
        except Exception:
            pass

    if args.dump_log:
        with open(args.dump_log, "w") as fh:
            fh.write("\n".join(OUT) + "\n")

    say("")
    say(f"probe finished at {time.strftime('%Y-%m-%dT%H:%M:%S%z')}; "
        f"exit {rc if rc else 0}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
