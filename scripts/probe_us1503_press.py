#!/usr/bin/env python3
"""US-1503 — does a REAL button press complete a parked request on real hardware?

US-1509 (the `PendingUp` slot) and US-1510 (single-occupancy) are built and
verified in the emulator / host seam. US-1503 closes the loop: does a physical
press, on the physical board, actually land the grant and let the parked request
finish — and finish on the channel it was issued on, without any other channel
seeing the answer?

TWO ARMS, and the second is not optional:

    --arm press     open a consent window, print a loud cue, WAIT for a human
                    to press the button, and record what happened.
    --arm control   the identical probe with nobody touching anything. It must
                    NOT complete; it must end on the window's own deadline.
                    Without it, "the request completed" proves nothing.

The window is opened by `authenticatorClientPIN` (**CTAP2 opcode 0x06** in the
`python-fido2` 2.2.1 dialect this firmware deliberately speaks — AGENTS.md §2,
do NOT "fix" it to the spec's 0x04), sub-command **0x06**
`getPinUvAuthTokenUsingUvWithPermissions`. That path needs only a touch, never
a PIN entry, and the firmware parks it: `hid_serve.rs` lists `0x06` in
`presence_windowed` and turns a one-byte `UpRequired` (0x3B) into a parked
`WindowTicket` plus a 30 s `CTAP_TOUCH_WINDOW_MS` keepalive window. It mints
nothing on a throwaway ECDH key and creates/moves/deletes no credential.

THE PRESS IS NOT FAKED. There is no virtual-authenticator path in this script
and none is wanted; the whole point is a finger on GPIO of one specific board.

Identity: the board is chosen by **USB iManufacturer + iSerial**, never by
hidraw node number. Node numbers on this machine have shifted more than once
(ours has been hidraw8, hidraw10 and hidraw9 at different times) and an earlier
brief in this same story called a node that had no sysfs backing at all. The
selection helpers are imported from `probe_ab_devices.py`, which already
does this correctly; nothing here re-implements discovery. If the board cannot
be identified by identity, the script exits rather than guessing.

Safety: never flashes, never factory-resets, never enters BOOTSEL, never
attaches a debugger, never opens the reference board's node, never sets/changes
a PIN, never creates or deletes a credential. The only writes that touch the
device are CTAPHID INIT / PING / CBOR / CANCEL.

Usage:
    PYTHON=/home/eddieoz/Projects/git/pico/pico-fido2/.test-venv/bin/python \\
        scripts/probe_us1503_press.py --arm press
    PYTHON=... scripts/probe_us1503_press.py --arm control

Exit codes:
    0  the arm ran and every measurement the brief asks for was observed
    2  the board could not be identified, or a step could not be run at all
    3  the final INIT+PING failed -- the board was NOT left answerable
"""

from __future__ import annotations

import argparse
import json
import math
import os
import select
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fido2 import cbor  # noqa: E402
from fido2.hid import open_connection  # noqa: E402
from fido2.hid.linux import LinuxCtapHidConnection  # noqa: E402

# Identity / framing helpers, reused rather than re-invented. `probe_ab_devices`
# already reads iManufacturer/iProduct/iSerial out of `lsusb -v` and refuses to
# pick a board when the match is not unique.
from probe_ab_devices import (  # noqa: E402
    BROADCAST_CID,
    DEVICE_A_MANUFACTURER,
    DEVICE_B_MANUFACTURER,
    CtapHidError,
    RawCtap,
    Timeout,
    enumerate_devices,
    pick,
    self_check,
)

TYPE_INIT = 0x80
CTAPHID_PING = 0x01
CTAPHID_INIT = 0x06
CTAPHID_CBOR = 0x10
CTAPHID_CANCEL = 0x11
CTAPHID_KEEPALIVE = 0x3B
CTAPHID_ERROR = 0x3F

CTAP2_MAKE_CREDENTIAL = 0x01  # fido2-2.2.1 dialect. Spec would say 0x02.
CTAP2_GET_INFO = 0x04  # spec would say 0x03
CTAP2_CLIENT_PIN = 0x06  # spec would say 0x04

KEEPALIVE_PROCESSING = 0x01
KEEPALIVE_UPNEEDED = 0x02

# CTAP2 status names, taken from the firmware's own `Ctap2Response`
# (apps/fido/src/ctap2.rs) rather than from a generic CTAP table. `probe_ab_devices`
# exports a CTAP1/transport table whose `status_name(0x2d)` reads
# "CTAP1_ERR_APPLICATION_ERROR" -- which is true of a CTAP1 status word and false
# here: 0x2D in a CTAP2 CBOR reply is `CTAP2_ERR_KEEPALIVE_CANCEL`, the exact
# byte `hid_serve.rs` sends when a window expires with no press.
CTAP2_STATUS_NAMES = {
    0x00: "CTAP2_OK", 0x01: "CTAP1_ERR_INVALID_COMMAND",
    0x02: "CTAP1_ERR_INVALID_PARAMETER", 0x03: "CTAP1_ERR_INVALID_LENGTH",
    0x11: "CTAP2_ERR_CBOR_UNEXPECTED_TYPE", 0x12: "CTAP2_ERR_INVALID_CBOR",
    0x14: "CTAP2_ERR_MISSING_PARAMETER", 0x15: "CTAP2_ERR_LIMIT_EXCEEDED",
    0x19: "CTAP2_ERR_CREDENTIAL_EXCLUDED", 0x21: "CTAP2_ERR_PROCESSING",
    0x22: "CTAP2_ERR_INVALID_CREDENTIAL", 0x23: "CTAP2_ERR_USER_ACTION_PENDING",
    0x24: "CTAP2_ERR_OPERATION_PENDING", 0x26: "CTAP2_ERR_UNSUPPORTED_ALGORITHM",
    0x27: "CTAP2_ERR_OPERATION_DENIED", 0x28: "CTAP2_ERR_KEY_STORE_FULL",
    0x2A: "CTAP2_ERR_UNSUPPORTED_OPTION", 0x2B: "CTAP2_ERR_INVALID_OPTION",
    0x2D: "CTAP2_ERR_KEEPALIVE_CANCEL", 0x2E: "CTAP2_ERR_NO_CREDENTIALS",
    0x2F: "CTAP2_ERR_USER_ACTION_TIMEOUT", 0x30: "CTAP2_ERR_NOT_ALLOWED",
    0x31: "CTAP2_ERR_PIN_INVALID", 0x33: "CTAP2_ERR_PIN_AUTH_INVALID",
    0x34: "CTAP2_ERR_PIN_AUTH_BLOCKED", 0x35: "CTAP2_ERR_PIN_NOT_SET",
    0x36: "CTAP2_ERR_PIN_REQUIRED", 0x37: "CTAP2_ERR_PIN_POLICY_VIOLATION",
    0x38: "CTAP2_ERR_PIN_TOKEN_EXPIRED", 0x39: "CTAP2_ERR_REQUEST_TOO_LARGE",
    0x3A: "CTAP2_ERR_ACTION_TIMEOUT", 0x3B: "CTAP2_ERR_UP_REQUIRED",
    0x3C: "CTAP2_ERR_UV_BLOCKED", 0x3D: "CTAP2_ERR_INTEGRITY_FAILURE",
    0x3E: "CTAP2_ERR_INVALID_SUBCOMMAND", 0x3F: "CTAP2_ERR_UV_INVALID",
    0x40: "CTAP2_ERR_UNAUTHORIZED_PERMISSION", 0x7F: "CTAP1_ERR_OTHER",
}


def ctap2_status(code: int) -> str:
    return CTAP2_STATUS_NAMES.get(code, f"CTAP2_UNKNOWN_STATUS(0x{code:02x})")

# firmware/src/presence.rs:CTAP_TOUCH_WINDOW_MS = 30_000. This is only how long
# the probe WAITS; the deadline the device actually used is read off the wire
# and compared against this, never assumed.
WINDOW_S = 30.0
WINDOW_SLACK_S = 8.0

PING_TIMEOUT = 5.0

# P-256 base point. A real curve point is required: the firmware parses the
# coordinates with `parse_cose_ec2_p256_bytes`, so a dummy pair is rejected with
# PinAuthInvalid before the presence gate is ever consulted. The point is fixed
# rather than generated so the request bytes are reproducible; nothing security
# bearing rests on it and the token that comes back is never printed.
P256_GX = bytes.fromhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
P256_GY = bytes.fromhex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")

THROWAWAY_RP = "us1503-press.invalid"

RESULT: dict = {}


def say(*a):
    print(*a, flush=True)


def banner(text: str, ch: str = "=", width: int = 78) -> None:
    say("")
    say(ch * width)
    say(text)
    say(ch * width)


# --------------------------------------------------------------------------
# framing: RawCtap for the wire, plus a full timestamped frame log
# --------------------------------------------------------------------------


class Board(RawCtap):
    """`RawCtap` with two additions US-1503 needs and cannot get from it.

    1. **A complete frame log.** `RawCtap.read_frame` raises `Timeout` on a
       frame for a *different* channel, which is correct for "wait for my
       reply" and useless for "prove nobody else saw the answer". Here every
       frame read is decoded and logged with its channel, frame command and
       timestamp, and nothing is ever dropped for being on the wrong channel.

    2. **A bounded write.** US-1501 measured this board blocking an OUT write
       to ETIMEDOUT for the duration of a consent window, so an unbounded
       `connection.write_packet()` here would turn "the device is busy" into
       "the probe hangs". Writes are non-blocking and deadline-bounded; every
       stall is counted and reported rather than hidden, because a stall is a
       measurement (it is the shape US-1501 recorded), not a bug to swallow.
    """

    def __init__(self, dev):
        super().__init__(dev["descriptor"], open_connection(dev["descriptor"]))
        os.set_blocking(self.fd, False)
        self._prepend_report_id = isinstance(self.conn, LinuxCtapHidConnection)
        self.events: list[dict] = []
        self.write_stalls = 0
        self.write_failures: list[str] = []
        self._pend: dict[int, dict] = {}

    # -- write ---------------------------------------------------------
    def _write(self, packet):  # noqa: D102 - overrides RawCtap._write
        # `RawCtap._write` delegates to `connection.write_packet`, and the
        # Linux backend PREPENDS a report ID to every OUT write. Dropping it
        # mis-frames every packet; the first draft of this override did, and
        # the symptom was a self-test PING that never echoed while INIT on the
        # broadcast channel still answered (the broadcast reply's first CID
        # byte gets eaten as the report ID, so INIT hides the fault). Hence
        # PING, and hence `selftest`.
        if self._prepend_report_id:
            packet = b"\0" + packet
        view = memoryview(packet)
        deadline = time.monotonic() + 5.0
        while view:
            try:
                n = os.write(self.fd, view)
                view = view[n:]
            except BlockingIOError:
                self.write_stalls += 1
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.write_failures.append(
                        f"OUT endpoint not drained after 5.0s "
                        f"({self.write_stalls} stall(s)) -- frame NOT delivered"
                    )
                    return
                select.select([], [self.fd], [], min(remaining, 0.05))
            except OSError as e:
                self.write_failures.append(f"{type(e).__name__}: {e}")
                return

    # -- read ----------------------------------------------------------
    def next_frame(self, timeout: float) -> dict | None:
        """One decoded CTAPHID frame, or None if nothing arrived in `timeout`."""
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            return None
        try:
            pkt = os.read(self.fd, self.desc.report_size_in)
        except BlockingIOError:
            return None
        if len(pkt) < 5:
            self.events.append({"t": time.monotonic(), "kind": "short",
                                "raw": pkt.hex()})
            return None
        cid = int.from_bytes(pkt[0:4], "big")
        cmd_byte = pkt[4]
        if cmd_byte & TYPE_INIT:
            cmd = cmd_byte & 0x7F
            length = struct.unpack_from(">H", pkt, 5)[0]
            body = pkt[7:]
            if length <= len(body):
                return self._emit(cid, cmd, body[:length])
            self._pend[cid] = {"cmd": cmd, "length": length,
                               "buf": bytearray(body), "t0": time.monotonic()}
            return None
        p = self._pend.get(cid)
        if p is None:
            self.events.append({"t": time.monotonic(), "kind": "stray_cont",
                                "cid": f"{cid:08x}", "raw": pkt.hex()})
            return None
        p["buf"] += pkt[5:]
        if len(p["buf"]) >= p["length"]:
            del self._pend[cid]
            return self._emit(cid, p["cmd"], bytes(p["buf"][:p["length"]]))
        return None

    def _emit(self, cid, cmd, body) -> dict:
        ev = {"t": time.monotonic(), "kind": "frame", "cid": f"{cid:08x}",
              "cid_int": cid, "cmd": cmd, "len": len(body), "body": body}
        if cmd == CTAPHID_KEEPALIVE and body:
            ev["keepalive"] = f"0x{body[0]:02x}"
        if cmd == CTAPHID_ERROR and body:
            ev["error"] = f"0x{body[0]:02x}"
        self.events.append(ev)
        return ev

    def frames(self, since: float = 0.0) -> list[dict]:
        return [e for e in self.events if e["kind"] == "frame" and e["t"] >= since]


def describe_cbor(payload: bytes) -> str:
    """Describe a CTAP2 answer WITHOUT printing a secret.

    A successful 0x06 answer carries an encrypted pinUvAuthToken. Its bytes are
    evidence of a grant landing but printing them into a committed doc is a bad
    habit to normalise, so only the shape is recorded.
    """
    if not payload:
        return "(empty)"
    status = payload[0]
    if len(payload) == 1:
        return f"status 0x{status:02x} ({ctap2_status(status)})"
    try:
        decoded = cbor.decode(payload[1:])
        keys = []
        for k, v in decoded.items():
            if isinstance(v, (bytes, bytearray)):
                keys.append(f"{k}: bstr({len(v)}) [not printed]")
            elif isinstance(v, dict):
                keys.append(f"{k}: map({sorted(v.keys())})")
            else:
                keys.append(f"{k}: {v!r}")
        return f"status 0x{status:02x} ({ctap2_status(status)}) + " + ", ".join(keys)
    except Exception:
        return f"status 0x{status:02x} ({ctap2_status(status)}) + {len(payload)-1} opaque bytes"


def uv_token_body() -> bytes:
    """`getPinUvAuthTokenUsingUvWithPermissions`, CTAP2 0x06 / sub 0x06."""
    cose = {1: 2, 3: -25, -1: 1, -2: P256_GX, -3: P256_GY}
    # Keys are CTAP2 integers, and ONLY those this firmware's `0x06` arm reads:
    # 1 pinUvAuthProtocol, 2 subCommand, 3 keyAgreement, 9 permissions. No
    # `rpId` -- `device_core.rs`'s parameter parser binds key 4 to
    # `pinUvAuthParam` and answers `InvalidCbor` for a *text* value there, so
    # adding an rpId string would be rejected before the presence gate.
    params = {1: 2, 2: 0x06, 3: cose, 9: 0x04}
    return bytes([CTAP2_CLIENT_PIN]) + cbor.encode(params)


def make_credential_body() -> bytes:
    """A MakeCredential that can never be completed.

    Only ever used as cross-channel traffic *while a window is already open*,
    where `hid_serve.rs` refuses it with `OPERATION_PENDING` before the app is
    reached at all -- so it creates nothing. The RP id is a reserved `.invalid`
    name for the same reason.
    """
    return bytes([CTAP2_MAKE_CREDENTIAL]) + cbor.encode(
        {1: THROWAWAY_RP, 2: {"id": THROWAWAY_RP, "name": "us1503"},
         3: [{"type": "public-key", "alg": -7}], 4: {"format": "packed",
         "authData": b"\0" * 37}, 5: {"1": b"\0" * 32, "2": b"\0" * 32}}
    )


def get_info_body() -> bytes:
    return bytes([CTAP2_GET_INFO])


# --------------------------------------------------------------------------
# identity
# --------------------------------------------------------------------------


def identify():
    inventory = enumerate_devices()
    banner("USB IDENTITY -- selected by descriptor, never by hidraw node number")
    for d in inventory:
        say(f"  {d['path']:<16} iManufacturer={d['manufacturer']!r} "
            f"iProduct={d['product']!r} iSerial={d['serial']!r} "
            f"bcdDevice={d['bcdDevice']} hid_serial={d['hid_serial']!r}")
    if not inventory:
        say("\n  No 1050:0407 device found. Stopping.")
        sys.exit(2)
    ours = pick(inventory, DEVICE_A_MANUFACTURER, "OURS (press this one)")
    others = [d for d in inventory if d is not ours]
    if not others:
        say("  NOTE: only one board present; the reference board is not attached.")
    for d in others:
        say(f"  NOT TOUCHED: {d['path']} "
            f"({d['manufacturer']!r}, serial {d['serial']!r}) — this run never "
            f"opens this node.")
    say("")
    say(f"  >>> THE BOARD FOR THIS PROBE IS: iManufacturer={DEVICE_A_MANUFACTURER!r}, "
        f"iProduct={ours['product']!r}, iSerial={ours['serial']!r}  ({ours['path']}) <<<")
    return ours


# --------------------------------------------------------------------------
# the arm
# --------------------------------------------------------------------------


def run_arm(dev, arm: str, lead_in: float = 0.0, xtalk_scale: float = 1.0,
             press_from: float = 0.0) -> dict:
    """One full arm. Returns the measurement dict for that arm."""
    self_check(dev, DEVICE_A_MANUFACTURER)
    board = Board(dev)
    cid_a = board.selftest(f"{dev['path']} ({dev['serial']})")
    cid_b = None
    out: dict = {
        "arm": arm,
        "path": dev["path"],
        "serial": dev["serial"],
        "cid_a": f"{cid_a:08x}",
        "cid_b": None,
        "expect_completion": arm == "press",
    }
    say(f"\n  arm={arm}  channel A (the parked request) = 0x{cid_a:08x}  "
        f"expected outcome: "
        f"{'a real press completes it' if arm == 'press' else 'NOTHING, ends on the deadline'}")

    # Channel B is allocated BEFORE the window opens, on purpose. A CTAPHID
    # INIT written *into* a live window measured 0.3-0.6 s before its reply
    # returned -- the serve loop's read is bounded at one
    # CTAP_KEEPALIVE_PERIOD_MS while a window is occupied, so one message per
    # pass -- and until that reply lands there is no channel B to send a
    # competing request on. All four earlier press runs answered between
    # t+1.03 s and t+2.86 s, i.e. faster than any lead-in could have relied on,
    # so the competing traffic has to be *already scheduled* the instant the
    # window opens. A channel is just a CTAPHID channel; it needs no window,
    # and allocating it first costs the window nothing.
    t_b = time.monotonic()
    reply_b, _, _ = board.call(CTAPHID_INIT, os.urandom(8),
                               cid=BROADCAST_CID, timeout=PING_TIMEOUT)
    cid_b_init = struct.unpack_from(">I", reply_b, 8)[0]
    out["cid_b"] = f"{cid_b_init:08x}"
    out["cid_b_alloc_s"] = round(time.monotonic() - t_b, 3)
    say(f"  channel B pre-allocated before the window: 0x{cid_b_init:08x} "
        f"({out['cid_b_alloc_s']:.3f}s)")

    body = uv_token_body()
    say(f"  request: CTAP2 0x06 sub 0x06 (getPinUvAuthTokenUsingUvWithPermissions), "
        f"{len(body)} bytes, permissions=mc")
    say(f"  sent payload hex: {body.hex()}")

    if lead_in > 0:
        banner("STAND BY -- DO NOT PRESS YET", "!")
        say(f"  The window has NOT opened. Nothing you press now can be counted.")
        say(f"  The window opens {lead_in:.0f} s from now and then stays open "
            f"{WINDOW_S:.0f} s.")
        say(f"  Be ready to press and hold the button from that moment onward.")
        t_lead = time.monotonic()
        last = -1
        while time.monotonic() - t_lead < lead_in:
            left = lead_in - (time.monotonic() - t_lead)
            s_left = int(math.ceil(left))
            if s_left != last:
                last = s_left
                say(f"      stand by — {s_left:>2}s until the window opens")
            time.sleep(0.2)

    events: list[dict] = []
    t_open = time.monotonic()
    board.send_only(CTAPHID_CBOR, body, cid_a)
    say(f"  window opened at t+0.000s (write took "
        f"{time.monotonic() - t_open:.3f}s)")

    # Cross-channel schedule. Every step is a WRITE followed by the same read
    # loop, so nothing here can run unbounded. `dup()`-ing the hidraw node is
    # deliberately NOT used -- two fds share one interrupt endpoint and block
    # each other (documented on `RawCtap.multiplex`); a browser multiplexes on
    # CIDs over one connection, and so does this.
    # Cross-channel traffic has to land BEFORE the grant, or the arm proves
    # nothing about anti-harvest: the first press run answered at t+2.856 s,
    # earlier than the first scheduled step at t+3.0 s, so channel B never got
    # a chance to try anything. `xtalk_scale` squeezes the whole schedule into
    # the first few seconds so an operator who waits `press_from` seconds can
    # be sure every competing request was already refused by the time the
    # grant lands.
    # Offsets are deliberately front-loaded. While a window is open the serve
    # loop's read is bounded at one CTAP_KEEPALIVE_PERIOD_MS, so one message
    # per pass: a CTAPHID INIT written into a live window measured 0.3-0.6 s
    # before its reply came back, and channel B cannot be addressed before
    # then. Pushing the two COMPETING consent requests (mc_b, pin_b) to t+0.9
    # and t+1.2 is what guarantees they are on the wire before any plausible
    # human reaction time -- the two earlier press runs answered at t+2.856 s
    # and t+1.688 s, which is faster than any lead-in could have relied on.
    base_schedule = [
        (0.10, "mc_b", "MakeCredential on channel B (up_request) -- US-1510"),
        (0.25, "pin_b", "the same 0x06 on channel B -- US-1510 tag/occupancy"),
        (0.40, "getinfo_b", "authenticatorGetInfo on channel B (NOT windowed)"),
        (0.55, "ping_b", "PING on channel B -- is the bus still alive?"),
        (0.70, "ping_a", "PING back on channel A -- is the parked channel alive?"),
    ]
    schedule = [(round(t * xtalk_scale, 3), k, w) for t, k, w in base_schedule]
    out["xtalk_schedule"] = [{"t_rel_cue_s": t, "step": k, "what": w}
                             for t, k, w in schedule]
    pending = list(schedule)
    t_cue = time.monotonic()
    out["_t_cue"] = t_cue
    answer = None
    done_reason = "deadline"

    if arm == "press":
        banner(">>> PRESS AND HOLD THE BUTTON ON BOARD A NOW <<<", "#")
        say(f"  >>> {DEVICE_A_MANUFACTURER} / {dev['product']} / serial {dev['serial']} "
            f"on {dev['path']} <<<")
        say(f"  The window is {WINDOW_S:.0f} s long and is OPEN NOW.")
        if press_from > 0:
            say(f"  WAIT {press_from:.0f} s after this banner, THEN start "
                f"tapping once a second until the window closes.")
        say("  A quick tap is enough; if you are unsure whether the first one")
        say("  registered, keep tapping for the rest of the window. Nothing")
        say("  else is required, and a press after the window closes does nothing.")
    else:
        say("\n  CONTROL ARM: no press. Expecting the window's own deadline to "
            "end this, with a KEEPALIVE_CANCEL and no token.")

    last_tick = -1
    while True:
        now = time.monotonic()
        elapsed = now - t_cue
        # Once per whole second, not once per loop pass: the pass returns every
        # 50 ms and, while a human is deciding whether to press a button,
        # dozens of identical lines per second bury the countdown.
        sec = int(elapsed)
        if sec > last_tick:
            last_tick = sec
            left = max(0, int(round(WINDOW_S - elapsed)))
            if arm == "press":
                say(f"      ...waiting for the press — {left:>2}s of window left  "
                    f"(t+{elapsed:5.1f}s)")
            else:
                say(f"      ...no press, as designed — {left:>2}s of window left  "
                    f"(t+{elapsed:5.1f}s)")

        ev = board.next_frame(0.05)
        if ev is not None:
            log_frame(ev)
            # The answer to the PARKED request, on ITS OWN channel, as a CBOR
            # frame. This is the whole measurement.
            if ev["cid_int"] == cid_a and ev["cmd"] == CTAPHID_CBOR:
                answer = ev
                done_reason = "answer on channel A"
                break

        now = time.monotonic()
        elapsed = now - t_cue
        while pending and elapsed >= pending[0][0]:
            _, key, what = pending.pop(0)
            events.extend(fire_step(board, key, what, cid_a, events, out))
            # Replies to the competing requests are collected by
            # `resolve_steps` out of the shared frame log, so one step's
            # round-trip latency can never delay the NEXT step's write. That is
            # what makes "all competing traffic is on the wire before the grant"
            # a property of the schedule rather than of how fast a human
            # pressed.
            resolve_steps(board, events, out)
            # The cross-channel step consumes frames off the same fd the parked
            # answer arrives on. If it saw that answer, it belongs to THIS arm,
            # not to the step -- take it and stop rather than let the step's
            # own wait swallow the one measurement that matters.
            if not answer:
                for e in board.frames(t_cue):
                    if e["cid_int"] == cid_a and e["cmd"] == CTAPHID_CBOR:
                        answer = e
                        done_reason = "answer on channel A (seen during a cross-channel step)"
                        break
            if answer:
                break
        if answer:
            break
        if now - t_cue > WINDOW_S + WINDOW_SLACK_S:
            done_reason = "probe budget exhausted"
            break

    t_end = time.monotonic()
    out["done_reason"] = done_reason
    out["window_open_to_end_s"] = round(t_end - t_cue, 3)
    out["cross_channel_events"] = events
    out["write_stalls"] = board.write_stalls
    out["write_failures"] = board.write_failures

    # -- what the parked request answered ---------------------------------
    if answer is None:
        out["answer"] = None
        say("\n  NO CBOR answer arrived on channel A.")
    else:
        out["answer"] = {
            "status": f"0x{answer['body'][0]:02x}" if answer["body"] else None,
            "status_name": ctap2_status(answer["body"][0]) if answer["body"] else None,
            "len": answer["len"],
            # Never the bytes themselves: a successful 0x06 answer carries an
            # encrypted pinUvAuthToken, and `--json` output is committed. The
            # shape and length are the evidence; the token is not.
            "body_withheld": True,
            "description": describe_cbor(answer["body"]),
            "cue_to_answer_s": round(answer["t"] - t_cue, 3),
        }
        say(f"\n  ANSWER on channel A 0x{cid_a:08x}: {out['answer']['description']}")
        say(f"  cue -> answer: {out['answer']['cue_to_answer_s']:.3f}s "
            f"(window had {WINDOW_S:.0f}s)")

    # -- did anybody ELSE see that answer? ---------------------------------
    others = [e for e in board.frames(t_open)
              if e["cid_int"] not in (cid_a,) and e["cmd"] == CTAPHID_CBOR]
    out["cbor_frames_on_other_channels"] = [
        {"cid": e["cid"], "cmd": e["cmd"], "len": e["len"],
         "first_byte": f"0x{e['body'][0]:02x}" if e["body"] else None,
         "t_rel_cue_s": round(e["t"] - t_cue, 3),
         "description": describe_cbor(e["body"])}
        for e in others
    ]
    leaked = []
    if answer is not None:
        for e in others:
            if e["body"] and e["body"][0] == 0x00 and e["len"] == answer["len"] \
                    and e["body"] == answer["body"]:
                leaked.append(e)
    out["answer_leaked_to_other_channel"] = bool(leaked)
    # "Did channel B steal the grant?" is NOT "did channel B send any 0x00
    # CBOR frame" -- the deliberate getInfo on channel B answers 0x00 by design
    # and would make that test fire on a clean run. The question is whether the
    # COMPETING `0x06` on channel B was answered, and answered with a token.
    b_pin = [e for e in out["cross_channel_events"] if e.get("step") == "pin_b"]
    out["competing_pin_on_channel_b"] = b_pin
    out["tokens_minted_on_channel_b"] = any(
        (e.get("answer") or {}).get("status") == "0x00" for e in b_pin
    )
    say(f"  Competing 0x06 on channel B: "
        f"{b_pin[0]['result'] if b_pin else 'not attempted'}")
    say(f"\n  Other-channel CBOR frames seen during the whole arm: {len(others)}")
    for e in others:
        say(f"    channel 0x{e['cid']}  t+{e['t']-t_cue:6.3f}s  {describe_cbor(e['body'])}")
    say(f"  The parked request's answer was seen on NO other channel: "
        f"{'YES' if not out['answer_leaked_to_other_channel'] else 'NO -- LEAK'}")
    out["keepalives_on_a"] = [
        e["keepalive"] for e in board.frames(t_open)
        if e["cid_int"] == cid_a and e["cmd"] == CTAPHID_KEEPALIVE
    ]
    out["keepalive_count_a"] = len(out["keepalives_on_a"])
    say(f"  KEEPALIVE frames on channel A: {out['keepalive_count_a']} "
        f"{sorted(set(out['keepalives_on_a']))}")
    out["all_frames"] = [
        {"t_rel_cue_s": round(e["t"] - t_cue, 3), "cid": e["cid"],
         "cmd": f"0x{e['cmd']:02x}", "len": e["len"],
         "first_byte": (f"0x{e['body'][0]:02x}" if e["body"] else None)}
        for e in board.frames(t_open)
    ]
    out["selftest_cid"] = f"{cid_a:08x}"
    # One last sweep: a competing request written just before the grant may be
    # answered after it. Resolve whatever is still outstanding so the record
    # shows the refusal rather than a gap.
    resolve_steps(board, events, out)

    # Leave nothing parked. `cancel()` is the US-1505 arm; it is also harmless
    # when no window is open (the firmware answers silence, not an error
    # frame), so it is sent unconditionally rather than on a guess.
    # `RawCtap.cancel()` is not used here: it reads with `read_message`, which
    # raises on a frame belonging to another channel, and a competing reply
    # still in flight from this arm turns cleanup into a spurious failure.
    # Write the CANCEL and drain for a bounded moment instead.
    try:
        board.send_only(CTAPHID_CANCEL, b"", cid=cid_a)
        cancelled = "written"
        t_drain = time.monotonic() + 2.0
        while time.monotonic() < t_drain:
            board.next_frame(0.1)
        cancelled += ", drained 2.0s for a reply (none is owed: the firmware "
        cancelled += "answers a cancelled command's refusal, not an ack)"
    except Exception as e:  # noqa: BLE001 - cleanup must never mask a measurement
        cancelled = f"{type(e).__name__}: {e}"
    out["cancel_sent"] = str(cancelled)
    say(f"\n  CTAPHID_CANCEL on channel A after the arm: {cancelled}")
    board.close()
    out.pop("_t_cue", None)
    return out


def log_frame(ev: dict) -> None:
    if ev.get("kind") != "frame":
        return
    name = {CTAPHID_KEEPALIVE: "KEEPALIVE", CTAPHID_CBOR: "CBOR",
            CTAPHID_ERROR: "ERROR", CTAPHID_PING: "PING",
            CTAPHID_INIT: "INIT"}.get(ev["cmd"], f"cmd0x{ev['cmd']:02x}")
    extra = ""
    if ev["cmd"] == CTAPHID_KEEPALIVE and ev["body"]:
        extra = f" status 0x{ev['body'][0]:02x}"
    elif ev["cmd"] == CTAPHID_CBOR and ev["body"]:
        extra = f" {describe_cbor(ev['body'])}"
    elif ev["cmd"] == CTAPHID_ERROR and ev["body"]:
        extra = f" error 0x{ev['body'][0]:02x}"
    say(f"      <- channel 0x{ev['cid']} {name} len={ev['len']}{extra}")


def _payload_for(key: str):
    if key == "ping_b":
        return CTAPHID_PING, b"us1503-xtalk", "ping"
    if key == "ping_a":
        return CTAPHID_PING, b"us1503-park", "ping"
    if key == "getinfo_b":
        return CTAPHID_CBOR, get_info_body(), "cbor"
    if key == "mc_b":
        return CTAPHID_CBOR, make_credential_body(), "cbor"
    if key == "pin_b":
        return CTAPHID_CBOR, uv_token_body(), "cbor"
    raise KeyError(key)


def fire_step(board: Board, key: str, what: str, cid_a: int,
              events: list, out: dict) -> list:
    """Put ONE competing request on the wire. Returns immediately.

    Deliberately does not wait for the reply. Waiting is what made the first
    two press runs unable to answer the question at all: the operator pressed
    at t+2.856 s and then t+1.688 s, and a step that blocks on its own round
    trip cannot guarantee it is written before a human's finger lands. The
    WRITE is what has to be ordered against the grant; the reply only has to
    arrive eventually, and `resolve_steps` picks it out of the shared frame log
    afterwards.
    """
    evs = [{"t_rel_cue_s": round(time.monotonic() - out["_t_cue"], 3),
            "step": key, "what": what}]
    say(f"      [cross-channel] {what}")

    if key == "init_b":
        nonce = os.urandom(8)
        board.send_only(CTAPHID_INIT, nonce, cid=BROADCAST_CID)
        evs[-1].update({"sent_on": "ffffffff", "kind": "init",
                        "sent_payload_hex": nonce.hex(),
                        "result": "written, awaiting reply"})
        say("      [cross-channel] CTAPHID INIT written on broadcast")
        return evs

    cid_b = int(out["cid_b"], 16) if out.get("cid_b") else None
    if cid_b is None:
        evs[-1].update({"kind": "skipped", "result": "SKIPPED: no channel B yet"})
        say("      [cross-channel] skipped, no channel B")
        return evs

    cmd, payload, kind = _payload_for(key)
    cid = cid_a if key == "ping_a" else cid_b
    board.send_only(cmd, payload, cid=cid)
    evs[-1].update({"sent_on": f"{cid:08x}", "kind": kind, "cmd": cmd,
                    "sent_payload_hex": payload.hex(),
                    "result": "written, awaiting reply"})
    say(f"      [cross-channel] written on channel 0x{cid:08x}")
    return evs


def resolve_steps(board: Board, events: list, out: dict) -> None:
    """Fill in each fired step's reply from the shared frame log.

    Non-destructive and idempotent, so the main loop can call it every pass. A
    step is resolved by the first frame matching the frame command it wrote, on
    the channel it wrote to, that arrived after it was written. Anything still
    unresolved is left explicitly unresolved rather than guessed.
    """
    t0 = out["_t_cue"]
    for ev in events:
        if "kind" not in ev or "answer" in ev:
            continue
        if ev["kind"] == "init":
            for f in board.frames(t0):
                if f["cmd"] != CTAPHID_INIT or f["len"] < 17:
                    continue
                cid_b = struct.unpack_from(">I", f["body"], 8)[0]
                out["cid_b"] = f"{cid_b:08x}"
                ev["init_reply_hex"] = f["body"].hex()
                ev["answer"] = {"t_rel_s": round(f["t"] - t0, 3)}
                ev["result"] = f"channel B = 0x{cid_b:08x}"
                say(f"      [cross-channel] channel B allocated: 0x{cid_b:08x}")
                break
            continue
        if ev["kind"] == "skipped":
            continue
        cid_i = int(ev["sent_on"], 16)
        cmd = ev["cmd"]
        want = bytes.fromhex(ev["sent_payload_hex"])
        for f in board.frames(t0):
            if f["t"] < ev["t_rel_cue_s"] + t0 or f["cid_int"] != cid_i:
                continue
            if f["cmd"] != cmd:
                continue
            if ev["kind"] == "ping":
                if f["body"] != want:
                    continue
                ev["answer"] = {"echo_ok": True, "t_rel_s": round(f["t"] - t0, 3)}
                ev["result"] = "PING echoed"
            else:
                b = f["body"]
                ev["answer"] = {
                    "status": f"0x{b[0]:02x}" if b else None,
                    "status_name": ctap2_status(b[0]) if b else None,
                    "len": f["len"], "description": describe_cbor(b),
                    "t_rel_s": round(f["t"] - t0, 3)}
                ev["result"] = f"answered {describe_cbor(b)}"
            say(f"      [cross-channel] {ev['step']}: {ev['result']} "
                f"at t+{ev['answer']['t_rel_s']:.3f}s")
            break


# --------------------------------------------------------------------------
# liveness
# --------------------------------------------------------------------------


def final_liveness(dev) -> dict:
    """Fresh INIT + PING on a brand-new channel. Nothing cached, nothing reused."""
    self_check(dev, DEVICE_A_MANUFACTURER)
    say("")
    banner("FINAL CHECK -- is the board still answerable?")
    board = Board(dev)
    res = {}
    try:
        reply, _, _ = board.call(CTAPHID_INIT, os.urandom(8),
                                 cid=BROADCAST_CID, timeout=PING_TIMEOUT)
        if reply is None or len(reply) < 17:
            raise CtapHidError(0x01)
        cid = struct.unpack_from(">I", reply, 8)[0]
        res["init_ok"] = True
        res["new_channel"] = f"{cid:08x}"
        res["init_reply_hex"] = reply.hex()
        say(f"  CTAPHID INIT on broadcast: OK, new channel 0x{cid:08x}")
        say(f"    reply: {reply.hex()}")
        say(f"    bytes 13..15 (YubiKey firmware version, per AGENTS.md): "
            f"{reply[13]}.{reply[14]}.{reply[15]}")
        probe = b"US-1503-FINAL-PING"
        t0 = time.monotonic()
        echo, _, _ = board.call(CTAPHID_PING, probe, cid=cid,
                                timeout=PING_TIMEOUT)
        res["ping_ok"] = echo == probe
        res["ping_latency_ms"] = round((time.monotonic() - t0) * 1000, 1)
        res["ping_echo_hex"] = echo.hex() if echo else None
        say(f"  CTAPHID PING on 0x{cid:08x}: "
            f"{'echo OK' if res['ping_ok'] else 'ECHO MISMATCH'} in "
            f"{res['ping_latency_ms']} ms")
    except (Timeout, CtapHidError, OSError) as e:
        res["init_ok"] = False
        res["error"] = f"{type(e).__name__}: {e}"
        say(f"  FINAL CHECK FAILED: {type(e).__name__}: {e}")
    finally:
        board.close()
    return res


# --------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--arm", choices=["press", "control", "both"], required=True,
                    help="press = the real button arm; control = identical, no press")
    ap.add_argument("--json", help="write the raw measurement dict here")
    ap.add_argument("--xtalk-scale", type=float, default=1.0,
                    help="multiply every cross-channel step's offset. Use a value "
                         "< 1 to finish all competing traffic before the press.")
    ap.add_argument("--press-from", type=float, default=0.0,
                    help="advisory: tell the operator to start pressing this many "
                         "seconds after the window opens. Purely a cue -- the "
                         "grant, if any, is read off the wire.")
    ap.add_argument("--lead-in", type=float, default=0.0,
                    help="seconds of 'STAND BY, do not press yet' BEFORE the window "
                         "opens. The first draft of this probe had no lead-in and "
                         "the operator was told to react to a banner on stdout; "
                         "when the output is piped or buffered that banner never "
                         "reaches them, the operator presses nothing, and the run "
                         "comes back indistinguishable from a control. The lead-in "
                         "moves the decision off 'watch the output' and onto "
                         "'press for the whole window', which cannot be missed.")
    args = ap.parse_args()

    dev = identify()
    arms = ["press", "control"] if args.arm == "both" else [args.arm]

    banner("US-1503 -- REAL BUTTON PRESS ON REAL HARDWARE", "#")
    say(f"  iManufacturer={DEVICE_A_MANUFACTURER!r} iSerial={dev['serial']!r}")
    say(f"  Reference board present: "
        f"{'yes (' + DEVICE_B_MANUFACTURER + ') -- never opened by this run' if any(d['manufacturer'] == DEVICE_B_MANUFACTURER for d in enumerate_devices()) else 'not attached'}")
    say("  No flash, no factory reset, no BOOTSEL, no debugger, no SWD.")
    say("  No PIN is set, changed or read. No credential is created, moved or deleted.")

    out = {"started": time.time(), "serial": dev["serial"],
           "path": dev["path"], "arms": []}
    for arm in arms:
        banner(f"ARM: {arm.upper()}")
        out["arms"].append(run_arm(dev, arm,
                                      args.lead_in if arm == "press" else 0.0,
                                      args.xtalk_scale, args.press_from))

    out["final"] = final_liveness(dev)
    out["finished"] = time.time()

    say("")
    banner("SUMMARY")
    for a in out["arms"]:
        ans = a.get("answer")
        say(f"  arm={a['arm']:<8} completed={bool(ans and ans['status'] == '0x00')} "
            f"answer={ans['description'] if ans else 'NONE'} "
            f"cue->grant={ans['cue_to_answer_s'] if ans else '-'}s "
            f"leaked_to_other_channel={a['answer_leaked_to_other_channel']} "
            f"tokens_on_B={a['tokens_minted_on_channel_b']}")
    say(f"  board left answerable: "
        f"{'YES' if out['final'].get('ping_ok') else 'NO -- ' + str(out['final'].get('error'))}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(out, f, indent=2, default=str)
        say(f"\n  raw measurements written to {args.json}")

    ok = out["final"].get("ping_ok")
    for a in out["arms"]:
        want = a["expect_completion"]
        got = bool(a.get("answer") and a["answer"]["status"] == "0x00")
        if want != got:
            ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())