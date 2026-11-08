"""US-1759 (RESCUE-WRITE-PRESENCE) — the rescue WRITE presence window, in the emulator.

The `fapico2-emulation` binary attaches the shared presence runtime at boot,
but until this story nothing exercised it end to end: the rescue app auto-acked
(the host default) and the emulator has no button. The window mode —
``FAPICO2_RESCUE_PRESENCE=window`` — wires the rescue app's grant to the shared
runtime's ``window_grant`` (the device's own injection, ``main.rs:1247``) and
gives the harness the two controls the button used to be:

* a press injection (CCID body ``0x50``) and
* the ordered presence-event trace (CCID body ``0x51``) — Window / Press /
  Armed / Discarded / Grant with tag and clock, ``note()``d by the runtime
  itself, read from the log rather than reconstructed.

This file is the story's deliverable — an emulator run of the rescue WRITE
flow that produces the trace — and the instrumentation substrate US-1760 and
US-1763 judge the fix against. The retry contract exercised here is today's
(join-or-open: the first WRITE answers ``6985``, the press arms the retry, the
retry consumes it), which is exactly the contract the 2026-11-08 PicoForge
ceremony proves the client implements.
"""

from __future__ import annotations

import re
import time

from harness.rescue_ccid import (
    READ_PHY_P2_ONE,
    TAG_LED_BRIGHTNESS,
    PRESS,
    TRACE,
    RescueEmu,
    parse_phy,
    read_trace,
    send_control,
    tlv,
    write_phy,
)

#: A benign one-record write: the LED brightness. Not the identity tier, not
#: the CCID-mask guard — the only thing under test here is presence.
BRIGHTNESS_WRITE = write_phy(tlv((TAG_LED_BRIGHTNESS, bytes([0x40]))))

_LINE = re.compile(
    r"^(?P<kind>Press|Armed|Discarded|Window|Grant) "
    r"tag=0x(?P<tag>[0-9A-F]{8}) t=(?P<t>\d+)ms delta=(?P<delta>\d+)ms$"
)


def parse_trace(text: str) -> list[dict]:
    """Parse the trace into ``[{kind, tag, t, delta}]``, oldest first."""
    out = []
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        assert m, f"unparsable trace line: {line!r}"
        out.append(
            {
                "kind": m["kind"],
                "tag": int(m["tag"], 16),
                "t": int(m["t"]),
                "delta": int(m["delta"]),
            }
        )
    return out


def test_the_documented_client_flow_produces_the_trace(tmp_path):
    """WRITE → 6985, press inside the window, retry → 9000; the trace tells the story."""
    with RescueEmu("presence", tmp_path,
                   extra_env={"FAPICO2_RESCUE_PRESENCE": "window"}) as emu:
        _, sw = emu.select()
        assert sw == 0x9000

        # First WRITE: no window yet, so the join-or-open gate opens one
        # under INS_WRITE (0x1C) and answers 6985 — the exact first attempt
        # of the 2026-11-08 ceremony.
        _, sw = emu.send(BRIGHTNESS_WRITE)
        assert sw == 0x6985

        # The operator's press, inside the lit period. The next serve pass's
        # drain tick (the button task's stand-in) arms it.
        send_control(emu.client, PRESS)
        time.sleep(0.3)

        trace = parse_trace(read_trace(emu.client))
        kinds = [e["kind"] for e in trace]
        assert kinds == ["Window", "Press", "Armed"], (
            f"expected Window → Press → Armed, got {kinds}"
        )
        window, press, armed = trace
        assert window["tag"] == 0x1C, "the window opens under INS_WRITE"
        assert press["tag"] == 0x00, "a press event carries no tag yet"
        assert armed["tag"] == 0x1C, "the arm binds to the window's tag"
        assert window["t"] <= press["t"] <= armed["t"], "the trace is ordered"

        # The retry joins the open window and consumes the armed grant —
        # the second APDU the documented client flow sends.
        _, sw = emu.send(BRIGHTNESS_WRITE)
        assert sw == 0x9000

        # And the write landed: the value round-trips through READ.
        blob, sw = emu.send(READ_PHY_P2_ONE)
        assert sw == 0x9000
        assert parse_phy(blob).get(TAG_LED_BRIGHTNESS) == bytes([0x40])

        # The grant is now on the trace, exactly once, bound to INS_WRITE.
        trace = parse_trace(read_trace(emu.client))
        grants = [e for e in trace if e["kind"] == "Grant"]
        assert len(grants) == 1, f"exactly one consumed grant expected: {trace}"
        assert grants[0]["tag"] == 0x1C
        armed_idx = [e["kind"] for e in trace].index("Armed")
        grant_idx = [e["kind"] for e in trace].index("Grant")
        assert armed_idx < grant_idx, "the grant consumes the arm, in order"


def test_a_retry_with_no_press_still_refuses(tmp_path):
    """Join-or-open without a press: the retry finds the window open and empty."""
    with RescueEmu("presence", tmp_path,
                   extra_env={"FAPICO2_RESCUE_PRESENCE": "window"}) as emu:
        _, sw = emu.select()
        assert sw == 0x9000

        _, sw = emu.send(BRIGHTNESS_WRITE)
        assert sw == 0x6985
        time.sleep(0.2)
        _, sw = emu.send(BRIGHTNESS_WRITE)
        assert sw == 0x6985, "the open window with no press must not grant"

        trace = parse_trace(read_trace(emu.client))
        assert [e["kind"] for e in trace] == ["Window"], (
            "one window, no press, no arm, no grant"
        )


def test_a_press_with_no_open_window_is_discarded(tmp_path):
    """Anti-harvest at the emulator level: a press with nothing pending arms nothing."""
    with RescueEmu("presence", tmp_path,
                   extra_env={"FAPICO2_RESCUE_PRESENCE": "window"}) as emu:
        _, sw = emu.select()
        assert sw == 0x9000

        # The press lands before any WRITE: no window is open, so the drain
        # tick discards it (US-921's anti-harvest, seen on the trace).
        send_control(emu.client, PRESS)
        time.sleep(0.3)

        # The subsequent WRITE opens its own window and finds no press to
        # arm — the discarded press cannot be harvested for it.
        _, sw = emu.send(BRIGHTNESS_WRITE)
        assert sw == 0x6985

        trace = parse_trace(read_trace(emu.client))
        kinds = [e["kind"] for e in trace]
        assert kinds == ["Press", "Discarded", "Window"], (
            f"expected Press → Discarded → Window, got {kinds}"
        )


def test_the_default_mode_still_auto_acks(tmp_path):
    """The knob is opt-in: without it the rescue WRITE auto-acks as always."""
    with RescueEmu("presence", tmp_path) as emu:
        _, sw = emu.select()
        assert sw == 0x9000
        _, sw = emu.send(BRIGHTNESS_WRITE)
        assert sw == 0x9000, "the default mode must stay the host auto-ack"
        # And the 0x51 control is gated on the presence mode (post-review):
        # in the default mode the body reaches the dispatcher like any other
        # frame, and the Rescue app's header guard answers 6700 — the trace
        # channel does not exist outside window/block mode.
        data, sw = emu.send(TRACE)
        assert (data, sw) == (b"", 0x6700), f"unexpected 0x51 default answer: {data!r} {sw:04X}"""


# -- US-1762 (RESCUE-WRITE-PRESENCE, Shape A): the blocking rescue gate -------
#
# The device's rescue gate is now the US-914 blocking wait (10 s, D-5): the
# first WRITE waits for the press inside the APDU. The emulator mirrors it
# (`FAPICO2_RESCUE_PRESENCE=block`, `emul_rescue_block_grant`). The
# press-during-the-wait leg is NOT drivable here — the emulator is
# single-threaded, so while the WRITE blocks, the serve loop cannot read the
# CCID control channel a press rides on; the timeout leg is, and the press
# path is `wait_grant`'s own (presence suite) plus US-1766's hardware
# re-ceremony.

def test_block_mode_times_out_as_6985(tmp_path):
    """No press: the blocking WRITE waits its 10 s bound, then answers 6985."""
    with RescueEmu("presence", tmp_path,
                   extra_env={"FAPICO2_RESCUE_PRESENCE": "block"}) as emu:
        _, sw = emu.select()
        assert sw == 0x9000

        t0 = time.monotonic()
        _, sw = emu.send(BRIGHTNESS_WRITE)
        elapsed = time.monotonic() - t0
        assert sw == 0x6985, "the no-press timeout must answer byte-exact 6985"
        assert 9.5 <= elapsed < 19, (
            f"the wait must hold ~10 s (the D-5 bound), took {elapsed:.1f}s"
        )

        # The blocking shape opens no cross-call window and arms nothing.
        trace = parse_trace(read_trace(emu.client))
        assert trace == [], f"no events expected on a timed-out wait: {trace}"

        # And the write did not happen.
        blob, sw = emu.send(READ_PHY_P2_ONE)
        assert sw == 0x9000
        assert parse_phy(blob).get(TAG_LED_BRIGHTNESS) != bytes([0x40])
