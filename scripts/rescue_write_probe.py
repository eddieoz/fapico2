#!/usr/bin/env python3
"""US-1761 (RESCUE-WRITE-PRESENCE): the rescue WRITE presence-window hardware probe.

⚠️ CONTRACT DRIFT (post-US-1762): this script was written against the
US-1761 retry contract. On a board flashed with US-1762's Shape A blocking
gate, the FIRST WRITE blocks up to 10 s (a press inside it grants
in-request), so legs A/C/G/D/E narrate the wrong world — their hypotheses
(press timing across a 15 s cross-call window; the armed-grant expiry) no
longer exist. The US-1761 diagnosis artifacts in docs/audits/ were produced
with this script against the OLD capture build and remain valid FOR THAT
BUILD. Re-base the legs before the next hardware run.


Drives the PicoForge client flow over PC/SC — the exact APDUs the client
sends on a config save (``tests/harness/rescue_ccid.py``'s transcriptions of
``picoforge/src/hal/rescue/ops.rs``) — against the **apdu-trace capture
build**, which installs the presence-event hook (`main.rs:453`) and pins the
US-922 drain CID to `a55a5a5a`. Each leg separates one of the EPIC's three
hypotheses; the operator provides the finger, the script narrates and times.

Legs (the EPIC's spread):

  A early          WRITE 6985 -> press immediately -> retry   (H1/H2/H3 baseline)
  B middle         WRITE 6985 -> press at ~7 s    -> retry
  C late           WRITE 6985 -> press at ~13 s   -> retry    (inside the 15 s
                                                               window, outside
                                                               nothing yet)
  G grant-expiry   WRITE 6985 -> press at ~1 s -> retry at ~12 s (>10 s after
                   the press, window still open)  — the H2 expiry variant
  E held           the button is HELD before the WRITE — no edge while pending
  D no-press       WRITE 6985 -> no press -> wait past the 15 s deadline ->
                   WRITE again opens a fresh window
  F foreign-window INVALID AS SCRIPTED (see the 2026-11-08 diagnosis audit's
                   residuals): the raw U2F REGISTER is not servable over
                   CTAPHID_MSG yet (AGENTS.md §4) and the CCID T=1 session
                   resets — excluded from the default --legs for that reason.
                   H3(b)'s no-theft refusal is pinned by the host logic suite.

After the last leg the US-922 ring is drained over CTAPHID vendor 0x42 on the
pinned CID and the presence events (E_PRESS..E_PGRANT, dbg.rs 50..54) are
rendered in ring order — the ordered trace the three-way rubric is applied to.

Prerequisites (one-time):
  - the capture image flashed:
        cargo build --release -p fapico2-firmware --features apdu-trace
        python3 firmware/uf2gen.py target/thumbv8m.main-none-eabi/release/fapico2-firmware \\
            firmware/fapico2-presence-capture.uf2
    then flash `firmware/fapico2-presence-capture.uf2` over BOOTSEL.
  - pcscd sees the board (pyscard), python-fido2 importable, operator ready.

Run:

    ../pico-fido2/.test-venv/bin/python scripts/rescue_write_probe.py \\
        --out docs/audits/<dir>/rescue-write-presence-trace.txt

⚠️ One-shot pull: the ring holds 512 records — do not touch the card between
the last leg and the drain.
"""
import argparse
import struct
import sys
import time
from pathlib import Path

from smartcard.System import readers
from smartcard.util import toBytes

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests"))  # harness package import (convention)

RESCUE_AID = toBytes("A0 58 3F C1 9B 7E 4F 21")
CLA = 0x80
TAG_LED_BRIGHTNESS = 0x05
#: A benign one-record write — the same brightness record the harness tests
#: use, so a successful leg visibly changes (and a READ round-trips) a value
#: that harms nothing.
WRITE_PAYLOAD = bytes([TAG_LED_BRIGHTNESS, 0x01, 0x40])
WRITE_PHY = bytes([CLA, 0x1C, 0x01, 0x00, len(WRITE_PAYLOAD)]) + WRITE_PAYLOAD
READ_PHY = bytes([CLA, 0x1E, 0x01, 0x01, 0x00])

SW_OK = 0x9000
SW_CONDITIONS = 0x6985

#: US-922 drain (apdu-trace capture build): vendor command 0x42 on the pinned
#: CID (`main.rs`, the US-933 arm).
DBG_CMD = 0x42
DRAIN_CID = bytes([0xA5, 0x5A, 0xA5, 0x5A])
ENTRY = 24
ENTRIES = 512

E_PRESS, E_PARM, E_PDISCARD, E_PWINDOW, E_PGRANT = 50, 51, 52, 53, 54
EVENT_NAMES = {
    E_PRESS: "Press",
    E_PARM: "Armed",
    E_PDISCARD: "Discarded",
    E_PWINDOW: "Window",
    E_PGRANT: "Grant",
}
#: The record's `a` for presence events is the tag; 0x1C is the rescue applet's
#: INS_WRITE — the tag the gate binds.
INS_WRITE = 0x1C


def select_rescue(conn):
    data, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x04, 0x04, len(RESCUE_AID)] + list(RESCUE_AID))
    return (sw1 << 8) | sw2


def apdu(conn, raw):
    data, sw1, sw2 = conn.transmit(list(raw))
    return bytes(data), (sw1 << 8) | sw2


def narrate(msg):
    print(f"\n{'=' * 62}\n{msg}\n{'=' * 62}", flush=True)


def wait_for_operator(seconds, what):
    print(f"    >>> {what}", flush=True)
    time.sleep(seconds)


def write_and_wait(conn, leg, press_after, retry_after, note=""):
    """One WRITE -> (press) -> retry leg. Returns (sw1, sw2) of the retry."""
    _, sw = apdu(conn, WRITE_PHY)
    print(f"  [{leg}] WRITE -> {sw:04X} ({'window should now be open' if sw == SW_CONDITIONS else 'UNEXPECTED'}){note}",
          flush=True)
    if press_after is not None:
        wait_for_operator(press_after, f"PRESS THE BUTTON NOW ({leg} leg)")
    if retry_after:
        print(f"    ... waiting {retry_after}s before the retry", flush=True)
        time.sleep(retry_after)
    _, sw = apdu(conn, WRITE_PHY)
    print(f"  [{leg}] retry WRITE -> {sw:04X} ({'GRANTED' if sw == SW_OK else 'refused'})", flush=True)
    return sw


def leg_held(conn):
    narrate("Leg E — the button is HELD before the WRITE (no edge while pending)")
    wait_for_operator(0, "HOLD THE BUTTON DOWN NOW and keep holding until told")
    time.sleep(1.0)
    _, sw = apdu(conn, WRITE_PHY)
    print(f"  [held] WRITE (button still held) -> {sw:04X}", flush=True)
    wait_for_operator(2.0, "you may release the button")
    _, sw = apdu(conn, WRITE_PHY)
    print(f"  [held] retry WRITE -> {sw:04X} ({'GRANTED' if sw == SW_OK else 'refused'})", flush=True)


def leg_no_press(conn):
    narrate("Leg D — no press; the 15 s window expires; the next WRITE opens a fresh one")
    _, sw = apdu(conn, WRITE_PHY)
    print(f"  [no-press] WRITE -> {sw:04X}", flush=True)
    print("    ... hands OFF the button for 17 s", flush=True)
    time.sleep(17)
    _, sw = apdu(conn, WRITE_PHY)
    print(f"  [no-press] WRITE after expiry -> {sw:04X} (fresh window expected)", flush=True)


def leg_foreign_window(conn):
    narrate("Leg F — a foreign (FIDO/CTAPHID) window holds the slot first (H3b)")
    from fido2.hid import list_descriptors, open_connection

    descs = [d for d in list_descriptors()
             if "fapico2" in (getattr(d, "product_name", "") or "").lower()]
    if not descs:
        raise SystemExit("no fapico2 HID device for the foreign-window leg")
    hid = open_connection(descs[0])
    # A CTAP1 U2F REGISTER, untouched: the MSG arm answers 6985 and opens a
    # keepalive window (u2f_up_refusal) — the slot is now held by a FIDO tag.
    challenge = bytes(range(32))
    appid = bytes(range(32, 64))
    payload = bytes([0x00, 0x01, 0x00, 0x00, 0x40]) + challenge + appid
    b = bytearray(64)
    b[0:4] = b"\x00\x00\x00\x01"
    b[4] = 0x80 | 0x03  # TYPE_INIT | MSG
    b[5:7] = len(payload).to_bytes(2, "big")
    b[7:7 + len(payload)] = payload
    hid.write_packet(bytes(b))
    pkt = bytes(hid.read_packet())
    n = int.from_bytes(pkt[5:7], "big")
    body = pkt[7:7 + n]
    print(f"  [foreign] U2F REGISTER (no touch) -> {body[-2:].hex()} "
          f"(6985 expected; the FIDO window is now open)", flush=True)

    _, sw = apdu(conn, WRITE_PHY)
    print(f"  [foreign] rescue WRITE while the FIDO window holds the slot -> {sw:04X}", flush=True)
    wait_for_operator(1.5, "PRESS THE BUTTON NOW (foreign-window leg)")
    _, sw = apdu(conn, WRITE_PHY)
    print(f"  [foreign] retry WRITE -> {sw:04X} "
          f"(6985 expected: no theft — this is the H3(b) signature)", flush=True)
    print("    ... waiting 31 s for the foreign window to expire", flush=True)
    time.sleep(31)


def drain_ring(vid=None, pid=None):
    """The US-922 drain (the us933 pull's protocol), inlined to keep the
    probe one file. Returns the raw ring bytes."""
    from fido2.hid import list_descriptors, open_connection

    def frame(channel, cmd, payload):
        b = bytearray(64)
        b[0:4] = channel
        b[4] = cmd | 0x80
        b[5:7] = len(payload).to_bytes(2, "big")
        b[7:7 + len(payload)] = payload
        return bytes(b)

    descs = [d for d in list_descriptors()
             if "fapico2" in (getattr(d, "product_name", "") or "").lower()
             and (vid is None or d.vid == vid) and (pid is None or d.pid == pid)]
    if len(descs) != 1:
        raise SystemExit(f"expected exactly one fapico2 HID device, got {descs}")
    conn = open_connection(descs[0])

    def xchg(payload):
        conn.write_packet(frame(DRAIN_CID, DBG_CMD, payload))
        pkt = bytes(conn.read_packet())
        n = int.from_bytes(pkt[5:7], "big")
        return pkt[7:7 + n]

    # The documented first-drain-after-boot flake: the first header exchange
    # can be answered by the CTAP_READ_CONFIG 00 reply; retry before giving up
    # (US-1761 audit residuals).
    hdr = b""
    for _ in range(4):
        hdr = xchg(b"\x01")
        if len(hdr) >= 6:
            break
        time.sleep(0.5)
    if len(hdr) < 6:
        raise SystemExit(f"drain refused ({hdr.hex()}) — is this the apdu-trace build?")
    count = struct.unpack_from("<I", hdr, 0)[0]
    entries = min(count, ENTRIES)
    buf = bytearray()
    empty = 0
    while len(buf) < entries * ENTRY:
        chunk = xchg(b"\x02" + struct.pack("<I", len(buf)))
        if not chunk:
            empty += 1
            if empty >= 3:
                break
            time.sleep(0.05)
            continue
        empty = 0
        buf += chunk
    return count, bytes(buf)


def render(buf, out):
    recs = []
    for off in range(0, len(buf) - ENTRY + 1, ENTRY):
        t_us, seq, task, event, _pad = struct.unpack_from("<QIBBH", buf, off)
        a, b = struct.unpack_from("<II", buf, off + 16)
        recs.append((t_us, seq, task, event, a, b))
    recs.sort(key=lambda r: r[1])  # ring order by seq
    lines = []
    for t_us, seq, task, event, a, b in recs:
        name = EVENT_NAMES.get(event)
        if name:
            lines.append(f"seq={seq:5d} t={t_us // 1000:8d}ms T{task} {name:9s} "
                         f"tag=0x{a:08X} b={b}")
        else:
            lines.append(f"seq={seq:5d} t={t_us // 1000:8d}ms T{task} event={event:3d} "
                         f"a=0x{a:08X} b=0x{b:08X}")
    text = "\n".join(lines)
    if out:
        Path(out).write_text(text + "\n")
        print(f"\nring dump written to {out}")
    print("\n--- presence events, ring order ---")
    for line in lines:
        if any(n in line for n in EVENT_NAMES.values()):
            print(line)
    return recs


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", help="write the decoded ring dump here")
    ap.add_argument("--legs", default="A,B,C,G,E,D",  # F excluded: invalid as scripted, see the docstring
                    help="comma-separated legs to run (default: all, in order)")
    ap.add_argument("--no-drain", action="store_true", help="skip the ring drain")
    args = ap.parse_args(argv)

    conns = []
    for r in readers():
        try:
            c = r.createConnection()
            c.connect()
            conns.append((r.name, c))
        except Exception:
            pass
    if not conns:
        sys.exit("no PC/SC reader with a card — is the board attached?")
    name, conn = next(((n, c) for n, c in conns if select_rescue(c) == SW_OK), None)
    if conn is None:
        sys.exit("no reader selected the Rescue applet")
    print(f"Rescue applet selected via {name}")

    legs = [l.strip().upper() for l in args.legs.split(",") if l.strip()]
    for leg in legs:
        if leg == "A":
            narrate("Leg A — press EARLY in the window")
            write_and_wait(conn, "early", press_after=0.5, retry_after=0.5)
        elif leg == "B":
            narrate("Leg B — press in the MIDDLE of the window (~7 s)")
            write_and_wait(conn, "middle", press_after=7, retry_after=0.5)
        elif leg == "C":
            narrate("Leg C — press LATE in the window (~13 s of 15)")
            write_and_wait(conn, "late", press_after=13, retry_after=0.5)
        elif leg == "G":
            narrate("Leg G — press EARLY, retry LATE (~12 s later: past the 10 s "
                    "armed-grant expiry, inside the 15 s window — the H2 variant)")
            write_and_wait(conn, "grant-expiry", press_after=1, retry_after=11)
        elif leg == "E":
            leg_held(conn)
        elif leg == "D":
            leg_no_press(conn)
        elif leg == "F":
            leg_foreign_window(conn)
        else:
            sys.exit(f"unknown leg {leg!r}")

    if not args.no_drain:
        narrate("Draining the US-922 ring (apdu-trace build, CID a55a5a5a)")
        count, buf = drain_ring()
        print(f"ring: {count} records ever written, pulled {len(buf) // ENTRY}")
        render(buf, args.out)
        narrate("Apply the three-way rubric (EPIC fact 6):\n"
                "  Window ABSENT at attempt time (or Armed under a foreign tag) -> H3\n"
                "  window open, NO Press during it                              -> H1\n"
                "  Press present, Armed absent (or Armed but the retry refuses) -> H2")


if __name__ == "__main__":
    main()
