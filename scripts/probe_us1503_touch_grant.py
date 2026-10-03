#!/usr/bin/env python3
"""US-1503 touch-grant instrument + CTAPHID wire capture (the X.com A/B).

Three things, one script:

1. **`--case press`** — open a real consent window on OUR board with
   `authenticatorClientPIN` 0x06 / sub 0x06 (the parked path proven in
   `probe_us1503_press.py`; request shapes are IMPORTED from there, not
   re-derived), print the PRESS-NOW banner, and observe with timestamps:
   the keepalive stream, whether the press lands (a final CBOR answer on the
   parked channel), the final status byte, and the latency. One case per
   invocation so a human can be prompted before every press.

2. **`--case busy`** — the same, with competing traffic on a second channel
   fired inside the window (the shape the X.com popup resembles).

3. **`--capture`** — a PASSIVE, strictly read-only CTAPHID frame logger. It
   opens one board's hidraw node by USB identity (never by node number,
   never /dev/hidrawN by hard-coded index), never writes a byte, and logs
   every frame the device sends (command, CID, length, payload, timestamp)
   to a JSONL file while a human drives a real site in a real browser. Run
   it once against our board and once against the C reference board and
   difference the flows. `--analyze FILE` reprints the summary from any
   JSONL, so a capture whose process was killed is still analysable.

hidraw notes that shape what capture can and cannot see: on Linux every open
hidraw reader receives a copy of every IN report, so a passive sniffer works
beside the browser — but hidraw never replays host->device writes to other
readers. Capture therefore sees the device's side (INIT replies, CBOR
answers, keepalives, errors) and infers the requests from the answers; every
inference in `--analyze` output is labelled as one.

Board identity (from the brief): OURS is iManufacturer `EddieOz`, iSerial
`94746395`; the REFERENCE is `Pol Henarejos`, iSerial `7C36644DFF8A74C7`.
Selection is by descriptor identity through `probe_ab_devices.pick`, which
refuses to guess when the match is not unique. The reference board is only
ever opened by `--capture --board reference`, and even then READ-ONLY (the
write path raises on first use).

Safety: no flashing, no factory reset, no BOOTSEL, no SWD, no PIN set/changed,
no credential created. Writes in `--case` mode are INIT/PING/CBOR/CANCEL only,
against the EddieOz board only.

Usage:
    PYTHON=/home/eddieoz/Projects/git/pico/pico-fido2/.test-venv/bin/python
    $PYTHON scripts/probe_us1503_touch_grant.py --case press --trial 1
    $PYTHON scripts/probe_us1503_touch_grant.py --case busy
    $PYTHON scripts/probe_us1503_touch_grant.py --capture --board ours --duration 240 --out /tmp/cap-ours-x.jsonl
    $PYTHON scripts/probe_us1503_touch_grant.py --analyze /tmp/cap-ours-x.jsonl

Exit codes: 0 = ran and the board was left answerable (case mode) / capture
completed or was interrupted cleanly (capture mode); 2 = board identity not
found; 1 = the case's expected observation did not happen.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fido2 import cbor  # noqa: E402

from probe_ab_devices import (  # noqa: E402
    BROADCAST_CID,
    DEVICE_A_MANUFACTURER,
    DEVICE_B_MANUFACTURER,
    CtapHidError,
    Timeout,
    enumerate_devices,
    pick,
    self_check,
)

# The working request shapes and the frame-logging Board are reused from the
# press probe rather than re-derived (per the brief). Importing it executes
# only module-level definitions; nothing is sent on import.
from probe_us1503_press import (  # noqa: E402
    CTAPHID_CBOR,
    CTAPHID_ERROR,
    CTAPHID_INIT,
    CTAPHID_KEEPALIVE,
    CTAPHID_PING,
    PING_TIMEOUT,
    TYPE_INIT,
    WINDOW_S,
    WINDOW_SLACK_S,
    Board,
    banner,
    ctap2_status,
    describe_cbor,
    final_liveness,
    fire_step,
    get_info_body,
    log_frame,
    make_credential_body,
    resolve_steps,
    uv_token_body,
)

CMD_NAMES = {
    CTAPHID_PING: "PING",
    CTAPHID_INIT: "INIT",
    0x08: "WINK",
    0x11: "CANCEL",
    CTAPHID_CBOR: "CBOR",
    CTAPHID_KEEPALIVE: "KEEPALIVE",
    CTAPHID_ERROR: "ERROR",
    0x90: "MSG",
}

THROWAWAY_RP = "us1503-touch.invalid"


def say(*a):
    print(*a, flush=True)


# --------------------------------------------------------------------------
# capture: a Board that is physically incapable of writing
# --------------------------------------------------------------------------


class Sniffer(Board):
    """`Board` with the write path amputated.

    Everything else (non-blocking fd, bounded reads, full frame log, message
    reassembly) is inherited unchanged. Any attempt to write raises instead of
    emitting a frame, so a future edit that reuses this object for a probe
    cannot silently turn a passive capture into an active one.
    """

    def __init__(self, dev):
        super().__init__(dev)
        self.t0_mono = time.monotonic()
        self.wall0 = time.time()

    def _write(self, packet):  # noqa: D102 - overrides Board._write
        raise RuntimeError(
            "capture mode is strictly read-only: a write was attempted "
            f"({len(packet)} bytes) and refused"
        )


def to_jsonl(ev: dict, sn: Sniffer) -> dict:
    rec = {
        "wall": time.strftime("%H:%M:%S", time.localtime(sn.wall0 + ev["t"] - sn.t0_mono))
        + f".{int((ev['t'] - sn.t0_mono) % 1 * 1000):03d}",
        "t_rel_s": round(ev["t"] - sn.t0_mono, 3),
        "cid": ev["cid"],
        "cmd": ev["cmd"],
        "cmd_name": CMD_NAMES.get(ev["cmd"], f"0x{ev['cmd']:02x}"),
        "len": ev["len"],
        "hex": ev["body"].hex(),
    }
    if ev["cmd"] == CTAPHID_KEEPALIVE and ev["body"]:
        rec["keepalive_status"] = f"0x{ev['body'][0]:02x}"
    return rec


def classify_response(body: bytes) -> str:
    """Describe a CTAP2 answer on the IN wire. Secrets stay withheld.

    A 1-byte body is a bare status. A success with a body is decoded only far
    enough to name what it answers; bstr payloads (attestations, signatures,
    encrypted tokens) are never printed.
    """
    if not body:
        return "empty"
    status = body[0]
    if len(body) == 1:
        return f"status 0x{status:02x} ({ctap2_status(status)})"
    if status != 0x00:
        return (f"status 0x{status:02x} ({ctap2_status(status)}) + "
                f"{len(body) - 1} trailing bytes")
    try:
        decoded = cbor.decode(body[1:])
    except Exception:
        return f"status 0x00 (CTAP2_OK) + {len(body) - 1} opaque bytes (CBOR decode failed)"
    if isinstance(decoded, dict):
        names = {k if isinstance(k, str) else f"#{k}" for k in decoded}
        if "fmt" in names and "attStmt" in names:
            return "status 0x00 (CTAP2_OK) + MakeCredential ATTESTATION (ceremony COMPLETED)"
        if "authData" in names and "sig" in names:
            return "status 0x00 (CTAP2_OK) + GetAssertion ASSERTION (ceremony COMPLETED)"
        if "keyAgreement" in names or "pinUvAuthToken" in names:
            return ("status 0x00 (CTAP2_OK) + clientPIN response "
                    f"(keys {sorted(names)}, bstr values withheld)")
        if "versions" in names:
            return "status 0x00 (CTAP2_OK) + GetInfo (see GetInfo section)"
        return f"status 0x00 (CTAP2_OK) + map with keys {sorted(names)}"
    return f"status 0x00 (CTAP2_OK) + {type(decoded).__name__}"


def analyze(events: list[dict], t0_mono: float, label: str = "") -> None:
    frames = [e for e in events if e["kind"] == "frame"]
    say("")
    banner(f"CAPTURE SUMMARY {label} -- {len(frames)} frames")
    by_cmd: dict[int, int] = {}
    for e in frames:
        by_cmd[e["cmd"]] = by_cmd.get(e["cmd"], 0) + 1
    say("  frames by command: " + ", ".join(
        f"{CMD_NAMES.get(c, hex(c))}={n}" for c, n in sorted(by_cmd.items())))

    inits = [e for e in frames if e["cmd"] == CTAPHID_INIT and e["len"] >= 17]
    for e in inits[:4]:
        fw = f"{e['body'][5]}.{e['body'][6]}.{e['body'][7]}"
        caps = f"0x{e['body'][8]:02x}"
        say(f"  INIT reply t+{e['t'] - t0_mono:7.3f}s cid=0x{e['cid']} "
            f"fw={fw} capFlags={caps} (bytes 13..15 are the YubiKey version per AGENTS.md)")

    errors = [e for e in frames if e["cmd"] == CTAPHID_ERROR]
    for e in errors:
        say(f"  CTAPHID ERROR t+{e['t'] - t0_mono:7.3f}s cid=0x{e['cid']} "
            f"code=0x{e['body'][0]:02x}" if e["body"] else "  CTAPHID ERROR (empty)")

    cbors = [e for e in frames if e["cmd"] == CTAPHID_CBOR]
    say(f"  CBOR responses: {len(cbors)}")
    for e in cbors:
        say(f"    t+{e['t'] - t0_mono:7.3f}s cid=0x{e['cid']} len={e['len']:4d}  "
            f"{classify_response(e['body'])}")

    getinfos = []
    for e in cbors:
        if e["len"] > 1 and e["body"][0] == 0x00:
            try:
                m = cbor.decode(e["body"][1:])
            except Exception:
                continue
            if isinstance(m, dict) and any(k in (m if all(isinstance(k, str) for k in m) else {})
                                          for k in ("versions", "options")):
                getinfos.append((e, m))
    for e, m in getinfos[:2]:
        say(f"  GetInfo seen at t+{e['t'] - t0_mono:.3f}s cid=0x{e['cid']} -- full map "
            f"(no secrets in GetInfo):")
        say("    " + json.dumps(
            {str(k): (v.hex() if isinstance(v, (bytes, bytearray)) else v)
             for k, v in m.items()}, default=str)[:1500])

    # consent windows: per-CID runs of KEEPALIVE 0x02 (UPNEEDED) bracketed by
    # whatever ends them. 0x01 keepalives are the pre-command "processing"
    # tick and do not open a window.
    windows = []
    cur = None
    for e in frames:
        if e["cmd"] == CTAPHID_KEEPALIVE and e["body"] and e["body"][0] == 0x02:
            if cur is None:
                cur = {"cid": e["cid"], "t0": e["t"], "n": 1, "last": e["t"]}
            elif cur["cid"] == e["cid"] and e["t"] - cur["last"] < 3.0:
                cur["n"] += 1
                cur["last"] = e["t"]
            else:
                windows.append({**cur, "t1": cur["last"],
                                "outcome": "no IN answer observed after last keepalive"})
                cur = {"cid": e["cid"], "t0": e["t"], "n": 1, "last": e["t"]}
        elif cur is not None and e["cid"] == cur["cid"]:
            if e["cmd"] == CTAPHID_CBOR:
                windows.append({**cur, "t1": e["t"], "outcome":
                                f"ANSWERED {classify_response(e['body'])}"})
                cur = None
            elif e["cmd"] == CTAPHID_ERROR:
                windows.append({**cur, "t1": e["t"], "outcome":
                                f"ended with CTAPHID ERROR 0x{e['body'][0]:02x}"
                                if e["body"] else "ended with CTAPHID ERROR"})
                cur = None
    if cur is not None:
        windows.append({**cur, "t1": cur["last"],
                        "outcome": "STILL OPEN at capture end (or closed with no IN answer)"})
    say(f"  consent windows (KEEPALIVE 0x02 UPNEEDED runs): {len(windows)}")
    for w in windows:
        say(f"    cid=0x{w['cid']} t+{w['t0'] - t0_mono:7.3f}s .. "
            f"t+{w['t1'] - t0_mono:7.3f}s ({w['t1'] - w['t0']:6.3f}s, "
            f"{w['n']:3d} keepalives)  ->  {w['outcome']}")


# --------------------------------------------------------------------------
# capture main
# --------------------------------------------------------------------------


def run_capture(board_key: str, out_path: str, duration: float) -> int:
    inventory = enumerate_devices()
    banner("US-1503 CAPTURE -- passive, read-only, selected by USB identity")
    for d in inventory:
        say(f"  {d['path']:<16} iManufacturer={d['manufacturer']!r} "
            f"iSerial={d['serial']!r}")
    expected = DEVICE_A_MANUFACTURER if board_key == "ours" else DEVICE_B_MANUFACTURER
    other = DEVICE_B_MANUFACTURER if board_key == "ours" else DEVICE_A_MANUFACTURER
    if not any(d["manufacturer"] == expected for d in inventory):
        say(f"\n  FATAL: no device with iManufacturer={expected!r}. Stopping.")
        return 2
    dev = pick(inventory, expected, f"RECORDING THIS ONE ({board_key})")
    self_check(dev, expected)
    for d in inventory:
        if d["manufacturer"] == other:
            say(f"  NOT OPENED: {d['path']} ({d['manufacturer']!r}, serial {d['serial']!r})")
    say(f"  Recording from {dev['path']} ({dev['manufacturer']!r} / {dev['serial']!r})")
    say(f"  Writes on this fd raise by construction. Duration {duration:.0f}s.")
    say("")

    sn = Sniffer(dev)
    say(f"  RECORDING. Every frame the device sends is logged to {out_path}", )
    say("  >>> NOW DRIVE THE BROWSER. Nothing is written to the device. <<<")
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "a") as f:
        deadline = time.monotonic() + duration
        last_tick = -1
        while time.monotonic() < deadline:
            ev = sn.next_frame(0.2)
            if ev is not None:
                f.write(json.dumps(to_jsonl(ev, sn)) + "\n")
                f.flush()
            el = time.monotonic() - sn.t0_mono
            if int(el) > last_tick:
                last_tick = int(el)
                left = max(0, int(round(deadline - time.monotonic())))
                say(f"      ...recording ({len(sn.events)} frames so far, {left}s left)")
    sn.close()
    analyze(sn.events, sn.t0_mono, label=f"({board_key}, {dev['path']})")
    say(f"  raw JSONL: {out_path}")
    return 0


def analyze_file(path: str) -> int:
    events = []
    t0 = None
    with open(path) as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            t = rec.get("t_rel_s")
            if t is None:
                continue
            if t0 is None:
                t0 = t
            body = bytes.fromhex(rec["hex"]) if rec.get("hex") else b""
            ev = {"kind": "frame", "t": t, "cid": rec.get("cid", "?"),
                  "cid_int": None, "cmd": rec.get("cmd", -1), "len": rec.get("len", 0),
                  "body": body}
            events.append(ev)
    analyze(events, t0 or 0.0, label=f"(from {path})")
    return 0


# --------------------------------------------------------------------------
# press / busy case
# --------------------------------------------------------------------------


def run_case(dev, case: str, trial: int, lead_in: float) -> dict:
    self_check(dev, DEVICE_A_MANUFACTURER)
    board = Board(dev)
    cid_a = board.selftest(f"{dev['path']} ({dev['serial']})")
    out: dict = {"case": case, "trial": trial, "cid_a": f"{cid_a:08x}"}
    say(f"\n  case={case} trial={trial}  parked channel A = 0x{cid_a:08x}")

    cid_b = None
    if case == "busy":
        # Channel B is allocated BEFORE the window opens (an INIT written into
        # a live window costs 0.3-0.6 s -- see probe_us1503_press.py §run_arm).
        reply_b, _, _ = board.call(CTAPHID_INIT, os.urandom(8),
                                   cid=BROADCAST_CID, timeout=PING_TIMEOUT)
        cid_b = struct.unpack_from(">I", reply_b, 8)[0]
        out["cid_b"] = f"{cid_b:08x}"
        say(f"  channel B (competing traffic) = 0x{cid_b:08x}, pre-allocated")

    body = uv_token_body()
    say(f"  request: CTAP2 0x06 sub 0x06 getPinUvAuthTokenUsingUvWithPermissions, "
        f"{len(body)} bytes")

    if lead_in > 0:
        banner("STAND BY -- DO NOT PRESS YET", "!")
        say(f"  The window opens {lead_in:.0f} s from now and stays open "
            f"{WINDOW_S:.0f} s. Press once it is open.")
        t_lead = time.monotonic()
        last = -1
        while time.monotonic() - t_lead < lead_in:
            s_left = int(math.ceil(lead_in - (time.monotonic() - t_lead)))
            if s_left != last:
                last = s_left
                say(f"      stand by — {s_left:>2}s until the window opens")
            time.sleep(0.2)

    t_open = time.monotonic()
    board.send_only(CTAPHID_CBOR, body, cid_a)
    say(f"  window opened at t+0.000s")
    banner(">>> PRESS AND HOLD THE BUTTON ON THE EddieOz BOARD NOW <<<", "#")
    say(f"  >>> {dev['product']} / serial {dev['serial']} on {dev['path']} <<<")
    say(f"  The window is {WINDOW_S:.0f} s long. A quick tap is enough; if unsure, "
        f"keep tapping until the window closes.")

    schedule = []
    if case == "busy":
        base = [
            (0.10, "mc_b", "MakeCredential on channel B (up_request)"),
            (0.25, "pin_b", "the same 0x06 on channel B"),
            (0.40, "getinfo_b", "authenticatorGetInfo on channel B (NOT windowed)"),
            (0.55, "ping_b", "PING on channel B"),
        ]
        schedule = list(base)
        out["xtalk_schedule"] = [{"t_rel_s": t, "step": k, "what": w} for t, k, w in base]
    pending = list(schedule)
    events: list[dict] = []
    out["_t_cue"] = t_open
    out["cid_b"] = f"{cid_b:08x}" if cid_b else None
    answer = None
    done_reason = "deadline"

    last_tick = -1
    while True:
        now = time.monotonic()
        elapsed = now - t_open
        if int(elapsed) > last_tick:
            last_tick = int(elapsed)
            left = max(0, int(round(WINDOW_S - elapsed)))
            say(f"      ...waiting — {left:>2}s of window left (t+{elapsed:5.1f}s)")

        ev = board.next_frame(0.05)
        if ev is not None:
            log_frame(ev)
            if ev["cid_int"] == cid_a and ev["cmd"] == CTAPHID_CBOR:
                answer = ev
                done_reason = "answer on channel A"
                break

        elapsed = time.monotonic() - t_open
        while pending and elapsed >= pending[0][0]:
            _, key, what = pending.pop(0)
            events.extend(fire_step(board, key, what, cid_a, events, out))
            resolve_steps(board, events, out)
            for e in board.frames(t_open):
                if e["cid_int"] == cid_a and e["cmd"] == CTAPHID_CBOR:
                    answer = e
                    done_reason = "answer on channel A (seen during a cross-channel step)"
                    break
            if answer:
                break
        if answer:
            break
        if time.monotonic() - t_open > WINDOW_S + WINDOW_SLACK_S:
            done_reason = "probe budget exhausted"
            break

    t_end = time.monotonic()
    out["done_reason"] = done_reason
    out["window_open_to_end_s"] = round(t_end - t_open, 3)

    if answer is None:
        out["answer"] = None
        say("\n  NO CBOR answer arrived on channel A within the probe budget.")
    else:
        last_ka = [e["t"] for e in board.frames(t_open)
                   if e["cid_int"] == cid_a and e["cmd"] == CTAPHID_KEEPALIVE]
        out["answer"] = {
            "status": f"0x{answer['body'][0]:02x}" if answer["body"] else None,
            "status_name": ctap2_status(answer["body"][0]) if answer["body"] else None,
            "description": describe_cbor(answer["body"]),
            "open_to_answer_s": round(answer["t"] - t_open, 3),
            "last_keepalive_to_answer_s":
                round(answer["t"] - last_ka[-1], 3) if last_ka else None,
        }
        say(f"\n  ANSWER on channel A: {out['answer']['description']}")
        say(f"  window-open -> answer: {out['answer']['open_to_answer_s']:.3f}s")
        if out["answer"]["last_keepalive_to_answer_s"] is not None:
            say(f"  last keepalive -> answer (upper bound on press->completion): "
                f"{out['answer']['last_keepalive_to_answer_s']:.3f}s")

    kas = [(e["t"], e["body"][0] if e["body"] else None)
           for e in board.frames(t_open)
           if e["cid_int"] == cid_a and e["cmd"] == CTAPHID_KEEPALIVE]
    out["keepalive_count_a"] = len(kas)
    out["keepalive_statuses"] = sorted({f"0x{s:02x}" for _, s in kas if s is not None})
    gaps = [round(b[0] - a[0], 3) for a, b in zip(kas, kas[1:])]
    if gaps:
        gaps_sorted = sorted(gaps)
        out["keepalive_interval_s"] = {"min": gaps_sorted[0],
                                       "median": gaps_sorted[len(gaps_sorted) // 2],
                                       "max": gaps_sorted[-1]}
    say(f"  KEEPALIVEs on A: {len(kas)} statuses {out['keepalive_statuses']}"
        + (f" intervals(min/med/max) "
           f"{out['keepalive_interval_s']['min']}/{out['keepalive_interval_s']['median']}/"
           f"{out['keepalive_interval_s']['max']}s" if gaps else ""))

    others = [e for e in board.frames(t_open)
              if e["cid_int"] != cid_a and e["cmd"] == CTAPHID_CBOR]
    out["other_channel_cbors"] = [
        {"cid": e["cid"], "t_rel_s": round(e["t"] - t_open, 3),
         "description": describe_cbor(e["body"])} for e in others]
    out["answer_leaked_to_other_channel"] = bool(
        answer and any(e["body"] == answer["body"] for e in others))
    if case == "busy":
        resolve_steps(board, events, out)
        out["cross_channel_events"] = [
            {k: v for k, v in e.items() if k in
             ("step", "what", "result", "sent_on")} for e in events]
        tokens_b = any((e.get("answer") or {}).get("status") == "0x00"
                       for e in events if e.get("step") == "pin_b")
        out["tokens_minted_on_channel_b"] = tokens_b
        say(f"  other-channel CBOR frames: {len(others)}; answer leaked: "
            f"{out['answer_leaked_to_other_channel']}; token minted on B: {tokens_b}")

    try:
        board.send_only(CTAPHID_CANCEL, b"", cid=cid_a)
        t_drain = time.monotonic() + 2.0
        while time.monotonic() < t_drain:
            board.next_frame(0.1)
        out["cancel_sent"] = "written + drained 2.0s"
    except Exception as e:  # noqa: BLE001
        out["cancel_sent"] = f"{type(e).__name__}: {e}"
    board.close()
    out.pop("_t_cue", None)
    return out


# --------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--case", choices=["press", "busy"],
                    help="press = open the window and wait for a human press; "
                         "busy = the same with competing traffic in flight")
    ap.add_argument("--trial", type=int, default=0, help="trial label")
    ap.add_argument("--lead-in", type=float, default=10.0,
                    help="seconds of stand-by before the window opens")
    ap.add_argument("--capture", action="store_true",
                    help="passive read-only frame capture (see module docstring)")
    ap.add_argument("--board", choices=["ours", "reference"], default="ours",
                    help="which identity to record in --capture mode")
    ap.add_argument("--duration", type=float, default=240.0,
                    help="capture seconds before auto-stop")
    ap.add_argument("--out", default=None, help="capture JSONL path")
    ap.add_argument("--analyze", metavar="JSONL", help="summarize a capture file")
    ap.add_argument("--json", help="write the press/busy measurement dict here")
    args = ap.parse_args()

    if args.analyze:
        return analyze_file(args.analyze)

    if args.capture:
        if args.out is None:
            ap.error("--capture needs --out PATH.jsonl")
        return run_capture(args.board, args.out, args.duration)

    if not args.case:
        ap.error("choose --case press|busy, or --capture, or --analyze")

    inventory = enumerate_devices()
    banner("US-1503 TOUCH-GRANT -- REAL PRESS ON REAL HARDWARE (EddieOz board only)")
    for d in inventory:
        say(f"  {d['path']:<16} iManufacturer={d['manufacturer']!r} "
            f"iSerial={d['serial']!r}")
    if not any(d["manufacturer"] == DEVICE_A_MANUFACTURER for d in inventory):
        say("\n  FATAL: our board (EddieOz) not found. Stopping.")
        return 2
    dev = pick(inventory, DEVICE_A_MANUFACTURER, "OURS (the only board this run opens)")
    self_check(dev, DEVICE_A_MANUFACTURER)
    for d in inventory:
        if d["manufacturer"] == DEVICE_B_MANUFACTURER:
            say(f"  NOT TOUCHED: {d['path']} ({d['manufacturer']!r}, "
                f"serial {d['serial']!r})")
    say("  No flash, no factory reset, no BOOTSEL, no debugger. No PIN "
        "set/changed/read. No credential created.")

    out = run_case(dev, args.case, args.trial, args.lead_in)
    out["final"] = final_liveness(dev)
    say("")
    banner("SUMMARY")
    ans = out.get("answer")
    say(f"  case={out['case']} trial={out['trial']} "
        f"completed={bool(ans and ans['status'] == '0x00')} "
        f"answer={ans['description'] if ans else 'NONE'} "
        f"open->answer={ans['open_to_answer_s'] if ans else '-'}s "
        f"keepalives={out['keepalive_count_a']}")
    say(f"  board left answerable: "
        f"{'YES' if out['final'].get('ping_ok') else 'NO -- ' + str(out['final'].get('error'))}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(out, f, indent=2, default=str)
        say(f"  raw measurement written to {args.json}")
    ok = out["final"].get("ping_ok")
    want_completion = args.case == "press"
    got = bool(ans and ans["status"] == "0x00")
    if want_completion and not got:
        ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
