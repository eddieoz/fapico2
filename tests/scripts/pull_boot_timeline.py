#!/usr/bin/env python3
"""Drain the `boot-timeline` capture build's ring and print the boot timeline.

The question this exists to answer is "where does the first boot after a
reflash go?". A human counting seconds on a blinking LED cannot tell a
22-second flash erase from a 22-second SHA walk, and the previous passes at
this bug guessed wrong twice from exactly that. So: build the image
(`./build-timeline.sh`), flash it, let the device enumerate, and read the
`E_PHASE` records the boot path stamped.

Ring record layout (24 bytes, little-endian — see `dbg::log`):
    t_us u64, seq u32, task u8, event u8, pad u16, a u32, b u32

`E_PHASE` (event 60) carries `a` = the `dbg::P_*` phase id. The record's own
`t_us` is the measurement, so this script works in deltas between consecutive
phases and never needs a timestamp field. The first phase seen is used as
the origin, and the report prints both the absolute offset from it and the
gap since the previous phase — the gap is the number that answers the
question.

No probe is involved. The `boot-timeline` build pins the drain CID and
drains over CTAP-HID *after* enumeration, which matters: attaching an SWD
probe during a boot makes every OTP read return 0xFFFFFFFF and the boot
then dies on a key row it reads perfectly well unattached (AGENTS.md,
"HARDWARE VALIDATION"). Nothing here reads RTT, so the probe can stay
detached for the whole measurement.

Drain protocol and `decode()` come from `us933_pull_trace.py` — one ring, one
wire format, one decoder.

Usage:
    ./build-timeline.sh
    # flash firmware/fapico2.timeline.uf2 over BOOTSEL, wait for fa20:0002
    python3 tests/scripts/pull_boot_timeline.py --cid 7b07b007
    python3 tests/scripts/pull_boot_timeline.py --cid 7b07b007 --out boot1.txt
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO / "tests"))

import us933_pull_trace as trace  # noqa: E402  (path is set above)

E_PHASE = 60

# `dbg::ENTRIES` — the ring's record capacity. A `count` above this means the
# oldest records were overwritten, which matters here: the ring is 512 deep
# and a busy session wraps it in seconds, so a wrapped pull silently loses
# the early boot phases that are the interesting ones.
RING_CAPACITY = 512

# The `dbg::P_*` table (firmware/src/dbg.rs). Kept as a literal here rather
# than parsed out of the Rust: the decoder has to be readable on its own, and
# a parse that silently returns an empty table on a rename is worse than a
# stale name that shows up as "unknown phase N". `--check-phase-table`
# compares the two and fails loudly when they drift.
PHASES = {
    1: "main entered (pre-HAL-init)",
    2: "embassy_rp::init returned",
    3: "trng ready (clock proven + sanity draw)",
    4: "store key derived (OTP + chipid)",
    5: "secure store mounted",
    6: "boot entropy ensured",
    7: "DRBG instantiated",
    8: "fw manifest decided",
    9: "C->Rust migration done",
    10: "FIDO app booted",
    11: "OATH app booted",
    12: "persist gate #1 in",
    13: "persist gate #1 out",
    14: "trussed backend booted",
    15: "dispatcher built",
    16: "persist gate #2 in",
    17: "persist gate #2 out",
    18: "USB up",
    19: "serve tasks spawned",
}

# Events worth showing next to the timeline, because they explain a decision
# the phase markers bracket rather than measure. Rendered as one annotation
# line each, at their own timestamp.
ANNOTATIONS = {
    32: "E_FWLEN manifest region length (a)",
    33: "E_FWHASH running-image hash prefix (a)",
    34: "E_FWSTORED stored manifest (a=32|0, b=prefix)",
    35: "E_FWDECIDE **0=Load 1=WipeAndFresh** (a, b=prefix)",
    36: "E_FWSTAMP last-known-good stamp (a=1 ok)",
    37: "E_FWWIPE secure-slot wipe (a=1 ok, b=compiled in)",
    17: "E_PST persist gate start (b=dirty app count)",
    18: "E_PSD persist gate done (a=ok, b=elapsed us)",
}


def render(recs, ring_wrapped: bool) -> str:
    out: list[str] = ["boot timeline (decoded from the boot-timeline ring)", ""]
    if ring_wrapped:
        out.append(
            "  NOTE: the ring wrapped (512 records). Only the most recent 512"
            " records\n        are present; early phases may be gone and the"
            " 'since' column is\n        measured from the first record still"
            " in the ring, not from main entry.\n"
        )

    phases = [(t, a) for (t, _s, _task, ev, a, _b) in recs if ev == E_PHASE]
    if not phases:
        return "\n".join(out) + "\n  no E_PHASE records — is this a boot-timeline build?\n"

    origin = phases[0][0]
    out.append(f"  {'since':>10}  {'gap':>10}  phase")
    out.append(f"  {'-' * 10}  {'-' * 10}  {'-' * 46}")
    prev = origin
    for t, pid in phases:
        gap_ms = (t - prev) / 1000.0
        at_ms = (t - origin) / 1000.0
        out.append(f"  {at_ms:9.1f}m  {gap_ms:9.1f}m  {PHASES.get(pid, f'**unknown phase {pid}**')}")
        prev = t

    marks = [(t, ev, a, b) for (t, _s, _task, ev, a, b) in recs if ev in ANNOTATIONS and ev != E_PHASE]
    if marks:
        out.append("")
        out.append("  annotations (US-919 decision + persist timing)")
        out.append(f"  {'since':>10}  detail")
        out.append(f"  {'-' * 10}  {'-' * 46}")
        for t, ev, a, b in marks:
            at_ms = (t - origin) / 1000.0
            name = ANNOTATIONS[ev]
            detail = name if ev not in (35, 37, 18) else f"{name}  a={a} b={b}"
            out.append(f"  {at_ms:9.1f}m  {detail}")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cid", required=True,
                    help="CTAP-HID drain channel as 4 hex bytes (boot-timeline pins 7b07b007)")
    ap.add_argument("--out", type=Path, help="write the report here as well as to stdout")
    ap.add_argument("--vid", type=lambda s: int(s, 16), default=None)
    ap.add_argument("--pid", type=lambda s: int(s, 16), default=None)
    ap.add_argument("--path", default=None)
    ap.add_argument("--check-phase-table", action="store_true",
                    help="verify this file's PHASES table still matches dbg.rs, then exit")
    args = ap.parse_args()

    if args.check_phase_table:
        src = (REPO / "firmware" / "src" / "dbg.rs").read_text(encoding="utf-8")
        found = {}
        for line in src.splitlines():
            line = line.split("//", 1)[0].strip()
            if not line.startswith("pub const P_"):
                continue
            decl, _, init = line.partition("=")
            ident = decl.replace("pub const ", "").split(":")[0].strip()
            try:
                found[int(init.strip().rstrip(";"))] = ident
            except ValueError:
                continue
        # Compare the id sets, not the descriptions: the prose lives next to
        # the constant in dbg.rs and here, and a rewording is not a drift that
        # can break a decode. A renumber or a removed phase is.
        if sorted(found) != sorted(PHASES):
            print("FAIL: this script's PHASES table has drifted from dbg.rs")
            print(f"  script ids: {sorted(PHASES)}")
            print(f"  dbg.rs ids: {sorted(found)}")
            return 1
        print(f"PASS: {len(PHASES)} phase ids agree with firmware/src/dbg.rs")
        return 0

    channel = bytes.fromhex(args.cid.replace(" ", ""))
    if len(channel) != 4:
        ap.error("--cid must be 4 hex bytes, e.g. 7b07b007")

    conn = trace._open_device(args)
    count, entry_size, buf = trace.drain(conn, channel)
    recs = trace.decode(buf, entry_size)
    # `count` is records ever written; the ring holds min(count, ENTRIES), so
    # count > capacity means the oldest records are gone.
    report = render(recs, ring_wrapped=count > RING_CAPACITY)
    report = f"ring: {count} record(s), {entry_size} B each\n\n" + report
    print(report)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
        print(f"written: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
