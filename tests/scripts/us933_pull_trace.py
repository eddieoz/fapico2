#!/usr/bin/env python3
"""US-933: pull and decode the APDU trace ring from an apdu-trace capture build.

The `apdu-trace` capture build (US-933) records full CCID APDU exchanges
into the US-922 dbg-ladder RAM ring (`firmware/src/dbg.rs`) and drains it
over the CTAP-HID vendor command 0x42. Capture builds pin the drain CID to
the fixed `a5 5a a5 5a` (no probe is attached to read an RTT-printed
channel); dbg-log builds keep the per-boot random channel printed to the
RTT console only. This script drives that drain
and decodes the ring into the per-APDU table that fills §3 of
docs/tasks/openpgp-pw3-change-rootcause.md.

Ring record layout (24 bytes, little-endian fields — see `dbg::log`):
    t_us u64, seq u32, task u8, event u8, pad u16, a u32, b u32

APDU trace event codes (dbg.rs, US-933):
    40 E_APDU_SESS   a = per-boot session tag (the u32 BE bytes)
    41 E_APDU_REQ    a = request length, b = per-session APDU seq
    42 E_APDU_RSP    a = response length (incl. SW), b = status word
    43 E_APDU_CHUNK  a = bytes 0–4 BE, b = bytes 4–8 BE (8 bytes/record,
                     zero-padded tail)

Drain protocol (payload → response, dbg::handle_dbg):
    [0x01]           → [count_le32, entries u8, entry_size u8]
    [0x02, off_le32] → raw ring bytes from `off`, ≤ 57 bytes
    [0x03]           → clear (optional; NOT sent by default)

Requires python-fido2 (the test venv) for the raw HID transport. The
device reports product name "fapico2" (S-391-14 identity fa20:0002); pass
--vid/--pid/--path to pin it if several HID devices match.

⚠️ One-shot pull: the ring holds 512 records and a busy session wraps it
in seconds — pull IMMEDIATELY after the failing `passwd 3` exchange, and
do not touch the card between the failure and the pull.

Usage:
    .test-venv/bin/python tests/scripts/us933_pull_trace.py \
        --cid a1b2c3d4 --out docs/tasks/evidence/us933-device-trace.txt
"""

from __future__ import annotations

import argparse
import struct
import time
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests"))  # harness package import

DBG_CMD = 0x42
HID_FIRST_PAYLOAD = 57  # 64 - 7 header bytes
ENTRY = 24

E_APDU_SESS, E_APDU_REQ, E_APDU_RSP, E_APDU_CHUNK = 40, 41, 42, 43

SW_NAMES = {
    0x9000: "OK",
    0x6A82: "FILE NOT FOUND",
    0x6A88: "REFERENCED DATA NOT FOUND",
    0x6985: "CONDITIONS NOT SATISFIED",
    0x6D00: "INS NOT SUPPORTED",
}


def _frame(channel: bytes, cmd: int, payload: bytes) -> bytes:
    """One CTAP-HID init packet (64-byte report, no report-id byte)."""
    b = bytearray(64)
    b[0:4] = channel
    b[4] = cmd | 0x80
    b[5:7] = len(payload).to_bytes(2, "big")
    b[7:7 + len(payload)] = payload
    return bytes(b)


def _open_device(args):
    from fido2.hid import list_descriptors, open_connection

    descs = list_descriptors()
    cands = [
        d for d in descs
        if (args.vid is None or d.vid == args.vid)
        and (args.pid is None or d.pid == args.pid)
        and (args.path is None or str(d.path) == args.path)
        and (args.path is not None or args.vid is not None
             or args.pid is not None
             or "fapico2" in (getattr(d, "product_name", "") or "").lower())
    ]
    if not cands:
        raise SystemExit(
            "no HID device matched — pass --vid/--pid/--path (candidates: "
            + "; ".join(f"{d.vid:04x}:{d.pid:04x} {getattr(d, 'product_name', '')}" for d in descs)
            + ")"
        )
    if len(cands) > 1:
        raise SystemExit(
            "several HID devices matched — pass --path (candidates: "
            + "; ".join(str(d.path) for d in cands) + ")"
        )
    return open_connection(cands[0])


def drain(conn, channel: bytes, off: int = 0) -> tuple[int, int, bytes]:
    """Read the ring header (count, entry size) + the raw bytes from `off`."""
    def xchg(payload: bytes) -> bytes:
        conn.write_packet(_frame(channel, DBG_CMD, payload))
        pkt = bytes(conn.read_packet())
        # Reply: channel(4) cmd(1) len_be16(2) payload — cut at the frame's
        # own length so short final chunks don't drag in padding.
        n = int.from_bytes(pkt[5:7], "big")
        return pkt[7:7 + n]

    hdr = xchg(b"\x01")
    if len(hdr) < 6:
        raise SystemExit(f"drain refused (payload {hdr.hex()}) — wrong cid?")
    count = struct.unpack_from("<I", hdr, 0)[0]
    # The device packs ENTRIES (512) into a single u8, which truncates to 0 —
    # the header's entries byte is unusable on this build. Recover the real
    # record count from the u32 `count` (records ever written; the ring holds
    # min(count, ENTRIES) of them). hdr[4] kept as a fallback for builds
    # where it is genuine.
    entry_size = hdr[5]
    entries = min(count, 512) if hdr[4] == 0 else min(hdr[4], count)
    buf = bytearray()
    empty = 0
    while len(buf) < entries * entry_size:
        chunk = xchg(b"\x02" + struct.pack("<I", off + len(buf)))
        if not chunk:
            # The device serves the read asynchronously behind the CTAP-HID
            # assembler; an empty reply can race the request. Retry before
            # giving up (three consecutive empties = real end).
            empty += 1
            if empty >= 3:
                break
            time.sleep(0.05)
            continue
        empty = 0
        buf += chunk
    return count, entry_size, bytes(buf)


def decode(buf: bytes, entry_size: int) -> list[tuple]:
    """[(t_us, seq, task, event, a, b)] in ring order (by monotonic seq)."""
    recs = []
    for i in range(len(buf) // entry_size):
        r = buf[i * entry_size:(i + 1) * entry_size]
        if len(r) < ENTRY:
            break
        t_us, seq = struct.unpack_from("<Q", r, 0)[0], struct.unpack_from("<I", r, 8)[0]
        task, event = r[12], r[13]
        a, b = struct.unpack_from("<I", r, 16)[0], struct.unpack_from("<I", r, 20)[0]
        recs.append((t_us, seq, task, event, a, b))
    recs.sort(key=lambda r: r[1])
    return recs


def render(recs) -> str:
    lines = ["US-933 device APDU trace (decoded ring)", ""]
    tag = None
    # Reassembly: header record (REQ/RSP) + ceil(len/8) chunk records.
    pending: dict | None = None
    got: list[bytes] = []
    rows: list[tuple] = []
    sess_tag = None
    for (_, _, _, event, a, b) in recs:
        if event == E_APDU_SESS:
            sess_tag = a
        elif event in (E_APDU_REQ, E_APDU_RSP):
            pending = {"dir": "→" if event == E_APDU_REQ else "←",
                       "len": a, "meta": b}
            got = []
        elif event == E_APDU_CHUNK and pending is not None:
            got.append(a.to_bytes(4, "big") + b.to_bytes(4, "big"))
            total = pending["len"]
            if sum(len(g) for g in got) >= ((total + 7) // 8) * 8:
                data = b"".join(got)[:total] if total else b""
                rows.append((pending["dir"], data,
                             pending["meta"] if pending["dir"] == "←" else None))
                pending, got = None, []
    if sess_tag is not None:
        lines.append(f"session tag: {sess_tag:08x}")
    lines.append(f"{'dir':<4} {'len':>4} {'SW':<6} bytes (hex)")
    lines.append("-" * 100)
    for d, data, sw in rows:
        swtxt = f"{sw:04X} {SW_NAMES.get(sw, '')}" if sw is not None else "  --"
        lines.append(f"{d:<4} {len(data):>4} {swtxt:<16} {data.hex(' ')}")
    return "\n".join(lines)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cid", required=True,
                    help="per-boot drain channel, 4 hex bytes (from the RTT line)")
    ap.add_argument("--out", default=None,
                    help="write the decoded table here")
    ap.add_argument("--vid", type=lambda s: int(s, 16), default=None)
    ap.add_argument("--pid", type=lambda s: int(s, 16), default=None)
    ap.add_argument("--path", default=None)
    ap.add_argument("--clear", action="store_true",
                    help="clear the ring after the pull")
    args = ap.parse_args(argv)

    channel = bytes.fromhex(args.cid.replace(" ", ""))
    if len(channel) != 4:
        ap.error("--cid must be 4 hex bytes, e.g. a1b2c3d4")

    conn = _open_device(args)
    count, entry_size, buf = drain(conn, channel)
    if args.clear:
        conn.write_packet(_frame(channel, DBG_CMD, b"\x03"))
    recs = decode(buf, entry_size)
    text = render(recs)
    print(f"ring: {count} record(s), {entry_size} B each\n")
    print(text)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(f"\nwritten: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
