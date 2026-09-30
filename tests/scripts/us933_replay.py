#!/usr/bin/env python3
"""US-933 emulation counter-trace: replay the failing PW3-change flow.

Replays the exact user transcript against the emulation binary at HEAD:

    SELECT (AID D2 76 00 01 24 01)
    GET DATA 4F            (application identifier — response bytes kept)
    VERIFY   0x83 (PW3, factory default)
    CHANGE REFERENCE DATA  (INS 0x24, P1=0, P2=0x83, old || new)
    VERIFY   0x83 (PW3, new)   — post-change state probe
    STALE-STATE PROBE      — GET DATA 4F again + re-VERIFY factory PW3
                             (hypothesis (c): state owned by an older
                             binary / migration — visible as a 9000 from
                             the factory PW3 after the change)

and prints the per-APDU table (request → SW, response length) that feeds
the device-vs-emulation diff in docs/tasks/openpgp-pw3-change-rootcause.md.
With ``--write-evidence PATH`` the transcript is also written to that file
(default: docs/tasks/evidence/us933-emulation-trace.txt).

Runs its own private CCID relay + emulator instance (dedicated ports, temp
secure partition) — the same trio tests/harness/test_restart.py::CcidEmu
uses — so it is safe next to the shared harness. No third-party imports.

Exit status: 0 when the replay completed (regardless of any non-9000 SW —
a refusal IS a valid trace finding), 1 on harness failure.

Usage:
    python3 tests/scripts/us933_replay.py [--write-evidence PATH]
                                          [--keep] [--emulator BIN]
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests"))  # harness package import

from harness.test_restart import CcidEmu  # noqa: E402

OPENPGP_AID = bytes.fromhex("D27600012401")
PW3_FACTORY = b"12345678"
PW3_NEW = b"86429753"

DEFAULT_EVIDENCE = REPO / "docs" / "tasks" / "evidence" / "us933-emulation-trace.txt"


def _apdu(cla, ins, p1=0, p2=0, data=b""):
    return bytes([cla, ins, p1 & 0xFF, p2 & 0xFF, len(data)]) + data


def _pretty(req: bytes) -> str:
    return req.hex(" ")


def _sw(resp: bytes) -> int:
    return (resp[-2] << 8) | resp[-1]


def replay(emulator_bin: str | None = None):
    """Drive the transcript; return [(name, request, body, sw16, note)]."""
    emu = CcidEmu(
        paths={},
        hid_port=35988,  # dedicated (see the tests/harness port map)
    )
    emu.paths = {
        "keystore": _tmp("keystore"),
        "partition": _tmp("partition"),
        "piv": _tmp("piv"),
    }
    if emulator_bin:
        os.environ["FAPICO2_EMULATION_BIN"] = str(emulator_bin)
    rows = []

    def send(name, apdu, note=""):
        body, sw = emu.client.apdu(apdu[0], apdu[1], apdu[2], apdu[3], apdu[5:])
        rows.append((name, apdu, body, sw, note))
        return body, sw

    emu.start()
    try:
        send("SELECT", _apdu(0x00, 0xA4, 0x04, 0x00, OPENPGP_AID),
             "by-DF-name selection (INS A4, P1 04), AID D2 76 00 01 24 01")
        send("GET DATA 4F", _apdu(0x00, 0xCA, 0x4F, 0x00),
             "application identifier (response bytes retained)")
        send("VERIFY PW3 (factory)", _apdu(0x00, 0x20, 0x00, 0x83, PW3_FACTORY),
             "user password verify, old")
        send("CRD 0x24 0x83 old||new",
             _apdu(0x00, 0x24, 0x00, 0x83, PW3_FACTORY + PW3_NEW),
             "CHANGE REFERENCE DATA — the failing APDU")
        send("VERIFY PW3 (new)", _apdu(0x00, 0x20, 0x00, 0x83, PW3_NEW),
             "post-change state probe")
        send("GET DATA 4F (post)", _apdu(0x00, 0xCA, 0x4F, 0x00),
             "stale-state probe: is the AID still stable?")
        send("VERIFY PW3 (factory again)",
             _apdu(0x00, 0x20, 0x00, 0x83, PW3_FACTORY),
             "hypothesis (c) probe: 9000 here = stale factory state in force")
    finally:
        emu.stop()
    return rows


_TMP: dict[str, Path] = {}


def _tmp(kind: str) -> Path:
    if kind not in _TMP:
        _TMP[kind] = Path(tempfile.mkdtemp(prefix="us933-")) / kind
    return _TMP[kind]


def render(rows) -> str:
    lines = [
        "US-933 emulation counter-trace (per-APDU status words)",
        f"captured: {time.strftime('%Y-%m-%d %H:%M:%S %z')}",
        f"emulator: {os.environ.get('FAPICO2_EMULATION_BIN', REPO / 'target/x86_64-unknown-linux-gnu/debug/fapico2-emulation')} at HEAD",
        "",
        f"{'#':>2}  {'command':<26} {'APDU (hex)':<44} {'SW':<4} {'len':>4}  note",
        "-" * 120,
    ]
    for i, (name, req, body, sw, note) in enumerate(rows, 1):
        shown = _pretty(req) if len(req) <= 20 else _pretty(req[:18]) + " .."
        lines.append(f"{i:>2}  {name:<26} {shown:<44} {sw:04X} {len(body):>4}  {note}")
        if name.startswith("GET DATA 4F"):
            lines.append(f"    └ response body: {body.hex(' ')}")
    lines += [
        "",
        "Legend: SW 9000 = success; 63C-x = verification failed (x tries",
        "remaining); 6985 = conditions not satisfied; 6A86/6D00 = wrong P1/P2 /",
        "unsupported. The failing-transport question is whether the device's",
        "CRD row differs from this table (and how) — see the diff table in",
        "docs/tasks/openpgp-pw3-change-rootcause.md.",
    ]
    return "\n".join(lines)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write-evidence", default=str(DEFAULT_EVIDENCE))
    ap.add_argument("--emulator", default=None)
    ap.add_argument("--keep", action="store_true",
                    help="keep the private emulator scratch dirs")
    args = ap.parse_args(argv)

    rows = replay(args.emulator)
    text = render(rows)
    print(text)
    if args.write_evidence:
        path = Path(args.write_evidence)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
        print(f"\nevidence written: {path}")
    if not args.keep:
        import shutil

        for p in _TMP.values():
            shutil.rmtree(p.parent, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
