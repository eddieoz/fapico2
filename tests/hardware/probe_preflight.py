#!/usr/bin/env python3
"""US-1301 preflight: refuse to start a baseline run with a probe attached.

Why this exists
---------------

US-1301 has one pass condition and it is a *negative* one: the freeze must be
reproduced on a board **that has never had a debugger attached**. Per
`docs/SECURITY-ASSESSMENT-ROUND2.md` §22 (R2-26), a connected SWD debugger is
sufficient on its own to make this firmware fail its OTP read and dark-boot on a
board whose OTP is perfectly healthy.

That makes the baseline run's validity depend on a fact that is easy to
contaminate and easy to assert wrongly. The epic's own acceptance asks the story
to record "whether any tool that touches SWD was run at any point in the
session" — a self-report, which is worth exactly as much as the honesty of
whoever writes it. This script turns the part of that claim a machine can
establish into a check, so the recorded number carries evidence rather than an
assurance.

What it can and cannot establish
--------------------------------

It CAN establish, at the moment it runs:

  * no SWD probe is enumerated on the USB bus (by VID:PID and by product name);
  * no probe debugger is running (`openocd`, `pyocd`, `probe-rs`, `picoprobe`,
    `gdbserver`, `JLinkGDBServer`);
  * the board is in BOOTSEL, or absent — i.e. the run has not started against a
    stale state.

It CANNOT establish that nobody ran a debugger earlier in the session, before
this script was invoked. That is why it is a **preflight**, not a proof: it
bounds the contamination to "from this moment forward", and the story still has
to record what happened before it. Run it FIRST, before touching the board.

Exit status
-----------

0 when the preconditions hold (no probe found).
1 when a probe is detected or a debugger is running — **stop**, because any
number produced in that state is void and must be repeated from a power cycle
with the probe physically removed.
2 when the board is not in a startable state.

Usage:
    python3 tests/hardware/probe_preflight.py
    python3 tests/hardware/probe_preflight.py --require-bootsel
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

# Debug-probe USB IDs. Each is a VID:PID a probe enumerates when it is plugged
# in; seeing any of them means a probe is attached right now.
#
#   0d28:  Arm Mbed CMSIS-DAP (the on-board debugger on a Pico; also sold
#          standalone). Present on a stock Pico 2 unless desoldered, which is
#          exactly why "no probe connected" is not the same claim as "no probe
#          ever existed".
#   1366:  SEGGER J-Link.
#   0483:  STMicroelectronics ST-LINK (VID 0483, several PIDs).
#   c250:  Keil ULINK.
#   1fc9:  NXP MCU-Link.
PROBE_IDS = [
    ("0d28", "Arm Mbed CMSIS-DAP"),
    ("1366", "SEGGER J-Link"),
    ("0483", "STMicroelectronics ST-LINK"),
    ("c250", "Keil ULINK"),
    ("1fc9", "NXP MCU-Link"),
]

# Product-string fragments. A backup for a probe that enumerates under an ID
# not listed above, because "I did not recognise the VID:PID" must not read as
# "no probe".
PROBE_NAME_HINTS = ["cmsis-dap", "j-link", "jlink", "st-link", "stlink",
                    "ulink", "mcu-link", "mculink", "picoprobe"]

# Processes that drive SWD. A running one means a probe is in use even if the
# adapter has been unplugged mid-session.
DEBUGGER_PROCS = ["openocd", "pyocd", "probe-rs", "picoprobe", "gdbserver",
                  "JLinkGDBServer", "st-info", "st-flash"]

BOOTSEL_MARKERS = ("RP2BOOT", "RPI-RP2", "RP2350", "BOOTSEL")

# The board's own VID:PID once it enumerates. Seeing this means a flash is
# already done, i.e. the arm is mid-reproduction rather than at the start.
TARGET_VID, TARGET_PID = "fa20", "0002"


def _listdir(d: Path) -> list[Path]:
    """`iterdir` that tolerates an unreadable entry (`/media/<user>/...`)."""
    try:
        return list(d.iterdir())
    except OSError:
        return []


def _lsusb() -> list[tuple[str, str, str]]:
    """`[(vid, pid, product)]` for every enumerated USB device."""
    out: list[tuple[str, str, str]] = []
    try:
        text = subprocess.run(["lsusb"], capture_output=True, text=True,
                              timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return out
    for line in text.splitlines():
        # `Bus 001 Device 002: ID 2109:2813 VIA Labs, Inc. VL813 Hub`
        # Split on "ID " so the bus/device numbers can never be mistaken for
        # the VID — reading fields positionally is how a probe check ends up
        # comparing "001" against a VID list and always finding nothing.
        _, _, rest = line.partition("ID ")
        if not rest:
            continue
        vid_pid, _, name = rest.partition(" ")
        vid, _, pid = vid_pid.partition(":")
        if not vid or not pid:
            continue
        out.append((vid.lower(), pid.lower(), name.strip()))
    return out


def _running_debuggers() -> list[str]:
    """Names of debugger processes currently running."""
    try:
        text = subprocess.run(["ps", "-eo", "comm="], capture_output=True,
                              text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    names = [line.strip().lower() for line in text.splitlines() if line.strip()]
    return sorted({n for n in names if any(n.startswith(d) or d in n
                                           for d in DEBUGGER_PROCS)})


def _in_bootsel() -> bool:
    for vid, _pid, _name in _lsusb():
        if vid == "2e8a":  # the RP2040/RP2350 bootrom's own VID
            return True
    media = Path("/media")
    if media.is_dir():
        for one in _listdir(media):
            if one.name in BOOTSEL_MARKERS:
                return True
            if one.is_dir():
                for two in _listdir(one):
                    if two.name in BOOTSEL_MARKERS:
                        return True
    return False


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--require-bootsel", action="store_true",
                    help="also require the board to be in BOOTSEL right now "
                         "(the start state for a flash arm)")
    args = ap.parse_args(argv[1:])

    print("US-1301 preflight — the freeze must be reproduced with NO probe attached.")
    print(f"  (docs/SECURITY-ASSESSMENT-ROUND2.md §22 / R2-26: a connected SWD")
    print(f"  debugger is on its own sufficient to make this firmware dark-boot.)")
    print()

    devices = _lsusb()
    # One entry per *device*, not per matching rule: a J-Link trips both the
    # VID rule and the name rule, and reporting it twice would read as two
    # probes needing removal when there is one.
    probes: dict[tuple[str, str], tuple[str, str]] = {}
    for vid, pid, name in devices:
        reasons = [why for probe_vid, why in PROBE_IDS if vid == probe_vid]
        if any(h in name.lower() for h in PROBE_NAME_HINTS):
            reasons.append("product name matches a known probe")
        if reasons:
            probes[(vid, pid)] = (name, "; ".join(reasons))
    debuggers = _running_debuggers()

    print(f"USB devices enumerated: {len(devices)}")
    for vid, pid, name in devices:
        print(f"    {vid}:{pid}  {name}")

    print()
    if probes:
        print(f"FAIL: {len(probes)} probe device(s) enumerated.")
        for (vid, pid), (name, why) in sorted(probes.items()):
            print(f"    {vid}:{pid}  {name}   [{why}]")
        print()
        print("A baseline run in this state is VOID: it would measure the")
        print("debugger's effect, not the failure's. Unplug the probe, then")
        print("power-cycle the board and run this again.")
        return 1

    if debuggers:
        print(f"FAIL: debugger process(es) running: {', '.join(debuggers)}.")
        print("A probe may be in use even if the adapter was unplugged")
        print("mid-session. Stop them, power-cycle, and re-run.")
        return 1

    print("OK: no SWD probe enumerated, no debugger process running.")

    bootsel = _in_bootsel()
    already = any((v, p) == (TARGET_VID, TARGET_PID) for v, p, _n in devices)
    print()
    print(f"Board in BOOTSEL now: {'yes' if bootsel else 'no'}")
    if already:
        print(f"Target {TARGET_VID}:{TARGET_PID} is ENUMERATING — the arm is "
              f"mid-reproduction, not at its start.")
        return 2
    if args.require_bootsel and not bootsel:
        print("--require-bootsel was passed and no BOOTSEL volume/ROM is present.")
        return 2

    print()
    print("The run may proceed. Record, in the story, that this preflight was")
    print("run FIRST — it bounds probe contamination to 'from this moment")
    print("onward'. What happened BEFORE it is still a self-report.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
