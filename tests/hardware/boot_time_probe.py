#!/usr/bin/env python3
"""Measure wall-clock time from "the image is written" to "the device enumerates".

The observation this replaces was "22 s / 30 s / >90 s", which is a human
guessing at a blinking LED. Guessing produced two wrong root causes in a row
on this bug, so the number has to come from a clock.

It also separates two things a stopwatch-and-LED cannot separate:

  * a boot that is SLOW — the device eventually enumerates, and the phase
    table says where the time went;
  * a boot that is DEAD — it never enumerates. That is a different failure
    with a different fix, and on this device it has historically looked
    identical from the outside ("LED on, no USB, power cycle fixes it").

So this reports every attach/detach of the target VID:PID over the window,
not just the first arrival. A device that shows up, drops, and shows up
again is reported as such.

Modes
-----
  --after-eject     (default) wait for the BOOTSEL MSC volume to disappear,
                    which is the ROM finishing the write, then start timing.
                    This is the reflash arm.
  --after-enter     block for one Enter, then start timing. Use this for the
                    power-cycle arm, where the human has to press the button.

Stdlib only (no fido2, no pyscard) — it must run on a machine where the
device has not enumerated yet, which is exactly when it is needed.

Usage:
    python3 tests/hardware/boot_time_probe.py --label arm-c-different-image
    python3 tests/hardware/boot_time_probe.py --after-enter --label arm-a
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

TARGET_VID = "fa20"
TARGET_PID = "0002"
# Volume labels the RP2040/RP2350 ROM mounts its MSC under. Both
# chips differ again, so match on a set rather than one string.
BOOTSEL_MARKERS = ("RP2BOOT", "RPI-RP2", "RP2350", "BOOTSEL")
POLL_S = 0.01  # 10 ms — an enumeration that takes ~1 s is not a rounding error


def _listdir(d: Path) -> list[Path]:
    """`iterdir` that tolerates an unreadable entry.

    `/media` holds one directory per logged-in session, so an unrelated
    user's mount is both present and unreadable to us. A PermissionError
    here must not take down a probe that is in the middle of timing a boot.
    """
    try:
        return list(d.iterdir())
    except OSError:
        return []


def _usb_devices() -> dict[tuple[str, str], str]:
    """{(vid, pid): product} for every enumerated USB device."""
    out: dict[tuple[str, str], str] = {}
    base = Path("/sys/bus/usb/devices")
    if not base.is_dir():
        return out
    for d in base.iterdir():
        vid_file, pid_file = d / "idVendor", d / "idProduct"
        if not (vid_file.is_file() and pid_file.is_file()):
            continue
        try:
            vid = vid_file.read_text().strip().lower()
            pid = pid_file.read_text().strip().lower()
        except OSError:
            continue
        product = ""
        for pf in base.glob(f"{d.name}:*/product"):
            try:
                product = pf.read_text().strip()
            except OSError:
                pass
            break
        out[(vid, pid)] = product
    return out


def _is_bootsel(devices: dict[tuple[str, str], str]) -> bool:
    """True while the RP2350 ROM's MSC is mounted and the device is in BOOTSEL.

    Identified by the ROM's own VID, any PID, plus, as a fallback for hosts
    that filter it out of lsusb, the mounted RPI-RP2 volume. Matching on the
    VID alone rather than one PID is deliberate: the ROM uses 2e8a:0003 on
    RP2040 and 2e8a:000f on RP2350, and a check pinned to one of them
    silently reports "never in BOOTSEL" on the other — which on this board
    is the wrong one.
    """
    if any(vid == "2e8a" for vid, _pid in devices):
        return True
    # udisks2 nests the mount under the user's name (`/media/<user>/RP2350`),
    # so scan two levels under /media as well as one.
    media = Path("/media")
    if media.is_dir():
        for one in _listdir(media):
            if one.name in BOOTSEL_MARKERS:
                return True
            if one.is_dir():
                for two in _listdir(one):
                    if two.name in BOOTSEL_MARKERS:
                        return True
    return any(Path(f"/Volumes/{m}").exists() for m in BOOTSEL_MARKERS)


def _target_present(devices: dict[tuple[str, str], str]) -> bool:
    return (TARGET_VID, TARGET_PID) in devices


def wait_for_eject(timeout: float, log) -> float:
    """Block until BOOTSEL's MSC disappears. Returns seconds waited."""
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if not _is_bootsel(_usb_devices()):
            # One confirmation sample: a single missed read right at the
            # eject would otherwise start the clock ~10 ms early and, worse,
            # on a slow host could start it before the write finished.
            time.sleep(0.05)
            if not _is_bootsel(_usb_devices()):
                return time.monotonic() - t0
        time.sleep(POLL_S)
    raise SystemExit(
        f"no BOOTSEL volume to wait for after {timeout:.0f}s. Put the board in "
        "BOOTSEL and flash it, or pass --after-enter for a power-cycle arm."
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--label", default="run", help="arm name, e.g. arm-c-different-image")
    ap.add_argument("--after-eject", action="store_true",
                    help="start timing when the BOOTSEL MSC disappears (reflash arm)")
    ap.add_argument("--after-enter", action="store_true",
                    help="start timing on Enter (power-cycle arm)")
    ap.add_argument("--timeout", type=float, default=180.0,
                    help="give up after N seconds (default 180)")
    ap.add_argument("--out", type=Path, help="also write the result as JSON here")
    args = ap.parse_args()

    if args.after_enter == args.after_eject:
        # Default to the eject mode when neither flag is given.
        args.after_eject = not args.after_enter

    print(f"boot-time probe: arm={args.label} mode="
          f"{'eject' if args.after_eject else 'enter'} timeout={args.timeout:.0f}s")

    if args.after_enter:
        print("  power-cycle the board now, then press Enter here.")
        input()

    before = _target_present(_usb_devices())
    if args.after_eject:
        waited = wait_for_eject(args.timeout, print)
        print(f"  BOOTSEL MSC gone after {waited:.1f}s — starting clock")
        # If the device is *already* enumerated the instant the write
        # finished, the boot was fast enough that the 10 ms poll missed it.
        if _target_present(_usb_devices()):
            print("  already enumerated at t=0 — the boot completed inside one poll interval")
            return _emit({"label": args.label, "mode": "eject", "enumerated_ms": 0.0,
                          "events": [], "note": "already present at first sample"}, args.out)

    t0 = time.monotonic()
    events: list[dict] = []
    was_present = before
    enumerated_ms: float | None = None
    settle_until = float("inf")

    while True:
        elapsed = time.monotonic() - t0
        if elapsed > args.timeout:
            break
        now = _target_present(_usb_devices())
        if now != was_present:
            events.append({"t_ms": round(elapsed * 1000, 1),
                           "state": "attached" if now else "detached"})
            was_present = now
        if now and enumerated_ms is None:
            enumerated_ms = elapsed * 1000
            # Keep sampling a little past first arrival: a device that
            # attaches and immediately drops is the "dead boot" signature
            # and must not be reported as a fast successful one.
            settle_until = elapsed + 5.0
        if enumerated_ms is not None and elapsed >= settle_until:
            break
        time.sleep(POLL_S)

    # Compare against the attach event itself, not against a separately
    # rounded copy of it. `enumerated_ms` is the raw float and the event
    # carries `round(elapsed * 1000, 1)`, so `961.0999 > 961.1` is false but
    # the *rounded* 961.1 compares greater than the raw 961.0999 — which
    # counted the arrival as its own drop and printed "attached, then
    # dropped 1x" for a device that never dropped at all.
    attach_ms = next((e["t_ms"] for e in events if e["state"] == "attached"), None)
    dropped_after = [e for e in events
                     if attach_ms is not None and e["t_ms"] > attach_ms]
    result = {
        "label": args.label,
        "mode": "eject" if args.after_eject else "enter",
        "enumerated_ms": None if enumerated_ms is None else round(enumerated_ms, 1),
        "events": events,
        "dropped_after_enumeration": len(dropped_after),
    }
    if enumerated_ms is None:
        result["verdict"] = "DID NOT ENUMERATE — this is the dark-boot failure, not a slow boot"
    elif dropped_after:
        result["verdict"] = f"attached, then dropped {len(dropped_after)}x — unstable"
    else:
        result["verdict"] = "enumerated and stayed up"

    return _emit(result, args.out)


def _emit(result: dict, out: Path | None) -> int:
    print()
    print(json.dumps(result, indent=2))
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"written: {out}")
    return 0 if result.get("enumerated_ms") is not None and not result.get("dropped_after_enumeration") else 1


if __name__ == "__main__":
    raise SystemExit(main())
