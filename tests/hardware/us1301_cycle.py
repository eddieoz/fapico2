#!/usr/bin/env python3
"""US-1301: one freeze-reproduction cycle, driven end to end without a probe.

The procedure
-------------

US-1301 asks for three save-and-reboot cycles and three flash-and-reboot
cycles on a board that has never had a debugger attached, and a count of how
many froze. This script automates one cycle of either arm and reports whether
the device came back.

The flash arm, per cycle:

  1. assert the device is up as `fa20:0002`;
  2. `80 1F 01 00 00` — rescue REBOOT, mode BOOTSEL. Unauthenticated, so no
     PIN and no presence prompt, and no probe: it is the same APDU over CCID
     that PicoForge's `reboot_device(to_bootsel=true)` sends;
  3. wait for the RP2350 bootrom's MSC (`2e8a:*`, `RP2BOOT`/`RP2350`);
  4. copy the UF2 across, which the ROM's mass-storage path writes to flash;
  5. wait for the MSC to eject (the write finished);
  6. wait for `fa20:0002` to enumerate again.

A device that does not come back at step 6 is a freeze reproduction. That is
the whole measurement — the freeze's signature is pre-USB, so it cannot be
seen from the host at all, and "did it enumerate" is the only question the
host can answer honestly.

What this cannot do, and why it matters for the number
------------------------------------------------------

**It does not power-cycle the board.** Unplugging the cable needs a hand, so
the reboot between arms here is the rescue applet's BOOTSEL / normal reboot —
a watchdog-armed system reset, not the VBUS removal that §22 (R2-26) measured
as the only thing that clears the OTP `SW_LOCK` escalation.

So a "FROZEN" verdict from this script is *stronger* than US-1301's own
criterion: the device failed to return across a reset that is weaker than the
power cycle the story specifies. A "CAME BACK" verdict is **not** evidence the
freeze did not happen — it may have recovered on its own, exactly as §22 says
a system reset sometimes does. Only a person unplugging the cable can close
that gap. The script says which of the two a given cycle was, so the resulting
count is never silently read as stronger than it is.

Usage:
    python3 us1301_cycle.py --arm flash --uf2 ../../../fapico2/fapico2.uf2
    python3 us1301_cycle.py --arm save
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

TARGET_VID, TARGET_PID = "fa20", "0002"
BOOTSEL_MARKERS = ("RP2BOOT", "RPI-RP2", "RP2350", "BOOTSEL")
POLL_S = 0.05

BOOTSEL_TIMEOUT_S = 30.0
# Measured, not guessed. `AGENTS.md`:98-135 says the firmware boots in ~4 s
# *detached*, but the 2026-10-01 cycle-1 run saw no USB at all for 85 s — and
# because the recovery in that run turned out to be a human power cycle, the
# two cases were indistinguishable from the host until then. A timeout shorter
# than a slow-but-alive boot would therefore manufacture a freeze that is not
# there, which is the same class of error as reading the LED by eye: a verdict
# taken without the measurement to support it.
#
# 180 s is generous past any plausible boot. If the device has not enumerated
# by then it is not booting slowly, and the only remaining explanations are a
# park before USB or a dead device — both need a human to power cycle.
ENUM_TIMEOUT_S = 180.0
WRITE_SETTLE_S = 2.0


def _lsusb() -> list[tuple[str, str, str]]:
    try:
        text = subprocess.run(["lsusb"], capture_output=True, text=True,
                              timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    out = []
    for line in text.splitlines():
        _, _, rest = line.partition("ID ")
        if not rest:
            continue
        vid_pid, _, name = rest.partition(" ")
        vid, _, pid = vid_pid.partition(":")
        if vid and pid:
            out.append((vid.lower(), pid.lower(), name.strip()))
    return out


def _listdir(d: Path):
    try:
        return list(d.iterdir())
    except OSError:
        return []


def target_up() -> bool:
    return any((v, p) == (TARGET_VID, TARGET_PID) for v, p, _ in _lsusb())


def in_bootsel() -> tuple[bool, Path | None]:
    """`(in BOOTSEL, mount point)`, finding the volume up to two levels deep."""
    for one in _listdir(Path("/media")):
        if one.name in BOOTSEL_MARKERS and one.is_dir():
            return True, one
        if one.is_dir():
            for two in _listdir(one):
                if two.name in BOOTSEL_MARKERS and two.is_dir():
                    return True, two
    return False, None


def wait_for(predicate, timeout: float, what: str) -> bool:
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if predicate():
            return True
        time.sleep(POLL_S)
    print(f"  timeout: {what} did not happen within {timeout:.0f}s", flush=True)
    return False


def rescue_reboot(to_bootsel: bool) -> tuple[int, int]:
    """Send rescue REBOOT. Returns (sw1, sw2) — the APDU never returns on
    success, because the device leaves the bus while answering."""
    from smartcard.System import readers
    from smartcard.util import toBytes

    readers_list = list(readers())
    if not readers_list:
        raise SystemExit("no CCID reader — the device must be enumerating first")
    conn = readers_list[0].createConnection()
    conn.connect()
    try:
        conn.transmit([0x00, 0xA4, 0x04, 0x00, 0x08]
                      + list(toBytes("A0 58 3F C1 9B 7E 4F 21")))
        # P1 selects the mode: 0x00 normal, 0x01 BOOTSEL.
        _resp, sw1, sw2 = conn.transmit([0x80, 0x1F, 0x01 if to_bootsel else 0x00,
                                         0x00, 0x00])
        return sw1, sw2
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


def mgmt_write_config() -> tuple[int, int, str]:
    """Change one setting through the Management applet: read the config
    record, toggle a bit, write it back.

    US-1301 asks for "change one setting and save". This is the save the
    PicoForge client performs — a Management `WRITE_CONFIG` that persists
    through the secure partition and takes the persist gate. The exact bit
    toggled does not matter to the measurement; that it *saves durably* does.

    AID, CLA and INS are taken from `apps/mgmt/src/lib.rs` rather than guessed:
    AID `A0 00 00 05 27 47 11 17`, CLA `0x00`, `READ_CONFIG` INS `0x1D`,
    `WRITE_CONFIG` INS `0x1C`. (`0x1E` is `RESET`, not the write.)

    `WRITE_CONFIG` calls `user_present()` first (`apps/mgmt/src/lib.rs`:561),
    so the card asks for a touch. Per the 2026-09-30 hardware session the
    presence window **self-serves after ~8-9 s**, so this waits rather than
    pressing — no finger, and no debugger.
    """
    from smartcard.System import readers

    conn = list(readers())[0].createConnection()
    conn.connect()
    try:
        sel, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x04, 0x04, 0x08,
                                       0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17])
        if (sw1, sw2) != (0x90, 0x00):
            return sw1, sw2, f"management SELECT failed ({sw1:02x}{sw2:02x})"

        cfg, r1, r2 = conn.transmit([0x00, 0x1D, 0x00, 0x00, 0x00])
        if (r1, r2) != (0x90, 0x00):
            return r1, r2, f"READ_CONFIG failed ({r1:02x}{r2:02x})"

        body = bytearray(cfg)
        if not body:
            return 0x6F, 0x00, "empty config record, nothing to change"
        body[-1] ^= 0x01
        note = f"read {len(body)} B, toggled last byte"

        # The write blocks on presence; give the self-serving window room.
        t0 = time.monotonic()
        while True:
            w1, w2 = conn.transmit([0x00, 0x1C, 0x00, 0x00, len(body)] + list(body))
            if (w1, w2) == (0x90, 0x00):
                return w1, w2, f"{note}, saved"
            if w2 == 0x69 and time.monotonic() - t0 < 30.0:
                # Conditions of use not satisfied — the presence window has
                # not self-served yet. Wait and retry; do not press anything.
                time.sleep(1.0)
                continue
            return w1, w2, f"{note}, WRITE_CONFIG -> {w1:02x}{w2:02x}"
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--arm", choices=("flash", "save"), required=True)
    ap.add_argument("--uf2", type=Path, help="required for --arm flash")
    ap.add_argument("--index", type=int, default=1, help="cycle number, for the record")
    ap.add_argument("--out", type=Path, help="write the result as JSON here")
    args = ap.parse_args(argv[1:])

    if args.arm == "flash" and (args.uf2 is None or not args.uf2.is_file()):
        raise SystemExit("--arm flash needs --uf2 pointing at a built image")

    started = time.time()
    result = {
        "arm": args.arm,
        "index": args.index,
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "uf2_sha_prefix": (args.uf2.name if args.arm == "flash" else None),
        "detail": "",
    }

    if not target_up():
        print("FAIL: device is not enumerating as fa20:0002 to begin with.")
        result["verdict"] = "NOT-STARTABLE"
        return _emit(result, args.out)

    print(f"[{args.arm} #{args.index}] device up. Rebooting to BOOTSEL…", flush=True)
    try:
        sw = rescue_reboot(True)
        result["detail"] = f"reboot APDU -> {sw[0]:02x}{sw[1]:02x}"
    except Exception as exc:  # the device leaves the bus mid-APDU by design
        result["detail"] = f"reboot APDU: {type(exc).__name__} (expected: it reboots)"

    entered = wait_for(lambda: in_bootsel()[0], BOOTSEL_TIMEOUT_S, "BOOTSEL")
    mount = in_bootsel()[1] if entered else None
    if not entered or mount is None:
        result["verdict"] = "FAILED-TO-ENTER-BOOTSEL"
        result["detail"] += "; never entered BOOTSEL"
        return _emit(result, args.out)
    print(f"[{args.arm} #{args.index}] BOOTSEL up at {mount}", flush=True)

    if args.arm == "flash":
        dest = mount / args.uf2.name
        shutil.copyfile(args.uf2, dest)
        print(f"[{args.arm} #{args.index}] copied {args.uf2.name} -> {dest}",
              flush=True)
        # The ROM writes flash as the copy lands; eject is the "write finished"
        # signal, same as the US-1302 probe's --after-eject arm.
        time.sleep(WRITE_SETTLE_S)
        wait_for(lambda: not in_bootsel()[0], 120.0, "BOOTSEL eject")
        result["detail"] += f"; flashed {args.uf2.name}"
    else:
        print(f"[{args.arm} #{args.index}] changing one setting and saving…", flush=True)
        w1, w2, note = mgmt_write_config()
        result["detail"] += f"; save -> {w1:02x}{w2:02x} ({note})"
        print(f"[{args.arm} #{args.index}] {note}: {w1:02x}{w2:02x}", flush=True)
        if (w1, w2) != (0x90, 0x00):
            result["verdict"] = "SAVE-REJECTED"
            return _emit(result, args.out)
        # Reboot to exercise the save-then-boot path.
        try:
            rescue_reboot(False)
        except Exception:
            pass
        result["detail"] += "; rebooted"

    print(f"[{args.arm} #{args.index}] waiting for the device to enumerate…",
          flush=True)
    back = wait_for(target_up, ENUM_TIMEOUT_S, "enumeration")
    elapsed = time.time() - started
    if back:
        result["verdict"] = "CAME-BACK"
        print(f"[{args.arm} #{args.index}] OK — enumerated after {elapsed:.1f}s",
              flush=True)
    else:
        result["verdict"] = "FROZEN"
        result["needs_power_cycle"] = True
        print(f"[{args.arm} #{args.index}] *** DID NOT ENUMERATE in "
              f"{ENUM_TIMEOUT_S:.0f}s — freeze reproduction ***", flush=True)
        print("  Per R2-26 only VBUS removal clears this state. Unplug the "
              "cable, wait a few seconds, replug, and record that you did — a "
              "human power cycle is the only recovery, and the run cannot "
              "continue without it.", flush=True)

    result["elapsed_s"] = round(elapsed, 1)
    return _emit(result, args.out)


def _emit(result: dict, out: Path | None) -> int:
    print()
    print(json.dumps(result, indent=2))
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"written: {out}")
    # FROZEN is a *result*, not a tool failure: exit 0 so a multi-cycle run
    # keeps going and records every cycle.
    return 1 if result["verdict"] in ("NOT-STARTABLE", "FAILED-TO-ENTER-BOOTSEL",
                                      "SAVE-REJECTED") else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
