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


def rescue_write_phy_config() -> tuple[int, int, str]:
    """Change one device setting through the rescue applet's `WRITE`.

    **Not** the Management applet's `WRITE_CONFIG`. That is unconditionally
    refused on a device build: `apps/mgmt/src/lib.rs`:212 makes
    `default_user_present()` return `false` under `#[cfg(feature = "device")]`,
    and the Management applet — unlike FIDO, OATH, OTP and OpenPGP — is given
    no presence hook at all, so it answers `6985` instantly on every attempt.
    The rescue applet's `WRITE` needs no presence grant and is what PicoForge's
    configuration screen actually uses.

    The target TLV is chosen **by tag**, never by position, and the lock and
    serial tags are excluded by name: the config's last entry is
    `0a 01 00` = TAG_CONFIG_LOCK, value 0x00 (unlocked), and flipping that byte
    would lock out every later write until a factory reset.
    """
    from smartcard.System import readers

    conn = list(readers())[0].createConnection()
    conn.connect()
    try:
        sel, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x04, 0x00, 0x08,
                                       0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21])
        if (sw1, sw2) != (0x90, 0x00):
            return sw1, sw2, f"rescue SELECT failed ({sw1:02x}{sw2:02x})"

        # READ P1 = 0x01 (full PHY configuration).
        blob, r1, r2 = conn.transmit([0x80, 0x1E, 0x01, 0x00, 0x00])
        if (r1, r2) != (0x90, 0x00):
            return r1, r2, f"READ PhyConfig failed ({r1:02x}{r2:02x})"
        body = bytearray(blob)

        TAG_OPTIONS, TAG_LOCK, TAG_SERIAL = 0x06, 0x0A, 0x02
        i, chosen = 0, None
        while i + 2 <= len(body):
            tag, ln = body[i], body[i + 1]
            if tag == TAG_OPTIONS and ln >= 1:
                chosen = i + 2 + ln - 1
                break
            if tag in (TAG_LOCK, TAG_SERIAL) or ln == 0 or i + 2 + ln > len(body):
                i += 2 + ln if ln else 1
                continue
            i += 2 + ln
        if chosen is None:
            return 0x6F, 0x00, "no Options TLV to change"
        before = body[chosen]
        body[chosen] ^= 0x01

        # WRITE P1 = 0x01 (PhyConfig).
        _r, w1, w2 = conn.transmit([0x80, 0x1C, 0x01, 0x00, len(body)] + list(body))
        return w1, w2, f"Options 0x{before:02x} -> 0x{body[chosen]:02x}"
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

    if args.arm == "save":
        # The save arm writes over CCID, so it must NOT enter BOOTSEL first:
        # rebooting to the ROM removes the reader the save itself needs. (An
        # earlier revision did exactly that and stranded the board in BOOTSEL
        # with nothing to talk to.)
        print(f"[{args.arm} #{args.index}] device up. Changing one setting…",
              flush=True)
        w1, w2, note = rescue_write_phy_config()
        result["detail"] = f"save -> {w1:02x}{w2:02x} ({note})"
        print(f"[{args.arm} #{args.index}] {note}: {w1:02x}{w2:02x}", flush=True)
        if (w1, w2) != (0x90, 0x00):
            result["verdict"] = "SAVE-REJECTED"
            return _emit(result, args.out)
        # Now reboot, which is the step whose aftermath is being measured.
        # Do NOT swallow a failure here. The write leaves the reader in a
        # degraded state often enough that the reboot APDU fails to send, and
        # a silent `except: pass` turns that into a "cycle" that saved a
        # setting and then sat there, rebooting nothing — which is exactly
        # what happened to save cycle 2. A cycle that did not reboot did not
        # run.
        try:
            rescue_reboot(False)
            result["detail"] += "; reboot sent (normal)"
        except Exception as exc:
            result["verdict"] = "REBOOT-NOT-SENT"
            result["detail"] += f"; REBOOT FAILED: {type(exc).__name__}"
            print(f"[{args.arm} #{args.index}] the save landed but the reboot "
                  f"APDU did not send ({type(exc).__name__}). This is NOT a "
                  f"cycle — the board never rebooted.", flush=True)
            return _emit(result, args.out)
    else:
        print(f"[{args.arm} #{args.index}] device up. Rebooting to BOOTSEL…",
              flush=True)
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
        _flash_and_wait(args, result, mount)

    print(f"[{args.arm} #{args.index}] waiting for the device to enumerate…",
          flush=True)
    # It must be seen to LEAVE first. An earlier revision started polling for
    # `fa20:0002` immediately, which succeeded against the *pre-reboot* instance
    # and reported "came back in 2s" for a board that had not rebooted at all.
    # Only a device that was observed gone and came back has rebooted.
    wait_for(lambda: not target_up(), 30.0, "device to leave the bus")
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
              "cable, WAIT 5 SECONDS, replug, and record that you did.", flush=True)

    result["elapsed_s"] = round(elapsed, 1)
    return _emit(result, args.out)


def _flash_and_wait(args, result: dict, mount: Path) -> None:
    """Copy the image to the ROM's MSC and wait for the write to land."""
    dest = mount / args.uf2.name
    # The ROM's MSC can still be settling when it first appears: cycle 2 hit
    # EACCES on a volume that was writable a second later. Wait for it rather
    # than treating a not-yet-ready mount as a failed cycle.
    for _ in range(20):
        try:
            dest.touch(exist_ok=True)
            break
        except OSError:
            time.sleep(0.5)
    shutil.copyfile(args.uf2, dest)
    print(f"[flash #{args.index}] copied {args.uf2.name} -> {dest}", flush=True)
    # The ROM writes flash as the copy lands; eject is the "write finished"
    # signal, same as the US-1302 probe's --after-eject arm.
    time.sleep(WRITE_SETTLE_S)
    wait_for(lambda: not in_bootsel()[0], 120.0, "BOOTSEL eject")
    result["detail"] += f"; flashed {args.uf2.name}"


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
