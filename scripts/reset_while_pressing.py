#!/usr/bin/env python3
"""Hold the management factory reset open until the button is pressed.

The management applet's RESET (INS 0x1E) is gated on user presence
(`apps/mgmt/src/lib.rs::cmd_reset`), and the board button is the only presence
source on device (`button::button_poll_task`). The grant binds to the command's
tag — US-921's anti-harvest rule — so a press that arrives while no request is
pending arms nothing.

That means the APDU has to be **in flight** when the button goes down. This
loops INS 0x1E until it answers 0x9000 or the window closes, so a single press
lands. It stops at the first success, so it cannot reset twice.

Run it, then press the board button while it is running.
"""

import sys
import time

MGMT_AID = bytes.fromhex("A000000527471117")
INS_RESET = 0x1E

SW_OK = 0x9000
SW_CONDITIONS_NOT_SATISFIED = 0x6985


def main():
    seconds = int(sys.argv[1]) if len(sys.argv) > 1 else 45
    try:
        from smartcard import System
    except ImportError:
        print("pysmartcard is not installed in this interpreter", file=sys.stderr)
        return 1

    readers = System.readers()
    if not readers:
        print("no CCID reader — is the board plugged in?", file=sys.stderr)
        return 1

    card = readers[0].createConnection()
    card.connect()

    _, sw1, sw2 = card.transmit(
        [0x00, 0xA4, 0x04, 0x00, len(MGMT_AID)] + list(MGMT_AID) + [0x00, 0x00]
    )
    if (sw1 << 8) | sw2 != SW_OK:
        print(f"management SELECT failed {(sw1 << 8) | sw2:04X}")
        return 1

    print(f"Holding INS 0x1E open for {seconds}s — PRESS THE BOARD BUTTON NOW.")
    deadline = time.time() + seconds
    attempts = 0
    while time.time() < deadline:
        attempts += 1
        _, r1, r2 = card.transmit([0x00, INS_RESET, 0x00, 0x00, 0x00])
        sw = (r1 << 8) | r2
        if sw == SW_OK:
            print(f"\nFactory reset accepted on attempt {attempts}.")
            print("Every applet's state is now cleared. Re-run:")
            print("  python3 scripts/probe_oath_default_code.py")
            return 0
        if sw != SW_CONDITIONS_NOT_SATISFIED:
            print(f"\nunexpected status {sw:04X} on attempt {attempts}")
            return 1
        time.sleep(0.05)
        if attempts % 40 == 0:
            sys.stdout.write(".")
            sys.stdout.flush()

    print(
        f"\nNo press registered in {seconds}s ({attempts} attempts). "
        "The applet is still refusing with 6985 — no user-presence grant."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
