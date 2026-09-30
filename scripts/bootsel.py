#!/usr/bin/env python3
"""Drive the pico-keys-sdk *rescue* app to reboot the device or enter BOOTSEL.

The C firmware (pico-fido2 build) ships a rescue app on CCID:

    AID  A0 58 3F C1 9B 7E 4F 21
    80 1F 01 00 00   reboot into BOOTSEL (user presence: press board button)
    80 1F 00 00 00   plain reboot into the running firmware

See docs/bootsel.md. NOTE: the fapico2 RUST build does not implement the
rescue app yet, so this script only works on the C firmware; on the Rust
build use the physical button sequence instead (see docs/bootsel.md).

Requires: pcscd running and pyscard (`pip install pyscard`).
"""

import argparse
import getpass
import os
import shutil
import sys
import time

try:
    from smartcard.System import readers
    try:
        # Classic pyscard layout (e.g. 2.3.1): the generic CardConnection
        # base class is a no-op stub; the real PCSC transport is
        # PCSCCardConnection.
        from smartcard.pcsc.PCSCCardConnection import (
            PCSCCardConnection as CardConnection,
        )
    except ImportError:
        from smartcard.CardConnection import CardConnection
except ImportError:
    sys.exit("pyscard is required: pip install pyscard")

from smartcard.Exceptions import SmartcardException

try:
    from smartcard.Exceptions import CommError, NoSmartcardException
except ImportError:
    # Older pyscard (e.g. 2.3.1 with the classic smartcard.* layout) does not
    # define these in smartcard.Exceptions; PCSC-layer failures surface as
    # SmartcardException subclasses, so fall back to the base class.
    CommError = SmartcardException
    NoSmartcardException = SmartcardException

RESCUE_AID = bytes.fromhex("A0583FC19B7E4F21")
SW_OK = 0x9000
SW_CONDITIONS_NOT_SATISFIED = 0x6985
SW_FILE_NOT_FOUND = 0x6A82

MCU_NAMES = {0: "unknown", 1: "RP2350", 2: "ESP32-S3", 3: "emulation", 4: "ESP32-S2"}

USER_PRESENCE_TIMEOUT_S = 30  # button.c default when up_btn is unset


def die(msg):
    sys.exit("bootsel: " + msg)


def pick_reader(explicit=None):
    if explicit:
        return explicit
    found = readers()
    if not found:
        die("no smart-card readers found (is pcscd running? device in app mode?)")
    # Newer pyscard returns PCSCReader objects; some forks return [name, path]
    # tuples. Normalise to the pcscd reader-name string.
    names = [r[0] if isinstance(r, (list, tuple)) else str(r) for r in found]
    pico = [n for n in names if "pico" in n.lower()]
    if pico:
        return pico[0]
    if len(names) == 1:
        return names[0]
    die(
        "multiple readers, none named *pico*; pass --reader:\n  "
        + "\n  ".join(names)
    )


def transmit(conn, apdu):
    data, sw1, sw2 = conn.transmit(list(apdu))
    return bytes(data), (sw1 << 8) | sw2


def select_rescue(conn):
    """SELECT the rescue AID; returns the info blob or dies with guidance."""
    body, sw = transmit(conn, [0x00, 0xA4, 0x04, 0x00, 0x08] + list(RESCUE_AID))
    if sw == SW_FILE_NOT_FOUND:
        die(
            "rescue AID not found (SW 6A82): the running firmware does not "
            "implement the rescue app (e.g. fapico2 Rust build).\n"
            "Use the button sequence: hold BOOTSEL, press RESET, release "
            "RESET, keep holding BOOTSEL until the RP2350 volume appears.\n"
            "See docs/bootsel.md."
        )
    if sw != SW_OK:
        die("SELECT rescue AID failed: SW %04X" % sw)
    return body


def show_info(body):
    # Header is 4 bytes (MCU, product, fw major, fw minor); the trailing
    # serial field length varies by firmware build (12 B on the pico-fido2
    # C release), so accept anything longer than the header.
    if len(body) < 4:
        die("unexpected rescue SELECT response length %d" % len(body))
    print("MCU:            %s" % MCU_NAMES.get(body[0], "0x%02X" % body[0]))
    print("Product:        0x%02X" % body[1])
    print("Firmware:       %d.%d" % (body[2], body[3]))
    print("Serial:         %s" % body[4:].hex().upper())


def wait_for_volume(mount, timeout_s):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if os.path.isdir(mount) and os.path.ismount(mount):
            return True
        time.sleep(0.5)
    return False


def wait_for_reader(timeout_s):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if readers():
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def do_reboot(conn, bootsel, tries, flash, mount, wait_app):
    info = select_rescue(conn)
    show_info(info)
    ins = 0x01 if bootsel else 0x00
    for attempt in range(1, tries + 1):
        if bootsel:
            print(
                "\nAbout to reboot into BOOTSEL. Press/hold the BOARD BUTTON now"
                "\n(device-side user-presence window: ~%ds). Waiting for the "
                "APDU to complete..." % USER_PRESENCE_TIMEOUT_S
            )
        try:
            body, sw = transmit(conn, [0x80, 0x1F, ins, 0x00, 0x00])
        except (CommError, NoSmartcardException):
            # Reader vanished mid-response: the secure reboot already started.
            sw = SW_OK
        if sw == SW_OK:
            break
        if sw == SW_CONDITIONS_NOT_SATISFIED and bootsel:
            print("button press not seen (SW 6985); retry %d/%d" % (attempt, tries))
            continue
        die("reboot APDU failed: SW %04X" % sw)
    else:
        die("no user presence within %d attempts" % tries)

    if not bootsel:
        print("reboot command accepted; device is restarting into app mode.")
        if wait_app:
            print("waiting for the card to re-enumerate...")
            if not wait_for_reader(30):
                die("reader did not reappear within 30s")
            print("device is back in app mode.")
        return

    print("reboot command accepted; waiting for the BOOTSEL volume %s ..." % mount)
    if not wait_for_volume(mount, 30):
        die("BOOTSEL volume did not appear within 30s")
    print("BOOTSEL volume mounted at %s" % mount)

    if flash:
        if not os.path.isfile(flash):
            die("no such file: %s" % flash)
        dest = os.path.join(mount, os.path.basename(flash))
        print("flashing %s -> %s ..." % (flash, dest))
        shutil.copyfile(flash, dest)
        os.sync()
        if os.path.getsize(dest) != os.path.getsize(flash):
            die("flash copy size mismatch")
        print("waiting for the device to finish flashing and restart...")
        # The bootrom unmounts/reboots once the copy is committed; poll the
        # volume going away, then the card reader coming back in app mode.
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and os.path.ismount(mount):
            time.sleep(0.5)
        if wait_app:
            print("waiting for the card to re-enumerate in app mode...")
            if not wait_for_reader(60):
                die("reader did not reappear within 60s")
        print("done: firmware flashed, device in app mode.")
    else:
        print("device is in BOOTSEL mode; copy your .uf2 to %s manually." % mount)


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--info", action="store_true",
                      help="SELECT the rescue AID and print MCU/product/version/serial")
    mode.add_argument("--reboot", action="store_true",
                      help="reboot into the running firmware (no button needed)")
    mode.add_argument("--bootsel", action="store_true",
                      help="reboot into BOOTSEL (press the board button)")
    p.add_argument("--flash", metavar="UF2",
                   help="with --bootsel: copy UF2 to the BOOTSEL volume and wait")
    p.add_argument("--reader", help="pcscd reader name (default: auto-detect *pico*)")
    p.add_argument("--tries", type=int, default=3,
                   help="user-presence attempts for --bootsel (default 3)")
    p.add_argument("--mount",
                   default="/media/%s/RP2350" % getpass.getuser(),
                   help="BOOTSEL volume mount point (default %(default)s)")
    p.add_argument("--no-wait-app", dest="wait_app", action="store_false",
                   help="do not wait for the card to re-enumerate after restart")
    args = p.parse_args()

    if args.flash and not args.bootsel:
        p.error("--flash requires --bootsel")

    reader_name = pick_reader(args.reader)
    print("reader: %s" % reader_name)
    conn = CardConnection(reader_name)
    conn.connect()
    # user-presence APDU blocks up to ~30s on device; the timeout is a safety
    # net (older pyscard CardConnection has no set_timeout — the device-side
    # 30 s window bounds the call anyway).
    if hasattr(conn, "set_timeout"):
        conn.set_timeout(60000)
    try:
        if args.info:
            show_info(select_rescue(conn))
            return
        do_reboot(conn, bootsel=args.bootsel, tries=args.tries,
                  flash=args.flash, mount=args.mount, wait_app=args.wait_app)
    except NoSmartcardException:
        die("no card on reader %r (device powered? in app mode?)" % reader_name)
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


if __name__ == "__main__":
    main()
