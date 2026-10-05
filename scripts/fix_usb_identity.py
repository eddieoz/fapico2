#!/usr/bin/env python3
"""Read and repair the device's stored USB identity over CTAPHID.

Why this exists
---------------
The VID/PID that Rescue `WRITE PhyConfig` stores is applied at USB
enumeration (``platform/src/usb.rs:425-437``), and the CCID driver only binds
a device whose ``(VID, PID)`` pair is in its table
(``/usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist``). Choose a pair
the host does not know and the board stays enumerable over USB but produces
**no PC/SC reader at all** -- so the Rescue applet, the one surface with no
PIN, stops being reachable. That is a self-lockout, and it is invisible from
the GUI: PicoForge reports "Online - FIDO" (yellow) rather than an error,
because its FIDO leg still works.

This script repairs it over the FIDO carrier, which needs no PC/SC:

    read   -- 0x41 CONFIG_READ (0x0D), ungated: no PIN, no token
    write  -- 0x41 CONFIG_WRITE (0x0C), needs an ``acfg`` pinUvAuthToken

Usage
-----
    scripts/fix_usb_identity.py                     # read only, then prompt
    scripts/fix_usb_identity.py --set FA20:0002
    scripts/fix_usb_identity.py --list-known       # pairs this host can bind

The change is stored immediately but applied at the **next enumeration**:
unplug and replug the board (or press RUN) afterwards. Nothing on this
channel reboots the MCU for you.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import os
import plistlib
import struct
import sys

CTAPHID_CBOR = 0x10
CTAP2_VENDOR_41 = 0x41
SUB_CONFIG_WRITE = 0x0C
SUB_CONFIG_READ = 0x0D
TARGET_PHY = 0x01

TAG_VIDPID = 0x00
PERM_ACFG = 0x20

LIBCCID_PLIST = "/usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist"

# Statuses CONFIG_WRITE can answer, so a failure is readable rather than a hex
# dump. Names are the CTAP2 spec's.
STATUS = {
    0x00: "OK",
    0x02: "INVALID_PARAMETER",
    0x0C: "INVALID_COMMAND (wrong opcode)",
    0x12: "INVALID_CBOR",
    0x2B: "UNSUPPORTED_OPTION (record has no destination here)",
    0x2C: "INVALID_LENGTH / zero USB-interface mask",
    0x28: "KEYSTORE_FULL -- the write did NOT persist",
    0x2E: "??",
    0x33: "PIN_AUTH_INVALID (bad MAC -- this charges a strike)",
    0x34: "PIN_AUTH_BLOCKED (latched; needs a power cycle)",
    0x36: "PIN_AUTH_REQUIRED",
    0x3E: "INVALID_SUBCOMMAND",
    0x40: "PIN_AUTH_INVALID / permission -- the token lacks PERM_ACFG",
    0x7A: "?? keepalive",
}


def die(msg: str) -> "NoReturn":  # type: ignore[valid-type]
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def find_device():
    """Open the first fapico2 CTAPHID device."""
    try:
        from fido2.hid import CtapHidDevice
    except ImportError:
        die(
            "python-fido2 is not importable by this interpreter. Use the repo's\n"
            "         test venv, e.g.\n"
            "           ../pico-fido2/.test-venv/bin/python "
            "scripts/fix_usb_identity.py ...\n"
            "         or set PICO_FIDO2_VENV (see AGENTS.md, 'The pytest interpreter')."
        )

    for dev in CtapHidDevice.list_devices():
        name = dev.product_name or ""
        if "fapico2" in name.lower():
            return dev, name
    # Fall back to the only device that answers GetInfo as ours.
    for dev in CtapHidDevice.list_devices():
        try:
            r = dev.call(CTAPHID_CBOR, b"\x04\xc0")
            if r[:1] == b"\x00":
                return dev, dev.product_name or "?"
        except Exception:
            continue
    die("no fapico2 CTAPHID device found (is the board plugged in?)")


def vendor(dev, body: dict) -> bytes:
    """Send a 0x41 request; return the response body. Raises on non-zero status."""
    from fido2 import cbor

    payload = bytes([CTAP2_VENDOR_41]) + cbor.encode(body)
    reply = dev.call(CTAPHID_CBOR, payload)
    status = reply[0]
    if status != 0x00:
        name = STATUS.get(status, "unknown")
        die(f"device answered 0x{status:02X} ({name})")
    return cbor.decode(reply[1:]) if len(reply) > 1 else {}


TAGS = {
    0x00: "VidPid", 0x04: "LedGpio", 0x05: "LedBrightness", 0x06: "Options",
    0x08: "PresenceTimeout", 0x09: "UsbProduct", 0x0A: "Curves",
    0x0B: "EnabledUsbItf", 0x0C: "LedDriver", 0x0D: "LedOrder",
    0x0E: "LedNum", 0x0F: "UsbManufacturer",
}


def parse_tlv(blob: bytes) -> list:
    out, i = [], 0
    while i + 2 <= len(blob):
        tag, ln = blob[i], blob[i + 1]
        out.append((tag, blob[i + 2:i + 2 + ln]))
        i += 2 + ln
    return out


def read_config(dev) -> list:
    """CONFIG_READ, ungated. Note the params are an inline CBOR *map*."""
    body = vendor(dev, {1: SUB_CONFIG_READ, 2: {1: TARGET_PHY}})
    blob = body.get(1)
    if not isinstance(blob, bytes):
        die("CONFIG_READ returned no key 1 blob")
    return parse_tlv(blob)


def show(dev) -> None:
    print("stored PHY record (0x41 CONFIG_READ, ungated):")
    for tag, val in read_config(dev):
        shown = val.hex() if tag not in (0x09, 0x0F) else \
            val.rstrip(b"\x00").decode("utf-8", "replace")
        extra = ""
        if tag == TAG_VIDPID and len(val) == 4:
            vid, pid = struct.unpack(">HH", val)
            extra = f"   <- USB {vid:04X}:{pid:04X}"
        print(f"  0x{tag:02X} {TAGS.get(tag, '?'):16s} = {shown}{extra}")


def known_pairs():
    """(vid, pid) pairs this host's libccid can actually bind."""
    if not os.path.exists(LIBCCID_PLIST):
        return []
    with open(LIBCCID_PLIST, "rb") as f:
        p = plistlib.load(f)
    vids = [int(x, 16) for x in p.get("ifdVendorID", [])]
    pids = [int(x, 16) for x in p.get("ifdProductID", [])]
    return list(zip(vids, pids))


def list_known() -> None:
    pairs = known_pairs()
    if not pairs:
        die(f"cannot read {LIBCCID_PLIST}")
    print(f"{len(pairs)} pair(s) this host's CCID driver will bind:\n")
    for vid, pid in sorted(pairs):
        mark = "  <- fapico2 default" if (vid, pid) == (0xFA20, 0x0002) else ""
        print(f"  {vid:04X}:{pid:04X}{mark}")
    print(
        "\nAny pair not listed above leaves the board invisible to PC/SC, and\n"
        "therefore unreachable over the Rescue applet."
    )


def get_token(dev, pin: str) -> bytes:
    """A pinUvAuthToken carrying PERM_ACFG.

    Sub-command 0x09 (getPinUvAuthTokenUsingPinWithPermissions) is the *only*
    route: 0x08 is not implemented and 0x06 is refused, and a legacy
    getPinToken (0x05) token arrives with zero permissions and is rejected by
    the identity gate.
    """
    from fido2.ctap2 import ClientPin
    from fido2.ctap2.base import Ctap2

    ctap = Ctap2(dev)
    opts = ctap.info.options
    if not opts.get("clientPin"):
        die("the device reports no clientPin -- there is no PIN to authorise with")
    if opts.get("pinUvAuthToken") is not True:
        die(
            "the device does not advertise pinUvAuthToken; the library would "
            "silently fall back to a legacy token that CONFIG_WRITE refuses"
        )
    cp = ClientPin(ctap)
    return cp.get_pin_token(pin, permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG)


def write_vidpid(dev, vid: int, pid: int, token: bytes) -> None:
    blob = bytes([TAG_VIDPID, 0x04]) + struct.pack(">HH", vid, pid)
    params = {1: TARGET_PHY, 2: blob}
    from fido2 import cbor

    params_bytes = cbor.encode(params)
    mac = hmac.new(
        token,
        b"\xff" * 32 + bytes([CTAP2_VENDOR_41, SUB_CONFIG_WRITE]) + params_bytes,
        hashlib.sha256,
    ).digest()[:16]
    vendor(dev, {
        1: SUB_CONFIG_WRITE,
        2: params,
        3: 1,          # pinUvAuthProtocol must be 1
        4: mac,
    })
    print(f"\nstored {vid:04X}:{pid:04X} -- now unplug and replug the board.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--set", metavar="VID:PID",
                    help="store a new identity (4 hex digits each)")
    ap.add_argument("--list-known", action="store_true",
                    help="list the VID:PID pairs this host's CCID driver knows")
    args = ap.parse_args()

    if args.list_known:
        list_known()
        return 0

    dev, name = find_device()
    print(f"device: {name}\n")
    show(dev)
    print()

    if not args.set:
        pairs = known_pairs()
        current = None
        for tag, val in read_config(dev):
            if tag == TAG_VIDPID and len(val) == 4:
                current = struct.unpack(">HH", val)
        if current and current not in pairs:
            print(
                f"WARNING: {current[0]:04X}:{current[1]:04X} is not in this host's\n"
                "         libccid table, so no PC/SC reader appears and the Rescue\n"
                "         applet is unreachable. PicoForge shows this as a yellow\n"
                "         'Online - FIDO', not as an error.\n"
            )
            print("         Fix it with:  scripts/fix_usb_identity.py --set FA20:0002")
        else:
            print("Identity looks fine. Pass --set VID:PID to change it,")
            print("or --list-known to see what this host can bind.")
        dev.close()
        return 0

    try:
        vid, pid = (int(x, 16) for x in args.set.split(":"))
    except ValueError:
        die("--set wants VID:PID as four hex digits each, e.g. FA20:0002")
    if not (0 < vid <= 0xFFFF and 0 < pid <= 0xFFFF):
        die("VID and PID must both be non-zero (0x0000:0000 is not applied)")

    pin = getpass.getpass("device PIN: ")
    try:
        token = get_token(dev, pin)
    except Exception as exc:
        dev.close()
        die(f"could not obtain a pinUvAuthToken: {exc}")

    try:
        write_vidpid(dev, vid, pid, token)
    finally:
        dev.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())