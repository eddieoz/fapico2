#!/usr/bin/env python3
"""One-shot check: can a first-party client authenticate to OATH on this board?

Answers the question US-1553's default access code exists to answer, on real
hardware rather than in a test: SELECT the OATH applet, derive the key exactly
as picoforge and yubikit do, and VALIDATE.

    python3 scripts/probe_oath_default_code.py [--wipe]

`--wipe` additionally runs the **management applet factory reset** (INS 0x1E)
first, which clears OATH's durable state so the applet re-provisions its
default. That is destructive to *every* applet's state, so it is opt-in.

The derivation is the contract, not an implementation detail
(`apps/oath/Cargo.toml`): *"the applet stores a **derived** key, never the
password"*.

* picoforge `src/hal/applets/oath.rs` — `derive_access_key`:
  `PBKDF2-HMAC-SHA1(password, device_id, 1000, 16)`
* `yubikit/oath.py` — `_derive_key(salt, passphrase)`, byte-identical

and the salt is the `71` device-id TLV in the SELECT response, which
`oath_core.rs::select_apdu` documents as "the PBKDF2 salt a host uses for the
access key".

Exit status: 0 if the derived key authenticates, 1 otherwise.
"""

import argparse
import hashlib
import hmac
import sys

DEFAULT_PASSWORD = b"123456"
OATH_AID = bytes.fromhex("A0000005272101")
MGMT_AID = bytes.fromhex("A000000527471117")

TAG_DEVICE_ID = 0x71
TAG_CHALLENGE = 0x74
TAG_RESPONSE = 0x75

INS_LIST = 0xA1
INS_VALIDATE = 0xA3
INS_MGMT_RESET = 0x1E

SW_OK = 0x9000


def tlv(body, tag):
    """The first TLV with `tag`, or None."""
    i = 0
    while i + 1 < len(body):
        t, ln = body[i], body[i + 1]
        if t == tag:
            return body[i + 2 : i + 2 + ln]
        i += 2 + ln
    return None


def derive_access_key(password, device_id):
    """picoforge `derive_access_key` / yubikit `_derive_key`."""
    return hashlib.pbkdf2_hmac("sha1", password, device_id, 1000, 16)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--wipe",
        action="store_true",
        help="run the management factory reset first (clears ALL applet state)",
    )
    args = ap.parse_args()

    try:
        from smartcard import System
    except ImportError:
        print("pysmartcard is not installed in this interpreter", file=sys.stderr)
        return 1

    readers = System.readers()
    if not readers:
        print("no CCID reader — is the board plugged in?", file=sys.stderr)
        return 1
    print(f"reader: {readers[0]}")

    card = readers[0].createConnection()
    card.connect()

    def select(aid):
        resp, sw1, sw2 = card.transmit(
            [0x00, 0xA4, 0x04, 0x00, len(aid)] + list(aid) + [0x00, 0x00]
        )
        sw = (sw1 << 8) | sw2
        return bytes(resp[:-2]), sw

    def apdu(ins, p1, p2, data):
        resp, sw1, sw2 = card.transmit(
            [0x00, ins, p1, p2, len(data)] + list(data) + [0x00]
        )
        return bytes(resp[:-2]), (sw1 << 8) | sw2

    if args.wipe:
        _, sw = select(MGMT_AID)
        if sw != SW_OK:
            print(f"management SELECT failed {sw:04X}")
            return 1
        _, sw = apdu(INS_MGMT_RESET, 0, 0, b"")
        print(f"management factory reset: {sw:04X}")
        if sw != SW_OK:
            print("  reset refused — the management applet gates it on user presence")
            return 1

    body, sw = select(OATH_AID)
    print(f"OATH SELECT: {sw:04X}")
    if sw != SW_OK:
        print("  the applet did not select; nothing below is meaningful")
        return 1

    chal = tlv(body, TAG_CHALLENGE)
    device_id = tlv(body, TAG_DEVICE_ID)
    print(f"  74 challenge : {chal.hex() if chal else 'ABSENT'}")
    print(f"  71 device_id : {device_id.hex() if device_id else 'ABSENT'}")

    if not chal or not device_id:
        print(
            "\nNo 74 challenge means this applet holds NO access code, so there is "
            "nothing to authenticate against and VALIDATE cannot succeed. That is "
            "the pre-US-1553 state — check the running image."
        )
        return 1

    key = derive_access_key(DEFAULT_PASSWORD, device_id)
    proof = hmac.new(key, chal, hashlib.sha1).digest()
    data = (
        bytes([TAG_RESPONSE, len(proof)])
        + proof
        + bytes([TAG_CHALLENGE, 8])
        + bytes(range(1, 9))
    )
    _, sw = apdu(INS_VALIDATE, 0, 0, data)
    print(f"\nVALIDATE with PBKDF2-derived '{DEFAULT_PASSWORD.decode()}': {sw:04X}")

    if sw == SW_OK:
        _, sw = apdu(INS_LIST, 0, 0, b"")
        print(f"LIST after VALIDATE: {sw:04X}")
        print("\nRESULT: a first-party client can authenticate. This is the fix.")
        return 0

    print(f"\nRESULT: authentication still fails ({sw:04X}).")
    print(
        "The board is not holding the provisioned default — a plain UF2 reflash\n"
        "does not wipe the secure partition, so an access code set in an earlier\n"
        "session survives every flash and `provision_default_access_code` leaves\n"
        "it alone. Re-run with --wipe to clear it and confirm."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
