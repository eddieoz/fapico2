#!/usr/bin/env python3
"""Put a marker in the secure store and read it back — proving US-919 from outside.

The question the US-919 build parameter exists to answer is "does flashing a
different image destroy this device's secrets?", and the answer has to be
observable from the HOST. The device's own log records what the firmware
decided (`E_FWDECIDE` / `E_FWWIPE`), but that is the code reporting on
itself, and a control that can only be checked by the thing it controls has
not been shown to work.

So this drives a real CTAP2 PIN round-trip against the live token:

    set     a PIN (or clear it), so the secure store definitely holds state
    check   does that PIN still authenticate?

A PIN lives in the FIDO keystore, which lives in the sealed secure-partition
image. A US-919 wipe empties that store, so after a wipe the PIN is gone and
`get_pin_token` fails. After a boot that admits the image, it still works.
That is a binary observable produced by an independent stack, and it is the
difference between "the log line said the wipe was skipped" and "the
credentials were still there afterwards".

`get_pin_retries` is deliberately NOT the observable. It reads 8 on this
device whether or not a PIN is set, so it cannot distinguish the two states —
worth saying, because it is the obvious thing to reach for and it looks like
it works.

Usage (needs the test venv for python-fido2):
    .test-venv/bin/python tests/hardware/store_marker.py set   123456
    .test-venv/bin/python tests/hardware/store_marker.py check 123456

Exit status: 0 = the PIN authenticates (store intact), 1 = it does not
(store wiped or the PIN is different), 2 = the device was not reachable.
"""

from __future__ import annotations

import sys

TARGET_VID = 0xFA20


def _connect():
    from fido2.client import ClientPin, DefaultClientDataCollector, Fido2Client
    from fido2.hid import CtapHidDevice, list_descriptors, open_connection

    descs = [d for d in list_descriptors() if d.vid == TARGET_VID]
    if not descs:
        print("no fa20:0002 device on the bus", file=sys.stderr)
        raise SystemExit(2)
    if len(descs) > 1:
        print(f"several fa20:0002 devices; pass the one you mean", file=sys.stderr)
        raise SystemExit(2)
    dev = CtapHidDevice(descs[0], open_connection(descs[0]))
    client = Fido2Client(
        dev,
        client_data_collector=DefaultClientDataCollector("https://fapico2.probe",
                                                         verify=False),
    )
    return dev, client, ClientPin(client._backend.ctap2)


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] not in ("set", "check"):
        print(__doc__)
        return 2
    action, pin = argv[1], argv[2]
    dev, client, cp = _connect()
    try:
        if action == "set":
            try:
                cp.set_pin(pin)
                print(f"SET ok — the store now holds the PIN '{pin}'")
            except Exception as e:
                # A PIN already set means change_pin, not set_pin.
                print(f"set failed ({type(e).__name__}: {e}); trying change_pin",
                      file=sys.stderr)
                cp.change_pin(pin, pin)
                print(f"SET ok (via change_pin) — the store holds the PIN '{pin}'")
            return 0

        try:
            cp.get_pin_token(pin)
        except Exception as e:
            print(f"CHECK: the PIN '{pin}' does NOT authenticate "
                  f"({type(e).__name__}) — the store does not hold it, so the "
                  f"boot either wiped the store or never had it")
            return 1
        print(f"CHECK: the PIN '{pin}' authenticates — the secure store survived "
              f"this boot")
        return 0
    finally:
        dev.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
