#!/usr/bin/env python
"""A/B probe for the two GetAssertion lookup paths on the attached board.

Run from the repo root with the pico-fido2 test venv:

    ../pico-fido2/.test-venv/bin/python scripts/probe_allowlist_ab.py [RP_ID]

The script, for one RP (default `pam://ShadowL`, pass `ssh:` for the SSH key):

1. mints a PIN token (the board is alwaysUv, so every GA needs one),
2. GetAssertion **without an allowList** — the resident-enumeration path that
   demonstrably works on the board — and prints the credential ID it matched,
3. GetAssertion **with an allowList holding exactly that credential ID** — the
   by-ID probe path that fails on hardware — and prints the CTAP2 status.

Both assertions carry `up: true`, so touch the key when it blinks. The PIN is
read from the terminal and never stored.
"""

import getpass
import sys

from fido2.ctap2 import Ctap2, ClientPin
from fido2.ctap2.base import Ctap2 as Ctap2Base
from fido2.hid import CtapHidDevice

RP = sys.argv[1] if len(sys.argv) > 1 else "pam://ShadowL"


def status(exc):
    code = getattr(exc, "code", None)
    return f"CTAP2 error 0x{code:02x}" if code is not None else repr(exc)


devs = list(CtapHidDevice.list_devices())
if not devs:
    sys.exit("no CTAPHID device found")
sess = Ctap2(devs[0])

info = sess.get_info()
pin_set = info.options.get("clientPin", False)
if not pin_set:
    sys.exit("no PIN set on the device")

pin = getpass.getpass(f"PIN (rp={RP!r}): ")
cp = ClientPin(sess)
token = cp.get_pin_token(pin, permissions=ClientPin.PERMISSION.GET_ASSERTION, permissions_rpid=RP)
proto = cp.protocol.VERSION
print(f"token minted for rp {RP!r}: ok (pinUvAuthProtocol {proto})")

# 1. The enumeration path: no allowList.
challenge = b"\x00" * 32
try:
    resp = sess.get_assertion(
        RP, challenge,
        options={"up": True},
        pin_uv_param=cp.protocol.authenticate(token, challenge), pin_uv_protocol=proto,
    )
    cred_id = bytes(resp.credential["id"])
    print(f"1. GA without allowList: OK — matched credential id {cred_id.hex()}")
except Exception as e:
    sys.exit(f"1. GA without allowList failed: {status(e)} — enumeration broken too, paste this")

# 2. The by-ID probe path: allowList with exactly the id we just got.
allow = [{"id": cred_id, "type": "public-key"}]
challenge2 = b"\x01" * 32
try:
    resp2 = sess.get_assertion(
        RP, challenge2,
        allow_list=allow,
        options={"up": True},
        pin_uv_param=cp.protocol.authenticate(token, challenge2), pin_uv_protocol=proto,
    )
    print("2. GA with allowList  : OK — the by-ID probe works for this credential")
except Exception as e:
    print(f"2. GA with allowList  : FAILED — {status(e)}  (0x2e = NO_CREDENTIALS, "
          "0x36 = PUAT_REQUIRED; the by-ID probe path is the defect)")
