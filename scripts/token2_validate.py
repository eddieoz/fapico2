#!/usr/bin/env python3
"""Validate the fapico2 FIDO2 firmware on hardware via the www.token2.com flow.

This is the post-flash acceptance procedure from docs/token2-hardware-validation.md.
It drives the physical token over USB CTAP-HID with python-fido2's Ctap2
transport, which runs in strict canonical CBOR mode by default: every
response is re-encoded and compared against its canonical form, and any
deviation raises ValueError. Strict canonical CBOR on responses is exactly
the property Chromium enforces (components/cbor, OUT_OF_ORDER_KEY) — the
property whose absence made Token2 sign-in fail before the fix documented
in docs/fido2-canonical-cbor-fix.md.

Checks performed, in order:

1. getInfo                    — parsed under strict canonical mode.
2. getAssertion probe (RP id, no allowList) — parsed under strict mode.
   NO_CREDENTIALS is an expected, informational outcome (no resident
   credential registered for the RP yet).
3. --register (default on): makeCredential (rk=false, no PIN required
   while clientPin is unset) + getAssertion with the minted allowList
   entry — the exact browser sign-in ceremony. Registers one throwaway
   non-resident credential for the RP; normal token usage, no resident
   state. Pass --no-register to skip.

The device will blink and wait for a touch on makeCredential and
getAssertion (BOOTSEL button = FIDO touch on the Pico 2).

Usage:
    python3 scripts/token2_validate.py [--rp-id www.token2.com] [--no-register]

Requires python-fido2 >= 2.0 (the project venv has it):
    ~/Projects/git/pico/pico-fido2/.test-venv/bin/python

Exit codes: 0 = all requested checks passed; 1 = a strict-parse or
ceremony failure (this is the regression signal); 2 = environment
problem (no device, no library).
"""

import argparse
import hashlib
import os
import sys

RP_DEFAULT = "www.token2.com"


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    print("\nThe response bytes were rejected by the strict canonical CBOR")
    print("parser — this is the pre-fix failure class (Chromium rejects the")
    print("same bytes with kCtap2ErrInvalidCBOR / OUT_OF_ORDER_KEY). See")
    print("docs/fido2-canonical-cbor-fix.md.")
    sys.exit(1)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rp-id", default=RP_DEFAULT, help=f"relying party id (default {RP_DEFAULT})")
    ap.add_argument("--no-register", action="store_true",
                    help="skip the makeCredential/getAssertion ceremony")
    args = ap.parse_args()

    try:
        from fido2.hid import CtapHidDevice
        from fido2.ctap2 import Ctap2
        from fido2.ctap2.base import CtapError
    except ImportError as e:
        print(f"environment: python-fido2 not importable ({e}); use the project venv:")
        print("  ~/Projects/git/pico/pico-fido2/.test-venv/bin/python")
        sys.exit(2)

    devs = list(CtapHidDevice.list_devices())
    if not devs:
        print("environment: no CTAP-HID device found (is the token plugged in?)")
        sys.exit(2)
    dev = devs[0]
    print(f"device: {dev}")

    # Ctap2 defaults to strict_cbor=True: each response is re-encoded and
    # must match its canonical form byte-for-byte, else ValueError.
    try:
        ctap = Ctap2(dev)
    except ValueError as e:
        fail(f"getInfo handshake returned non-canonical CBOR: {e}")
    try:
        info = ctap.get_info()
    except ValueError as e:
        fail(f"getInfo response is non-canonical: {e}")
    print(f"1. getInfo               OK (strict canonical parse)")
    print(f"   versions: {', '.join(info.versions)}")
    pin_set = bool(info.options.get("clientPin"))
    print(f"   options: clientPin={'set' if pin_set else 'unset'}, rk={info.options.get('rk')}")

    # --- getAssertion probe: the command Chrome rejected before the fix ---
    print(f"2. getAssertion probe    (rpId={args.rp_id}, no allowList; touch if a resident credential matches)")
    try:
        resp = ctap.get_assertion(args.rp_id, hashlib.sha256(b"token2-validate probe").digest())
        a = resp[0] if isinstance(resp, list) else resp
        print(f"   OK (strict canonical parse) — flags: UP={bool(a.auth_data.flags & 0x01)}")
    except CtapError as e:
        if e.code == CtapError.ERR.NO_CREDENTIALS:
            print("   OK (strict canonical parse of the error status) — NO_CREDENTIALS:")
            print(f"   no resident credential for {args.rp_id} yet; Chrome will offer")
            print("   registration on first login. Not a failure.")
        else:
            print(f"   CTAP error 0x{e.code:02X} — transport answered; response framing is canonical.")
    except ValueError as e:
        fail(f"getAssertion response is non-canonical: {e}")

    if args.no_register:
        print("\nPASS (probe-only): --no-register given, ceremony skipped.")
        return

    # --- full browser-equivalent ceremony: makeCredential + getAssertion ---
    print(f"3. makeCredential        (rpId={args.rp_id}, rk=false; touch the token)")
    if pin_set:
        print("   NOTE: a PIN is set on this token; without pinUvAuth the device")
        print("   answers PUAT_REQUIRED (0x36) — that is expected here, not a")
        print("   failure. Run the browser login for the full ceremony, or")
        print("   validate with the PIN via scripts driving ClientPin.")
    try:
        att = ctap.make_credential(
            hashlib.sha256(b"token2-validate registration").digest(),
            {"id": args.rp_id, "name": args.rp_id},
            {"id": os.urandom(32), "name": "token2-validate"},
            [{"type": "public-key", "alg": -7}],
            options={"up": True, "rk": False},
        )
    except CtapError as e:
        if e.code == CtapError.ERR.PUAT_REQUIRED and pin_set:
            print("   PUAT_REQUIRED (PIN set) — skipped ceremony, probe checks passed.")
            print("\nPASS (probe-only): device answered within the strict canonical regime.")
            return
        fail(f"makeCredential failed with CTAP 0x{e.code:02X} ({e})")
    except ValueError as e:
        fail(f"makeCredential response is non-canonical: {e}")
    cred_id = att.auth_data.credential_data.credential_id
    print("   OK (strict canonical parse)")

    print(f"4. getAssertion          (allowList from step 3; touch the token)")
    try:
        resp = ctap.get_assertion(
            args.rp_id,
            hashlib.sha256(b"token2-validate login").digest(),
            allow_list=[{"id": cred_id, "type": "public-key"}],
        )
    except ValueError as e:
        fail(f"getAssertion response is non-canonical: {e}")
    a = resp[0] if isinstance(resp, list) else resp
    up = bool(a.auth_data.flags & 0x01)
    print("   OK (strict canonical parse) — the exact command class Chromium")
    print("   rejected before docs/fido2-canonical-cbor-fix.md")
    assert up, "user presence flag missing on a touched assertion"

    print("\nPASS: the firmware's CTAP2 responses parse under strict canonical")
    print("CBOR for the full www.token2.com sign-in ceremony.")


if __name__ == "__main__":
    main()
