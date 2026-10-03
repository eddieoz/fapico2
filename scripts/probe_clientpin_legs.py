#!/usr/bin/env python3
"""The decisive clientPIN experiment: can our board mint a pinUvAuthToken
through the leg a conformant CTAP 2.1 client actually uses?

demo.yubico.com sends userVerification:"discouraged".  Our board answers the
resulting token-less authenticatorMakeCredential with CTAP2_ERR_PUAT_REQUIRED
(measured).  Per CTAP 2.1 the client must then acquire a pinUvAuthToken via
getPinUvAuthTokenUsingPinWithPermissions - and that is the whole difference
between token2.com (works) and demo.yubico.com / X.com (does not).

python-fido2 2.2.1 chooses the sub-command:

    permissions is None  -> ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY  (0x05)
    permissions given    -> ClientPin.CMD.GET_TOKEN_USING_PIN         (0x09)

so this runs the real ECDH + PIN handshake on both legs and prints which one
the board answers.

Our parser reads `permissions` from CBOR map key 9 and rpId from key 10
(device_core.rs:1629-1638); CTAP 2.1 §6.5.5.1 sends them at keys 7 and 8, and
python-fido2's args() follows the spec.

Usage: probe_clientpin_legs.py [/dev/hidraw8] [123456]
"""
import sys

from fido2.hid import open_device
from fido2 import ctap
from fido2.ctap2 import ClientPin, Ctap2
from fido2.ctap2.pin import PinProtocolV1

CTAP2_ERRORS = {
    0x02: "INVALID_PARAMETER", 0x03: "INVALID_LENGTH",
    0x11: "CBOR_UNEXPECTED_TYPE", 0x12: "INVALID_CBOR",
    0x14: "MISSING_PARAMETER", 0x31: "PIN_INVALID", 0x32: "PIN_BLOCKED",
    0x33: "PIN_AUTH_INVALID", 0x34: "PIN_AUTH_BLOCKED", 0x35: "PIN_NOT_SET",
    0x36: "PUAT_REQUIRED", 0x3E: "INVALID_SUBCOMMAND",
    0x3F: "UV_INVALID", 0x40: "UNAUTHORIZED_PERMISSION",
}


def show(exc):
    code = getattr(exc, "code", None)
    if code is None:
        return f"{type(exc).__name__}: {exc}"
    return f"0x{code:02x} {CTAP2_ERRORS.get(code, code)}"


def attempt(label, fn):
    try:
        return f"OK - token minted ({fn()})"
    except ctap.CtapError as exc:
        return show(exc)
    except Exception as exc:  # noqa: BLE001
        return f"{type(exc).__name__}: {exc}"


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "/dev/hidraw8"
    pin_value = sys.argv[2] if len(sys.argv) > 2 else "123456"

    print(f"ClientPin.CMD values: LEGACY=0x{ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY:02x} "
          f"(getPinUvAuthToken)  PIN=0x{ClientPin.CMD.GET_TOKEN_USING_PIN:02x} "
          f"(getPinUvAuthTokenUsingPinWithPermissions)")
    with open_device(path) as dev:
        ctap2 = Ctap2(dev)
        cp = ClientPin(ctap2, PinProtocolV1())
        print(f"device {path}: {ctap2.info.options}")

        print("\n  get_pin_retries()                      : "
              + attempt("r", lambda: cp.get_pin_retries()))
        print("  get_pin_token(pin)            [0x05 leg] : "
              + attempt("t", lambda: f"{len(cp.get_pin_token(pin_value))}B"))
        print("  get_pin_token(pin, perms, rpid) [0x09 leg] : "
              + attempt("t", lambda: f"{len(cp.get_pin_token(
                  pin_value,
                  permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,
                  permissions_rpid='demo.yubico.com'))}B"))
        print("\n  This is the whole asymmetry: the 0x05 leg is the one a "
              "token2-style\n  stack reaches; the 0x09 leg is the one Chrome "
              "reaches after PUAT_REQUIRED.")


if __name__ == "__main__":
    main()