#!/usr/bin/env python3
"""A/B what each board does with the EXACT request demo.yubico.com sends.

Captured from the live page (Chrome console, [WATRACE] create):

    publicKey: { attestation: "direct",
                 authenticatorSelection: { requireResidentKey: false,
                                          residentKey: "discouraged",
                                          userVerification: "discouraged" },
                 excludeCredentials: [], rp: {id: "demo.yubico.com"}, ... }

userVerification:"discouraged" means Chrome sends authenticatorMakeCredential
with NO pinUvAuthParam.  For each board this records, using the library's own
encoders (hand-rolled CBOR in this family has produced false results before):

  1. clientPIN 0x01 getPinRetries       -> is a PIN set at all?
  2. authenticatorMakeCredential, no token, several option shapes
                                      -> PUAT_REQUIRED, or success?
  3. clientPIN 0x06 UsingUvWithPermissions and 0x09 UsingPinWithPermissions
                                      -> what the client gets next.

Keepalives are counted, but NOT read as an arm on their own: the reference
emits a baseline keepalive on clientPIN because it enters its blocking button
wait before answering.  An arm is only claimed where the board parks and no
answer arrives at all.

`0x09` answering MISSING_PARAMETER here is correct, not a fault: the sub-
command needs `keyAgreement` and `pinHashEnc`, which only exist after the ECDH
handshake. `probe_clientpin_legs.py` runs that handshake and shows both legs
mint.

Opcodes are this family's dialect, NOT CTAP 2.1's: makeCredential 0x01,
getInfo 0x04, clientPIN 0x06 (python-fido2 2.2.1 Ctap2.CMD).

Usage: probe_mc_uv_ab.py /dev/hidraw10 /dev/hidraw8
"""
import sys

from fido2.hid import open_device
from fido2 import ctap
from fido2.cose import ES256, EdDSA
from fido2.ctap2.base import Ctap2

# rp and user are plain dicts on purpose. PublicKeyCredentialUserEntity types
# `id` as str and base64-encodes it, which puts a CBOR *text string* where
# CTAP2 §6.1.2 requires bytes; the authenticator correctly answers
# INVALID_CBOR, and the probe then reports a device fault that is not there.

RP_ID = "demo.yubico.com"

CTAP2_ERRORS = {
    0x00: "SUCCESS", 0x01: "INVALID_COMMAND", 0x02: "INVALID_PARAMETER",
    0x03: "INVALID_LENGTH", 0x11: "CBOR_UNEXPECTED_TYPE", 0x12: "INVALID_CBOR",
    0x14: "MISSING_PARAMETER", 0x15: "LIMIT_EXCEEDED",
    0x24: "OPERATION_PENDING", 0x25: "OPERATION_TIMED_OUT",
    0x2B: "UNSUPPORTED_OPTION", 0x2C: "INVALID_OPTION", 0x2D: "KEEPALIVE_CANCEL",
    0x2E: "NO_CREDENTIALS", 0x2F: "USER_ACTION_TIMEOUT", 0x30: "NOT_ALLOWED",
    0x31: "PIN_INVALID", 0x32: "PIN_BLOCKED", 0x33: "PIN_AUTH_INVALID",
    0x34: "PIN_AUTH_BLOCKED", 0x35: "PIN_NOT_SET", 0x36: "PUAT_REQUIRED",
    0x37: "PIN_POLICY_VIOLATION", 0x39: "REQUEST_TOO_LARGE",
    0x3A: "ACTION_TIMEOUT", 0x3B: "UP_REQUIRED", 0x3C: "UV_BLOCKED",
    0x3E: "INVALID_SUBCOMMAND", 0x3F: "UV_INVALID",
    0x40: "UNAUTHORIZED_PERMISSION",
}

LABELS = {
    "/dev/hidraw8": "OURS (fapico2)",
    "/dev/hidraw10": "REFERENCE (C)",
}


def show_exc(exc):
    code = getattr(exc, "code", None)
    if code is None:
        return f"{type(exc).__name__}: {exc}"
    return f"0x{code:02x} {CTAP2_ERRORS.get(code, code)}"


def run(fn):
    try:
        out = fn()
        return f"OK {out}" if out else "OK"
    except ctap.CtapError as exc:
        return show_exc(exc)
    except Exception as exc:  # noqa: BLE001 - a probe reports, never raises
        return f"{type(exc).__name__}: {exc}"


def mc(client, options, ka):
    return client.make_credential(
        client_data_hash=b"\xaa" * 32,
        rp={"id": RP_ID, "name": "Yubico Demo"},
        user={"id": b"\x02" * 32, "name": "Yubico demo user",
              "displayName": "Yubico demo user"},
        key_params=[{"type": "public-key", "alg": -7},
                    {"type": "public-key", "alg": -8}],
        exclude_list=[],
        options=options,
        pin_uv_param=None,
        on_keepalive=ka.append,
    )


def probe(path):
    print(f"===== {LABELS.get(path, 'board')}  {path}")
    with open_device(path) as dev:
        client = Ctap2(dev)

        ka = []
        r = run(lambda: client.client_pin(None, 0x01, on_keepalive=ka.append))
        print(f"  clientPIN 0x01 getPinRetries              : {r}")

        shapes = [
            ("options ABSENT", None),
            ("options {rk:false}", {"rk": False}),
            ("options {rk:false, uv:false}", {"rk": False, "uv": False}),
            ("options {rk:true}", {"rk": True}),
            ("options {rk:true, uv:true}", {"rk": True, "uv": True}),
        ]
        for name, opts in shapes:
            ka = []
            r = run(lambda o=opts, k=ka: _fmt(mc(client, o, k)))
            print(f"  MC token-less  {name:<31}: {r:<30} keepalives={len(ka)}")

        for sub, name in ((0x06, "0x06 UsingUvWithPermissions"),
                          (0x09, "0x09 UsingPinWithPermissions")):
            ka = []
            r = run(lambda s=sub, k=ka: client.client_pin(
                1, s, permissions=0x01, permissions_rpid=RP_ID,
                on_keepalive=k.append))
            print(f"  clientPIN {name:<31}: {r:<30} keepalives={len(ka)}")
    print()


def _fmt(res):
    return f"fmt={res.fmt}"


def main():
    for path in (sys.argv[1:] or ["/dev/hidraw10", "/dev/hidraw8"]):
        probe(path)


if __name__ == "__main__":
    main()