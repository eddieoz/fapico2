#!/usr/bin/env python3
"""Does our U2F (CTAP1) path actually work?  Chrome tried it and died there.

Chrome's own log, driving demo.yubico.com/webauthn-technical/registration
against this board, reads:

    device_response_converter.cc:403 -> {1: ["U2F_V2", "FIDO_2_0", ...], ...}
    fido_device.cc:70 The device supports the CTAP2 protocol.
    fido_hid_device.cc:455 Unknown CTAPHID command: 59 02
    u2f_register_operation.cc:195 Unexpected status 27264 from U2F device
    fido_device_authenticator.cc:1505 CTAP error response code 127 received
    make_credential_request_handler.cc:825 Ignoring status 1

27264 == 0x6A80 == U2F SW_WRONG_DATA.  Chrome entered a U2F register, the
device answered wrongly, and the whole CTAP2 MakeCredential was abandoned.
Our GetInfo advertises U2F_V2 unconditionally (ctap2.rs:697); the reference
withholds it whenever alwaysUv is true (cbor_get_info.c:96-99), which holds
whenever a PIN is set and the keydev is locked.

This measures the U2F path directly, over a real CTAPHID channel (an INIT
handshake first - CTAPHID 11.2.1 requires it, and skipping it returns
ERR_INVALID_MSG, which is what a naive probe sees):

  1. U2F VERSION over CTAPHID MSG (0x03), payload 0x05 -> must be "U2F_V2"
  2. U2F REGISTER over CTAPHID MSG, Chrome's exact shape

There is no CTAPHID VERSION command: CTAPHID defines PING, MSG, LOCK, INIT,
WINK, CBOR, CANCEL, KEEPALIVE and ERROR. The U2F version string arrives as a
raw one-byte message over CTAPHID_MSG.

Usage: probe_u2f_path.py [/dev/hidraw8]
"""
import sys

from fido2.hid import open_device, CTAPHID

PATH = sys.argv[1] if len(sys.argv) > 1 else "/dev/hidraw8"

# U2F over CTAPHID, as a browser builds it (CTAP1 / U2F raw messages).
U2F_REGISTER = 0x01
U2F_AUTHENTICATE = 0x02
U2F_VERSION = 0x05
PROTOCOL_U2F = 0x02


def show(label, fn):
    try:
        print(f"  {label:<42}: OK {fn()!r}")
    except Exception as exc:  # noqa: BLE001 - a probe reports, never raises
        code = getattr(exc, "code", None)
        name = getattr(exc, "name", "")
        print(f"  {label:<42}: {type(exc).__name__}"
              + (f" 0x{code:02x} {name}" if code is not None else f": {exc}"))


def u2f_register_request(rp_id, client_data, key_handle=b"\x00" * 64):
    """The exact APDU layout Chrome sends for U2F register (CTAP1)."""
    import hashlib
    chal = hashlib.sha256(b"probe-challenge").digest()
    app = hashlib.sha256(rp_id.encode()).digest()
    chal_param = hashlib.sha256(client_data).digest()
    auth_data = chal + app + b"\x05" + (0).to_bytes(4, "big") + \
        bytes([len(key_handle)]) + key_handle
    return (bytes([U2F_REGISTER]) + chal + app
            + bytes([len(key_handle)]) + key_handle
            + chal_param + bytes([PROTOCOL_U2F])
            + bytes([len(auth_data)]) + auth_data)


def main():
    with open_device(PATH) as dev:
        # `with` performs the CTAPHID INIT handshake, which every later command
        # depends on.
        print(f"channel open on {PATH}")

        show("U2F VERSION over CTAPHID MSG (payload 0x05)",
             lambda: dev.call(CTAPHID.MSG, bytes([U2F_VERSION])))

        show("U2F REGISTER over CTAPHID MSG (Chrome shape)",
             lambda: dev.call(CTAPHID.MSG,
                              u2f_register_request("demo.yubico.com",
                                                   b'{"type":"webauthn.create"}')))


if __name__ == "__main__":
    main()