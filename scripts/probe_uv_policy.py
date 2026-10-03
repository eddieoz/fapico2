#!/usr/bin/env python3
"""Read the UV policy each board advertises, and what each answers to a
token-less MakeCredential.

The reference has three build/runtime UV policies in
cbor_make_credential.c:373-404:

  AUV          : pin set && !pinUvAuthParam && options.uv != true  -> PUAT_REQUIRED
  MCUV_NOTRQD  : pin set && options.uv == false && !pinUvAuthParam
                 && options.rk == true                             -> PUAT_REQUIRED
  neither      : pin set && !pinUvAuthParam && options.uv == false -> PUAT_REQUIRED

Only the first two differ in the `uv` *absent* case, and GetInfo advertises
which one is live (`alwaysUv`, `makeCredUvNotRqd`), so a pure read predicts
the behaviour.  This probe does that read on both boards.

Usage:  probe_uv_policy.py /dev/hidraw8 /dev/hidraw10
"""
import sys
import time

from fido2.hid import open_device
from fido2.ctap2.base import Ctap2


def get_info(path):
    dev = open_device(path)
    with dev:
        return dev.call(Ctap2.CMD.GET_INFO, b"")


def show(label, path):
    print(f"=== {label}  {path}")
    try:
        info = get_info(path)
    except Exception as exc:  # noqa: BLE001 - probe reports, never raises
        print(f"    ERROR: {exc}")
        return None
    print(f"    versions           : {info.versions}")
    print(f"    extensions         : {info.extensions}")
    opts = info.options
    print(f"    options.present    : {opts!r}")
    for key in ("rk", "up", "clientPin", "pinUvAuthToken", "uv",
                "rk_credProtect", "largeBlobs", "credMgmt", "authnrCfg",
                "makeCredUvNotRqd", "alwaysUv"):
        print(f"      {key:<18}: {getattr(opts, key, '<absent>')!r}")
    print(f"    maxMsgSize         : {info.max_msg_size}")
    print(f"    pinUvAuthProtocols : {info.pin_uv_auth_protocols}")
    return info


def main():
    paths = sys.argv[1:] or ["/dev/hidraw8", "/dev/hidraw10"]
    infos = []
    for p in paths:
        infos.append(show(p, p))
        print()
    time.sleep(0.3)

    a, b = (infos + [None, None])[:2]
    if a and b:
        print("--- policy diff")
        for key in ("alwaysUv", "makeCredUvNotRqd", "uv", "up", "rk", "pinUvAuthToken"):
            va, vb = getattr(a.options, key, "<absent>"), getattr(b.options, key, "<absent>")
            flag = "  <-- DIFFERS" if va != vb else ""
            print(f"    {key:<18}: ours={va!r}  reference={vb!r}{flag}")


if __name__ == "__main__":
    main()