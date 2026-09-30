#!/usr/bin/env python3
"""P7-D1 — matrix Row 2 (FIDO2 over HID) re-run on the final S-723 image.

Adapted from the P7-C2 ceremony (tests/scripts/p7_c2_ceremony.py) with two
authoritative changes (S-731-1 brief):
  * NO client-side strictness relaxation — plain get_info() runs
    python-fido2 1.2.0's canonical-CBOR check unrelaxed. The row-2 residual
    note (tstr-sort fix `559d53e0`) is exactly what this re-run verifies.
  * PIN probe before set: the board may already carry a PIN from the
    P7-C2/C3 era. One probe with the era PIN; on any other outcome we STOP
    (never retry a state-changing PIN op).

Writes one verbatim evidence file per step into
docs/tasks/evidence/p7-d1/ (p7d1-C…p7d1-H), like the p7-c7 pattern.
"""
import sys
import os
import hmac as _hmac
import hashlib
import secrets

from fido2.hid import CtapHidDevice
from fido2.ctap2 import (Ctap2, ClientPin, CredentialManagement, LargeBlobs,
                         Config)
from fido2.ctap2.pin import PinProtocolV1
from fido2.ctap2.base import CtapError

EVID = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "..", "docs", "tasks", "evidence", "p7-d1")
PIN = "1234"          # P7-C2/C3-era PIN (probe target)
FAILED = False


class Step:
    """Tee a step's verbatim output to stdout and its evidence file."""
    def __init__(self, name, filename):
        self.name = name
        self.path = os.path.join(EVID, filename)
        self._fh = None

    def __enter__(self):
        self._fh = open(self.path, "w")
        print("===== step %s -> %s" % (self.name, self.path))
        return self

    def __exit__(self, *exc):
        self._fh.close()

    def line(self, txt=""):
        print(txt)
        self._fh.write(txt + "\n")


def stop(msg):
    print("STOP: " + msg)
    sys.exit(2)


def main():
    global FAILED
    dev = next(CtapHidDevice.list_devices(), None)
    if dev is None:
        stop("no CtapHidDevice found")
    ctap = Ctap2(dev)

    # ---- C: strict get_info (THE verification: no relaxation monkeypatch) --
    with Step("C strict getInfo", "p7d1-C-fido-getinfo.log") as out:
        out.line("# python-fido2 1.2.0 strict canonical-CBOR get_info() —")
        out.line("# NO client-side strictness relaxation (verifies 559d53e0)")
        info = ctap.get_info()
        out.line("get_info(): versions %s" % (list(info.versions),))
        out.line("           aaguid %s" % info.aaguid)
        out.line("           maxMsgSize %s" % info.max_msg_size)
        out.line("           options %s" % sorted(info.options.items()))
        if "FIDO_2_1" not in info.versions:
            stop("FIDO_2_1 absent from strict get_info")

    # ---- D: PIN probe (one attempt only) -----------------------------------
    with Step("D pin probe", "p7d1-D-fido-pin.log") as out:
        pin_cfg = ClientPin(ctap, PinProtocolV1())
        token = None
        try:
            token = pin_cfg.get_pin_token(PIN, permissions=0x37)
            out.line("probe get_pin_token('1234', perms 0x37): OK "
                     "(PIN already set from P7-C2/C3 era — NOT set again)")
        except CtapError as e:
            out.line("probe get_pin_token('1234'): CtapError %r" % (e,))
            if e.code == 0x31:  # PinRequired -> factory PIN-less state
                out.line("PIN not set (0x31 PinRequired) -> setPIN('1234')")
                pin_cfg.set_pin(PIN)
                out.line("setPIN: OK")
                token = pin_cfg.get_pin_token(PIN, permissions=0x37)
                out.line("PIN-permissioned token (0x37): OK")
            else:
                stop("PIN probe failed with unexpected CtapError — NOT "
                     "retrying (one-probe discipline): %r" % (e,))
        if token is None:
            stop("no PIN token obtained")
        out.line("token len %d" % len(token))

    # ---- E: makeCredential rk=True + extensions, getAssertion verify -------
    with Step("E MC rk + GA verify", "p7d1-E-fido-mc-ga.log") as out:
        client_hash = bytes(range(32))
        param = _hmac.new(token, client_hash, hashlib.sha256).digest()[:16]
        mc = ctap.make_credential(
            client_hash, {"id": "example.com"}, {"id": b"user-p7d1"},
            [{"type": "public-key", "alg": -7}],
            extensions={"credProtect": 2, "hmac-secret": True},
            options={"rk": True}, pin_uv_param=param, pin_uv_protocol=1)
        out.line("MC: authData %d bytes, flags %s"
                 % (len(bytes(mc.auth_data)), hex(mc.auth_data.flags)))
        cose_key = mc.auth_data.credential_data.public_key
        ga = ctap.get_assertion("example.com", client_hash,
                                pin_uv_param=param, pin_uv_protocol=1)
        ga.verify(client_hash, cose_key)
        out.line("getAssertion: signature verified (python-fido2)")

    # ---- F: credMgmt enumerate ---------------------------------------------
    with Step("F credMgmt", "p7d1-F-fido-credmgmt.log") as out:
        cm = CredentialManagement(ctap, PinProtocolV1(), token)
        meta = cm.get_metadata()
        out.line("credMgmt metadata: %s" % (meta,))
        rps = list(cm.enumerate_rps())
        # python-fido2 1.2.0 returns dicts keyed by RESULT tag ints, not
        # tuples (review fix S-731-1)
        rp_ids = [e.get(CredentialManagement.RESULT.RP) for e in rps]
        out.line("credMgmt RPs: %d %s" % (len(rps), rp_ids))
        if not rps:
            stop("credMgmt: no RPs after rk=True MC")
        rp_hash = rps[0][CredentialManagement.RESULT.RP_ID_HASH]
        creds = list(cm.enumerate_creds(rp_hash))
        out.line("credMgmt creds for first RP: %d" % len(creds))
        if not creds:
            stop("credMgmt: no creds for first RP")

    # ---- G: largeBlobs put + get --------------------------------------------
    with Step("G largeBlobs", "p7d1-G-fido-largeblobs.log") as out:
        lb = LargeBlobs(ctap, PinProtocolV1(), token)
        lbk = secrets.token_bytes(32)
        data = secrets.token_bytes(64)
        lb.put_blob(lbk, data)
        got = lb.get_blob(lbk)
        out.line("largeBlobs put+get: %s"
                 % ("round-trip OK" if got == data
                    else "MISMATCH %r" % got))
        if got != data:
            FAILED = True

    # ---- H: authenticatorConfig toggle (state-restoring) --------------------
    with Step("H authnrCfg", "p7d1-H-fido-authnrcfg.log") as out:
        cfg = Config(ctap, PinProtocolV1(), token)
        cfg.toggle_always_uv()
        out.line("authenticatorConfig toggle alwaysUv: OK (1)")
        cfg.toggle_always_uv()
        out.line("authenticatorConfig toggle alwaysUv: OK (2, state restored)")

    print()
    print("ROW-2 RE-RUN %s (P7-D1, S-731-1)" % ("PASS" if not FAILED else "FAIL"))
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
