#!/usr/bin/env python3
"""P7-D2 phase 1 — matrix Row 2 (FIDO2/U2F over HID), PIN-free leg.

Adapted from tests/scripts/p7_d1_fido.py per the repin brief: the board is
factory-fresh (FIDO PIN UNSET) and the firmware has a history of PIN-anomaly
wedges (sticky 0x34, PIN-gating of PIN-free MC) — so this leg is designed
PIN-free:
  * strict (unrelaxed) get_info() — python-fido2 1.2.0 canonical-CBOR check,
    no client-side relaxation monkeypatch;
  * U2F (CTAP1) register + authenticate exactly ONCE (the fixed capacity:
    one register consumes one slot);
  * NO PIN ops, NO credMgmt, NO makeCredential.

One attempt per state-changing op; on unexpected failure record verbatim
and exit non-zero without retrying.

Output: docs/tasks/evidence/p7-d2/p7d2-C2-fido-getinfo.log
        docs/tasks/evidence/p7-d2/p7d2-C3-fido-u2f.log
"""
import os
import sys
import hashlib

from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2
from fido2.ctap1 import Ctap1

EVID = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "..", "docs", "tasks", "evidence", "p7-d2")


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
    dev = next(CtapHidDevice.list_devices(), None)
    if dev is None:
        stop("no CtapHidDevice found")
    ctap = Ctap2(dev)

    # ---- C2: strict get_info (NO relaxation) -------------------------------
    with Step("C2 strict getInfo", "p7d2-C2-fido-getinfo.log") as out:
        out.line("# python-fido2 1.2.0 strict canonical-CBOR get_info() —")
        out.line("# NO client-side strictness relaxation (PIN-free leg; "
                 "PIN UNSET on this factory-fresh board, no PIN ops)")
        info = ctap.get_info()
        out.line("get_info(): versions %s" % (list(info.versions),))
        out.line("           aaguid %s" % info.aaguid)
        out.line("           maxMsgSize %s" % info.max_msg_size)
        out.line("           options %s" % sorted(info.options.items()))
        if "FIDO_2_1" not in info.versions:
            stop("FIDO_2_1 absent from strict get_info")

    # ---- C3: U2F register + authenticate, exactly one register -------------
    with Step("C3 U2F register+auth (one register)",
              "p7d2-C3-fido-u2f.log") as out:
        out.line("# U2F (CTAP1) over HID — exactly ONE register (fixed "
                 "capacity: a register consumes a slot); NO PIN, NO "
                 "credMgmt, NO makeCredential")
        ctap1 = Ctap1(dev)
        rp_id = "example.com"
        app_param = hashlib.sha256(rp_id.encode()).digest()
        challenge = bytes(range(32))
        reg = ctap1.register(app_param, challenge)
        out.line("register: key_handle %d bytes, public_key %d bytes, "
                 "sig %d bytes, cert %d bytes"
                 % (len(reg.key_handle), len(reg.public_key),
                    len(reg.signature), len(reg.certificate)))
        try:
            reg.verify(app_param, challenge)
            out.line("register: attestation signature verified "
                     "(python-fido2)")
        except Exception as e:
            # One attempt, then STOP — the register already consumed a
            # store slot and a corrective re-register is FORBIDDEN (the
            # binding one-U2F-register-max rule). Note: the attestation
            # self-signature check is NOT part of the row-2 bar (P7-C2
            # verified via CTAP2 MC+GA; the soak register-once leg skips
            # attestation verification), but it is recorded verbatim.
            out.line("register: attestation verify FAILED client-side: "
                     "%s: %s" % (type(e).__name__, e))
            stop("U2F attestation verify failed — authenticate NOT "
                 "attempted (key handle unusable without the local "
                 "verification context); NO re-register (one register "
                 "max)")
        auth = ctap1.authenticate(app_param, challenge, reg.key_handle)
        out.line("authenticate: sig %d bytes, counter %d"
                 % (len(auth.signature), auth.counter))
        auth.verify(app_param, challenge, reg.public_key)
        out.line("authenticate: signature verified (python-fido2)")

    print()
    # All failure paths exit via stop() (or the exception propagates);
    # reaching this line means every step passed.
    print("ROW-2 (PIN-FREE LEG) PASS (P7-D2 phase 1)")
    sys.exit(0)


if __name__ == "__main__":
    main()
