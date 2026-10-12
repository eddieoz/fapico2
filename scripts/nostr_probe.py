#!/usr/bin/env python3
"""The Nostr presence-gate hardware probe (audit D2/D6/D7 evidence).

Drives the final tip over CCID/PC-SC: one press per gated command family,
an untouched-control refusal, and the management-RESET wipe (D6). The
user provides the finger; this script narrates each step and waits.

Run it with the venv python (pyscard lives there):

    ../pico-fido2/.test-venv/bin/python scripts/nostr_probe.py

Constants are resolved from the source, never from memory:
  - NOSTR_AID   apps/nostr/src/lib.rs   (NOSTR_AID)
  - MGMT_AID    apps/src/registry.rs    (AID_MANAGEMENT)
  - INS_RESET   apps/mgmt/src/lib.rs    (0x1E, touch-gated itself)
"""
import sys
from smartcard.System import readers
from smartcard.util import toBytes

NOSTR_AID = toBytes("F0 00 00 00 02")
MGMT_AID = toBytes("A0 00 00 05 27 47 11 17")
INS_LIST_KEYS = 0x11
INS_GENERATE_KEY = 0x13
INS_DELETE_KEY = 0x19
INS_RESET = 0x1E  # the management applet's RESET


def select(conn, aid):
    data, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x04, 0x00, len(aid)] + list(aid))
    return (sw1 << 8) | sw2, bytes(data)


def main():
    conns = []
    for r in readers():
        try:
            c = r.createConnection()
            c.connect()
            conns.append((r.name, c))
        except Exception:
            pass
    if not conns:
        sys.exit("no PC/SC reader with a card — is the board attached?")
    name, conn = next(((n, c) for n, c in conns
                       if select(c, NOSTR_AID)[0] == 0x9000), None)
    if conn is None:
        sys.exit("no reader selected the Nostr applet")
    print(f"Nostr applet selected via {name}")

    def apdu(ins, p1=0, data=b""):
        d, s1, s2 = conn.transmit([0x00, ins, p1, 0x00, len(data)] + list(data))
        return (s1 << 8) | s2, bytes(d)

    def list_keys():
        sw, data = apdu(INS_LIST_KEYS)
        n = data[0] if data else -1
        return sw, n

    print("\n[0/5] baseline: LIST_KEYS")
    sw, n = list_keys()
    print(f"  -> SW={sw:#06x} n_identities={n}")

    input("\n[1/5] GENERATE_KEY idx0 — TOUCH the board when the LED lights, then press Enter to send… ")
    sw, data = apdu(INS_GENERATE_KEY, 0)
    print(f"  -> SW={sw:#06x} data={len(data)}B (expect 9000 + 32-byte npub after your press)")

    input("\n[2/5] GENERATE_KEY idx0 again — DO NOT touch; press Enter to send… ")
    sw, _ = apdu(INS_GENERATE_KEY, 0)
    print(f"  -> SW={sw:#06x} (expect 6985 after the 10 s wait — the untouched control; "
          "SW 6A84 means idx0 was already occupied by step 1, re-run with a free idx)")

    input("\n[3/5] DELETE_KEY idx0, no payload — TOUCH; press Enter… ")
    sw, data = apdu(INS_DELETE_KEY, 0)
    print(f"  -> SW={sw:#06x} data={len(data)}B (expect 9000 + the destroyed npub)")

    input("\n[4/5] management RESET (D6: Nostr included) — TOUCH when mgmt's prompt lights; press Enter… ")
    sw, _ = select(conn, MGMT_AID)
    assert sw == 0x9000, f"mgmt SELECT failed: {sw:#06x}"
    sw, _ = apdu(INS_RESET)
    print(f"  -> SW={sw:#06x} (expect 9000)")

    print("\n[5/5] re-select Nostr and LIST_KEYS — D6's proof")
    sw, _ = select(conn, NOSTR_AID)
    assert sw == 0x9000, f"re-select failed: {sw:#06x}"
    sw, n = list_keys()
    verdict = "D6 VERIFIED (reset wiped Nostr)" if (sw == 0x9000 and n == 0) else "UNEXPECTED"
    print(f"  -> SW={sw:#06x} n_identities={n} — {verdict}")

    conn.disconnect()


if __name__ == "__main__":
    main()
