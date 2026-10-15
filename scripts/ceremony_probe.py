#!/usr/bin/env python3
"""The custody-ceremony hardware probe (US-1718 evidence).

Drives the ceremony over CCID/PC-SC on a sacrificial board and records:
  - GET_INFO before (flags must show bit 2 pending on a PIN-set board),
  - SET_PIN (touch-free — the PIN is the consent),
  - the timed CEREMONY_START (the duration bound the extension prints),
  - GET_INFO after (bit 2 cleared — the marker stands),
  - LIST_KEYS / GET_PUBKEY after (the identity set survived the reseat).

Run with the venv python (pyscard lives there):

    ../pico-fido2/.test-venv/bin/python scripts/ceremony_probe.py [pin]

The PIN argument defaults to 731742. The ceremony burns the OTP custody
page — **irreversible**; run it only on the sacrificial board.
"""
import sys
import time

from smartcard.System import readers
from smartcard.util import toBytes

NOSTR_AID = toBytes("F0 00 00 00 02")
INS_GET_INFO = 0x10
INS_LIST_KEYS = 0x11
INS_GET_PUBKEY = 0x12
INS_SET_PIN = 0x1C
INS_CEREMONY_START = 0x1E
FLAG_PIN_SET = 0x01
FLAG_SESSION_UNLOCKED = 0x02
FLAG_MIGRATION_PENDING = 0x04
CAP_CEREMONY = 0x0008


def select(conn, aid):
    data, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x04, 0x00, len(aid)] + list(aid))
    return (sw1 << 8) | sw2, bytes(data)


def apdu(conn, ins, p1=0, data=b""):
    d, sw1, sw2 = conn.transmit([0x00, ins, p1, 0x00, len(data)] + list(data))
    return (sw1 << 8) | sw2, bytes(d)


def flags(info):
    return info[7] if len(info) >= 8 else 0


def main():
    pin = sys.argv[1].encode() if len(sys.argv) > 1 else b"731742"
    for r in readers():
        try:
            c = r.createConnection()
            c.connect()
            if select(c, NOSTR_AID)[0] == 0x9000:
                break
        except Exception:
            continue
    else:
        sys.exit("no reader selected the Nostr applet")

    sw, info = apdu(c, INS_GET_INFO)
    caps = (info[2] << 8) | info[3]
    print(f"[state] GET_INFO sw={sw:04X} caps=0x{caps:04X} n_identities={info[6]} "
          f"flags=0x{flags(info):02X}")
    if not caps & CAP_CEREMONY:
        sys.exit("the board does not advertise CAP_CEREMONY — is this the ceremony build?")
    if flags(info) & FLAG_PIN_SET:
        print("[pin]   PIN already set (flags bit 0) — skipping SET_PIN")
    else:
        sw, _ = apdu(c, INS_SET_PIN, p1=0, data=pin)
        print(f"[pin]   SET_PIN sw={sw:04X}")
        if sw != 0x9000:
            sys.exit("SET_PIN refused")
        sw, info = apdu(c, INS_GET_INFO)
        print(f"[state] flags=0x{flags(info):02X}")

    if not flags(info) & FLAG_MIGRATION_PENDING:
        sys.exit("bit 2 does not stand — the ceremony has nothing to migrate")

    sw, keys = apdu(c, INS_LIST_KEYS)
    n = keys[0] if keys else -1
    print(f"[pre]   LIST_KEYS sw={sw:04X} n_identities={n}")

    print(f"[run]   CEREMONY_START — burning and reseating ({n} identity/identities + the PIN record)…")
    t0 = time.perf_counter()
    sw, body = apdu(c, INS_CEREMONY_START)
    dt = time.perf_counter() - t0
    print(f"[run]   sw={sw:04X} body={body.hex()} "
          f"migrated={int.from_bytes(body[0:2], 'big') if len(body) >= 2 else '?'} "
          f"already={int.from_bytes(body[2:4], 'big') if len(body) >= 4 else '?'}")
    print(f"[run]   DURATION: {dt:.3f} s")

    sw, info = apdu(c, INS_GET_INFO)
    f = flags(info)
    print(f"[post]  GET_INFO sw={sw:04X} flags=0x{f:02X} "
          f"(pending={bool(f & FLAG_MIGRATION_PENDING)} — bit 2 must be CLEAR)")
    sw, keys = apdu(c, INS_LIST_KEYS)
    n2 = keys[0] if keys else -1
    print(f"[post]  LIST_KEYS sw={sw:04X} n_identities={n2} (must equal the pre count)")
    if n2:
        sw, pub = apdu(c, INS_GET_PUBKEY, p1=0)
        print(f"[post]  GET_PUBKEY idx0 sw={sw:04X} len={len(pub)} (must be 9000/95)")


if __name__ == "__main__":
    main()
