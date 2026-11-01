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
#: The PIN custody dialect (US-1691..1694, US-1702). Touch-free by design:
#: the PIN is the consent. CCID legs only here — the emulator never
#: exposes the Nostr HID interface, so the HID arm of this dialect is
#: exercised by driving these same INS through the extension on hardware
#: (US-1704's transcript), not by this PC-SC script.
INS_VERIFY_PIN = 0x1B
INS_SET_PIN = 0x1C  # P1 0 = SET, P1 1 = CHANGE
INS_LOCK = 0x1D
#: US-1742 — the touch-policy verb. P1 0 = enable touch (friction-free),
#: P1 1 = bypass on for the three signing arms (open session + a press).
INS_SET_TOUCH_POLICY = 0x1F
SW_OK = 0x9000
SW_PIN_LOCKED = 0x63C0
SW_PIN_NOT_SET = 0x6A82
SW_PIN_SESSION_REQUIRED = 0x6982
SW_TOUCH_REQUIRED = 0x6985
#: US-1746 — caps bit 4 (the verb exists) and flags bit 3 (bypass armed).
CAP_TOUCH_POLICY = 0x0010
FLAG_TOUCH_BYPASS = 0x08


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

    # ---- US-1704: the optional --pin legs ------------------------------
    #
    # --pin walks the custody dialect over the *device*: SET (the leg
    # asks for a fresh PIN on stdin — no default, because a PIN nobody
    # chose is not a PIN), VERIFY, the gate opening and closing on a
    # gated command family, LOCK, and the durable 63CX rows. Reaching
    # the HID arm of this dialect needs the extension driving the same
    # INS over WebHID; the transcript records what the CCID leg saw and
    # what the extension echoed back.
    if "--pin" in sys.argv:
        import getpass
        pin = getpass.getpass("PIN to establish (6..64 chars): ").encode()
        assert 6 <= len(pin) <= 64, "the PIN must be 6..64 bytes"
        print("\n[P1] SET_PIN")
        sw, _ = apdu(INS_SET_PIN, 0, pin)
        print(f"  -> SW={sw:#06x} (expect 9000; 6A82 = already set)")
        print("\n[P2] SIGN while locked — the gate word")
        sw, _ = apdu(INS_GENERATE_KEY, 0)
        print(f"  -> SW={sw:#06x} (expect {SW_PIN_SESSION_REQUIRED:#06x} before any touch prompt)")
        print("\n[P3] VERIFY_PIN")
        sw, _ = apdu(INS_VERIFY_PIN, 0, pin)
        print(f"  -> SW={sw:#06x} (expect 9000)")
        print("\n[P4] two wrong VERIFYs then the right one — the 63CX rows")
        wrong = b"000000"
        for _ in range(2):
            sw, _ = apdu(INS_VERIFY_PIN, 0, wrong)
            print(f"  -> SW={sw:#06x} (expect 63C2, then 63C1)")
        sw, _ = apdu(INS_VERIFY_PIN, 0, pin)
        print(f"  -> SW={sw:#06x} (expect 9000; the success resets the counter)")
        print("\n[P5] LOCK")
        sw, _ = apdu(INS_LOCK)
        print(f"  -> SW={sw:#06x} (expect 9000)")
        print("\n[P6] verify survives deselect: re-select the applet, then VERIFY")
        sw, _ = select(conn, NOSTR_AID)
        assert sw == 0x9000
        sw, _ = apdu(INS_VERIFY_PIN, 0, pin)
        print(f"  -> SW={sw:#06x} (expect 9000 — the session is applet-global, not per-connection)")
        print("\n--pin legs done; the full gated-command matrix is the emulator suite's")
        conn.disconnect()
        return

    # ---- US-1749: the optional --touch-bypass legs ----------------------
    #
    # --touch-bypass walks the policy verb over the *device* (CCID): the
    # advertisement, the disable leg's consent chain (closed-session
    # refusal, verify, the consent press), the ten-signature chain that
    # must cost zero further touches, LOCK clearing the flag, the
    # friction-free enable leg, and the power-cycle leg — the user
    # unplugs and replugs mid-run and the script reconnects, proving the
    # RAM flag died with the power. The HID leg of the same matrix rides
    # the extension on hardware (the probe is PC-SC only); its
    # observations are recorded in the audit transcript beside these.
    if "--touch-bypass" in sys.argv:
        import getpass

        def connect():
            for r in readers():
                try:
                    c = r.createConnection()
                    c.connect()
                    if select(c, NOSTR_AID)[0] == SW_OK:
                        return r.name, c
                except Exception:
                    pass
            sys.exit("no reader selected the Nostr applet")

        def session():
            """A fresh (reader, transmit) pair — the power-cycle leg rebuilds it."""
            n, c = connect()
            print(f"  (connected via {n})")

            def a(ins, p1=0, data=b""):
                d, s1, s2 = c.transmit([0x00, ins, p1, 0x00, len(data)] + list(data))
                return (s1 << 8) | s2, bytes(d)

            return a, c

        a, conn = session()
        print("\n[T1] GET_INFO — the advertisement")
        sw, data = a(0x10)
        assert sw == SW_OK and len(data) == 8
        caps = int.from_bytes(data[2:4], "big")
        flags = data[7]
        assert caps & CAP_TOUCH_POLICY, f"caps {caps:#06x} lacks the touch-policy bit"
        print(f"  -> caps={caps:#06x} flags={flags:#02x} (CAP_TOUCH_POLICY set, "
              f"bypass {'ARMED' if flags & FLAG_TOUCH_BYPASS else 'clear'})")

        print("\n[T2] SET_TOUCH_POLICY P1=1 before any verify — the refusal")
        sw, _ = a(INS_SET_TOUCH_POLICY, 1)
        expect = "6A82 (no PIN)" if sw == SW_PIN_NOT_SET else "6982 (session closed)"
        print(f"  -> SW={sw:#06x} (expect {expect})")
        assert sw in (SW_PIN_NOT_SET, SW_PIN_SESSION_REQUIRED)

        pin = getpass.getpass("PIN (the board's, to open the session): ").encode()
        print("\n[T3] VERIFY_PIN")
        sw, _ = a(INS_VERIFY_PIN, 0, pin)
        print(f"  -> SW={sw:#06x} (expect 9000)")
        assert sw == SW_OK

        print("\n[T4] SET_TOUCH_POLICY P1=1 — TOUCH the board when the LED lights")
        input("      (the consent press), then press Enter to send… ")
        sw, _ = a(INS_SET_TOUCH_POLICY, 1)
        print(f"  -> SW={sw:#06x} (expect 9000)")
        assert sw == SW_OK
        sw, data = a(0x10)
        flags = data[7]
        assert flags & FLAG_TOUCH_BYPASS, "the advertisement must follow the flag"
        print(f"  -> flags={flags:#02x} — FLAG_TOUCH_BYPASS stands")

        print("\n[T5] the ten-signature chain — DO NOT touch the board; "
              "if the LED lights, the bypass failed")
        sw, data = a(0x11)  # LIST_KEYS
        assert sw == SW_OK and data and data[0] >= 1, "an identity is needed for the chain"
        for i in range(10):
            sw, data = a(0x15, 0, bytes(32))  # SIGN idx0
            assert sw == SW_OK, f"sign {i + 1}/10 refused {sw:#06x} — the bypass did not hold"
        print("  -> 10/10 signs answered 9000 with no touch")

        print("\n[T6] LOCK — the flag must die with the session")
        sw, _ = a(INS_LOCK)
        print(f"  -> SW={sw:#06x}")
        sw, data = a(0x10)
        flags = data[7]
        assert not flags & FLAG_TOUCH_BYPASS, "LOCK must clear the flag"
        sw, _ = a(INS_SET_TOUCH_POLICY, 1)
        print(f"  -> flags={flags:#02x}, disable-now answers {sw:#06x} "
              f"(expect 6982 — the session closed with the lock)")
        assert sw == SW_PIN_SESSION_REQUIRED

        print("\n[T7] the enable leg — friction-free in this locked state")
        sw, _ = a(INS_SET_TOUCH_POLICY, 0)
        print(f"  -> SW={sw:#06x} (expect 9000, no touch)")
        assert sw == SW_OK

        input("\n[T8] POWER CYCLE: unplug the board, wait 5 s, replug, then press Enter… ")
        a, conn = session()
        sw, data = a(0x10)
        flags = data[7]
        assert not flags & FLAG_TOUCH_BYPASS, "the RAM flag must die with the power"
        print(f"  -> flags={flags:#02x} — the bypass is gone after the power cycle")

        print("\n--touch-bypass legs done; the HID arm of this matrix rides the "
              "extension (US-1749's transcript records both)")
        conn.disconnect()
        return

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
