"""Phase 1 recon: capture device identity on every interface an attacker sees."""
import sys, json, struct, hashlib
sys.path.insert(0, "/home/eddieoz/Projects/git/pico/fapico2/redteam")
from ctaphid import CTAPHID, INIT, CBOR, PING, WINK, CANCEL, MSG, VENDOR
from ccid import Card, toBytes

def dump(label, b):
    print("  %s (%d): %s" % (label, len(b), b.hex()))

print("=== CTAPHID INIT (raw, hidraw8) ===")
h = CTAPHID()
chan, cmd, payload = h.init()
print("  allocated CID: %08x  iface=%d fw=%d.%d.%d caps=%02x" % (h.cid, h.proto, *h.fw, h.caps))
print("  fw bytes 13..15 (yubikit reads as FIRMWARE version): %d.%d.%d" % (payload[13], payload[14], payload[15]))
chan = h.cid

print("\n=== CTAPHID PING (echo integrity) ===")
try:
    r = h.ping(chan, b"REDBULL" * 8 + b"!")
    print("  ping echo ok len=%d tail=%s" % (len(r), r[-16:].hex()))
except Exception as e:
    print("  ping FAIL: %s" % e)

print("\n=== CTAPHID WINK ===")
try:
    r = h.wink(chan)
    print("  wink resp: %s" % r.hex())
except Exception as e:
    print("  wink: %s" % e)

print("\n=== CTAP2 authenticatorGetInfo (opcode 0x04, python-fido2 dialect) ===")
try:
    r = h.cbor(chan, bytes([0x04]))
    print("  status: %02x" % r[0])
    body = r[1:]
    import cbor2
    info = cbor2.loads(body)
    print(json.dumps({str(k): (v.hex() if isinstance(v, bytes) and len(str(v)) > 60 else v) for k, v in sorted(info.items())}, indent=2, default=str))
except ImportError:
    dump("raw getInfo", r)
except Exception as e:
    print("  getInfo FAIL: %s" % e)

print("\n=== CTAP2 GetInfo with CTAP 2.1 opcode 0x03 (spec dialect — protocol downgrade probe) ===")
try:
    r = h.cbor(chan, bytes([0x03]), timeout=3)
    print("  status: %02x len=%d" % (r[0], len(r)))
    dump("body", r[1:])
except Exception as e:
    print("  -> %s" % e)

print("\n=== CTAP2.1 authenticatorConfig (0x0D) without auth token ===")
try:
    r = h.cbor(chan, bytes([0x0D, 0x01]), timeout=3)
    print("  status: %02x (%s)" % (r[0], r[1:].hex()))
except Exception as e:
    print("  -> %s" % e)

h.close()

print("\n=== CCID: management applet READ_CONFIG (0x1D) ===")
try:
    c = Card()
    resp, sw = c.select("A000000527471117")
    print("  SELECT mgmt SW=%04X len=%d" % (sw, len(resp)))
    dump("mgmt identity", resp)
    # management READ_CONFIG
    r, sw = c.apdu(0x00, 0x1D)
    print("  READ_CONFIG SW=%04X" % sw)
    dump("config TLV", r)
    c.disconnect()
except Exception as e:
    print("  CCID FAIL: %s" % e)

print("\n=== CCID: OATH AID select — 7-byte vs 8-byte (Java yubikit mismatch probe) ===")
for aid, note in (("A0000005272101", "7-byte (ykman python)"),
                  ("A000000527210101", "8-byte (yubikit Java)")):
    try:
        c = Card()
        resp, sw = c.select(aid)
        print("  %s %s -> SW=%04X resp=%s" % (aid, note, sw, resp.hex()[:64]))
        c.disconnect()
    except Exception as e:
        print("  %s FAIL: %s" % (aid, e))

print("\n=== CCID: OpenPGP select + AID ===")
try:
    c = Card()
    resp, sw = c.select("D276000124010304000000000000000000")
    print("  SELECT PGP SW=%04X" % sw)
    dump("application id", resp)
    c.disconnect()
except Exception as e:
    print("  PGP FAIL: %s" % e)
