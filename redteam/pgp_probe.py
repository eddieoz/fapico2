"""OpenPGP card 3.4 attack battery over CCID.

Tests the classic OpenPGP card attack surface:
  1. Unauthenticated DOs (fingerprint, name, AID) — information disclosure
  2. PW status (00C4) — retry counters, PW validity, whether PW1 is cached
  3. Signature without PW1 (PSO:CDS) — must be refused
  4. INTERNAL AUTHENTICATE without PW1
  5. Private key template import before PW3 (PUT DO 4D)
  6. ECDH/PSO:DECIPHER oracle — uniform error for malformed points
  7. Resetting code / RESET RETRY COUNTER without it
"""
import sys, time
sys.path.insert(0, "/home/eddieoz/Projects/git/pico/fapico2/redteam")
from ccid import Card

AID = "D276000124010304000000000000000000"

c = Card()
r, sw = c.select(AID)
print("SELECT OpenPGP SW=%04X len=%d" % (sw, len(r)))
print("  AID response: %s" % r.hex())

def get_data(do_hex, name):
    tag = bytes.fromhex(do_hex)
    try:
        resp, sw = c.apdu(0x00, 0xCA, p1=0x3F, p2=0x00, data=tag, le=0)
        print("  GET DATA %-22s (%s) SW=%04X len=%d %s" % (name, do_hex, sw, len(resp), resp.hex()[:60]))
        return resp, sw
    except Exception as e:
        print("  GET DATA %-22s err %s" % (name, str(e)[:40]))
        return None, None

print("\n=== 1. Unauthenticated DOs ===")
for do, name in (("4F", "AID"), ("5B", "Name"), ("65", "Cardholder"),
                 ("5F2D", "Language"), ("6E", "URL"), ("73", "Discreet verify?"),
                 ("5F50", "URL?"), ("C4", "PW status"), ("CD", "Private keys?"),
                 ("CE", "Fingerprints?"), ("F0", "Extended caps")):
    get_data(do, name)

print("\n=== 2. PW status (00C4) — retry counters ===")
r, sw = get_data("C4", "PW status bytes")
if r and len(r) >= 7:
    print("    PW1 max=%d retries=%d  PW3 max=%d retries=%d  (byte4: PW1 valid-for=%d)"
          % (r[4], r[5], r[6], r[7] if len(r) > 7 else -1, r[4]))

print("\n=== 3. PSO:COMPUTE DIGITAL SIGNATURE without PW1 ===")
# INS 0x2A, P1=0x9E, P2=0x9A (sign), with a dummy 32-byte digest
try:
    resp, sw = c.apdu(0x00, 0x2A, p1=0x9E, p2=0x9A, data=b"\x00" * 32)
    print("  PSO:CDS (no PW1) SW=%04X len=%d %s  <- 6982/6A80 expected, 9000 = VULN" % (sw, len(resp), resp.hex()[:40]))
except Exception as e:
    print("  PSO:CDS err: %s" % str(e)[:60])

print("\n=== 4. INTERNAL AUTHENTICATE without PW1 ===")
try:
    resp, sw = c.apdu(0x00, 0x88, p1=0x00, p2=0x00, data=b"\x01" + b"\x00" * 20)
    print("  INTERNAL AUTHENTICATE SW=%04X len=%d %s  <- 6982/6A88 expected" % (sw, len(resp), resp.hex()[:40]))
except Exception as e:
    print("  INTERNAL AUTHENTICATE err: %s" % str(e)[:60])

print("\n=== 5. PUT DO (template import) before PW3 ===")
# Try to import a private key template without admin PIN
template = bytes([0x00]) + b"\x01" + b"\x00" * 6   # 7F48 control reference
try:
    resp, sw = c.apdu(0x00, 0xDA, p1=0x3F, p2=0x00, data=template, le=0)
    print("  PUT DO (no PW3) SW=%04X  <- 6982/6A80 expected, 9000 = VULN" % sw)
except Exception as e:
    print("  PUT DO err: %s" % str(e)[:60])

print("\n=== 6. PSO:DECIPHER ECDH oracle — malformed points ===")
# Invalid-curve / small-subgroup attack: feed several malformed ciphertexts
# and check whether (status word, output length) differ.
oracle = {}
malformed = {
    "zero": b"\x00" * 32,
    "one": b"\x01" + b"\x00" * 31,
    "all-FF": b"\xff" * 32,
    "small-order": bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
    "P-256 order": bytes.fromhex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
    "invalid-coord": bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
}
for name, ct in malformed.items():
    try:
        body = b"\xa4\x01\x09" + b"\x00" * 65  # AID-like prefix + point
        body = bytes([0xA0]) + b"\x80" + b"\x41" + b"\x04" + ct  # 80|04 as tag/length
        resp, sw = c.apdu(0x00, 0x2A, p1=0xFF, p2=0x00, data=b"\xB6" + body, le=0)
        sig = (sw, len(resp))
        oracle[name] = sig
        print("  PSO:DECIPHER %-14s SW=%04X len=%d" % (name, sw, len(resp)))
    except Exception as e:
        oracle[name] = ("err", str(e)[:30])
        print("  PSO:DECIPHER %-14s err %s" % (name, str(e)[:40]))
distinct = set(oracle.values())
print("  => %d distinct (sw,len) responses across malformed inputs: %s"
      % (len(distinct), "UNIFORM (no oracle)" if len(distinct) == 1 else "DISTINGUISHABLE = potential oracle"))

print("\n=== 7. RESET RETRY COUNTER without resetting code ===")
try:
    resp, sw = c.apdu(0x00, 0x2C, p1=0x00, p2=0x00, data=b"\x00" * 8)
    print("  RESET RETRY COUNTER SW=%04X  <- 6982/63CX expected" % sw)
except Exception as e:
    print("  RESET RETRY COUNTER err: %s" % str(e)[:60])

print("\n=== 8. GET CHALLENGE / VERIFY empty ===")
try:
    resp, sw = c.apdu(0x00, 0x84, p1=0x00, p2=0x00, data=b"\x00" * 8)
    print("  GET CHALLENGE SW=%04X len=%d %s  <- randomness quality" % (sw, len(resp), resp.hex()[:40]))
except Exception as e:
    print("  GET CHALLENGE err: %s" % str(e)[:60])
try:
    resp, sw = c.apdu(0x00, 0x20, p1=0x00, p2=0x82, data=b"1234")
    print("  VERIFY PW1 (wrong '1234') SW=%04X  <- 63Cx expected (retries decremented)" % sw)
except Exception as e:
    print("  VERIFY err: %s" % str(e)[:60])

c.disconnect()