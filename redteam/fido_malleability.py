"""FIDO2 malleability + store-flood battery (CTAPHID, raw).

Malleability questions that need no credential:
  1. Does the device REFLECT a client-claimed `up`/`uv` flag into anything it
     returns, or does it enforce its own state? (NDSS attack-6 class: a device
     that echoes claimed flags is exploitable exactly like the alwaysUv lie.)
  2. Is the getInfo response reproducible byte-for-byte (a device that varies
     it leaks per-call state, e.g. a counter or a nonce)?
  3. Does a mutated response frame get accepted on the next command (i.e. does
     the device validate anything about the channel it just used)?
  4. Store flood: hammer credMgmt / largeBlobs / makeCredential without a
     token and confirm bounded errors and no state damage.
"""
import sys, time, hashlib, cbor2
sys.path.insert(0, "/home/eddieoz/Projects/git/pico/fapico2/redteam")
from ctaphid import CTAPHID

h = CTAPHID("/dev/hidraw8")
h.init()
cid = h.cid

def cmd(name, payload, timeout=6.0):
    try:
        r = h.cbor(cid, payload, timeout)
        print("  %-40s status=0x%02x len=%d" % (name, r[0], len(r) - 1))
        return r
    except Exception as e:
        print("  %-40s %s" % (name, str(e)[:50]))
        return None

print("=== 1. getInfo determinism (per-call state leak?) ===")
a = h.cbor(cid, bytes([0x04]))[1:]
time.sleep(0.3)
b = h.cbor(cid, bytes([0x04]))[1:]
print("  getInfo byte-identical across calls: %s" % (a == b))
if a != b:
    print("  first : %s" % a[:64].hex())
    print("  second: %s" % b[:64].hex())

print("\n=== 2. flag coercion: claim uv/up the device does not honour ===")
# getAssertion with options claiming up=false,uv=false on a PIN-set device
for opts, nm in (({"up": False, "uv": False}, "up=false uv=false"),
                 ({"up": True, "uv": False}, "up=true uv=false"),
                 ({"up": False, "uv": True}, "up=false uv=true"),
                 ({"up": True, "uv": "discouraged"}, "uv=discouraged"),
                 ({}, "no options")):
    body = {1: b"redteam.example", 2: b"\x22" * 32, 3: opts}
    cmd("getAssertion %s" % nm, bytes([0x02]) + cbor2.dumps(body), 4.0)

print("\n=== 3. makeCredential flag coercion (up=false must still be refused) ===")
for opts, nm in (({"up": False}, "up=false"),
                 ({"up": True, "uv": "discouraged"}, "up=true uv=discouraged"),
                 ({"up": True, "rk": True}, "rk=true"),
                 ({"up": True, "uv": "required"}, "uv=required")):
    mc = {1: {"id": b"redteam.example", "name": "RT"},
          2: {"id": b"\x22" * 32, "name": "U"},
          3: {"alg": -7, "type": "public-key"},
          4: b"\x33" * 32, 5: {}, 7: opts}
    cmd("makeCredential %s" % nm, bytes([0x01]) + cbor2.dumps(mc), 4.0)

print("\n=== 4. store flood without a token (bounded errors, no damage) ===")
print("  -- largeBlobs --")
for i, m in enumerate(({"1": 1024, "2": 0}, {"1": 4096, "2": 4096},
                       {"1": 65535, "2": 0}, {"1": 0, "2": 0})):
    cmd("largeBlobs get %s" % m, bytes([0x0C]) + cbor2.dumps({1: int(m["1"]), 2: int(m["2"])}), 4.0)
cmd("largeBlobs set 1KiB", bytes([0x0C]) + cbor2.dumps(
    {1: 1024, 2: 0, 3: b"\xAA" * 1024}), 6.0)

print("  -- credMgmt (every subcommand, no token) --")
for sub in range(1, 0x12):
    cmd("credMgmt sub %02X" % sub, bytes([0x0A]) + cbor2.dumps({1: sub}), 3.0)

print("  -- authenticatorConfig (every subcommand, no token) --")
for sub in range(1, 0x0C):
    cmd("config sub %02X" % sub, bytes([0x0D]) + cbor2.dumps({1: sub}), 3.0)

print("\n=== 5. device still coherent after the flood? ===")
r = h.cbor(cid, bytes([0x04]))
print("  getInfo status=0x%02x len=%d" % (r[0], len(r) - 1))
ok = h.ping(cid, b"ALIVE-AFTER-FLOOD")
print("  PING: %s" % ("ALIVE" if ok == b"ALIVE-AFTER-FLOOD" else "BROKEN: %r" % ok))

h.close()