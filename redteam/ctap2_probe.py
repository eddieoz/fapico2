"""CTAP2 auth-state probes: PIN state, token-less ops, vendor channels, largeBlobs."""
import sys, time, json
sys.path.insert(0, "/home/eddieoz/Projects/git/pico/fapico2/redteam")
from ctaphid import CTAPHID
import cbor2

h = CTAPHID()
h.init()
chan = h.cid
print("cid=%08x" % chan)

def cbor_cmd(name, payload, timeout=10.0):
    try:
        r = h.cbor(chan, payload, timeout)
        st = r[0]
        body = r[1:]
        print("%-38s status=%02x len=%d %s" % (name, st, len(body), body.hex()[:100]))
        return st, body
    except Exception as e:
        print("%-38s EXC: %s" % (name, str(e)[:80]))
        return None, None

# --- PIN state ---------------------------------------------------------
# authenticatorClientPIN (0x06): {1: protocol, 2: subCommand}
cbor_cmd("clientPIN getPinRetries p=1", bytes([0x06]) + cbor2.dumps({1: 1, 2: 1}))
cbor_cmd("clientPIN getKeyAgreement p=1", bytes([0x06]) + cbor2.dumps({1: 1, 2: 2}))
cbor_cmd("clientPIN getKeyAgreement p=2", bytes([0x06]) + cbor2.dumps({1: 2, 2: 2}))
cbor_cmd("clientPIN setPIN no auth (p=1)", bytes([0x06]) + cbor2.dumps({1: 1, 2: 3, 3: b"\x00" * 16, 4: b"\x00" * 16}))
# authenticatorConfig (0x0D) proper map form: {1: subCommand}
cbor_cmd("config 0x01 enableEnterprise no tok", bytes([0x0D]) + cbor2.dumps({1: 1}))
cbor_cmd("config 0x03 toggleAlwaysUv no tok", bytes([0x0D]) + cbor2.dumps({1: 3}))

# --- token-less makeCredential (up=required default) -------------------
mc = {
    1: {"id": b"redteam-example.com", "name": "RedTeam Probe"},
    2: {"id": b"\x11" * 32, "name": "RT User"},
    3: {"alg": -7, "type": "public-key"},
    4: b"\x00" * 32,
    7: 0,
}
t0 = time.time()
st, body = cbor_cmd("makeCredential token-less", bytes([0x01]) + cbor2.dumps(mc), timeout=8.0)
print("   (elapsed %.1fs — device likely blinking for touch)" % (time.time() - t0))

# --- getAssertion without any rpId -------------------------------------
cbor_cmd("getAssertion no rpId", bytes([0x02]) + cbor2.dumps({}))
cbor_cmd("getAssertion unknown rp", bytes([0x02]) + cbor2.dumps({1: b"unknown-never-registered.example", 2: b"\x00" * 32}))

# --- largeBlobs read (0x0C): {1: get, 2: offset, 3: length} ------------
cbor_cmd("largeBlobs get 1024@0", bytes([0x0C]) + cbor2.dumps({1: True, 2: 0, 3: 1024}), timeout=15)

# --- vendor channels ---------------------------------------------------
cbor_cmd("unknown opcode 0x00", bytes([0x00]))
cbor_cmd("unknown opcode 0x41", bytes([0x41]))
cbor_cmd("unknown opcode 0x42", bytes([0x42]))
cbor_cmd("unknown opcode 0xFE", bytes([0xFE]))
cbor_cmd("unknown opcode 0xFF", bytes([0xFF]))

# --- credMgmt (0x0A) metadata without PIN token ------------------------
cbor_cmd("credMgmt getCredsMetadata", bytes([0x0A]) + cbor2.dumps({1: 0x01}))
cbor_cmd("credMgmt enumerateRpsBegin", bytes([0x0A]) + cbor2.dumps({1: 0x02}))

h.close()
print("\nNOTE: a touch prompt may be pending on the device from token-less makeCredential; canceling")
