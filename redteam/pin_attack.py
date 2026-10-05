"""PIN retry counter state machine + timing, with minimal retry burn."""
import sys, time, statistics
sys.path.insert(0, "/home/eddieoz/Projects/git/pico/fapico2/redteam")
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, ClientPin
from fido2.ctap1 import Ctap1
from fido2 import ctap

dev = next(CtapHidDevice.list_devices())
ctap2 = Ctap2(dev)
cp = ClientPin(ctap2)

def retries():
    return cp.get_pin_retries()

r0 = retries()
print("pin retries baseline: %s" % (r0,))

# --- timing of an UNAUTHENTICATED command (baseline device latency) ------
t = []
for _ in range(30):
    t0 = time.perf_counter(); retries(); t.append(time.perf_counter() - t0)
print("getPinRetries latency: median=%.2fms p95=%.2fms" % (
    statistics.median(t) * 1000, sorted(t)[28] * 1000))

# --- CTAP1 (U2F) downgrade probe on a PIN-set board ----------------------
try:
    c1 = Ctap1(dev)
    c1.ping(b"downgrade-probe")
    print("CTAP1 PING: OK (transport alive)")
except Exception as e:
    print("CTAP1 PING err:", e)
try:
    c1 = Ctap1(dev)
    reg = c1.register(b"\x00" * 32, b"\x01" * 32)
    print("CTAP1 REGISTER: ACCEPTED — downgrade possible!", reg[:8].hex())
except ctap.CtapError as e:
    print("CTAP1 REGISTER refused: %s" % e)
except Exception as e:
    print("CTAP1 REGISTER: %s: %s" % (type(e).__name__, e))

# --- wrong PIN #1 (6 digits) with timing ----------------------------------
t0 = time.perf_counter()
try:
    cp.get_pin_token("000000")
    print("!! PIN 000000 WORKED — device PIN is trivially guessable")
except ctap.CtapError as e:
    print("wrong PIN (000000) refused: %s (%s) in %.2fms" % (e.code, e, (time.perf_counter()-t0)*1000))
r1 = retries()
print("pin retries after 1 wrong: %s  (decrement: %s)" % (r1, r0[3] - r1[3] if r1 and r0 else "?"))

# --- wrong PIN #2 (longer, to detect length-based early exit) -------------
t0 = time.perf_counter()
try:
    cp.get_pin_token("1234567890123")
except ctap.CtapError as e:
    print("wrong PIN (13 chars) refused: %s in %.2fms" % (e.code, (time.perf_counter()-t0)*1000))
r2 = retries()
print("pin retries after 2 wrong: %s" % r2)

# --- pinUvAuth token permission probing ----------------------------------
# legacy leg (subCommand 0x05, no permissions) vs 2.1 leg (0x09 with perms)
from fido2.ctap2.pin import PinProtocolV1
# (no further wrong attempts — retries are a consumable resource)
print("\nSTOPPING PIN attempts: 2 of %d retries burned" % (r0[3] if r0 else "?"))
