"""Timing side-channel on clientPIN verify — measurement only, INCONCLUSIVE by design.

The concern: if PIN comparison early-exits on the first mismatching digit (or
leaks length), an attacker with USB access can narrow the PIN remotely. This
script measures the *host-observable* latency of wrong-PIN getPinToken calls.

HONEST LIMITATION (docs/audits/2026-11-05-redteam-quality-audit.md T1): the getPinToken path runs a
full ECDH handshake (~1.2 s measured) that dominates the verify stage, and USB
jitter is milliseconds. With the sample budget a retry counter forces, NO
implementation of the leak this script names could move these numbers — a
clean spread here is NOT evidence of absence. A real proof needs verify-stage
isolation (differential against a no-ECDH command) and >=30 same-length
samples. This probe exists to record the baseline and to catch a gross
(per-second) defect, nothing more.

Retry budget is computed from the device at run time, never narrated: this
script spends exactly RETRY_BUDGET of the remaining attempts and refuses to
run below a safety floor. Exit codes: 0 no gross anomaly · 1 gross timing
defect · 2 environment/insufficient budget.
"""
import sys, time, statistics
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, ClientPin
from fido2 import ctap

RETRY_BUDGET = 3      # attempts this script may burn
RETRY_FLOOR = 3       # never take the device below this many remaining

dev = next(CtapHidDevice.list_devices())
cp = ClientPin(Ctap2(dev))
remaining = cp.get_pin_retries()
if isinstance(remaining, tuple):
    remaining = remaining[0]
print("retries remaining: %s" % remaining)
if remaining is None or remaining - RETRY_BUDGET < RETRY_FLOOR:
    print("INSUFFICIENT BUDGET: refusing to burn below the floor (%d)" % RETRY_FLOOR)
    sys.exit(2)

def timed_wrong(pin):
    t0 = time.perf_counter()
    try:
        cp.get_pin_token(pin)
        return (time.perf_counter() - t0) * 1000, "ACCEPTED?!"
    except ctap.CtapError as e:
        return (time.perf_counter() - t0) * 1000, "0x%02X" % e.code

# same length (6 digits), different values — a gross per-value leak would show
samples = {}
for pin in ("000000", "999999", "123456"):
    ms, st = timed_wrong(pin)
    samples[pin] = ms
    print("  PIN %-8s -> %8.1f ms  %s" % (pin, ms, st))

print("\nretries after timing test: %s" % (cp.get_pin_retries(),))
spread = max(samples.values()) - min(samples.values())
print("same-length spread: %.1f ms over %d samples (ECDH-dominated transport)" %
      (spread, len(samples)))
if spread > 500:
    print("GROSS ANOMALY: spread over 500 ms — investigate before any further claim")
    sys.exit(1)
print("INCONCLUSIVE by construction: the ~%.0f ms ECDH handshake and the sample "
      "budget mask any per-digit leak (see module docstring). This run is a "
      "baseline record, not a clean bill." % statistics.median(list(samples.values())))
sys.exit(0)
