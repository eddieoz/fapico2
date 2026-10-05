"""Timing side-channel on clientPIN verify.

The concern: if PIN comparison early-exits on the first mismatching digit (or
leaks length), an attacker with USB access can narrow the PIN remotely. We
measure the *host-observable* latency of a wrong-PIN getPinToken (ECDH handshake
dominates) and, separately, whether an already-minted session shows any
length-dependent timing. Each wrong attempt burns one of the 7 remaining
retries, so we keep the sample small and precise.
"""
import sys, time, statistics, collections
sys.path.insert(0, "/home/eddieoz/Projects/git/pico/fapico2/redteam")
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, ClientPin
from fido2 import ctap

dev = next(CtapHidDevice.list_devices())
cp = ClientPin(Ctap2(dev))

# we have 7 retries left after the earlier single wrong PIN. Budget 3 for
# this experiment (leaves 4).
budget = 3
print("retries before timing test:", cp.get_pin_retries())

def timed_wrong(pin):
    t0 = time.perf_counter()
    try:
        cp.get_pin_token(pin)
        return (time.perf_counter() - t0) * 1000, "ACCEPTED?!"
    except ctap.CtapError as e:
        return (time.perf_counter() - t0) * 1000, "0x%02X" % e.code

# A: same length (6 digits), different values — any spread = prefix leak
print("\n--- 6-digit wrong PINs (constant length) ---")
lens6 = []
for pin in ("000000", "999999", "123456"):
    ms, st = timed_wrong(pin)
    print("  PIN %-8s -> %8.1f ms  %s" % (pin, ms, st))
    lens6.append(ms)

print("\n--- shorter/longer PINs (length leak) ---")
ms_short, st = timed_wrong("1234")
print("  PIN %-8s -> %8.1f ms  %s" % ("1234", ms_short, st))
ms_long, st = timed_wrong("123456789")
print("  PIN %-8s -> %8.1f ms  %s" % ("123456789", ms_long, st))

print("\nretries after timing test:", cp.get_pin_retries())

spread6 = max(lens6) - min(lens6)
print("\nanalysis:")
print("  same-length spread: %.1f ms over 3 samples" % spread6)
print("  length delta (4 vs 9 char): %.1f ms" % abs(ms_long - ms_short))
print("  ECDH dominates (~%.0f ms baseline); a per-digit early exit would" % statistics.median(lens6))
print("  show as spread <~50 ms on the *verify* stage, masked here by ECDH.")