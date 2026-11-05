"""PIN retry-counter persistence across a POWER CYCLE (operator performs the unplug).

The brute-force question: if the retry counter is RAM-only, every unplug
restores 8 attempts and PIN guessing is unbounded; if it is flash-resident,
the guesses are capped for the store's lifetime. (The related *unauthenticated
reboot* leg — no hands on the board at all — is reboot_retry.py.)

Reads the counter, tells the operator to power-cycle, then re-reads.

    exit 0  counter persisted (brute force bounded)   ·  exit 1 RESET (defect)
"""
import sys, time
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, ClientPin


def retries_or_none():
    try:
        dev = next(CtapHidDevice.list_devices())
        return ClientPin(Ctap2(dev)).get_pin_retries()
    except StopIteration:
        return None


before = retries_or_none()
if before is None:
    print("device not visible — power-cycle, then rerun (exit 2)")
    sys.exit(2)
print("retries before power cycle: %s" % (before,))

print("\nACTION: unplug the board now, wait 2 s, plug it back in, then press Enter.")
input("ready? ")
for attempt in range(30):
    after = retries_or_none()
    if after is not None:
        break
    print("waiting for device (%d s)" % attempt, flush=True)
    time.sleep(2)
else:
    print("device did not come back within 60 s (exit 2)")
    sys.exit(2)

print("retries after power cycle: %s" % (after,))
if before == after:
    print("PERSISTED — the counter is flash-resident; replug brute force is capped")
    sys.exit(0)
print("RESET — the counter is RAM-only: every power cycle restores full attempts")
sys.exit(1)
