"""Post power-cycle: does the PIN retry counter persist in flash?

Before the freeze the sequence was:
  baseline retries = 8
  wrong PIN #1     -> PIN_INVALID, retries 7
  unauthenticated Rescue REBOOT -> enumeration failure (board frozen)
  user power-cycled the board

If retries now read 8, the counter lives in RAM only and every power cycle
restores all attempts: PIN guessing becomes unbounded. If it reads 7, the
counter is flash-resident and brute force is capped at 8 attempts per
credential store lifetime.
"""
import sys, time
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, ClientPin

for attempt in range(30):
    try:
        dev = next(CtapHidDevice.list_devices())
        break
    except StopIteration:
        print("waiting for device (%d s)" % attempt, flush=True)
        time.sleep(2)
else:
    sys.exit("device not visible")

cp = ClientPin(Ctap2(dev))
print("retries after power cycle:", cp.get_pin_retries())