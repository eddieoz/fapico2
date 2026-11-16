"""Check retry counter persistence across an unauthenticated REBOOT."""

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import hw_guard
hw_guard.require(
    what='the first real hidraw device (FIDO clientPIN getPinRetries) plus the CCID Rescue applet — issues an unauthenticated normal REBOOT (P1=0x00) and waits for the board to re-enumerate',
    destructive=False,
)

import sys, time
sys.path.insert(0, "/home/eddieoz/Projects/git/pico/fapico2/redteam")
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, ClientPin
from ccid import Card

dev = next(CtapHidDevice.list_devices())
r_before = ClientPin(Ctap2(dev)).get_pin_retries()
print("retries before reboot: %s" % (r_before,))

# --- unauthenticated REBOOT via the Rescue applet (P1=0x00 normal reboot) --
c = Card()
resp, sw = c.select("A0583FC19B7E4F21")
print("rescue SELECT SW=%04X" % sw)
r, sw = c.apdu(0x80, 0x1F, p1=0x00, p2=0x00)
print("REBOOT(normal) SW=%04X — board should drop off the bus" % sw)
c.disconnect()

# wait for the board to come back
print("waiting for re-enumeration ...")
for i in range(60):
    time.sleep(1)
    try:
        dev = next(CtapHidDevice.list_devices())
        break
    except StopIteration:
        continue
else:
    print("!! device did not come back within 60 s")
    sys.exit(1)
time.sleep(2)
r_after = ClientPin(Ctap2(next(CtapHidDevice.list_devices()))).get_pin_retries()
print("retries after unauthenticated reboot: %s" % (r_after,))
print("=> retry counter %s across reboot" %
      ("RESETS (brute-force unbounded)" if r_after[0] != r_before[0] else "PERSISTS"))
