"""US-1902 red fixture: device enumeration BEFORE the consent guard.

Kept in the suite as documentation of the hazard hw_guard prevents: this
script touches the device (here: the stub records the call) before the
guard can refuse, so even a correct refusal comes too late. The
check_hw_isolation gate (US-1906) makes this order a rule violation.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, REPO)

from fido2.hid import CtapHidDevice  # noqa: E402  (the stub)

next(CtapHidDevice.list_devices(), None)  # the hazard: enumerate first

import hw_guard  # noqa: E402

hw_guard.require(what="stub device (US-1902 unsafe-order fixture)")
print("unreachable: the guard must have refused")
