"""US-1902 green fixture: the consent guard BEFORE device enumeration.

The order every device-lane script must use (US-1903/1904/1905 wire it
everywhere): the guard's refusal happens with zero device contact.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, REPO)

import hw_guard  # noqa: E402

hw_guard.require(what="stub device (US-1902 safe-order fixture)")

from fido2.hid import CtapHidDevice  # noqa: E402  (the stub)

next(CtapHidDevice.list_devices(), None)
print("unreachable: the guard must have refused")
