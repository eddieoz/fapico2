"""US-1902 stub backend: stands in for python-fido2's HID layer.

``CtapHidDevice.list_devices`` appends one line to the file named by the
``HW_GUARD_RECORD`` environment variable every time it is called, so a
test can prove whether device enumeration preceded a guard refusal.
"""
import os


class CtapHidDevice:
    @classmethod
    def list_devices(cls):
        record = os.environ.get("HW_GUARD_RECORD")
        if record:
            with open(record, "a") as fh:
                fh.write("list_devices called\n")
        return iter(())
