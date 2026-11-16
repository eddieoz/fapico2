"""US-1907 TDD: an unreachable emulator is a loud failure that never touches PC-SC.

The ``CtapPcscDevice`` fallback in ``tests/conftest.py``'s ``Device`` was
dead-by-luck, not refused-by-construction: fido2 2.2.1's ``list_devices``
raises before the fallback line, but any of a fido2 upgrade (1.x OSError-
swallowing semantics), a shim returning ``[]``, or a try/except added
upstream re-arms it — and then ``test_010_pin.py::test_lockout`` reproduces
the 2026-11-16 incident exactly (nine wrong PINs to PIN_BLOCKED, then
``authenticatorReset``) on the first real PC/SC reader.

These tests simulate the arming change and require the loud, port-naming
refusal instead. Host pytest; the happy-path case skips when no emulator
is listening (it is pinned so the loud failure cannot be achieved by
breaking discovery).
"""
from __future__ import annotations

import socket
import sys

import pytest

EMU_HOST = "127.0.0.1"
EMU_PORT = 35962


def _emulator_listening() -> bool:
    try:
        with socket.create_connection((EMU_HOST, EMU_PORT), timeout=1):
            return True
    except OSError:
        return False


def _poison_pcsc(monkeypatch) -> None:
    """A poisoned sys.modules entry: any ``import fido2.pcsc`` raises."""
    monkeypatch.setitem(sys.modules, "fido2.pcsc", None)


def test_empty_discovery_fails_loudly_naming_emulator(monkeypatch):
    """The exact change that would arm the old fallback: the shim yields
    nothing. Device must refuse loudly naming the emulator port and the
    never-real-hardware rule — never enumerate PC-SC."""
    import conftest

    monkeypatch.setattr("fido2.hid.list_descriptors", lambda: [])
    _poison_pcsc(monkeypatch)
    with pytest.raises(RuntimeError) as exc:
        conftest.Device()
    msg = str(exc.value)
    assert EMU_HOST in msg and str(EMU_PORT) in msg
    assert "never attach to real hardware" in msg


def test_refused_connection_fails_loudly_never_pcsc(monkeypatch):
    """Emulator port refusing: the same loud failure, with the original
    error named — and no PC-SC enumeration anywhere behind it."""
    import conftest

    def _refuse(descriptor):
        raise ConnectionRefusedError("intentionally refused (US-1907)")

    monkeypatch.setattr("fido2.hid.open_connection", _refuse)
    _poison_pcsc(monkeypatch)
    with pytest.raises(RuntimeError) as exc:
        conftest.Device()
    msg = str(exc.value)
    assert EMU_HOST in msg and str(EMU_PORT) in msg
    assert "never attach to real hardware" in msg
    assert "ConnectionRefusedError" in msg or "refused" in msg


@pytest.mark.skipif(not _emulator_listening(),
                    reason="emulator not listening on 127.0.0.1:35962")
def test_live_emulator_still_constructs_over_usb_hid():
    """The happy path is pinned: with the emulator live, Device constructs
    and reports the USB HID channel — the loud refusal cannot be achieved
    by breaking discovery."""
    import conftest

    d = conftest.Device()
    assert d.dev is not None
