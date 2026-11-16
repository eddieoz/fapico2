"""US-1908 TDD: the PIV suite kills only what it spawned.

``tests/piv/conftest.py`` pattern-kills *every* ``fapico2-emulation`` /
``ccid_relay.py`` process on the host (``pgrep -f`` + SIGTERM at session
``__init__``, ``restart()`` and fixture teardown). Under ``./run_tests.sh``
the shared relay + emulator are NOT ancestors of the pytest process, so the
moment the piv suite starts, the shared pair dies — and everything after it
that needs the shared pair (``tests/openpgp``, the root openpgp files) hits
``ccid_card``'s silent ``pytest.skip`` and does not run.

The fix (this story): a PRIVATE port pair for the piv relay/emulator (which
removes the conflict that motivated the pattern-kill) and cleanup scoped to
the recorded ``Popen`` handles. Host pytest — a stand-in process plays the
victim; no emulator, no hardware.
"""
from __future__ import annotations

import importlib.util
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PIV_CONFTEST = REPO_ROOT / "tests" / "piv" / "conftest.py"

# the shared pair run_tests.sh starts — the piv suite must never touch it
SHARED_CCID_PORT = 35963
SHARED_CLIENT_PORT = 35970


def _load_piv_conftest():
    spec = importlib.util.spec_from_file_location(
        "_fapico2_piv_conftest_us1908", str(PIV_CONFTEST))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Marker:
    """A stand-in victim whose command line names an emulator-looking string."""

    def __init__(self, name: str) -> None:
        self.name = name
        # bash (not dash): exec -a sets argv[0], so the kernel cmdline reads
        # "fapico2-emulation-...  sleep 30" — the pgrep -f shape that pattern
        # cleanup matches
        self.proc = subprocess.Popen(
            ["bash", "-c", "exec -a %s sleep 30" % name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def alive(self) -> bool:
        return self.proc.poll() is None

    def cleanup(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=5)


# --------------------------------------------------------------------------
# documentation of the defect: a pattern kill is ownership-blind
# --------------------------------------------------------------------------

def test_pattern_kill_documented_kills_unrelated_processes():
    """The defect class, reproduced with a stand-in victim: ``pgrep -f`` +
    SIGTERM over a command-line pattern kills processes the caller does not
    own. This is exactly how the piv suite killed run_tests.sh's shared
    emulator. Kept permanently, like US-1902's unsafe-order fixture, as the
    documentation of what the recorded-handle cleanup prevents."""
    marker = Marker("fapico2-emulation-us1908-doc-marker")
    try:
        time.sleep(0.2)
        assert marker.alive()
        out = subprocess.run(["pgrep", "-f", marker.name],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        assert out.stdout.strip(), "marker not visible to pgrep -f"
        for tok in out.stdout.split():
            try:
                os.kill(int(tok), signal.SIGTERM)
            except (ProcessLookupError, PermissionError, ValueError):
                pass
        time.sleep(0.3)
        assert not marker.alive(), "pattern kill left an unowned process alive"
    finally:
        marker.cleanup()


# --------------------------------------------------------------------------
# red tests — fail against the current pattern-kill / shared-port tree
# --------------------------------------------------------------------------

def test_piv_conftest_has_no_pattern_kill():
    """The piv conftest must not invoke any pgrep/pkill-style cleanup (a
    mention in a docstring is fine — an invocation is the defect)."""
    src = PIV_CONFTEST.read_text(encoding="utf-8")
    assert "_pkill" not in src
    # an invocation would name pgrep as an argument to a subprocess helper;
    # a docstring mention does not
    assert '"pgrep"' not in src and "'pgrep'" not in src


def test_piv_uses_a_private_port_pair():
    """The piv relay must not fight run_tests.sh's shared pair."""
    mod = _load_piv_conftest()
    assert mod.CCID_PORT != SHARED_CCID_PORT
    assert mod.CLIENT_PORT != SHARED_CLIENT_PORT
    # and the emulator must be pointed at the private dial-in, not the default
    src = PIV_CONFTEST.read_text(encoding="utf-8")
    assert "FAPICO2_CCID_PORT" in src, (
        "the piv emulator dials the default shared port unless pointed at the "
        "private relay")
    assert "FAPICO2_HID_PORT" in src, (
        "the piv emulator binds the shared HID port (35962) unless pointed at "
        "a private one")


# --------------------------------------------------------------------------
# green tests — the recorded-handle cleanup helper
# --------------------------------------------------------------------------

def test_cleanup_kills_only_recorded_handles():
    mod = _load_piv_conftest()
    victim_a = subprocess.Popen(["sleep", "30"])
    victim_b = subprocess.Popen(["sleep", "30"])
    bystander = Marker("fapico2-emulation-us1908-bystander")
    try:
        mod.kill_recorded(victim_a, victim_b)
        deadline = time.time() + 10
        while time.time() < deadline and (victim_a.poll() is None or victim_b.poll() is None):
            time.sleep(0.05)
        assert victim_a.poll() is not None, "recorded handle not killed"
        assert victim_b.poll() is not None, "recorded handle not killed"
        assert bystander.alive(), "cleanup killed a process it was not given"
    finally:
        bystander.cleanup()
        victim_a.kill()
        victim_b.kill()


def test_cleanup_is_idempotent_on_exited_handles():
    mod = _load_piv_conftest()
    exited = subprocess.Popen(["true"])
    exited.wait(timeout=5)
    # must not raise on an already-exited handle
    mod.kill_recorded(exited, None)


def test_stop_uses_the_recorded_handle_cleanup():
    """stop() itself must route through kill_recorded (so the fixture
    teardown's cleanup is the same recorded-handle path)."""
    src = PIV_CONFTEST.read_text(encoding="utf-8")
    assert "def kill_recorded" in src
    assert "kill_recorded(" in src.split("def stop(")[1].split("def ")[0]
