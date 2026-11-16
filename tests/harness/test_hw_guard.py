"""US-1900/1901/1902 TDD: the hardware-lane consent guard (hw_guard.py).

Every device-lane script (redteam/, tests/hardware/, tests/soak/, the
tests/scripts device scripts) must refuse to run when run without explicit
consent:

- without ``FAPICO2_HW_TESTS=1`` the script exits 2 naming what it would
  have opened, before any device enumeration; the literal ``1`` is the
  only accepted value — a truthy string set by habit does not open the
  lane;
- destructive legs (PIN burns, wipes, red-team attacks) additionally
  require an interactive terminal and a typed ``YES``; a non-interactive
  session — which is what an agent session is — exits 3 even with the
  env var set.

The exit-code contract is driven in-process through ``SystemExit`` codes
with a monkeypatched environment and stdin (so the suite stays
host-runnable with no emulator and no hardware); one case runs through a
real interpreter so the exit code is a process exit code. The two
ordering fixtures of US-1902 run as real child processes with fully
literal argv, each recording any device-enumeration call to a file so
the test can prove whether enumeration preceded the refusal.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "hw_guard_fixtures"
UNSAFE_FIXTURE = FIXTURES / "unsafe_order.py"
SAFE_FIXTURE = FIXTURES / "safe_order.py"
RECORD_VAR = "HW_GUARD_RECORD"

# make the repo-root module importable (tests/conftest.py puts tests/, not
# the repository root, on sys.path)
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import hw_guard  # noqa: E402

WHAT = "the first real hidraw device (FIDO/CTAPHID), consuming PIN retry attempts"


class NonTty:
    def isatty(self):
        return False


class Tty:
    def isatty(self):
        return True


# --------------------------------------------------------------------------
# US-1900 — the guard refuses without consent
# --------------------------------------------------------------------------

def test_refuses_without_env_var(monkeypatch, capsys):
    monkeypatch.delenv("FAPICO2_HW_TESTS", raising=False)
    with pytest.raises(SystemExit) as exc:
        hw_guard.require(what=WHAT)
    assert exc.value.code == 2
    out = capsys.readouterr().out
    assert WHAT in out
    assert "FAPICO2_HW_TESTS=1" in out


def test_refusal_output_is_actionable_text_not_a_traceback(monkeypatch, capsys):
    monkeypatch.delenv("FAPICO2_HW_TESTS", raising=False)
    with pytest.raises(SystemExit) as exc:
        hw_guard.require(what=WHAT)
    assert exc.value.code == 2
    out = capsys.readouterr().out
    assert "Traceback" not in out
    # the rule must be stated: hardware lanes are never automated
    assert "hardware" in out.lower() or "device" in out.lower()


def test_allows_literal_one(monkeypatch, capsys):
    monkeypatch.setenv("FAPICO2_HW_TESTS", "1")
    # must return without raising
    hw_guard.require(what=WHAT)
    assert WHAT in capsys.readouterr().out  # the acknowledgement echoes the surface


@pytest.mark.parametrize("bad", ["yes", "true", "0", "", "YES", "1.0", " 1"])
def test_any_value_other_than_literal_one_refuses(monkeypatch, bad):
    monkeypatch.setenv("FAPICO2_HW_TESTS", bad)
    with pytest.raises(SystemExit) as exc:
        hw_guard.require(what=WHAT)
    assert exc.value.code == 2, "value %r must not open the lane" % bad


def test_real_process_refuses_with_exit_2():
    """One case through a real interpreter: the exit code is a process
    exit code, not only a SystemExit."""
    code = "import hw_guard; hw_guard.require(what='probe surface')"
    r = subprocess.run(["python3", "-c", code], capture_output=True,
                       text=True, timeout=30, shell=False)
    assert r.returncode == 2
    assert "probe surface" in r.stdout
    assert "Traceback" not in r.stderr


# --------------------------------------------------------------------------
# US-1901 — the destructive tier refuses a non-interactive caller
# --------------------------------------------------------------------------

def test_destructive_non_tty_exits_3_even_with_consent(monkeypatch, capsys):
    monkeypatch.setenv("FAPICO2_HW_TESTS", "1")
    monkeypatch.setattr(sys, "stdin", NonTty())
    with pytest.raises(SystemExit) as exc:
        hw_guard.require(what=WHAT, destructive=True)
    assert exc.value.code == 3
    combined = capsys.readouterr().out.lower()
    assert "terminal" in combined or "interactive" in combined


def test_destructive_without_env_var_still_exits_2(monkeypatch):
    # tiering must not weaken the base refusal
    monkeypatch.delenv("FAPICO2_HW_TESTS", raising=False)
    with pytest.raises(SystemExit) as exc:
        hw_guard.require(what=WHAT, destructive=True)
    assert exc.value.code == 2


def test_destructive_tty_correct_token_proceeds(monkeypatch, capsys):
    monkeypatch.setenv("FAPICO2_HW_TESTS", "1")
    monkeypatch.setattr(sys, "stdin", Tty())
    monkeypatch.setattr("builtins.input", lambda prompt="": "YES\n")
    # must not raise SystemExit
    hw_guard.require(what=WHAT, destructive=True)
    assert "YES" in capsys.readouterr().out


def test_destructive_tty_wrong_token_refuses(monkeypatch):
    monkeypatch.setenv("FAPICO2_HW_TESTS", "1")
    monkeypatch.setattr(sys, "stdin", Tty())
    monkeypatch.setattr("builtins.input", lambda prompt="": "no\n")
    with pytest.raises(SystemExit) as exc:
        hw_guard.require(what=WHAT, destructive=True)
    assert exc.value.code == 3


def test_destructive_prompt_echoes_what_will_burn(monkeypatch, capsys):
    """The operator sees what is consumed before typing the token."""
    monkeypatch.setenv("FAPICO2_HW_TESTS", "1")
    monkeypatch.setattr(sys, "stdin", Tty())
    monkeypatch.setattr("builtins.input", lambda prompt="": "YES\n")
    hw_guard.require(what=WHAT, destructive=True)
    out = capsys.readouterr().out
    # the banner naming the surface precedes the consent acknowledgement
    assert out.index("DESTRUCTIVE device lane: %s" % WHAT) < out.index("consent accepted")


# --------------------------------------------------------------------------
# US-1902 — the guard fires before any device enumeration
# --------------------------------------------------------------------------

def _run_unsafe_fixture() -> subprocess.CompletedProcess:
    return subprocess.run(
        ["python3", str(UNSAFE_FIXTURE)],
        capture_output=True, text=True, timeout=30, shell=False,
    )


def _run_safe_fixture() -> subprocess.CompletedProcess:
    return subprocess.run(
        ["python3", str(SAFE_FIXTURE)],
        capture_output=True, text=True, timeout=30, shell=False,
    )


def test_unsafe_order_documented_enumerates_before_refusal(monkeypatch, tmp_path):
    """The red fixture: enumerate first, require after — kept as the
    documentation of the hazard the guard prevents. The script exits 2,
    but the device was already opened: the record file is non-empty."""
    record = tmp_path / "record.log"
    monkeypatch.setenv(RECORD_VAR, str(record))
    r = _run_unsafe_fixture()
    assert r.returncode == 2
    assert record.read_text().strip() != ""


def test_safe_order_refuses_with_zero_enumerations(monkeypatch, tmp_path):
    record = tmp_path / "record.log"
    monkeypatch.setenv(RECORD_VAR, str(record))
    r = _run_safe_fixture()
    assert r.returncode == 2
    # zero enumerations: the stub only creates the record file on a call
    assert not record.exists() or record.read_text().strip() == ""
