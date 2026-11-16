"""Consent gate for the hardware lanes.

Every script that can open a real device — ``redteam/``, ``tests/hardware/``,
``tests/soak/`` (usb transport) and the ``tests/scripts`` device scripts —
calls ``hw_guard.require`` as its first executable statement, before any
device enumeration (several of these scripts enumerate at module import
time, e.g. ``redteam/pin_attack.py:9``).

Contract (US-1900/1901, EPIC HW-LANE-CONSENT, docs/tasks/EPIC-hardware-lane-consent.md):

- Without ``FAPICO2_HW_TESTS=1`` the call prints what the script would have
  opened and what it consumes, names the opt-in, and ``sys.exit(2)``.
- The literal ``1`` is the only accepted value: a truthy string set by
  habit (``yes``, ``true``, ``0``...) is a refusal.
- ``destructive=True`` legs (PIN burns, wipes, red-team attacks)
  additionally require an interactive terminal and a typed ``YES``: with
  the env var set but stdin not a TTY the call exits 3; at a terminal the
  operator must type ``YES`` after seeing what will be consumed. An agent
  session runs non-interactively by definition, so the destructive tier is
  unreachable to it under any environment.

The emulator gate suites under ``tests/`` never call this module: they are
socket-bound to 127.0.0.1:35962 and cannot reach hardware (see the epic's
facts). The refusal message is where a session learns the difference
between the two lanes.
"""
from __future__ import annotations

import os
import sys

ENV_VAR = "FAPICO2_HW_TESTS"
CONFIRM_TOKEN = "YES"
_RULE = (
    "Hardware lanes are never part of any automated suite. The emulator "
    "gate (./run_tests.sh) runs against 127.0.0.1:35962 and never touches "
    "a real board."
)


def require(what: str, destructive: bool = False) -> None:
    """Refuse unless the operator has consented to this specific device lane.

    Exit codes: 2 = no consent (env var absent or not the literal ``1``);
    3 = destructive leg without an interactive terminal or without the
    typed ``YES`` token. Returns normally only when the lane is open.
    """
    value = os.environ.get(ENV_VAR)
    if value != "1":
        print("REFUSED: this script would open %s." % what)
        print("Consent: set %s=1 for this one command, e.g." % ENV_VAR)
        print("    %s=1 python3 %s" % (ENV_VAR, _script_name()))
        print("Why: %s" % _RULE)
        sys.exit(2)

    if destructive:
        if not sys.stdin.isatty():
            print("REFUSED: %s is a DESTRUCTIVE device lane (%s)." % (_script_name(), what))
            print(
                "It burns consumable device state (PIN retry attempts, wipes, "
                "attack legs). It requires an interactive terminal and a typed "
                "confirmation, and cannot run from a non-interactive session "
                "(exit 3). Run it yourself from a terminal you sit at."
            )
            sys.exit(3)

        print("DESTRUCTIVE device lane: %s" % what)
        print("This burns consumable device state. Type %s to proceed "
              "(anything else refuses)." % CONFIRM_TOKEN)
        try:
            answer = input()
        except EOFError:
            # Ctrl-D is not a consent token: refuse cleanly, no traceback
            answer = ""
        if answer.strip() != CONFIRM_TOKEN:
            print("REFUSED: confirmation token not typed. Device untouched.")
            sys.exit(3)

    print("[hw-guard] consent accepted: %s" % what)


def _script_name() -> str:
    import inspect

    frame = inspect.stack()
    # frame 0 = _script_name itself, 1 = require, 2 = the caller (the
    # device-lane script)
    if len(frame) > 2:
        return os.path.basename(frame[2].filename)
    return "<unknown>"


def refuse_exit_code() -> int:
    """The refusal exit code, exported for the gates and the docs."""
    return 2
