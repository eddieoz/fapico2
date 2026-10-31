#!/usr/bin/env python3
"""probe_seed_restore — reproduce the seed-restore wallet field report on two
live boards (US-1733, EPIC FIDO-SEED-ROOT).

The field report (2026-10-31 diagnosis): a seed exported from board A and
imported into board B, then re-registering the same passkey, produced a
**different wallet** on B. This probe reproduces that scenario end to end and
answers the only question it turns on:

    SAME-KEY      exit 0  — the seed governs the FIDO derivation root; the
                            phrase is the wallet (the fix, US-1734/1735/1736)
    DIFFERENT-KEY exit 1  — the seed is inert; restoring it changes nothing
                            (the defect, pre-epic)

while printing both boards' credential IDs and COSE public keys as the
evidence artifact.

# The flow

  1. Board A: ensure it is seed-governed — export its seed, or (if it has
     none) install a freshly drawn one first.
  2. Board B: load that same seed (a reset-first board: see the guards).
  3. Register the SAME resident identity (rp `fapico2-probe.local`, user
     `probe`) on BOTH boards via python-fido2, no PIN (both boards must be
     PIN-less — the guards below enforce it).
  4. Compare the two registrations' credential IDs and COSE public keys.

# The guards — the probe never destroys

* Both boards must be **PIN-less**. A PIN-set board (a) would need a PIN
  token this touch-only probe deliberately never mints and (b) is very
  likely holding resident credentials the LOAD would orphan. The probe
  checks `clientPIN 0x01 getPinRetries` on both boards and refuses with
  reset guidance when a PIN answers. Resetting (`ykman fido reset`, or a
  CTAP2 authenticatorReset) clears the PIN and the passkeys but **not** the
  vendor seed, so it is lossless for the seed leg.
* After US-1737 lands, the firmware itself refuses a LOAD while residents
  exist (`0x30`); this probe maps that status to the same reset-first
  guidance rather than retrying.
* Everything mutating is touch-gated on the board; every prompt names the
  board's path.

# Evidence, not CI

Like `probe_uv_policy.py`, this is a hardware artifact and is deliberately
NOT wired into CI: it needs two live boards and a human for the touches.

# Interpreters

Built on the surface `backup_fido.py` (whose wire layer it imports) and
`probe_mc_uv_ab.py` already verify on both host interpreters — the test venv
(fido2 2.2.1) and system python3 (fido2 1.2.0).

Usage:
    probe_seed_restore.py --a HIDPATH --b HIDPATH
    probe_seed_restore.py            # with exactly two boards on the bus
"""

from __future__ import annotations

import argparse
import secrets
import sys

import fido2.cbor as cbor
from fido2 import ctap
from fido2.ctap2.base import Ctap2
from fido2.hid import open_device

# The `0x41` wire layer, the MSE channel, the AEAD, the touch prompts — all
# backup_fido's, deliberately: a second copy of the vendor dialect is a
# second way to drift from the firmware's.
from backup_fido import (  # noqa: E402  (script-local sibling import)
    BackupError,
    CTAP2_OK,
    SUB_LOAD,
    _prose,
    _select_device,
    _touch_prompt_for,
    export_seed,
    read_state,
    restore_seed,
)

RP_ID = "fapico2-probe.local"
USER_ID = b"probe"
USER_NAME = "probe"

CTAP2_ERR_PIN_NOT_SET = 0x35

# The CTAP2 status the LOAD refusal (US-1737) answers while residents exist.
CTAP2_ERR_NOT_ALLOWED = 0x30

# Set once the probe has installed a fresh seed on board A: from that moment
# the board holds seed material that was never written down, and ANY abort —
# a touch timeout, a refusal on board B, a crash — must tell the operator
# that board A was mutated and how to recover the seed (exportable until
# `finalize`). An undisclosed half-state is the one thing worse than
# stopping.
BOARD_A_MUTATED = False


def _abort_disclosure() -> None:
    if BOARD_A_MUTATED:
        _prose(
            "\nNOTE: this run installed a freshly drawn seed on board A "
            "before aborting. That seed's phrase was never printed — but the "
            "seed is still on board A and exportable (`backup_fido.py "
            "export`) until you run `finalize`. Export it or re-provision "
            "board A; do not leave it in limbo."
        )


def pin_is_set(path: str) -> bool:
    """`clientPIN 0x01 getPinRetries` as the PIN-state probe.

    A PIN-less board answers PIN_NOT_SET (0x35); a PIN-set board answers the
    retry count. Anything else — a timeout, an unexpected status — is treated
    as *unknown*, and unknown refuses: the probe never guesses about a board
    it is about to mutate.
    """
    with open_device(path) as dev:
        client = Ctap2(dev)
        try:
            client.client_pin(None, 0x01)
            return True
        except ctap.CtapError as exc:
            if getattr(exc, "code", None) == CTAP2_ERR_PIN_NOT_SET:
                return False
            raise RuntimeError(
                f"could not determine the PIN state of {path} ({exc}) — "
                "refusing to proceed on an unknown board"
            ) from exc


def ensure_seed_governed(path: str) -> bytes:
    """The seed board A must hold before anything registers on it.

    `has_seed` ⇒ export it. No seed ⇒ draw one from the OS CSPRNG and install
    it (touch), so the probe is self-contained on a stock board. A board with
    residents but no seed is refused by the firmware itself (the reset-first
    gate, 0x30) — mapped here to the same guidance `load_seed` gives, because
    the generic STATUS_HELP text for 0x30 describes EXPORT semantics and
    would misdirect. Once the fresh seed is installed the board is MUTATED:
    the caller's abort paths must disclose that (see `BOARD_A_MUTATED`).
    """
    with open_device(path) as dev:
        state = read_state(dev)
        if state["has_seed"]:
            _prose(f"board A at {path} holds a seed — exporting it…")
            seed = export_seed(dev, _touch_prompt_for(path))
            _prose("(the exported seed's phrase is NOT printed — this probe "
                   "moves the raw seed between the two boards)")
            return seed
        fresh = secrets.token_bytes(32)
        _prose(
            f"board A at {path} has no seed. Installing a freshly drawn one "
            "(touch board A when prompted)…"
        )
        try:
            restore_seed(dev, fresh, _touch_prompt_for(path))
        except BackupError as exc:
            if exc.status == CTAP2_ERR_NOT_ALLOWED:
                _prose(
                    "the firmware REFUSED the install (0x30 NotAllowed): "
                    "board A still holds resident credentials, and installing "
                    "a seed that governs derivation would orphan their keys. "
                    "authenticatorReset (ykman fido reset) wipes passkeys, "
                    "then re-run this probe."
                )
                raise SystemExit(2) from exc
            raise
        after = read_state(dev)
        if not after["has_seed"]:
            raise BackupError(f"board A did not retain the installed seed: {after}")
        global BOARD_A_MUTATED
        BOARD_A_MUTATED = True
        return fresh


def load_seed(path: str, seed: bytes) -> None:
    """Install `seed` on board B — the step the whole epic is about."""
    _prose(f"loading board A's seed into board B at {path} (touch board B)…")
    try:
        with open_device(path) as dev:
            restore_seed(dev, seed, _touch_prompt_for(path))
            state = read_state(dev)
    except BackupError as exc:
        if exc.status == CTAP2_ERR_NOT_ALLOWED:
            _prose(
                "the firmware REFUSED the load (0x30 NotAllowed): board B still "
                "holds resident credentials, and installing a seed that "
                "governs derivation would orphan their keys. "
                "authenticatorReset (ykman fido reset) wipes passkeys, then "
                "restore again."
            )
            raise SystemExit(2) from exc
        raise
    if not state["has_seed"]:
        raise BackupError(f"board B did not retain the loaded seed: {state}")


def register(path: str) -> tuple[bytes, bytes, bytes]:
    """One resident registration on a PIN-less board; return (cred_id, x, y).

    The request shape mirrors `probe_mc_uv_ab.py`: rp and user are plain
    dicts (a typed user entity would put a CBOR text string where CTAP2
    requires bytes), no pinUvAuthParam (the board is PIN-less, so
    makeCredUvNotRqd), options `{rk: true}` — the wallet credential class
    this epic is about. Touch on the named board.
    """
    _prose(f"registering rp '{RP_ID}' user '{USER_NAME}' on {path} — touch now…")
    with open_device(path) as dev:
        client = Ctap2(dev)
        response = client.make_credential(
            client_data_hash=b"\xbb" * 32,
            rp={"id": RP_ID, "name": "seed-restore probe"},
            user={"id": USER_ID, "name": USER_NAME},
            key_params=[{"type": "public-key", "alg": -7}],
            exclude_list=[],
            options={"rk": True},
        )
        return parse_registration(bytes(response.auth_data))


def parse_registration(auth_data: bytes) -> tuple[bytes, bytes, bytes]:
    """attestedCredentialData out of the authData — offsets every sibling
    parser uses: rpIdHash(32) flags(1) signCount(4) aaguid(16) credIdLen(2)
    credId COSE-key."""
    if not auth_data[32] & 0x40:
        raise BackupError("registration came back without attested credential data")
    id_len = int.from_bytes(auth_data[53:55], "big")
    cred_id = auth_data[55 : 55 + id_len]
    cose, _rest = cbor.decode_from(auth_data[55 + id_len :])
    if not isinstance(cose, dict):
        raise BackupError("the attested COSE key did not decode as a map")
    x, y = cose.get(-2), cose.get(-3)
    if not (isinstance(x, bytes) and isinstance(y, bytes)):
        raise BackupError("the attested COSE key has no P-256 coordinates")
    return cred_id, x, y


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="probe_seed_restore.py",
        description=(
            "Export board A's seed into board B, register the same identity "
            "on both, and report SAME-KEY or DIFFERENT-KEY (US-1733)."
        ),
    )
    parser.add_argument("--a", metavar="HIDPATH", help="board A's HID path")
    parser.add_argument("--b", metavar="HIDPATH", help="board B's HID path")
    args = parser.parse_args(argv)

    if args.a and args.b:
        path_a, path_b = args.a, args.b
    elif not args.a and not args.b:
        # No paths given: exactly two boards must answer, and the tool says
        # so rather than guessing — the same discipline backup_fido's
        # _select_device applies, applied across two boards.
        import backup_fido

        devices, notes = backup_fido.find_devices(None)
        for note in notes:
            _prose(note)
        if len(devices) != 2:
            _prose(
                f"{len(devices)} board(s) answer; give --a and --b paths "
                "exactly when two are present, or pass them explicitly."
            )
            return 2
        path_a, path_b = devices[0][1], devices[1][1]
    else:
        parser.error("pass both --a and --b, or neither")

    _prose(f"board A: {path_a}\nboard B: {path_b}")

    # Guard 1: both boards PIN-less, or refuse. (Guard 2 — "no residents" —
    # is enforced by the firmware itself once US-1737 lands; pre-epic the
    # PIN-less requirement plus the operator's reset is the contract, and
    # the header documents it.)
    for path, role in ((path_a, "A"), (path_b, "B")):
        if pin_is_set(path):
            _prose(
                f"board {role} at {path} has a PIN set. Reset it first "
                "(ykman fido reset, or a CTAP2 authenticatorReset) — a reset "
                "clears the PIN and passkeys but not the vendor seed — and "
                "re-run this probe."
            )
            return 2

    seed = ensure_seed_governed(path_a)
    load_seed(path_b, seed)

    cred_a, xa, ya = register(path_a)
    cred_b, xb, yb = register(path_b)

    _prose("")
    _prose("board A credential ID: " + cred_a.hex())
    _prose("board B credential ID: " + cred_b.hex())
    _prose("board A public key x:  " + xa.hex())
    _prose("board A public key y:  " + ya.hex())
    _prose("board B public key x:  " + xb.hex())
    _prose("board B public key y:  " + yb.hex())

    if cred_a != cred_b:
        _prose("\ncredential IDs DIFFER — the resident-ID derivation itself "
               "drifted; that is not a seed-root defect but it must not happen")
        return 3

    if (xa, ya) == (xb, yb):
        print("SAME-KEY")
        _prose("the same seed reproduced the same passkey wallet on both boards.")
        return 0
    print("DIFFERENT-KEY")
    _prose(
        "the same seed, the same identity, different keys — the seed is "
        "inert (the 2026-10-31 field report, reproduced)."
    )
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BackupError as exc:
        _prose(f"error: {exc}")
        _abort_disclosure()
        sys.exit(2)
    except SystemExit:
        # `load_seed` and `ensure_seed_governed` exit 2 with their own
        # reset-first guidance; the disclosure rides on top of it.
        _abort_disclosure()
        raise
    except KeyboardInterrupt:
        _prose("\naborted")
        _abort_disclosure()
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001 - a probe reports, never crashes bare
        _prose(f"error: {type(exc).__name__}: {exc}")
        _abort_disclosure()
        sys.exit(1)
