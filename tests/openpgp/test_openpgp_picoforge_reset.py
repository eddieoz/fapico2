"""US-154 (PICOForge-COMPAT): the factory-reset path the reference client
drives (``picoforge/src/hal/applets/openpgp.rs:438-457``) — up to ten wrong
VERIFYs against PW1 then PW3, then TERMINATE DF (``00 E6 00 00``) and
ACTIVATE FILE (``00 44 00 00``).

This is the device-path twin of ``apps/openpgp/tests/picoforge_reset.rs``:
that file exercises opcard over the trussed-virt RAM client, this one drives
the same code through the emulated firmware over CCID. The two are kept
because the findings below are properties of the *card*, and a card property
that only ever held on one backend would be a finding about the harness, not
about the firmware.

Three facts are pinned, and none of them is what the client assumes:

* **The card never answers ``6983``.** The client breaks its retry loop on
  ``6983`` (``OperationBlocked``). The card answers ``63C2``, ``63C1``, then
  ``63C0`` — and ``63C0`` for every attempt after that, because
  ``verification_status`` reports the exhausted counter through its
  ``RemainingRetries(0)`` arm (``vendor/opcard/src/state.rs:1316-1318``); the
  ``6983`` arm is only reachable with a migration source configured
  (``state.rs:1319-1327``) and a factory card has none. The client's ``break``
  is therefore dead code against this card: it always spends all ten attempts
  per PIN and only then proceeds. The end state is right — both counters reach
  zero — so the reset works, but by exhaustion rather than by detection.
* **TERMINATE succeeds on the PW3-*locked* arm.** ``terminate_df`` accepts
  ``admin_verified() || is_locked(Pw3)``
  (``vendor/opcard/src/command.rs:528-535``) and the client never VERIFYs
  PW3, it burns its retries, so only the second arm can be the one that
  fires. This is the *opposite* arm from the one the root conftest's
  ``restore_factory_card`` relies on — that helper VERIFYs PW3 first and
  terminates through ``admin_verified()``.
* **The card must already be personalised.** ``terminate_df`` refuses with
  ``6985`` while ``factory_defaults_in_force()``
  (``command.rs:518-522``), and that flag is set until *both* PINs have been
  changed off the shipped defaults (``state.rs:1348-1350``). This holds even
  with PW3 locked, so a never-personalised card is unreachable for this flow.

ACTIVATE is the other half and is deliberately the opposite: it authenticates
nobody (§7.2.17, ``command.rs:576-592``) and then runs a full
``factory_reset``. That is spec-correct OpenPGP behaviour and it also means an
unauthenticated party can wipe the card. Pinned explicitly so the posture is
a recorded decision rather than an accident.

**State scoping.** The ``card`` fixture is the session-scoped emulator-backed
one from the ROOT conftest and is NOT redefined here. This test destroys card
state — it zeroes both PIN retry counters and terminates the card — so it
runs inside a function-scoped fixture that owns the teardown. Recovery needs
no PIN of its own: by the time teardown runs, PW3 is locked either way, so
TERMINATE is authorised through the locked arm, and ACTIVATE needs no
authentication at all. That makes the teardown byte-identical to the client's
own reset sequence, and it is why the shared ``pin_gate_lifted`` fixtures are
not used here: their ``restore_factory_card`` VERIFYs ``GATE_PW3`` first,
which a card with a zeroed PW3 counter cannot answer.
"""

import pytest

from card_const import FACTORY_PASSPHRASE_PW1, FACTORY_PASSPHRASE_PW3
from openpgp_card import iso7816_compose

# INS codes this flow sends.
INS_VERIFY = 0x20
INS_SELECT_AID = 0xA4
INS_GET_DATA = 0xCA
INS_GET_CHALLENGE = 0x84
INS_TERMINATE = 0xE6
INS_ACTIVATE = 0x44

# Reference bytes in P2 of a VERIFY.
PW1_REF = 0x81
PW3_REF = 0x83

# The exact wrong PIN the client sends, and how many times it sends it.
_WRONG_PIN = b"00000000"
_CLIENT_ATTEMPTS = 10

# `0xC4` retry-counter offsets: PW1, reset code, PW3. The reset code is
# never touched by this flow, so it is compared before/after rather than
# against a literal — a card with no reset code installed reports 0 there.
_C4_PW1 = 4
_C4_RESET_CODE = 5
_C4_PW3 = 6

# The counter is hardcoded (MAX_RETRIES, vendor/opcard/src/state.rs:800) and
# no APDU can raise it: the only PUT DATA 0xC4 writer accepts the retry
# fields only when they are 0x7F
# (vendor/opcard/src/command/data.rs:1080-1106).
_MAX_RETRIES = 3

# The PINs the root conftest lifts the factory-defaults gate with, repeated
# here so this module owns its own preconditions. The shared fixtures cannot
# be reused for teardown (see the module docstring) and a precondition that
# only exists in the fixture's setup would be invisible to a reader.
_GATE_PW1 = b"246813"
_GATE_PW3 = b"86429753"


def _send(card, apdu):
    return card._OpenPGP_Card__reader.send_cmd(apdu)


def _sw(resp):
    return (resp[-2] << 8) | resp[-1]


def _verify_raw(card, ref, pin):
    """VERIFY with an explicit PIN, returning the SW rather than raising.

    ``OpenPGP_Card.cmd_verify`` raises on anything but 9000, which is right
    for the suite and wrong here: this test is about the status words a
    rejected PIN produces.
    """
    return _sw(_send(card, iso7816_compose(INS_VERIFY, 0x00, ref, pin)))


def _get_data(card, tag):
    """GET DATA (INS 0xCA) for `tag`, returning ``(body, sw)``.

    The tag goes in P1-P2 per spec §7.1. The body is reassembled across the
    ``61XX``/GET RESPONSE chain, because 0x6E is far longer than one Le.
    """
    tagh, tagl = tag >> 8, tag & 0xFF
    resp = _send(card, iso7816_compose(INS_GET_DATA, tagh, tagl, b"", le=254))
    body, sw = resp[:-2], _sw(resp)
    while sw & 0xFF00 == 0x6100:
        chunk = _send(card, iso7816_compose(0xC0, 0x00, 0x00, b"", le=sw & 0xFF or 256))
        body, sw = body + chunk[:-2], _sw(chunk)
    return body, sw


def _pw_status(card):
    body, sw = _get_data(card, 0xC4)
    assert sw == 0x9000, "GET DATA 0xC4: %04X" % sw
    assert len(body) >= 7, "0xC4 is %d bytes" % len(body)
    return body


def _client_wrong_pin_loop(card, ref):
    """The client's inner loop, transcribed, returning every SW it saw.

    ``openpgp.rs:441-449`` sends ten VERIFYs and breaks on 6983, swallowing
    everything else. Keeping the whole vector is what turns the zeroing
    attempt's status word into a pinned fact rather than an assumption.
    """
    return [_verify_raw(card, ref, _WRONG_PIN) for _ in range(_CLIENT_ATTEMPTS)]


def _personalise(card):
    """Move both PINs off the shipped defaults, idempotently.

    Mirrors the root conftest's ``lift_factory_pin_gate``; the same two
    constants and the same factory-first ordering, so a factory verify that
    succeeds burns no retry counter.
    """
    try:
        card.cmd_verify(3, FACTORY_PASSPHRASE_PW3)
    except ValueError:
        card.cmd_verify(3, _GATE_PW3)
        card.cmd_verify(1, _GATE_PW1)
    else:
        card.cmd_change_reference_data(1, FACTORY_PASSPHRASE_PW1 + _GATE_PW1)
        card.cmd_change_reference_data(3, FACTORY_PASSPHRASE_PW3 + _GATE_PW3)


def _terminate(card):
    return _sw(_send(card, iso7816_compose(INS_TERMINATE, 0x00, 0x00, b"")))


def _activate(card):
    return _sw(_send(card, iso7816_compose(INS_ACTIVATE, 0x00, 0x00, b"")))


@pytest.fixture
def personalised_card(card):
    """A card with the factory-defaults gate lifted, restored on the way out.

    The teardown is TERMINATE + ACTIVATE with no PIN: by then PW3 is locked
    either way, so TERMINATE is authorised through the locked arm, and
    ACTIVATE requires no authentication. Byte-identical to the client's own
    reset sequence, so the test and its cleanup cannot disagree about what
    a reset is.
    """
    _personalise(card)
    try:
        yield card
    finally:
        act = _activate(card)
        assert act == 0x9000, "teardown could not restore the card: ACTIVATE %04X" % act


def test_terminate_activate_resets(require_live_card, personalised_card):
    card = personalised_card
    before = _pw_status(card)
    assert (
        before[_C4_PW1] == _MAX_RETRIES and before[_C4_PW3] == _MAX_RETRIES
    ), "expected a personalised card with full counters: %s" % before.hex()
    reset_code_before = before[_C4_RESET_CODE]

    # --- the client's blocking loop, verbatim --------------------------------
    for label, ref in (("PW1", PW1_REF), ("PW3", PW3_REF)):
        sws = _client_wrong_pin_loop(card, ref)
        assert sws[0] == 0x63C2, "%s attempt 1: %04X" % (label, sws[0])
        assert sws[1] == 0x63C1, "%s attempt 2: %04X" % (label, sws[1])
        assert sws[2] == 0x63C0, (
            "%s attempt 3 is the one that zeroes the counter and it says 63C0, "
            "NOT 6983 - the client's break (openpgp.rs:446) never fires" % label
        )
        assert all(sw == 0x63C0 for sw in sws[3:]), (
            "%s must keep reporting 63C0 once exhausted: %s"
            % (label, " ".join("%04X" % sw for sw in sws))
        )
        assert 0x6983 not in sws, (
            "the client's break condition is reachable on this card: %s"
            % " ".join("%04X" % sw for sw in sws)
        )

    blocked = _pw_status(card)
    assert blocked[_C4_PW1] == 0, "PW1 is not blocked: %s" % blocked.hex()
    assert blocked[_C4_PW3] == 0, "PW3 is not blocked: %s" % blocked.hex()
    assert blocked[_C4_RESET_CODE] == reset_code_before, (
        "the reset-code counter must not move: %s" % blocked.hex()
    )

    # --- TERMINATE, four bytes, no re-SELECT and no VERIFY ------------------
    assert _terminate(card) == 0x9000, "TERMINATE after the blocking loop must answer 9000"

    # The card really is terminated. The lifecycle gate
    # (vendor/opcard/src/command.rs:51-59) admits only SELECT, ACTIVATE and
    # TERMINATE; proving it with a refusal also rules out a TERMINATE that
    # silently no-opped and made every assertion below vacuous.
    _, sw = _get_data(card, 0xC4)
    assert sw == 0x6985, "GET DATA must be refused while terminated: %04X" % sw
    sw = _sw(_send(card, iso7816_compose(INS_GET_CHALLENGE, 0x00, 0x00, b"", le=8)))
    assert sw == 0x6985, "GET CHALLENGE must be refused while terminated: %04X" % sw
    sw = _verify_raw(card, PW3_REF, FACTORY_PASSPHRASE_PW3)
    assert sw == 0x6985, "VERIFY must be refused while terminated: %04X" % sw
    # SELECT is permitted by the gate but reports the termination state
    # (0x6285, Status::SelectedFileInTerminationState) instead of 9000.
    sw = _sw(
        _send(card, iso7816_compose(INS_SELECT_AID, 0x04, 0x00, b"\xD2\x76\x00\x01\x24\x01"))
    )
    assert sw == 0x6285, "SELECT while terminated: %04X" % sw
    # TERMINATE stays available (it is idempotent). This is the arm the
    # teardown falls back on when the test dies between the loop and ACTIVATE.
    assert _terminate(card) == 0x9000, "TERMINATE must stay available while terminated"

    # --- ACTIVATE, four bytes, no PIN ---------------------------------------
    assert _activate(card) == 0x9000, "ACTIVATE must answer 9000 with no authentication"

    restored = _pw_status(card)
    assert restored[_C4_PW1] == _MAX_RETRIES, "PW1 retries not restored: %s" % restored.hex()
    assert restored[_C4_PW3] == _MAX_RETRIES, "PW3 retries not restored: %s" % restored.hex()
    # delete_all_pins() really ran: the shipped PINs are back and the
    # personalised ones are gone, which a counter reset alone would not do.
    assert _verify_raw(card, PW1_REF, FACTORY_PASSPHRASE_PW1) == 0x9000, "factory PW1 not restored"
    assert _verify_raw(card, PW3_REF, FACTORY_PASSPHRASE_PW3) == 0x9000, "factory PW3 not restored"
    assert _verify_raw(card, PW3_REF, _GATE_PW3) != 0x9000, (
        "the personalised admin PIN survived the factory reset"
    )

    # Operational again: the gate is open and the app re-selects.
    assert card.cmd_select_openpgp() is True, "SELECT after ACTIVATE must answer 9000"
    _, sw = _get_data(card, 0xC4)
    assert sw == 0x9000, "GET DATA must be accepted again after ACTIVATE: %04X" % sw
    # The card is back where TERMINATE is once more refused, which is the
    # signature of a real re-initialisation rather than a state poke.
    assert _terminate(card) == 0x6985, "factory defaults are in force again after ACTIVATE"
