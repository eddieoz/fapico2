"""US-1703 — the PIN custody dialect over the CCID emulator.

The emulator registers Nostr over CCID only (AGENTS.md §8): the vendor-HID
arm is not exercised here — that is `nostr_probe.py`'s job on the board
(US-1704), because a green emulator suite says nothing about that arm.
Everything below drives the applet's own dialect through the dispatcher:
set → verify → sign, lock → the gate word, the durable 63CX retry rows,
the change ceremony, and the GET_INFO flags byte at each state transition.

GET_INFO layout: `applet_ver(2) ‖ caps(2) ‖ max_plaintext(2) ‖ n_identities(1)
‖ flags(1)` — flags bit 0 = PIN set, bit 1 = session unlocked (US-1700).
"""

import pytest

from nostr_ccid import (
    INS_GET_INFO,
    INS_IMPORT_KEY,
    INS_LOCK,
    INS_SET_PIN,
    INS_SIGN,
    INS_VERIFY_PIN,
    NostrEmu,
    SW_INS_NOT_SUPPORTED,
    SW_NO_SUCH_IDENTITY,
    SW_OK,
    SW_PIN_LOCKED,
    SW_PIN_NOT_SET,
    SW_PIN_SESSION_REQUIRED,
    SW_WRONG_DATA,
    apdu,
)

SCALAR = bytes([0x03]) + bytes(31)  # non-zero, below the curve order
PIN = b"731742"  # six bytes, the minimum
NEW_PIN = b"246813"
WRONG = b"000000"
DIGEST = bytes(32)


@pytest.fixture()
def emu(tmp_path):
    with NostrEmu("keymgmt", tmp_path) as e:
        assert e.select()[1] == SW_OK
        yield e


def flags(emu):
    data, _ = emu.send(apdu(INS_GET_INFO))
    return data[7]


def change_payload(current, new):
    # The applet's CHANGE payload shape: `lc(1) ‖ current(lc) ‖ new`.
    return bytes([len(current)]) + current + new


def test_get_info_flags_walk_the_three_states(emu):
    # No PIN: the v0.2.0-compatible zero.
    assert flags(emu) == 0x00
    # SET alone: bit 0.
    _, sw = emu.send(apdu(INS_SET_PIN, p1=0, data=PIN))
    assert sw == SW_OK
    assert flags(emu) == 0x01
    # VERIFY: bit 1 joins.
    _, sw = emu.send(apdu(INS_VERIFY_PIN, data=PIN))
    assert sw == SW_OK
    assert flags(emu) == 0x03
    # LOCK: bit 1 leaves, bit 0 stays.
    _, sw = emu.send(apdu(INS_LOCK))
    assert sw == SW_OK
    assert flags(emu) == 0x01


def test_verify_opens_the_gate_and_lock_closes_it(emu):
    _, sw = emu.send(apdu(INS_SIGN, p1=0, data=DIGEST))
    assert sw == SW_NO_SUCH_IDENTITY  # no gate: the honest store answer
    _, sw = emu.send(apdu(INS_SET_PIN, p1=0, data=PIN))
    assert sw == SW_OK
    _, sw = emu.send(apdu(INS_SIGN, p1=0, data=DIGEST))
    assert sw == SW_PIN_SESSION_REQUIRED, "locked board: the gate word"
    _, sw = emu.send(apdu(INS_VERIFY_PIN, data=PIN))
    assert sw == SW_OK
    _, sw = emu.send(apdu(INS_SIGN, p1=0, data=DIGEST))
    assert sw == SW_NO_SUCH_IDENTITY, "unlocked: the gate is gone"
    _, sw = emu.send(apdu(INS_LOCK))
    assert sw == SW_OK
    _, sw = emu.send(apdu(INS_SIGN, p1=0, data=DIGEST))
    assert sw == SW_PIN_SESSION_REQUIRED, "the lock closed it again"


def test_verify_opens_the_gate_for_a_real_sign(emu):
    _, sw = emu.send(apdu(INS_IMPORT_KEY, p1=0, data=SCALAR))
    assert sw == SW_OK
    _, sw = emu.send(apdu(INS_SET_PIN, p1=0, data=PIN))
    assert sw == SW_OK
    _, sw = emu.send(apdu(INS_SIGN, p1=0, data=DIGEST))
    assert sw == SW_PIN_SESSION_REQUIRED
    _, sw = emu.send(apdu(INS_VERIFY_PIN, data=PIN))
    assert sw == SW_OK
    data, sw = emu.send(apdu(INS_SIGN, p1=0, data=DIGEST))
    # npub(32) ‖ sig(64): the answer names the key that produced it.
    assert sw == SW_OK and len(data) == 96, "the BIP-340 signature, no touch hassle"


def test_wrong_pin_rows_are_durable_and_never_below_zero(emu):
    _, sw = emu.send(apdu(INS_SET_PIN, p1=0, data=PIN))
    assert sw == SW_OK
    for expected_left in (0x02, 0x01):
        _, sw = emu.send(apdu(INS_VERIFY_PIN, data=WRONG))
        assert sw == 0x63C0 | expected_left
    # The budget is durable across the connection the same session holds
    # it — the third wrong answer is the lockout word.
    _, sw = emu.send(apdu(INS_VERIFY_PIN, data=WRONG))
    assert sw == SW_PIN_LOCKED
    # Locked stays locked: the counter never goes below zero.
    _, sw = emu.send(apdu(INS_VERIFY_PIN, data=WRONG))
    assert sw == SW_PIN_LOCKED
    _, sw = emu.send(apdu(INS_VERIFY_PIN, data=PIN))
    assert sw == SW_PIN_LOCKED, "even the right PIN stays locked"


def test_change_pin_verifies_the_current_one(emu):
    _, sw = emu.send(apdu(INS_SET_PIN, p1=0, data=PIN))
    assert sw == SW_OK
    # CHANGE with a wrong current burns a retry: 63C2.
    _, sw = emu.send(apdu(INS_SET_PIN, p1=1, data=change_payload(WRONG, NEW_PIN)))
    assert sw == 0x63C2
    # CHANGE with the right current rewrites the verifier and resets the
    # counter: the old PIN now fails from a full budget (63C2, not 63C1).
    _, sw = emu.send(apdu(INS_SET_PIN, p1=1, data=change_payload(PIN, NEW_PIN)))
    assert sw == SW_OK
    _, sw = emu.send(apdu(INS_VERIFY_PIN, data=PIN))
    assert sw == 0x63C2, "the old PIN is wrong with a fresh counter"
    _, sw = emu.send(apdu(INS_VERIFY_PIN, data=NEW_PIN))
    assert sw == SW_OK
    # SET on a PIN-set board is the state refusal; CHANGE payload shape
    # errors are wrong data.
    _, sw = emu.send(apdu(INS_SET_PIN, p1=0, data=PIN))
    assert sw == 0x6A82  # SW_PIN_ALREADY_SET
    _, sw = emu.send(apdu(INS_SET_PIN, p1=1, data=b"too short"))
    assert sw == SW_WRONG_DATA


def test_pin_verbs_on_an_unset_board(emu):
    _, sw = emu.send(apdu(INS_VERIFY_PIN, data=PIN))
    assert sw == SW_PIN_NOT_SET
    _, sw = emu.send(apdu(INS_LOCK))
    assert sw == SW_OK, "LOCK is 9000 in every state"
    _, sw = emu.send(apdu(INS_VERIFY_PIN, data=b"short"))
    assert sw == SW_WRONG_DATA
    # The retired EXPORT byte stays refused in band (US-1699).
    _, sw = emu.send(apdu(0x1A, p1=0))
    assert sw == SW_INS_NOT_SUPPORTED
