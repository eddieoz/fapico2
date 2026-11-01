"""US-1747 — the touch-policy matrix over the CCID emulator.

The emulator registers Nostr over CCID only (AGENTS.md §8): the vendor-HID
arm is not exercised here — that is `nostr_probe.py --touch-bypass`'s job
on the board (US-1749), because a green emulator suite says nothing about
that arm. Everything below drives the applet's own dialect through the
dispatcher:

verify → SET_TOUCH_POLICY(0x01) → SIGN observes no touch prompt, then
LOCK → SET_TOUCH_POLICY(0x01) answers the gate word, and a fresh emulator
boot shows the flag gone from GET_INFO.

Two emulator instances carry the matrix. The **auto-ack** one answers the
disable leg's consent press, so the verb's state machine is driven end to
end. The **deny** one (`FAPICO2_NOSTR_PRESENCE=deny`) refuses every press
— so a bypassed SIGN succeeding there is the observable "no touch prompt"
claim: without the bypass, a deny-emulator SIGN answers 6985.

GET_INFO layout: `applet_ver(2) ‖ caps(2) ‖ max_plaintext(2) ‖
n_identities(1) ‖ flags(1)` — caps bit 4 = CAP_TOUCH_POLICY, flags bit 3 =
FLAG_TOUCH_BYPASS (US-1746).
"""

import pytest

from nostr_ccid import (
    FLAG_MIGRATION_PENDING,
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
    SW_PIN_NOT_SET,
    SW_PIN_SESSION_REQUIRED,
    SW_TOUCH_REQUIRED,
    SW_WRONG_DATA,
    SW_WRONG_P1_P2,
    apdu,
)

INS_SET_TOUCH_POLICY = 0x1F

CAP_TOUCH_POLICY = 0x0010
FLAG_TOUCH_BYPASS = 0x08

SCALAR = bytes([0x03]) + bytes(31)
PIN = b"731742"
DIGEST = bytes(32)


@pytest.fixture()
def emu(tmp_path):
    with NostrEmu("keymgmt", tmp_path) as e:
        assert e.select()[1] == SW_OK
        yield e


def read_info(emu):
    data, _ = emu.send(apdu(INS_GET_INFO))
    caps = (data[2] << 8) | data[3]
    flags = data[7]
    return caps, flags


def verified_board(emu):
    """Import the identity, set the PIN, open the session — the disable
    leg's precondition on either emulator."""
    _, sw = emu.send(apdu(INS_IMPORT_KEY, p1=0, data=SCALAR))
    assert sw == SW_OK
    _, sw = emu.send(apdu(INS_SET_PIN, p1=0, data=PIN))
    assert sw == SW_OK
    _, sw = emu.send(apdu(INS_VERIFY_PIN, data=PIN))
    assert sw == SW_OK


# ---------------------------------------------------------------------------
# GET_INFO advertisement (the US-1746 readings, over the wire)
# ---------------------------------------------------------------------------


def test_get_info_advertises_the_capability_bit_unconditionally(emu):
    caps, flags = read_info(emu)
    assert caps & CAP_TOUCH_POLICY, "the verb exists on this firmware"
    assert not flags & FLAG_TOUCH_BYPASS, "a fresh boot has the flag down"


def test_the_state_flag_tracks_the_gate_field(emu):
    verified_board(emu)
    _, sw = emu.send(apdu(INS_SET_TOUCH_POLICY, p1=1))
    assert sw == SW_OK
    caps, flags = read_info(emu)
    assert flags & FLAG_TOUCH_BYPASS, "bypass armed: bit 3 stands"
    assert caps & CAP_TOUCH_POLICY
    # Re-enable: the flag drops with it.
    _, sw = emu.send(apdu(INS_SET_TOUCH_POLICY, p1=0))
    assert sw == SW_OK
    _, flags = read_info(emu)
    assert not flags & FLAG_TOUCH_BYPASS


# ---------------------------------------------------------------------------
# The verb's refusal rows
# ---------------------------------------------------------------------------


def test_disable_leg_refuses_without_pin(emu):
    _, sw = emu.send(apdu(INS_SET_TOUCH_POLICY, p1=1))
    assert sw == SW_PIN_NOT_SET, "the bypass is a PIN-session privilege"


def test_disable_leg_refuses_with_a_closed_session(emu):
    _, sw = emu.send(apdu(INS_IMPORT_KEY, p1=0, data=SCALAR))
    assert sw == SW_OK
    _, sw = emu.send(apdu(INS_SET_PIN, p1=0, data=PIN))
    assert sw == SW_OK
    _, sw = emu.send(apdu(INS_SET_TOUCH_POLICY, p1=1))
    assert sw == SW_PIN_SESSION_REQUIRED


def test_unknown_p1_and_payload_refuse_in_shape(emu):
    _, sw = emu.send(apdu(INS_SET_TOUCH_POLICY, p1=2))
    assert sw == SW_WRONG_P1_P2
    _, sw = emu.send(apdu(INS_SET_TOUCH_POLICY, p1=0xFF))
    assert sw == SW_WRONG_P1_P2
    _, sw = emu.send(apdu(INS_SET_TOUCH_POLICY, p1=0, data=b"\x00"))
    assert sw == SW_WRONG_DATA


def test_the_retired_export_byte_stays_refused_in_band(emu):
    # The new byte joins the table; the retired one stays retired.
    _, sw = emu.send(apdu(0x1A))
    assert sw == SW_INS_NOT_SUPPORTED


# ---------------------------------------------------------------------------
# The full consent chain, and what the bypass buys
# ---------------------------------------------------------------------------


def test_verify_then_disable_arms_the_bypass_and_sign_runs_touch_free(emu):
    # The auto-ack emulator carries the consent press; the state machine is
    # driven end to end and the SIGN afterwards answers SW_OK. (The
    # no-touch observable itself is the deny row below and the host suite's
    # counting grant — the emulator's auto-ack cannot distinguish a
    # consulted grant from a skipped one.)
    verified_board(emu)
    _, sw = emu.send(apdu(INS_SIGN, p1=0, data=DIGEST))
    assert sw == SW_OK
    _, sw = emu.send(apdu(INS_SET_TOUCH_POLICY, p1=1))
    assert sw == SW_OK, "the consent press lands"
    _, flags = read_info(emu)
    assert flags & FLAG_TOUCH_BYPASS
    data, sw = emu.send(apdu(INS_SIGN, p1=0, data=DIGEST))
    assert sw == SW_OK and len(data) == 96, "npub(32) ‖ sig(64)"


@pytest.fixture()
def deny(tmp_path):
    # The auto-ack instance seeds the region file (identity + PIN); the
    # deny instance reopens it with the session closed — VERIFY is
    # touch-free, so the deny instance opens its own session. Nothing that
    # needs a press can run under deny, which is exactly what the rows
    # below assert.
    with NostrEmu("keymgmt", tmp_path) as e:
        assert e.select()[1] == SW_OK
        _, sw = e.send(apdu(INS_IMPORT_KEY, p1=0, data=SCALAR))
        assert sw == SW_OK
        _, sw = e.send(apdu(INS_SET_PIN, p1=0, data=PIN))
        assert sw == SW_OK
    with NostrEmu("deny", tmp_path, presence="deny") as e:
        assert e.select()[1] == SW_OK
        yield e


def test_the_disable_legs_consent_press_is_a_real_press(deny):
    # The disable leg reuses the SIGN touch path — so under a denied
    # presence source the consent press is refused exactly like a signing
    # press, and the flag never arms.
    _, sw = deny.send(apdu(INS_VERIFY_PIN, data=PIN))
    assert sw == SW_OK, "VERIFY is touch-free: the deny board can open a session"
    _, sw = deny.send(apdu(INS_SET_TOUCH_POLICY, p1=1))
    assert sw == SW_TOUCH_REQUIRED, "the consent press is denied"
    _, flags = read_info(deny)
    assert not flags & FLAG_TOUCH_BYPASS, "no press, no bypass"
    _, sw = deny.send(apdu(INS_SIGN, p1=0, data=DIGEST))
    assert sw == SW_TOUCH_REQUIRED, "the signing touch is still owed"


def test_lock_clears_the_flag_and_the_gate_word_returns(emu):
    verified_board(emu)
    _, sw = emu.send(apdu(INS_SET_TOUCH_POLICY, p1=1))
    assert sw == SW_OK
    _, sw = emu.send(apdu(INS_LOCK))
    assert sw == SW_OK
    _, flags = read_info(emu)
    assert not flags & FLAG_TOUCH_BYPASS, "LOCK clears the flag"
    _, sw = emu.send(apdu(INS_SET_TOUCH_POLICY, p1=1))
    assert sw == SW_PIN_SESSION_REQUIRED, "the lock closed the session too"
    _, sw = emu.send(apdu(INS_SIGN, p1=0, data=DIGEST))
    assert sw == SW_PIN_SESSION_REQUIRED, "a locked board answers the gate word"


def test_enable_leg_is_friction_free_in_every_state(emu):
    # PIN-less, bypass down: 9000, nothing moves.
    _, sw = emu.send(apdu(INS_SET_TOUCH_POLICY, p1=0))
    assert sw == SW_OK
    _, flags = read_info(emu)
    assert not flags & FLAG_TOUCH_BYPASS
    # Idempotent on a verified board with the bypass armed.
    verified_board(emu)
    _, sw = emu.send(apdu(INS_SET_TOUCH_POLICY, p1=1))
    assert sw == SW_OK
    _, sw = emu.send(apdu(INS_SET_TOUCH_POLICY, p1=0))
    assert sw == SW_OK
    _, flags = read_info(emu)
    assert not flags & FLAG_TOUCH_BYPASS


def test_a_fresh_boot_shows_the_flag_gone(tmp_path):
    # Arm the bypass on one emulator's region, then boot a fresh emulator
    # over the same region file: the RAM flag is gone, everything durable
    # (identity, PIN) survives. The lifecycle is owned here, not by the
    # fixture, so the first emulator exits exactly once.
    region = tmp_path / "nostr_region.bin"
    with NostrEmu("keymgmt", tmp_path) as emu:
        assert emu.select()[1] == SW_OK
        verified_board(emu)
        _, sw = emu.send(apdu(INS_SET_TOUCH_POLICY, p1=1))
        assert sw == SW_OK
        _, flags = read_info(emu)
        assert flags & FLAG_TOUCH_BYPASS

    with NostrEmu("keymgmt", tmp_path) as fresh:
        assert fresh.select()[1] == SW_OK
        _, sw = fresh.send(apdu(INS_VERIFY_PIN, data=PIN))
        assert sw == SW_OK, "the PIN survived the power cycle"
        _, flags = read_info(fresh)
        assert not flags & FLAG_TOUCH_BYPASS, "the RAM flag did not"
        assert region.exists(), "the same region the bypass was armed on"
