"""US-1651 — the Nostr applet over the real CCID transport (§2.7).

The SELECT leg of the acceptance: the applet answers `9000` on its AID
(`F0 00 00 00 02`, design §2.1), the dispatcher refuses an unregistered AID
with `6A82`, and the applet's own process arm refuses an unimplemented INS
with `6D00`. Every assertion runs against the emulation binary through a
private relay — the same bytes the OpenXrypt host (US-1668+) will one day
send.
"""

import pytest

from harness.nostr_ccid import (
    INS_EXPORT_KEY,
    INS_GET_INFO,
    NOSTR_AID,
    NostrEmu,
    SELECT_NOSTR,
    SW_INS_NOT_SUPPORTED,
    SW_OK,
    apdu,
)

UNREGISTERED_AID = bytes([0x00, 0xA4, 0x04, 0x04, 0x08]) + bytes.fromhex("FF" * 8)


@pytest.fixture()
def emu(tmp_path):
    with NostrEmu("select", tmp_path) as e:
        yield e


def test_select_answers_9000_with_no_body(emu):
    data, sw = emu.select()
    assert (data, sw) == (b"", SW_OK)


def test_select_can_be_repeated(emu):
    # A host re-selects before every logical channel reset (§2.4); the
    # dispatcher must not treat the second SELECT as a state change.
    assert emu.select()[1] == SW_OK
    assert emu.select()[1] == SW_OK


def test_unregistered_aid_is_6a82(emu):
    _, sw = emu.send(UNREGISTERED_AID)
    assert sw == 0x6A82


def test_unknown_ins_is_6d00(emu):
    assert emu.select()[1] == SW_OK
    # 0x1E is inside the §2.2 INS window but unassigned (0x1B grew a
    # VERIFY_PIN in US-1691); 0x00 is outside it.
    _, sw = emu.send(apdu(0x1E))
    assert sw == SW_INS_NOT_SUPPORTED
    _, sw = emu.send(apdu(0x00))
    assert sw == SW_INS_NOT_SUPPORTED


def test_public_reads_answer_on_the_selected_applet(emu):
    assert emu.select()[1] == SW_OK
    # Touch-free reads (§2.3) reach the applet's process arm directly, with
    # no further SELECT traffic, exactly as a client drives them.
    data, sw = emu.send(apdu(INS_GET_INFO))
    assert sw == SW_OK
    assert len(data) == 8
    # EXPORT_KEY is retired (US-1699): the byte answers 6D00, empty slot
    # or live slot alike — the command is gone, not state-dependent.
    _, sw = emu.send(apdu(INS_EXPORT_KEY, p1=0))
    assert sw == 0x6D00


def test_select_is_the_only_way_in(emu):
    # Without a SELECT the dispatcher has no applet to route to: the same
    # INS is refused with the dispatcher's "nothing here" (6A82).
    _, sw = emu.send(apdu(INS_GET_INFO))
    assert sw == 0x6A82
    # A truncated AID must not select either (the §2.1 prefix rule runs in
    # the registered direction: the registered AID is a prefix of the
    # request, and `F0 00 00 00` is not one of Nostr's).
    truncated = bytes([0x00, 0xA4, 0x04, 0x04, 0x03]) + NOSTR_AID[:3]
    _, sw = emu.send(truncated)
    assert sw == 0x6A82
    _, sw = emu.send(apdu(INS_GET_INFO))
    assert sw == 0x6A82
    # The full AID selects, and the very same INS is then served.
    assert emu.select()[1] == SW_OK
    _, sw = emu.send(apdu(INS_GET_INFO))
    assert sw == SW_OK
