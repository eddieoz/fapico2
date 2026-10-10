"""US-1651 — the key-management flow over the real CCID transport (§2.7).

The happy path (GENERATE → GET_PUBKEY → IMPORT → SIGN → SET_LABEL →
DELETE_KEY), the state refusals (6A84 occupied, 6A80 bad data), and the
presence story (§2.3): a second emulator with `FAPICO2_NOSTR_PRESENCE=deny`
reopens the *same* region file the auto-ack instance seeded and refuses
`SIGN` with `6985` — the deny hook (US-1646) is what makes the touch gate
observable over CCID, because the host build's default presence auto-acks.

Every APDU is the §2.2 transcription from `nostr_ccid`; the host tests in
`apps/nostr/tests/` own the cryptography.
"""

import pytest

from harness.nostr_ccid import (
    INS_DELETE_KEY,
    INS_EXPORT_KEY,
    INS_GENERATE_KEY,
    INS_GET_INFO,
    INS_GET_PUBKEY,
    INS_IMPORT_KEY,
    INS_LIST_KEYS,
    INS_SET_LABEL,
    INS_SIGN,
    NostrEmu,
    SW_INDEX_OCCUPIED,
    SW_NO_SUCH_IDENTITY,
    SW_OK,
    SW_TOUCH_REQUIRED,
    SW_WRONG_DATA,
    apdu,
)

SCALAR = bytes([0x02]) + bytes(31)  # non-zero, below the curve order


@pytest.fixture()
def emu(tmp_path):
    with NostrEmu("keymgmt", tmp_path) as e:
        assert e.select()[1] == SW_OK
        yield e


def test_get_info_layout_over_ccid(emu):
    data, sw = emu.send(apdu(INS_GET_INFO))
    assert sw == SW_OK
    # applet_ver(2) ‖ caps(2) ‖ max_plaintext(2) ‖ n_identities(1) ‖ flags(1)
    assert len(data) == 8
    assert data[0:2] == b"\x00\x01"  # APPLET_VERSION
    caps = int.from_bytes(data[2:4], "big")
    assert caps == 0x0003  # key mgmt (0x0001) + NIP-44 (0x0002), both served
    # The wire-cap value: the largest plaintext whose chunk-rounded padding
    # still fits MAX_WIRE (2074) — 1792 pads to itself, 1793 pads to 2048 and
    # would push the encrypt response off the wire.
    assert int.from_bytes(data[4:6], "big") == 1792  # max_plaintext
    assert data[6] == 0  # empty store


def test_generate_import_sign_round_trip(emu):
    npub0, sw = emu.send(apdu(INS_GENERATE_KEY, p1=0))
    assert sw == SW_OK and len(npub0) == 32

    npub1, sw = emu.send(apdu(INS_IMPORT_KEY, p1=1, data=SCALAR))
    assert sw == SW_OK and len(npub1) == 32 and npub1 != npub0

    data, sw = emu.send(apdu(INS_GET_PUBKEY, p1=1))
    assert sw == SW_OK
    assert data[:32] == npub1
    assert len(data) == 95  # npub(32) ‖ bech32 npub(63)

    sighash = bytes(range(32))
    data, sw = emu.send(apdu(INS_SIGN, p1=1, data=sighash))
    assert sw == SW_OK
    # npub(32) ‖ sig(64): the answer names the key that produced it (§2.2.0a).
    assert data[:32] == npub1 and len(data) == 96


def test_import_occupied_and_bad_scalar_are_refused(emu):
    assert emu.send(apdu(INS_GENERATE_KEY, p1=0))[1] == SW_OK
    # An occupied index: 6A84, whatever the occupant is.
    _, sw = emu.send(apdu(INS_IMPORT_KEY, p1=0, data=SCALAR))
    assert sw == SW_INDEX_OCCUPIED
    # The all-zero scalar is not a valid BIP-340 secret key: 6A80.
    _, sw = emu.send(apdu(INS_IMPORT_KEY, p1=1, data=bytes(32)))
    assert sw == SW_WRONG_DATA
    # And the state refusals are shape-first: a payload on GET_PUBKEY, which
    # takes none, is 6A80 before the store is touched.
    _, sw = emu.send(apdu(INS_GET_PUBKEY, p1=0, data=b"x"))
    assert sw == SW_WRONG_DATA


def test_list_keys_reports_the_live_set(emu):
    assert emu.send(apdu(INS_GENERATE_KEY, p1=0))[1] == SW_OK
    _, sw = emu.send(apdu(INS_IMPORT_KEY, p1=1, data=SCALAR))
    assert sw == SW_OK

    data, sw = emu.send(apdu(INS_LIST_KEYS))
    assert sw == SW_OK
    assert data[0] == 2  # n leads
    # entry = idx(1) ‖ flags(1) ‖ npub(32) ‖ label_len(1) ‖ label
    e0 = data[1:37]
    assert e0[0] == 0 and e0[2:34]  # slot 0, npub present
    assert e0[34] == 0  # no label yet


def test_set_label_delete_export_trio(emu):
    npub0, _ = emu.send(apdu(INS_GENERATE_KEY, p1=0))

    _, sw = emu.send(apdu(INS_SET_LABEL, p1=0, data=b"primary"))
    assert sw == SW_OK
    data, _ = emu.send(apdu(INS_LIST_KEYS))
    # entry = idx(1) ‖ flags(1) ‖ npub(32) ‖ label_len(1) ‖ label → the
    # label bytes start at data[36] (n at 0, entry at 1, len byte at 35).
    assert data[35] == 7
    assert data[36:43] == b"primary"

    data, sw = emu.send(apdu(INS_EXPORT_KEY, p1=0))
    assert sw == SW_OK and len(data) == 32  # the scalar comes back

    data, sw = emu.send(apdu(INS_DELETE_KEY, p1=0))
    assert sw == SW_OK and data == npub0  # the answer names what it destroyed
    _, sw = emu.send(apdu(INS_GET_PUBKEY, p1=0))
    assert sw == SW_NO_SUCH_IDENTITY


@pytest.fixture()
def deny(tmp_path):
    # The auto-ack instance seeds the region file; the deny instance then
    # reopens it, so SIGN reaches its touch gate with a live identity in the
    # slot — the only way `6985` (not `6A82`) is the honest answer.
    with NostrEmu("keymgmt", tmp_path) as e:
        assert e.select()[1] == SW_OK
        npub, sw = e.send(apdu(INS_GENERATE_KEY, p1=0))
        assert sw == SW_OK and len(npub) == 32
    with NostrEmu("deny", tmp_path, presence="deny") as e:
        assert e.select()[1] == SW_OK
        yield e


def test_sign_under_deny_presence_is_6985(deny):
    _, sw = deny.send(apdu(INS_SIGN, p1=0, data=bytes(range(32))))
    assert sw == SW_TOUCH_REQUIRED
    # Public reads are touch-free even under deny (§2.3).
    data, sw = deny.send(apdu(INS_GET_PUBKEY, p1=0))
    assert sw == SW_OK and len(data) == 95


def test_deny_gates_every_identity_creating_command(deny):
    for ins, p1 in ((INS_GENERATE_KEY, 1), (INS_IMPORT_KEY, 1)):
        _, sw = deny.send(apdu(ins, p1=p1, data=SCALAR if ins == INS_IMPORT_KEY else b""))
        assert sw == SW_TOUCH_REQUIRED
    # And the refusal order is state-before-touch (§2.2.0): SIGN against an
    # empty slot is 6A82 under deny too — an absent identity is refused
    # before any touch is asked for.
    _, sw = deny.send(apdu(INS_SIGN, p1=5, data=bytes(range(32))))
    assert sw == SW_NO_SUCH_IDENTITY
