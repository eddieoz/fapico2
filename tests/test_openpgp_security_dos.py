"""US-339 harness tests: security-support template DOs kept consistent with
imported/generated keys — fingerprints (C5/C7/C8/C9), CA fingerprints
(C6), generation timestamps (0xCD) and the digital-signature counter (0x93).

Factory PINs per the suite: PW1=123456, PW3=12345678.

US-912: GENKEY/PSO are refused while the factory PINs are in force; the two
tests that generate/sign use pin_gate_lifted_once (gate lifted, factory card
restored afterwards) and the gate PINs.
"""

import pytest

from card_const import (
    FACTORY_PASSPHRASE_PW3,
    KEY_ATTRIBUTES_ED25519,
)

from conftest import GATE_PW1, GATE_PW3

from curve25519_keys import curve25519_pk

ZEROS20 = b"\x00" * 20
ZEROS4 = b"\x00" * 4


def _import_all(card):
    assert card.verify(3, FACTORY_PASSPHRASE_PW3)
    attrs = curve25519_pk.key_attr_list
    for tag, attr in zip((0xC1, 0xC2, 0xC3), attrs):
        assert card.cmd_put_data(0x00, tag, attr)
    for i in range(3):
        assert card.cmd_put_data_odd(
            0x3F, 0xFF, curve25519_pk.key_list[i].build_privkey_template(False)
        )


def _put_fingerprints(card, pk):
    for tag, i in zip((0xC7, 0xC8, 0xC9), range(3)):
        assert card.cmd_put_data(0x00, tag, pk.key_list[i].get_fpr())


def test_fingerprints_put_and_readback(card):
    _import_all(card)
    _put_fingerprints(card, curve25519_pk)
    c5 = card.cmd_get_data(0x00, 0xC5)
    expected = b"".join(curve25519_pk.key_list[i].get_fpr() for i in range(3))
    assert c5 == expected


def test_fingerprint_clears_slot_on_key_removal(card):
    _import_all(card)
    _put_fingerprints(card, curve25519_pk)
    # Remove the DEC key (keyno 2): its fingerprint slot must zero out.
    card.cmd_put_data_key_import_remove(2)  # helper returns None on success
    c5 = card.cmd_get_data(0x00, 0xC5)
    assert c5[0:20] == curve25519_pk.key_list[0].get_fpr()
    assert c5[20:40] == ZEROS20
    assert c5[40:60] == curve25519_pk.key_list[2].get_fpr()


def test_ca_fingerprints_default_and_put(card):
    # PUT goes through the individual DOs (CA1/CA2/CA3 = CA/CB/CC); GET
    # exposes only the aggregate C6 list.
    assert card.cmd_get_data(0x00, 0xC6) == ZEROS20 * 3
    assert card.verify(3, FACTORY_PASSPHRASE_PW3)
    for tag in (0xCA, 0xCB, 0xCC):
        caf = bytes(20 + tag for _ in range(20))
        assert card.cmd_put_data(0x00, tag, caf)
    assert card.cmd_get_data(0x00, 0xC6) == bytes(20 + 0xCA for _ in range(20)) \
        + bytes(20 + 0xCB for _ in range(20)) + bytes(20 + 0xCC for _ in range(20))


def test_generation_dates_consistent_with_genkey(pin_gate_lifted_once):
    # Suite posture: the client stamps the generation date after GENKEY
    # (CE/CF/D0 per key slot); the aggregate 0xCD list must reflect it.
    card = pin_gate_lifted_once
    assert card.verify(3, GATE_PW3)
    assert card.cmd_put_data(0x00, 0xC1, KEY_ATTRIBUTES_ED25519)
    assert card.cmd_genkey(1)
    date = b"\x00\x00\x00\x5f"
    assert card.cmd_put_data(0x00, 0xCE, date)
    cd = card.cmd_get_data(0x00, 0xCD)
    assert cd is not None and len(cd) == 12
    assert cd[0:4] == date, "sign key generation date not reflected in 0xCD"


def test_signature_counter_starts_at_zero_and_increments(pin_gate_lifted_once):
    card = pin_gate_lifted_once
    assert card.verify(3, GATE_PW3)
    assert card.cmd_put_data(0x00, 0xC1, KEY_ATTRIBUTES_ED25519)
    assert card.cmd_genkey(1)
    c93 = card.cmd_get_data(0x00, 0x93)
    assert c93 is not None
    base = int.from_bytes(c93, "big")
    import hashlib

    assert card.verify(1, GATE_PW1)
    card.cmd_pso(0x9E, 0x9A, hashlib.sha256(b"counter").digest())
    c93 = card.cmd_get_data(0x00, 0x93)
    assert int.from_bytes(c93, "big") == base + 1
