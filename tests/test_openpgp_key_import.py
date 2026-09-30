"""US-335 harness tests: PUT DO key import (private key template, INS 0xDA /
DO 0x3FFF) for the non-RSA curves the suite covers — NIST P-256, Ed25519 and
Cv25519.

Flow mirrors the Gnuk suite chain (card_test_0_set_attr → card_test_1_import_keys
→ cmd_get_public_key): VERIFY PW3, PUT algorithm attributes (C1/C2/C3), import
each private key via PUT DO odd (4D template), then read the public key back
(GET 7F49 via INS 0x47 P1=0x81) and check it matches the imported key.

Factory PINs per the suite: PW1=123456, PW3=12345678.
"""

from card_const import (
    FACTORY_PASSPHRASE_PW3,
    KEY_ATTRIBUTES_CV25519,
    KEY_ATTRIBUTES_ECDSA_NISTP256R1,
    KEY_ATTRIBUTES_ED25519,
    KEY_ATTRIBUTES_ECDH_NISTP256R1,
)
from curve25519_keys import curve25519_pk
from nistp256r1_keys import nistp256r1_pk


def _setup_curves(card, pk):
    assert card.verify(3, FACTORY_PASSPHRASE_PW3)
    assert card.cmd_put_data(0x00, 0xC1, pk.key_attr_list[0])
    assert card.cmd_put_data(0x00, 0xC2, pk.key_attr_list[1])
    assert card.cmd_put_data(0x00, 0xC3, pk.key_attr_list[2])


def _import_all(card, pk):
    for i in range(3):
        t = pk.key_list[i].build_privkey_template(False)
        assert card.cmd_put_data_odd(0x3F, 0xFF, t)


def _pubkey_blob(card, keyno):
    return card.cmd_get_public_key(keyno)


# --- Ed25519 / Cv25519 (curve25519_pk: sign=Ed25519, dec=Cv25519, aut=Ed25519) --


def test_import_ed25519_and_cv25519(card):
    _setup_curves(card, curve25519_pk)
    _import_all(card, curve25519_pk)


def test_ed25519_pubkey_readback_matches_import(card):
    _setup_curves(card, curve25519_pk)
    _import_all(card, curve25519_pk)
    for keyno in (1, 3):
        blob = _pubkey_blob(card, keyno)
        q = curve25519_pk.key_list[keyno - 1].q
        assert q in blob, "public key %d not echoed back" % keyno


def test_cv25519_pubkey_readback_matches_import(card):
    _setup_curves(card, curve25519_pk)
    _import_all(card, curve25519_pk)
    blob = _pubkey_blob(card, 2)
    q = curve25519_pk.key_list[1].q
    assert q in blob, "Cv25519 public key not echoed back"


# --- NIST P-256 (sign/dec both ECDH-ish per suite key list) ---------------------


def test_import_nistp256r1(card):
    _setup_curves(card, nistp256r1_pk)
    _import_all(card, nistp256r1_pk)


def test_nistp256r1_pubkey_readback_matches_import(card):
    _setup_curves(card, nistp256r1_pk)
    _import_all(card, nistp256r1_pk)
    for keyno in (1, 2, 3):
        blob = _pubkey_blob(card, keyno)
        q = nistp256r1_pk.key_list[keyno - 1].q
        # P-256 keys store q without the 0x04 uncompressed prefix in the suite.
        assert q in blob, "P-256 public key %d not echoed back" % keyno


def test_algorithm_attributes_readback_after_setup(card):
    _setup_curves(card, curve25519_pk)
    # NOTE: opcard's 0xFA lists *supported* algorithms, so check the
    # per-key attribute DOs (C1/C2/C3). The card may append a 0xFF list
    # terminator (spec-legal algorithm list form).
    def _attr(tag, expected):
        got = card.cmd_get_data(0x00, tag)
        assert got is not None
        assert got.startswith(expected), (hex(tag), got.hex())

    _attr(0xC1, KEY_ATTRIBUTES_ED25519)
    _attr(0xC2, KEY_ATTRIBUTES_CV25519)
    _attr(0xC3, KEY_ATTRIBUTES_ED25519)

    _setup_curves(card, nistp256r1_pk)
    _attr(0xC1, KEY_ATTRIBUTES_ECDSA_NISTP256R1)
    _attr(0xC2, KEY_ATTRIBUTES_ECDH_NISTP256R1)
    _attr(0xC3, KEY_ATTRIBUTES_ECDSA_NISTP256R1)


def _gpg_style_template(pk, i):
    """gpg-style template: 7F48 carries 92 <privlen> 99 <publen> and
    5F48 carries d || 0x40||q (opcard's preferred import form)."""
    key = pk.key_list[i]
    keyspec = b"\xb6\xb8\xa4"[i:i + 1]
    d = key.d
    if i == 1:  # Cv25519: d stored big-endian in template
        d = bytes(reversed(d))
    pub = b"\x40" + key.q
    exthdr = keyspec + b"\x00" + b"\x7f\x48" + b"\x04" + b"\x92" + bytes([len(d)]) \
        + b"\x99" + bytes([len(pub)])
    suffix = b"\x5f\x48" + bytes([len(d) + len(pub)])
    body = exthdr + suffix + d + pub
    return b"\x4d" + bytes([len(body)]) + body


def test_import_gpg_style_template_with_public_key(card):
    _setup_curves(card, curve25519_pk)
    for i in range(3):
        assert card.cmd_put_data_odd(0x3F, 0xFF, _gpg_style_template(curve25519_pk, i))
    for keyno in (1, 2, 3):
        blob = _pubkey_blob(card, keyno)
        assert curve25519_pk.key_list[keyno - 1].q in blob
