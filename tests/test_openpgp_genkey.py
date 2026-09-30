"""US-338 harness tests: algorithm attributes (C1/C2/C3 PUT/GET) and ECC
on-card key generation (GENKEY, INS 0x47 P1=0x80).

Generated keys are proven live: Ed25519/ECDSA sign via PSO and verify with
the returned public key; X25519/P-256 decipher roundtrip against the
returned public key.

US-912: GENKEY/PSO are refused while the factory PINs are in force, so this
module lifts the gate (PW1/PW3 -> GATE_PW1/GATE_PW3) and restores a factory
card afterwards.
"""

import hashlib

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from card_const import (
    KEY_ATTRIBUTES_CV25519,
    KEY_ATTRIBUTES_ECDSA_NISTP256R1,
    KEY_ATTRIBUTES_ED25519,
    KEY_ATTRIBUTES_ECDH_NISTP256R1,
)
from conftest import GATE_PW1, GATE_PW3, lift_factory_pin_gate, restore_factory_card

DIGEST = hashlib.sha256(b"genkey consistency check").digest()


@pytest.fixture(scope="module")
def card(card):
    lift_factory_pin_gate(card)
    yield card
    restore_factory_card(card)


def _genkey(card, keyno):
    return card.cmd_genkey(keyno)


def _extract_point(blob):
    """Return the point from the 7F49 response's 86 DO, 0x40-prefixed.

    opcard echoes the point without the 0x40 uncompressed header (86 20 for
    32-byte Montgomery/Edwards points, 86 41 with 0x04 prefix for P-256)."""
    for hdr in (b"\x86\x21", b"\x86\x20", b"\x86\x41"):
        i = blob.find(hdr)
        if i >= 0:
            val = blob[i + 2 : i + 2 + (33 if hdr[1] == 0x21 else 32 if hdr[1] == 0x20 else 65)]
            if len(val) == 33:
                return val
            if len(val) == 65:
                return val
            if len(val) == 32:
                return b"\x40" + val
    raise AssertionError(blob.hex())


def _set_attr(card, keyno, attr):
    assert card.cmd_put_data(0x00, 0xC0 + keyno, attr)


# --- Ed25519 --------------------------------------------------------------------


def test_genkey_ed25519_signs_and_verifies(card):
    assert card.verify(3, GATE_PW3)
    _set_attr(card, 1, KEY_ATTRIBUTES_ED25519)
    blob = _genkey(card, 1)
    q = _extract_point(blob)[1:]  # strip the 0x40 header for Raw format
    assert card.verify(1, GATE_PW1)
    sig = card.cmd_pso(0x9E, 0x9A, DIGEST)
    Ed25519PublicKey.from_public_bytes(q).verify(sig, DIGEST)
    # Attribute and public key readbacks agree.
    assert card.cmd_get_data(0x00, 0xC1).startswith(KEY_ATTRIBUTES_ED25519)
    assert q in card.cmd_get_public_key(1)


def test_genkey_cv25519_decipher_roundtrip(card):
    assert card.verify(3, GATE_PW3)
    _set_attr(card, 2, KEY_ATTRIBUTES_CV25519)
    blob = _genkey(card, 2)
    q = _extract_point(blob)[1:]
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    data = b"\xa6\x25\x7f\x49\x22\x86\x20" + eph_pub
    assert card.verify(2, GATE_PW1)
    shared = card.cmd_pso(0x80, 0x86, data)
    assert shared == eph.exchange(X25519PublicKey.from_public_bytes(q))


def test_genkey_nistp256_signs_and_deciphers(card):
    assert card.verify(3, GATE_PW3)
    _set_attr(card, 1, KEY_ATTRIBUTES_ECDSA_NISTP256R1)
    _set_attr(card, 2, KEY_ATTRIBUTES_ECDH_NISTP256R1)
    sig_blob = _genkey(card, 1)
    sig_q = _extract_point(sig_blob)
    assert card.verify(1, GATE_PW1)
    sig = card.cmd_pso(0x9E, 0x9A, DIGEST)
    assert len(sig) == 64
    pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), sig_q
    )
    der = encode_dss_signature(
        int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    )
    pub.verify(der, DIGEST, ec.ECDSA(Prehashed(hashes.SHA256())))

    dec_blob = _genkey(card, 2)
    dec_q = _extract_point(dec_blob)
    eph = ec.generate_private_key(ec.SECP256R1())
    eph_pub = eph.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    )
    data = b"\xa6\x46\x7f\x49\x43\x86\x41" + eph_pub
    assert card.verify(2, GATE_PW1)
    shared = card.cmd_pso(0x80, 0x86, data)
    expected = eph.exchange(
        ec.ECDH(),
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), dec_q),
    )
    assert shared == expected[-32:]


def test_genkey_requires_admin(card):
    card.deauthenticate(3)
    try:
        card.cmd_genkey(1)
        raised = False
    except ValueError:
        raised = True
    assert raised
