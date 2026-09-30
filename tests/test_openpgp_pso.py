"""US-336 harness tests: PSO:SIGN (00 2A 9E 9A), PSO:DECIPHER (00 2A 80 86)
and INTERNAL AUTHENTICATE (00 88) over ECC keys imported via PUT DO (US-335).

Signature verification and ECDH reference computations use the `cryptography`
package (the suite's own pk_* helpers need libgcrypt via cffi, which this
environment does not provide).

US-912: PSO is refused while the factory PINs are in force, so this module
lifts the gate (PW1/PW3 -> GATE_PW1/GATE_PW3) and restores a factory card
afterwards.
"""

import hashlib

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.asymmetric.ec import (
    derive_private_key,
    ECDH,
    SECP256R1,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from conftest import GATE_PW1, GATE_PW3, lift_factory_pin_gate, restore_factory_card
from curve25519_keys import curve25519_pk


@pytest.fixture(scope="module")
def card(card):
    lift_factory_pin_gate(card)
    yield card
    restore_factory_card(card)

from nistp256r1_keys import nistp256r1_pk

PLAIN = b"This is a test message."
DIGEST = hashlib.sha256(PLAIN).digest()


def _setup_and_import(card, pk):
    assert card.verify(3, GATE_PW3)
    for tag, attr in zip((0xC1, 0xC2, 0xC3), pk.key_attr_list):
        assert card.cmd_put_data(0x00, tag, attr)
    for i in range(3):
        assert card.cmd_put_data_odd(0x3F, 0xFF, pk.key_list[i].build_privkey_template(False))


# --- Ed25519 / Cv25519 (sign key 0, dec key 1, aut key 2) ------------------------


def test_ed25519_pso_sign(card):
    _setup_and_import(card, curve25519_pk)
    assert card.verify(1, GATE_PW1)
    sig = card.cmd_pso(0x9E, 0x9A, DIGEST)
    priv = Ed25519PrivateKey.from_private_bytes(curve25519_pk.key_list[0].d)
    priv.public_key().verify(sig, DIGEST)  # raises on mismatch


def test_ed25519_internal_authenticate(card):
    _setup_and_import(card, curve25519_pk)
    assert card.verify(2, GATE_PW1)  # PW1 for "other" operations
    sig = card.cmd_internal_authenticate(DIGEST)
    priv = Ed25519PrivateKey.from_private_bytes(curve25519_pk.key_list[2].d)
    priv.public_key().verify(sig, DIGEST)


def test_cv25519_pso_decipher(card):
    _setup_and_import(card, curve25519_pk)
    assert card.verify(2, GATE_PW1)  # PW1 for "other" operations
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    # PSO:DECIPHER data per OpenPGP spec §7.2.11 (ECDH):
    # A6 <len> 7F49 <len> 86 <len> <ephemeral point>.
    data = b"\xa6\x25\x7f\x49\x22\x86\x20" + eph_pub
    shared = card.cmd_pso(0x80, 0x86, data)
    assert len(shared) == 32
    # The card stores the Gnuk big-endian scalar; opcard reverses it into
    # native (little-endian) X25519 form at import.
    card_priv = X25519PrivateKey.from_private_bytes(
        bytes(reversed(curve25519_pk.key_list[1].d))
    )
    expected = card_priv.exchange(eph.public_key())
    assert shared == expected


# --- NIST P-256 -------------------------------------------------------------------


def _p256_pub_bytes(q):
    return q if len(q) == 65 else b"\x04" + q


def test_nistp256r1_pso_sign(card):
    _setup_and_import(card, nistp256r1_pk)
    assert card.verify(1, GATE_PW1)
    sig = card.cmd_pso(0x9E, 0x9A, DIGEST)
    from cryptography.hazmat.primitives.asymmetric.utils import (
        encode_dss_signature,
    )
    from cryptography.hazmat.primitives import hashes

    prehashed = ec.ECDSA(Prehashed(hashes.SHA256()))
    d = int.from_bytes(nistp256r1_pk.key_list[0].d, "big")
    priv = derive_private_key(d, SECP256R1())
    # The card returns a raw r||s (64-byte) ECDSA signature over the digest.
    assert len(sig) == 64
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"),
                               int.from_bytes(sig[32:], "big"))
    priv.public_key().verify(der, DIGEST, prehashed)


def test_nistp256r1_internal_authenticate(card):
    _setup_and_import(card, nistp256r1_pk)
    assert card.verify(2, GATE_PW1)  # PW1 for "other" operations
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import (
        encode_dss_signature,
    )

    prehashed = ec.ECDSA(Prehashed(hashes.SHA256()))

    d = int.from_bytes(nistp256r1_pk.key_list[2].d, "big")
    priv = derive_private_key(d, SECP256R1())
    sig = card.cmd_internal_authenticate(DIGEST)
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"),
                               int.from_bytes(sig[32:], "big"))
    priv.public_key().verify(der, DIGEST, prehashed)


def test_nistp256r1_pso_decipher(card):
    _setup_and_import(card, nistp256r1_pk)
    assert card.verify(2, GATE_PW1)  # PW1 for "other" operations
    eph = derive_private_key(int.from_bytes(hashlib.sha256(b"eph").digest(), "big"), SECP256R1())
    eph_pub = eph.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    data = b"\xa6\x46\x7f\x49\x43\x86\x41" + eph_pub
    shared = card.cmd_pso(0x80, 0x86, data)
    expected = eph.exchange(
        ECDH(),
        derive_private_key(
            int.from_bytes(nistp256r1_pk.key_list[1].d, "big"), SECP256R1()
        ).public_key(),
    )
    # The card returns the shared point's X coordinate.
    assert shared == expected[-32:] or shared == expected
