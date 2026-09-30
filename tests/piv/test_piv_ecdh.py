"""PIV ECDH (0x3C) — RED until US-375 lands.

ECDH is the ADR-0001 addition (not in the C reference). Single APDU
``00 3C <alg> <slot> 7C <n> 81 <E>`` where ``E`` is the host's ephemeral
uncompressed public key; the card answers ``7C <m> 82 <Z>`` where ``Z`` is the
raw shared-secret x-coordinate (32 bytes P-256 / 48 bytes P-384).

The test imports a known private scalar (so the card's public key Q = d*G is
known), generates a fresh host ephemeral key, and asserts the card's ``Z``
equals the Python-computed ECDH shared secret ``host_private * Q`` (x-coord).

RED today: the current emulator answers 0x3C with ``6D00`` (and the 0xFE import
it relies on with ``6D00``), so the first 9000 assertion fails on a plain
protocol assertion. GREEN when US-374 (import) + US-375 (ECDH) land.
"""

from cryptography.hazmat.primitives.asymmetric import ec

from conftest import (
    ALGO_ECCP256,
    ALGO_ECCP384,
    SLOT_CARDAUTH,
    SW_OK,
    PINPOLICY_NEVER,
    secp256r1,
    secp384r1,
    field_size,
    scalar_bytes,
    expected_pubkey,
)

D_P256 = 2
D_P384 = 3


def _uncompressed(pub) -> bytes:
    n = pub.public_numbers()
    fs = (pub.curve_key_size + 7) // 8
    return b"\x04" + n.x.to_bytes(fs, "big") + n.y.to_bytes(fs, "big")


def _ecdh_and_check(piv, slot: int, algo: int, d: int, curve) -> None:
    fs = field_size(curve)
    # Import a known key -> card public key Q = d*G.
    assert piv.import_key(slot, algo, scalar_bytes(d, fs), PINPOLICY_NEVER) == SW_OK, \
        "IMPORT must answer 9000 (setup for ECDH)"
    card_pub = ec.derive_private_key(d, curve).public_key()
    # Fresh host ephemeral keypair.
    host_priv = ec.generate_private_key(curve)
    host_pub = _uncompressed(host_priv.public_key())
    data, sw = piv.ecdh(slot, algo, host_pub)
    assert sw == SW_OK, "ECDH must answer 9000 (got %04X)" % sw
    # Response: 7C <m> 82 <Z>  (Z = raw shared-secret x-coordinate).
    assert data[0] == 0x7C, "ECDH response must be a 7C template, got %s" % data[:3].hex()
    m = data[1]
    assert data[2] == 0x82, "ECDH response must carry an 82 shared-secret tag"
    z = data[3:3 + (m - 1)]
    assert len(z) == fs, "ECDH shared secret must be %d bytes (got %d)" % (fs, len(z))
    # Python cross-check: shared secret = host_private * Q (x-coordinate).
    expected = host_priv.exchange(ec.ECDH(), card_pub)
    assert z == expected, "ECDH Z %s != Python shared x-coord %s" % (z.hex(), expected.hex())


def test_ecdh_p256_slot_9e(piv):
    assert piv.mgm_auth() == SW_OK
    _ecdh_and_check(piv, SLOT_CARDAUTH, ALGO_ECCP256, D_P256, secp256r1())


def test_ecdh_p384_slot_9e(piv):
    assert piv.mgm_auth() == SW_OK
    _ecdh_and_check(piv, SLOT_CARDAUTH, ALGO_ECCP384, D_P384, secp384r1())
