"""PIV slot sign (0x87 to a key slot) — RED until US-375 lands.

Asserts the wire contract (C `cmd_authenticate` slot path, ECC-only per ADR
0001). Signing goes through ``00 87 <alg> <slot> 7C <n> 81 <msg>`` (C-parity,
NOT Yubico's 0x32 SIGN) and answers ``7C <olen+2> 82 <olen> <DER sig>``; the
DER signature is verified in Python against the imported key's public key over
the SHA-256 (P-256) / SHA-384 (P-384) hash of the message.

  * P-256 sign (slot 9C) and P-384 sign (slot 9D) -> 9000 + valid DER signature.
  * Sign on a slot with no key -> 6581.
  * Sign with an algorithm that does not match the stored key -> 6700.

RED today: the current emulator answers slot ``0x87`` with ``6A81`` (function
not yet supported) and ``0xFE`` (the key import these tests rely on) with
``6D00``, so each test's first 9000 assertion fails on a plain protocol
assertion. GREEN when US-374 (import) + US-375 (slot sign) land.
"""

from cryptography.hazmat.primitives import hashes

from conftest import (
    ALGO_ECCP256,
    ALGO_ECCP384,
    SLOT_SIG,
    SLOT_KEYMGM,
    RETIRED1,
    SW_OK,
    SW_MEMORY_FAILURE,
    SW_WRONG_DATA,
    PINPOLICY_NEVER,
    secp256r1,
    secp384r1,
    field_size,
    scalar_bytes,
    expected_pubkey,
    verify_ecdsa,
)

D_P256 = 2
D_P384 = 3


def _import(piv, slot: int, algo: int, d: int, curve) -> None:
    assert piv.import_key(slot, algo, scalar_bytes(d, field_size(curve)), PINPOLICY_NEVER) == SW_OK, \
        "IMPORT must answer 9000 (setup for the sign)"


def _sign_and_verify(piv, slot: int, algo: int, d: int, curve, hash_alg) -> None:
    msg = b"PIV slot-sign test vector"
    data, sw = piv.slot_sign(slot, algo, msg)
    assert sw == SW_OK, "slot sign must answer 9000 (got %04X)" % sw
    # C shape: 7C <olen+2> 82 <olen> <DER sig>.
    assert data[0] == 0x7C, "sign response must be a 7C template, got %s" % data[:4].hex()
    assert data[2] == 0x82, "sign response must carry an 82 signature tag"
    sig = data[4:4 + data[3]]
    assert sig, "sign response must carry a non-empty DER signature"
    # Python-side cross-check against the imported key's public key.
    verify_ecdsa(sig, msg, expected_pubkey(d, curve), curve, hash_alg)


def test_sign_p256_slot_9c(piv):
    assert piv.mgm_auth() == SW_OK
    curve = secp256r1()
    _import(piv, SLOT_SIG, ALGO_ECCP256, D_P256, curve)
    _sign_and_verify(piv, SLOT_SIG, ALGO_ECCP256, D_P256, curve, hashes.SHA256())


def test_sign_p384_slot_9d(piv):
    assert piv.mgm_auth() == SW_OK
    curve = secp384r1()
    _import(piv, SLOT_KEYMGM, ALGO_ECCP384, D_P384, curve)
    _sign_and_verify(piv, SLOT_KEYMGM, ALGO_ECCP384, D_P384, curve, hashes.SHA384())


def test_sign_no_key_returns_6581(piv):
    assert piv.mgm_auth() == SW_OK
    # RETIRED1 (0x82) is never populated by any other test -> a genuine no-key
    # slot (C `cmd_authenticate`: no key data -> SW_MEMORY_FAILURE 6581).
    data, sw = piv.slot_sign(RETIRED1, ALGO_ECCP256, b"no key here")
    assert sw == SW_MEMORY_FAILURE, "sign on an empty slot must answer 6581 (got %04X)" % sw
    assert data == b""


def test_sign_algo_mismatch_returns_6700(piv):
    assert piv.mgm_auth() == SW_OK
    # Import a P-256 key, then sign with the P-384 algorithm -> 6700.
    curve = secp256r1()
    _import(piv, SLOT_SIG, ALGO_ECCP256, D_P256, curve)
    data, sw = piv.slot_sign(SLOT_SIG, ALGO_ECCP384, b"mismatch")
    assert sw == SW_WRONG_DATA, "signing with a non-matching algo must answer 6700 (got %04X)" % sw
    assert data == b""
