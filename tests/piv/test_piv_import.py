"""PIV IMPORT key (0xFE) — RED until US-374 lands.

Asserts the wire contract (C `cmd_import_asym` parity, ECC-only per ADR 0001):
  * A known private scalar imported into a slot yields a GET METADATA (0xF7)
    public key that equals Q = d*G computed in Python — the load-bearing
    cross-check that the card did the scalar->point math correctly.
  * Negatives: bad scalar length -> 6984, no mgm -> 6982, bad alg -> 6700.

RED today: the current emulator answers 0xFE (and 0xF7) with ``6D00`` (INS not
implemented), so each test's first 9000 assertion fails on a plain protocol
assertion. GREEN when US-374 implements IMPORT + GET METADATA.
"""

import pytest

# These assert a contract that is written down but not implemented yet, so
# they are red by construction rather than by regression. They stay in the
# tree because the contract is the deliverable and the file documents why
# each assertion is shaped the way it is (see the module docstring).
#
# strict=False on purpose: an XPASS when the Rust story lands is reported
# but not a failure, so landing US-374/US-375 does not turn the gate red
# on the day it stops being xfail. To retire one of these, delete the
# marker -- a test that silently starts passing is not evidence the gate
# noticed it.
pytestmark = pytest.mark.xfail(
    reason='US-374 (IMPORT 0xFE + GET METADATA 0xF7) is not implemented; the card answers 6D00',
    strict=False,
)

from conftest import (
    ALGO_ECCP256,
    ALGO_ECCP384,
    SLOT_SIG,
    SLOT_KEYMGM,
    SW_OK,
    SW_SECURITY_STATUS_NOT_SATISFIED,
    SW_DATA_INVALID,
    SW_WRONG_DATA,
    ORIGIN_IMPORTED,
    PINPOLICY_NEVER,
    secp256r1,
    secp384r1,
    field_size,
    scalar_bytes,
    expected_pubkey,
    assert_point_on_curve,
    parse_metadata,
)

# Fixed, deterministic private scalars (valid: 1 <= d < n for both curves).
D_P256 = 2
D_P384 = 3


def _import_and_check(piv, slot: int, algo: int, d: int, curve) -> None:
    fs = field_size(curve)
    assert piv.import_key(slot, algo, scalar_bytes(d, fs), PINPOLICY_NEVER) == SW_OK, \
        "IMPORT %02X (P-256/384) must answer 9000" % algo
    meta_data, sw = piv.get_metadata(slot)
    assert sw == SW_OK, "GET METADATA must answer 9000 (got %04X)" % sw
    meta = parse_metadata(meta_data)
    assert meta["algo"] == algo, "metadata algo must be %02X" % algo
    assert meta["origin"] == ORIGIN_IMPORTED, "metadata origin must be IMPORTED (0x02)"
    # The load-bearing check: metadata pubkey == d*G computed in Python.
    expected = expected_pubkey(d, curve)
    assert meta["pubkey"] == expected, \
        "metadata pubkey %s != expected d*G %s" % (meta["pubkey"].hex(), expected.hex())
    assert_point_on_curve(meta["pubkey"], curve)


def test_import_known_scalar_p256(piv):
    assert piv.mgm_auth() == SW_OK
    _import_and_check(piv, SLOT_SIG, ALGO_ECCP256, D_P256, secp256r1())


def test_import_known_scalar_p384(piv):
    assert piv.mgm_auth() == SW_OK
    _import_and_check(piv, SLOT_KEYMGM, ALGO_ECCP384, D_P384, secp384r1())


def test_import_bad_scalar_length_rejected(piv):
    assert piv.mgm_auth() == SW_OK
    # P-256 requires a 32-byte scalar; 31 bytes -> 6984 (C SW_DATA_INVALID).
    assert piv.import_key(SLOT_SIG, ALGO_ECCP256, b"\x02" * 31, PINPOLICY_NEVER) == SW_DATA_INVALID


def test_import_requires_mgm_session(piv):
    # Autouse re-SELECT cleared the mgm session; C checks has_mgm first -> 6982.
    assert piv.import_key(SLOT_SIG, ALGO_ECCP256, scalar_bytes(D_P256, 32), PINPOLICY_NEVER) \
        == SW_SECURITY_STATUS_NOT_SATISFIED


def test_import_bad_alg_rejected(piv):
    assert piv.mgm_auth() == SW_OK
    # 0x05 is not a supported algorithm -> 6700 (C SW_WRONG_DATA).
    assert piv.import_key(SLOT_SIG, 0x05, b"\x02" * 32, PINPOLICY_NEVER) == SW_WRONG_DATA
