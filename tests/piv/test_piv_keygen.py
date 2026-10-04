"""PIV GEN KEY (0x47) — RED until US-374 lands.

Asserts the wire contract the Rust port must meet (C `cmd_asym_keygen` parity,
scoped to ECC per ADR 0001):
  * GEN KEY P-256 (slot 9A) and P-384 (slot 9C) answer 9000 with the public key
    ``7F 49 <len> 86 <ptlen> <04||X||Y>``; the point is self-consistent (right
    length, on-curve) and matches both the stored cert (X.509) and the
    GET METADATA (0xF7) public key.
  * GET METADATA reports algo / origin(0x01 generated) / pubkey.
  * Negatives: no mgm -> 6982, bad slot -> 6B00, bad alg -> 6984.

Every one of these is RED today: the current emulator answers 0x47 (and 0xF7)
with ``6D00`` (INS not implemented), so the first 9000 assertion in each test
fails on a plain protocol assertion — not a fixture/timeout crash. These turn
GREEN when US-374 implements GEN KEY + attestation + GET METADATA.
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
    reason='US-374 (GEN KEY 0x47 + attestation + GET METADATA) is not implemented; the card answers 6D00',
    strict=False,
)

from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives.asymmetric import ec

from conftest import (
    ALGO_ECCP256,
    ALGO_ECCP384,
    SLOT_AUTH,
    SLOT_SIG,
    OBJ_AUTHENTICATION,
    OBJ_SIGNATURE,
    SW_OK,
    SW_SECURITY_STATUS_NOT_SATISFIED,
    SW_WRONG_P1P2,
    SW_DATA_INVALID,
    ORIGIN_GENERATED,
    secp256r1,
    secp384r1,
    assert_point_on_curve,
    parse_metadata,
    parse_53_value,
    PivSession,
)

# C `make_ecdsa_response` shape: 7F 49 <len> 86 <ptlen> <point>.
RESP_7F = 0x7F
RESP_TPL_LEN = 0x49


def _genkey_response_pubkey(data: bytes):
    """Return the uncompressed point from a GEN KEY response body."""
    assert data[:2] == bytes([RESP_7F, RESP_TPL_LEN]), \
        "GEN KEY response must be 7F 49 <len> ..., got %s" % data[:4].hex()
    assert data[3] == 0x86, "GEN KEY response must carry an 86 point tag"
    ptlen = data[4]
    return data[5:5 + ptlen]


def _cert_public_point(cert) -> bytes:
    fs = (cert.public_key().curve_key_size + 7) // 8
    nums = cert.public_key().public_numbers()
    return b"\x04" + nums.x.to_bytes(fs, "big") + nums.y.to_bytes(fs, "big")


def _check_generated_key(piv: PivSession, slot: int, algo: int, curve, cert_fid: int) -> bytes:
    """Shared GEN KEY post-conditions: response/cert/metadata all agree."""
    data, sw = piv.gen_key(slot, algo)
    assert sw == SW_OK, "GEN KEY must answer 9000 (got %04X)" % sw
    point = _genkey_response_pubkey(data)
    assert_point_on_curve(point, curve)
    # Cert object (US-374 attestation) is readable and parses as X.509.
    cert_der, sw = piv.get_object(cert_fid)
    assert sw == SW_OK, "cert object 0x%04X must be present after GEN KEY" % cert_fid
    cert = load_der_x509_certificate(parse_53_value(cert_der))
    assert isinstance(cert.public_key(), ec.EllipticCurvePublicKey), "cert must be an EC cert"
    cert_point = _cert_public_point(cert)
    assert cert_point == point, "cert public key must match the GEN KEY response point"
    # GET METADATA: algo / origin / pubkey all consistent with the response.
    meta_data, sw = piv.get_metadata(slot)
    assert sw == SW_OK, "GET METADATA must answer 9000 (got %04X)" % sw
    meta = parse_metadata(meta_data)
    assert meta["algo"] == algo, "metadata algo must be %02X" % algo
    assert meta["origin"] == ORIGIN_GENERATED, "metadata origin must be GENERATED (0x01)"
    assert meta["pubkey"] == point, "metadata pubkey must match the GEN KEY response point"
    return point


def test_genkey_p256_slot_9a(piv):
    assert piv.mgm_auth() == SW_OK
    _check_generated_key(piv, SLOT_AUTH, ALGO_ECCP256, secp256r1(), OBJ_AUTHENTICATION)


def test_genkey_p384_slot_9c(piv):
    assert piv.mgm_auth() == SW_OK
    _check_generated_key(piv, SLOT_SIG, ALGO_ECCP384, secp384r1(), OBJ_SIGNATURE)


def test_genkey_requires_mgm_session(piv):
    # The autouse fixture re-SELECTed PIV, clearing the mgm session. C checks
    # has_mgm FIRST, so a well-formed GEN KEY without auth answers 6982.
    assert piv.gen_key(SLOT_AUTH, ALGO_ECCP256)[1] == SW_SECURITY_STATUS_NOT_SATISFIED


def test_genkey_bad_slot_rejected(piv):
    assert piv.mgm_auth() == SW_OK
    # 0x9B (card mgm) is not a key-generation slot. Task contract: 6B00.
    # (C `cmd_asym_keygen` returns 6A86 here — see README protocol notes.)
    assert piv.gen_key(0x9B, ALGO_ECCP256)[1] == SW_WRONG_P1P2


def test_genkey_bad_alg_rejected(piv):
    assert piv.mgm_auth() == SW_OK
    # 0x05 is not a supported ECC algorithm (ADR 0001: ECC-only). -> 6984.
    assert piv.gen_key(SLOT_AUTH, 0x05)[1] == SW_DATA_INVALID
