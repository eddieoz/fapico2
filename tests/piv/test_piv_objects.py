"""PIV data objects (GET/PUT DATA 0xC1xx) — GREEN now (US-373).

Covers the already-landed data-object surface: PUT/GET round-trip, the C
``tlv_format_len`` long-form length encodings (``81 xx`` for 128..255 and
``82 hi lo`` for >= 256), empty-53 clear, unknown-fid rejection (6581),
oversize rejection (6700), and the no-mgm-session gate (6982).

These assert exactly what the C reference firmware does (``cmd_piv_get_data`` /
``cmd_piv_put_data``) and the parity Rust port already implements — GREEN.
"""

from conftest import (
    OBJ_CHUID,
    OBJ_FINGERPRINTS,
    OBJ_SECURITY,
    OBJ_CAPABILITY,
    SW_OK,
    SW_WRONG_LENGTH,
    SW_MEMORY_FAILURE,
    SW_SECURITY_STATUS_NOT_SATISFIED,
    SW_FILE_NOT_FOUND,
)


def test_put_get_roundtrip(piv):
    assert piv.mgm_auth() == SW_OK
    value = bytes([0x30, 0x03, 0x50, 0x49, 0x56])  # 0x50 0x49 0x56 == "PIV"
    assert piv.put_object(OBJ_CHUID, value) == SW_OK
    data, sw = piv.get_object(OBJ_CHUID)
    assert sw == SW_OK
    # C `cmd_piv_get_data` answers `53 <len> <contents>`.
    assert data == bytes([0x53, len(value)]) + value


def test_get_200byte_uses_81xx_length_form(piv):
    assert piv.mgm_auth() == SW_OK
    value = b"\x5A" * 200
    assert piv.put_object(OBJ_FINGERPRINTS, value) == SW_OK
    data, sw = piv.get_object(OBJ_FINGERPRINTS)
    assert sw == SW_OK
    # 200 (0xC8) -> `81 C8` long-form length (C `tlv_format_len`).
    assert data[:3] == bytes([0x53, 0x81, 0xC8]), "200-byte object must use the 81 xx length form"
    assert len(data) == 3 + 200
    assert data[3:] == value


def test_get_2048byte_uses_82xx_length_form(piv):
    assert piv.mgm_auth() == SW_OK
    value = b"\x5A" * 2048
    assert piv.put_object(OBJ_SECURITY, value) == SW_OK
    data, sw = piv.get_object(OBJ_SECURITY)
    assert sw == SW_OK
    # 2048 (0x0800) -> `82 08 00` two-byte long form (C `tlv_format_len`).
    assert data[:4] == bytes([0x53, 0x82, 0x08, 0x00]), "2048-byte object must use the 82 hi lo length form"
    assert len(data) == 4 + 2048
    assert data[4:] == value


def test_put_empty_clears_object(piv):
    assert piv.mgm_auth() == SW_OK
    assert piv.put_object(OBJ_CAPABILITY, b"cap") == SW_OK
    assert piv.get_object(OBJ_CAPABILITY)[1] == SW_OK
    # Empty 53 clears the object (C `flash_clear_file`).
    assert piv.clear_object(OBJ_CAPABILITY) == SW_OK
    data, sw = piv.get_object(OBJ_CAPABILITY)
    assert sw == SW_FILE_NOT_FOUND
    assert data == b""


def test_put_unknown_fid_rejected_6581(piv):
    assert piv.mgm_auth() == SW_OK
    # 0xC104 has no file in the C table -> SW_MEMORY_FAILURE (6581).
    assert piv.put_object(0xC104, b"test") == SW_MEMORY_FAILURE


def test_put_oversize_rejected_6700(piv):
    assert piv.mgm_auth() == SW_OK
    # 53 payload over 2048 (C OPENPGP_MAX_OBJECT_SIZE) -> SW_WRONG_LENGTH (6700).
    assert piv.put_object(OBJ_SECURITY, b"\x5A" * 2049) == SW_WRONG_LENGTH
    # Exactly 2048 is still admitted.
    assert piv.put_object(OBJ_SECURITY, b"\x5A" * 2048) == SW_OK


def test_put_requires_mgm_session(piv):
    # The autouse fixture re-SELECTed PIV, clearing the mgm session.
    assert piv.put_object(OBJ_CHUID, b"x") == SW_SECURITY_STATUS_NOT_SATISFIED
    # GET DATA needs no mgm session (absent object -> 6A82, not 6982).
    assert piv.get_object(OBJ_FINGERPRINTS)[1] in (SW_OK, SW_FILE_NOT_FOUND)
