"""PIV status / identity / PIN / management-auth — GREEN now (US-371/372/373).

Covers the already-landed surface of the Rust PIV app: SELECT (FCI blob +
9000), GET VERSION (0xFD), GET SERIAL (0xF8), the PIN/PUK lifecycle (0x20/0x2C),
management-key single-challenge AUTHENTICATE (0x87/0x9B), and the
missing-data-object 6A82.

These assert exactly what the C reference firmware does (``piv.c``) and the
parity Rust port already implements — so they are GREEN against the current
emulator binary.
"""

from conftest import (
    PIV_AID,
    OBJ_FACIAL,
    SW_OK,
    SW_FILE_NOT_FOUND,
    SW_SECURITY_STATUS_NOT_SATISFIED,
    SW_DATA_INVALID,
    SW_PIN_BLOCKED,
)

# OBJ_FACIAL (0xC108) is deliberately reserved for the missing-object check here:
# no other test in the suite writes to it, so it stays absent (6A82).


def test_select_returns_fci(piv):
    data, s1, s2 = piv.apdu(0x00, 0xA4, 0x04, 0x00, PIV_AID)
    assert (s1, s2) == (0x90, 0x00), "SELECT PIV must answer 9000 (port emits the data directly)"
    assert len(data) == 44, "FCI blob must be 44 bytes, got %d" % len(data)
    # 0x4F application DO wrapping the 0x79 (PIV AID) template.
    assert data[:4] == bytes([0x4F, 0x02, 0x01, 0x00])
    assert data[4:15] == bytes([0x79, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00])
    # 0x50 application label, exactly as C `select_piv_aid` emits it.
    assert data[15:17] == bytes([0x50, 0x0D])
    assert data[17:30] == b"Pico Keys PIV"
    # 0xAC proprietary DO wrapping the algorithm capabilities (80 07 ... 2E).
    assert data[30:32] == bytes([0xAC, 0x0C])
    assert data[32:44] == bytes([0x80, 0x07, 0x07, 0x08, 0x0A, 0x0C, 0x11, 0x14, 0x2E, 0x06, 0x01, 0x00])


def test_get_version_is_5_7_0(piv):
    data, sw = piv.get_version()
    assert sw == SW_OK
    assert data == bytes([0x05, 0x07, 0x00]), "GET VERSION must report 5.7.0 (C PIV_VERSION 0x0507)"


def test_get_serial_is_dev_serial(piv):
    data, sw = piv.get_serial()
    assert sw == SW_OK
    assert data == bytes([0x31, 0x32, 0x33, 0x34]), "GET SERIAL must return the 0x31323334 dev serial"


def test_pin_lifecycle(piv):
    # Fresh state (fresh keystore, 3 retries, not authenticated).
    assert piv.query_pin() == 0x63C3, "fresh PIN query reports 3 tries left"
    # Correct PIN authenticates.
    assert piv.verify_pin("123456") == SW_OK
    assert piv.query_pin() == SW_OK, "while authenticated the query answers 9000"
    # Logout clears the session.
    assert piv.logout_pin() == SW_OK
    assert piv.query_pin() == 0x63C3
    # A wrong PIN spends one retry, then the correct PIN restores the counter.
    assert piv.verify_pin("000000") == 0x63C2
    assert piv.query_pin() == 0x63C2
    assert piv.verify_pin("123456") == SW_OK
    assert piv.query_pin() == SW_OK
    assert piv.logout_pin() == SW_OK
    # Exhaust the retries -> blocked (6983); even the correct PIN is rejected.
    assert piv.verify_pin("000000") == 0x63C2
    assert piv.verify_pin("000000") == 0x63C1
    assert piv.verify_pin("000000") == SW_PIN_BLOCKED
    assert piv.verify_pin("123456") == SW_PIN_BLOCKED, "blocked PIN rejects even the correct value"
    assert piv.query_pin() == SW_PIN_BLOCKED
    # PUK + new PIN unblocks (RESET RETRIES 0x2C) and resets the counter.
    assert piv.reset_retries("12345678", "123456") == SW_OK
    assert piv.query_pin() == 0x63C3, "after unblock the PIN has full retries again"
    assert piv.verify_pin("123456") == SW_OK


def test_mgm_authenticate(piv):
    # Single-challenge management auth with the default AES-192 key.
    assert piv.mgm_auth() == SW_OK
    # A management-protected op (PUT DATA) now succeeds -> has_mgm is set.
    assert piv.put_object(OBJ_FACIAL, b"tmp") == SW_OK
    assert piv.clear_object(OBJ_FACIAL) == SW_OK
    # A wrong key is rejected (SW_DATA_INVALID 6984).
    assert piv.mgm_auth(key=bytes(24)) == SW_DATA_INVALID


def test_missing_object_returns_6a82(piv):
    # GET DATA needs no mgm session; ensure the object is absent first.
    assert piv.mgm_auth() == SW_OK
    piv.clear_object(OBJ_FACIAL)  # no-op if already absent
    data, sw = piv.get_object(OBJ_FACIAL)
    assert sw == SW_FILE_NOT_FOUND, "absent 0xC1xx object must answer 6A82"
    assert data == b""
