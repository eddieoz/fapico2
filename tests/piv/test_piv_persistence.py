"""PIV keystore persistence across an emulator restart — RED until US-374 lands.

Verifies the host secure-store snapshot (``FAPICO2_PIV_KEYSTORE``): import a
key and PUT a data object, restart the emulator process against the SAME
keystore file, and confirm the key (via GET METADATA) and the object survive,
while the management-auth SESSION does NOT carry over (fresh session after a
power-on, per C ``init_piv``/``piv_unload``).

The restart re-launches the relay + emulator together (the relay exits when the
emulator disconnects) and re-establishes the client + SELECT — via
``piv.restart()`` in conftest.

RED today: the import (0xFE, US-374) answers ``6D00``, so the first 9000
assertion fails on a plain protocol assertion and the restart is never reached.
GREEN when US-374 implements IMPORT + GET METADATA (the restart/persistence
mechanism itself is exercised by the harness regardless).
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
    reason='US-374 (IMPORT + GET METADATA) is not implemented; the import the test restarts from answers 6D00',
    strict=False,
)

from conftest import (
    ALGO_ECCP256,
    SLOT_AUTH,
    OBJ_CHUID,
    OBJ_FACIAL,
    SW_OK,
    SW_SECURITY_STATUS_NOT_SATISFIED,
    PINPOLICY_NEVER,
    secp256r1,
    field_size,
    scalar_bytes,
    expected_pubkey,
    parse_metadata,
)

D_P256 = 2
OBJ_VALUE = b"piv-persistence-vector"


def test_key_and_object_persist_mgm_session_does_not(piv):
    curve = secp256r1()
    assert piv.mgm_auth() == SW_OK
    # 1. Import a known P-256 key and store a data object.
    assert piv.import_key(SLOT_AUTH, ALGO_ECCP256, scalar_bytes(D_P256, field_size(curve)),
                          PINPOLICY_NEVER) == SW_OK, \
        "IMPORT must answer 9000 (US-374)"
    assert piv.put_object(OBJ_CHUID, OBJ_VALUE) == SW_OK, "PUT DATA must answer 9000 (US-373)"
    # 2. Restart the emulator against the same keystore.
    piv.restart()
    # 3. The key (metadata pubkey) and the object survived the restart.
    meta_data, sw = piv.get_metadata(SLOT_AUTH)
    assert sw == SW_OK, "GET METADATA after restart must answer 9000 (got %04X)" % sw
    meta = parse_metadata(meta_data)
    assert meta["pubkey"] == expected_pubkey(D_P256, curve), \
        "imported key must persist across the restart"
    value, sw = piv.get_object_value(OBJ_CHUID)
    assert sw == SW_OK and value == OBJ_VALUE, "data object must persist across the restart"
    # 4. The management-auth session did NOT carry over (fresh power-on).
    assert piv.put_object(OBJ_FACIAL, b"x") == SW_SECURITY_STATUS_NOT_SATISFIED, \
        "mgm session must be cleared on restart (PUT DATA must answer 6982)"
