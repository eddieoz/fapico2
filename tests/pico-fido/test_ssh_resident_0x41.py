"""EPIC FIDO-SSH-RESIDENT-KEYS, US-1620 — libfido2 1.14's `read_rks` walk over
the emulator, on CTAP2 command `0x41`.

`ssh-keygen -K` drives libfido2 1.14.0, whose `credman_tx` sends every
credential-management operation under the hard-coded command byte
`CTAP_CBOR_CRED_MGMT_PRE` (`0x41`) — there is no `0x0A` fallback in that
release. This test replays libfido2's request sequence verbatim on `0x41`
and decodes each reply with the **preview** response keys libfido2 1.14.0
parses (metadata 1/2; rp 3/4/5; rk 6/7/8/9), which is the contract the device
twin test `apps/fido/tests/ssh_resident_download.rs::us1618_libfido2_read_rks_walk_on_0x41`
asserts without the emulator so CI holds it.

The MAC scope is the preview one — `subCommand ‖ cbor(params)`, with no
`0xFF*32` prefix — the same message libfido2's `credman_prepare_hmac` builds
and python-fido2's `CredentialManagement._call` builds.
"""

import pytest
from fido2 import cbor
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.utils import sha256

PIN = "12345678"


@pytest.fixture(scope="function")
def ssh_resident(device, client_pin):
    device.reset()
    client_pin.set_pin(PIN)
    device.doMC(rp={"id": "ssh:", "name": "Bate Goiko"}, rk=True)
    return device


def _ctap2(device):
    return device.client()._backend.ctap2


def test_libfido2_read_rks_walk_on_0x41(ssh_resident):
    ctap = _ctap2(ssh_resident)
    token = ClientPin(ctap).get_pin_token(
        PIN, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT
    )
    protocol = PinProtocolV2()

    def preview(sub, params=None):
        """A libfido2-1.14-shaped credMgmt request on command 0x41."""
        msg = bytes([sub]) + (cbor.encode(params) if params is not None else b"")
        req = {1: sub, 3: protocol.VERSION, 4: protocol.authenticate(token, msg)}
        if params is not None:
            req[2] = params
        return ctap.send_cbor(0x41, req)

    # getCredsMetadata — existing (1), remaining (2).
    meta = preview(1)
    assert 1 in meta and 2 in meta, "getCredsMetadata must answer preview keys 1/2"
    assert meta[1] == 1, "one resident credential was created"

    # enumerateRPsBegin — rp (3), rpIDHash (4), totalRPs (5).
    rps = preview(2)
    assert 3 in rps and 4 in rps and 5 in rps, "enumerateRPsBegin must answer 3/4/5"
    assert rps[5] == 1, "one RP"
    assert rps[4] == sha256(b"ssh:"), "rpIDHash must be sha256('ssh:')"

    # enumerateCredentialsBegin for the ssh: RP — user (6), credentialID (7),
    # publicKey (8), totalCredentials (9). libfido2 signs 0x04 ‖ cbor({1: hash}).
    creds = preview(4, {1: sha256(b"ssh:")})
    assert 6 in creds and 7 in creds and 8 in creds and 9 in creds, (
        "enumerateCredentialsBegin must answer 6/7/8/9"
    )
    assert creds[9] == 1, "one credential under the RP"

    # pack_public_key() per credential — libfido2's read_rks consumes the COSE
    # public key at key 8; a present-but-undecodable key is the only way it
    # errors, so assert it is a well-formed COSE EC2 map.
    pub = creds[8]
    assert pub[1] == 2 and pub[3] == -7, "publicKey must be a COSE ES256 key"
    assert len(pub[-2]) == 32 and len(pub[-3]) == 32