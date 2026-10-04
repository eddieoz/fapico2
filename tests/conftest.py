"""
fapico2 FIDO test entry point.

Provides the Device-based fixtures needed by the pico-fido test suite.
The HID transport is monkeypatched to talk to the emulator's TCP socket.
"""

import os
import sys
from pathlib import Path as _Path

ROOT = _Path(__file__).parent
for _p in (str(ROOT), str(ROOT / "harness"), str(ROOT / "pico-fido"), str(ROOT / "openpgp")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import pytest
from fido2 import hid as _hid
import fido2.hid.linux as _linux_hid
from hid_emul import list_descriptors, open_connection, get_descriptor

# Patch at the base module level (where CtapHidDevice.list_devices looks it up)
_hid.list_descriptors = list_descriptors
_hid.open_connection = open_connection
# Also patch linux backend
_linux_hid.list_descriptors = list_descriptors
_linux_hid.open_connection = open_connection

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, UserInteraction, ClientError, _Ctap1ClientBackend, DefaultClientDataCollector
from fido2.attestation import FidoU2FAttestation
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2
from fido2.server import Fido2Server
from fido2.ctap import CtapError
from fido2.webauthn import PublicKeyCredentialParameters, PublicKeyCredentialType, PublicKeyCredentialCreationOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, AuthenticatorSelectionCriteria, UserVerificationRequirement, PublicKeyCredentialRequestOptions
from fido2.ctap2.extensions import HmacSecretExtension, LargeBlobExtension, CredBlobExtension, CredProtectExtension, MinPinLengthExtension, CredPropsExtension, ThirdPartyPaymentExtension
from fido2.cose import ES256

DEFAULT_PIN='12345678'


def _pin_protocol(info):
    """The strongest pinUvAuthProtocol the authenticator advertises.

    The device is not assumed to speak V2 just because the client can: this
    reads the list the authenticator published in getInfo and picks from it, so
    the harness cannot sign with a protocol the device never claimed.
    """
    supported = info.options.get("pinUvAuthProtocols") or [1]
    return PinProtocolV2() if 2 in supported else PinProtocolV1()

class Packet(object):
    def __init__(self, data):
        self.data = data

    def ToWireFormat(self):
        return self.data

    @staticmethod
    def FromWireFormat(pkt_size, data):
        return Packet(data)

class CliInteraction(UserInteraction):
    def prompt_up(self):
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        return DEFAULT_PIN

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True

class DeviceSelectCredential:
    def __init__(self, number):
        pass

    def __call__(self, status):
        pass

class Device():
    def __init__(self, origin="https://example.com", user_interaction=CliInteraction(), uv="discouraged", rp={"id": "example.com", "name": "Example RP"}, attestation="direct"):
        self.__user = None
        self.__set_client(origin=origin, user_interaction=user_interaction, uv=uv)
        self.__set_server(rp=rp, attestation=attestation)

    def __verify_rp(rp_id, origin):
        return True

    def __set_client(self, origin, user_interaction, uv):
        self.__uv = uv
        self.__dev = None
        self.__origin = origin
        self.__user_interaction = user_interaction

        # Locate a device
        self.__dev = next(CtapHidDevice.list_devices(), None)
        self.dev = self.__dev
        if self.__dev is not None:
            print("Use USB HID channel.")
        else:
            try:
                from fido2.pcsc import CtapPcscDevice
                self.__dev = next(CtapPcscDevice.list_devices(), None)
                print("Use NFC channel.")
            except Exception as e:
                print("NFC channel search error:", e)

        if not self.__dev:
            print("No FIDO device found")
            sys.exit(1)

        extensions = [
            HmacSecretExtension(allow_hmac_secret=True),
            LargeBlobExtension(),
            CredBlobExtension(),
            CredProtectExtension(),
            MinPinLengthExtension(),
            CredPropsExtension(),
            ThirdPartyPaymentExtension()
        ]
        self.__client = Fido2Client(self.__dev, client_data_collector=DefaultClientDataCollector(self.__origin, verify=Device.__verify_rp), user_interaction=self.__user_interaction, extensions=extensions)

        if self.__client.info.options.get("uv") or self.__client.info.options.get("pinUvAuthToken"):
            self.__uv = "preferred"
            print("Authenticator supports User Verification")

        self.__client1 = Fido2Client(self.__dev, client_data_collector=DefaultClientDataCollector(self.__origin, verify=Device.__verify_rp), user_interaction=self.__user_interaction)
        self.__client1._backend = _Ctap1ClientBackend(self.__dev, user_interaction=self.__user_interaction)
        self.ctap1 = self.__client1._backend.ctap1

    def __set_server(self, rp, attestation):
        self.__rp = rp
        self.__attestation = attestation
        self.__server = Fido2Server(self.__rp, attestation=self.__attestation)
        self.__server.allowed_algorithms = [
            PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=p['alg'])
            for p in self.__client._backend.info.algorithms
        ]

    def client(self):
        return self.__client

    def user(self, user=None):
        if (self.__user is None):
            self.__user = {"id": b"user_id", "name": "A. User"}
        if (user is not None):
            self.__user = user
        return self.__user

    def rp(self, rp=None):
        if (self.__rp is None):
            self.__rp = {"id": "example.com", "name": "Example RP"}
        if (rp is not None):
            self.__rp = rp
        return self.__rp

    def send_data(self, cmd, data, timeout = 1.0, on_keepalive = None):
        if not isinstance(data, bytes):
            data = struct.pack("%dB" % len(data), *[ord(x) for x in data])
        with Timeout(timeout) as event:
            event.is_set()
            return self.dev.call(cmd, data, event, on_keepalive = on_keepalive)

    def cid(self):
        return self.dev._channel_id

    def set_cid(self, cid):
        self.dev._channel_id = int.from_bytes(cid, 'big')

    def recv_raw(self):
            with Timeout(1.0):
                r = self.dev._connection.read_packet()
            return r[4], r[7:]

    def send_raw(self, data, cid=None):
        if cid is None:
            cid = self.dev._channel_id.to_bytes(4, 'big')
        elif not isinstance(cid, bytes):
            cid = struct.pack("%dB" % len(cid), *[ord(x) for x in cid])
        if not isinstance(data, bytes):
            data = struct.pack("%dB" % len(data), *[ord(x) for x in data])
        data = cid + data
        l = len(data)
        if l != 64:
            pad = "\x00" * (64 - l)
            pad = struct.pack("%dB" % len(pad), *[ord(x) for x in pad])
            data = data + pad
        data = bytes(data)
        assert len(data) == 64
        self.dev._connection.write_packet(data)

    def reset(self):
        print("Resetting Authenticator...")
        try:
            self.__client._backend.ctap2.reset(on_keepalive=DeviceSelectCredential(1))
        except CtapError:
            print("Need to power cycle authentictor to reset..")
            self.reboot()
            self.__client._backend.ctap2.reset(on_keepalive=DeviceSelectCredential(1))

    def reboot(self):
        print("Please reboot authenticator and hit enter")
        try:
            inputimeout(prompt='>>', timeout=5)
        except Exception:
            pass

        self.__set_client(self.__origin, self.__user_interaction, self.__uv)
        self.__set_server(rp=self.__rp, attestation=self.__attestation)

    def MC(self, client_data_hash=Ellipsis, rp=Ellipsis, user=Ellipsis, key_params=Ellipsis, exclude_list=None, extensions=None, options=None, pin_uv_param=None, pin_uv_protocol=None, enterprise_attestation=None):
        client_data_hash = client_data_hash if client_data_hash is not Ellipsis else os.urandom(32)
        rp = rp if rp is not Ellipsis else self.__rp
        user = user if user is not Ellipsis else self.user()
        key_params = key_params if key_params is not Ellipsis else self.__server.allowed_algorithms
        att_obj = self.__client._backend.ctap2.make_credential(
            client_data_hash=client_data_hash,
            rp=rp,
            user=user,
            key_params=key_params,
            exclude_list=exclude_list,
            extensions=extensions,
            options=options,
            pin_uv_param=pin_uv_param,
            pin_uv_protocol=pin_uv_protocol,
            enterprise_attestation=enterprise_attestation
            )
        return {'res':att_obj,'req':{'client_data_hash':client_data_hash,
                        'rp':rp,
                        'user':user,
                        'key_params':key_params}}

    def doMC(self, client_data=Ellipsis, rp=Ellipsis, user=Ellipsis, key_params=Ellipsis, exclude_list=None, extensions=None, rk=None, user_verification=None, enterprise_attestation=None, event=None, ctap1=False):
        client_data = client_data if client_data is not Ellipsis else DefaultClientDataCollector(origin=self.__origin, verify=Device.__verify_rp)
        rp = rp if rp is not Ellipsis else self.__rp
        user = user if user is not Ellipsis else self.user()
        key_params = key_params if key_params is not Ellipsis else self.__server.allowed_algorithms
        if (ctap1 is True):
            client = self.__client1
        else:
            client = self.__client
        options=PublicKeyCredentialCreationOptions(
            rp=PublicKeyCredentialRpEntity.from_dict(rp),
            user=PublicKeyCredentialUserEntity.from_dict(user),
            pub_key_cred_params=key_params,
            exclude_credentials=exclude_list,
            extensions=extensions,
            challenge=os.urandom(32),
            authenticator_selection=AuthenticatorSelectionCriteria(
                require_resident_key=rk,
                user_verification=UserVerificationRequirement.REQUIRED if user_verification else UserVerificationRequirement.DISCOURAGED
            ),
            attestation=enterprise_attestation
        )
        client_data, rp_id = client_data.collect_client_data(options=options)
        result = client._backend.do_make_credential(
            options=options,
            client_data=client_data,
            rp_id=rp_id,
            enterprise_rpid_list=None,
            event=event
        )
        return {'res':result.response,'req':{'client_data':client_data,
                       'rp':rp,
                       'user':user,
                       'key_params':key_params},'client_extension_results':result.client_extension_results}

    def try_make_credential(self, options=None):
        if (options is None):
            options, _ = self.__server.register_begin(
            self.user(), user_verification=self.__uv, authenticator_attachment="cross-platform"
        )
        try:
            result = self.__client.make_credential(options["publicKey"])
        except ClientError as e:
            if (e.code == ClientError.ERR.CONFIGURATION_UNSUPPORTED):
                client_pin = ClientPin(self.__client._backend.ctap2)
                client_pin.set_pin(DEFAULT_PIN)
                result = self.__client.make_credential(options["publicKey"])
        return result

    def register(self, uv=None):
        create_options, state = self.__server.register_begin(
            self.user(), user_verification=uv or self.__uv, authenticator_attachment="cross-platform"
        )
        result = self.try_make_credential(create_options)
        auth_data = self.__server.register_complete(
            state=state, response=result
        )
        credentials = [auth_data.credential_data]
        print("New credential created!")
        print("CLIENT DATA:", result.response.client_data)
        print("ATTESTATION OBJECT:", result.response.attestation_object)
        print()
        print("CREDENTIAL DATA:", auth_data.credential_data)
        return (result, auth_data)

    def authenticate(self, credentials):
        request_options, state = self.__server.authenticate_begin(credentials, user_verification=self.__uv)
        result = self.__client.get_assertion(request_options["publicKey"])
        result = result.get_response(0)
        self.__server.authenticate_complete(
            state,
            credentials,
            result
        )
        print("Credential authenticated!")
        print("CLIENT DATA:", result.response.client_data)
        print()
        print("AUTH DATA:", result.response.authenticator_data)

    def GA(self, rp_id=Ellipsis, client_data_hash=Ellipsis, allow_list=None, extensions=None, options=None, pin_uv_param=None, pin_uv_protocol=None):
        rp_id = rp_id if rp_id is not Ellipsis else self.__rp['id']
        client_data_hash = client_data_hash if client_data_hash is not Ellipsis else os.urandom(32)
        att_obj = self.__client._backend.ctap2.get_assertion(
        rp_id=rp_id,
        client_data_hash=client_data_hash,
        allow_list=allow_list,
        extensions=extensions,
        options=options,
        pin_uv_param=pin_uv_param,
        pin_uv_protocol=pin_uv_protocol
        )
        return {'res':att_obj,'req':{'rp_id':rp_id,
                        'client_data_hash':client_data_hash}}

    def GNA(self):
        return self.__client._backend.ctap2.get_next_assertion()

    def GA_with_pin(self, rp_id=Ellipsis, client_data_hash=Ellipsis, allow_list=None, extensions=None, options=None):
        """getAssertion carrying a pinUvAuthToken, signed the way a client signs it.

        US-1529/US-1533: on a PIN-set device a token-less getAssertion is refused
        with PUAT_REQUIRED, and it is refused BEFORE the credential lookup ever
        happens (AGENTS.md section 4). A raw `GA()` therefore only reaches the
        lookup for the tests that are deliberately about that refusal; a raw-`GA`
        test about anything else -- algorithm coverage, allow-list filtering,
        channel isolation -- was written against pico-fido, where the device
        served a token-less assertion, and has to authenticate here first.

        Falls through to the token-less path when no PIN is set, so the same
        test is meaningful on either side of a set/clear.
        """
        rp_id = rp_id if rp_id is not Ellipsis else self.__rp['id']
        client_data_hash = client_data_hash if client_data_hash is not Ellipsis else os.urandom(32)
        ctap2 = self.__client._backend.ctap2
        try:
            token = ClientPin(ctap2).get_pin_token(
                DEFAULT_PIN, ClientPin.PERMISSION.GET_ASSERTION, rp_id
            )
        except CtapError as e:
            # Ask the DEVICE whether a PIN exists rather than reading
            # `ctap2.info.options["clientPin"]`: that info object is cached on the
            # client, so a fixture that called device.reset() and set a PIN since
            # the last getInfo would still read False here, and the token-less
            # fallback would silently re-break the test this helper exists to fix.
            if e.code != CtapError.ERR.PIN_NOT_SET:
                raise
            return self.GA(
                rp_id=rp_id,
                client_data_hash=client_data_hash,
                allow_list=allow_list,
                extensions=extensions,
                options=options,
            )
        protocol = _pin_protocol(ctap2.get_info())
        att_obj = ctap2.get_assertion(
            rp_id=rp_id,
            client_data_hash=client_data_hash,
            allow_list=allow_list,
            extensions=extensions,
            options=options,
            pin_uv_param=protocol.authenticate(token, client_data_hash),
            pin_uv_protocol=protocol.VERSION,
        )
        return {'res': att_obj, 'req': {'rp_id': rp_id,
                        'client_data_hash': client_data_hash}}

    def doGA(self, client_data=Ellipsis, rp_id=Ellipsis, allow_list=None, extensions=None, user_verification=None, event=None, ctap1=False, check_only=False):
        client_data = client_data if client_data is not Ellipsis else DefaultClientDataCollector(origin=self.__origin, verify=Device.__verify_rp)
        if (ctap1 is True):
            client = self.__client1
        else:
            client = self.__client

        rp_id = rp_id if rp_id is not Ellipsis else self.__rp['id']
        options=PublicKeyCredentialRequestOptions(
            challenge=os.urandom(32),
            rp_id=rp_id,
            allow_credentials=allow_list,
            user_verification=UserVerificationRequirement.REQUIRED if user_verification else UserVerificationRequirement.DISCOURAGED,
            extensions=extensions
        )
        client_data, rp_id = client_data.collect_client_data(options=options)
        if (ctap1 is True):
            client = self.__client1
        else:
            client = self.__client
        try:
            result = client._backend.do_get_assertion(
                options=options,
                client_data=client_data,
                rp_id=rp_id,
                event=event
            )
        except ClientError as e:
            if (e.code == ClientError.ERR.CONFIGURATION_UNSUPPORTED):
                client_pin = ClientPin(self.__client._backend.ctap2)
                client_pin.set_pin(DEFAULT_PIN)
                result = client._backend.do_get_assertion(
                    options=options,
                    client_data=client_data,
                    rp_id=rp_id,
                    event=event
                )
            else:
                raise
        return {'res':result,'req':{'client_data':client_data,
                       'rp_id':rp_id}}


from numbers import Number
from threading import Event, Timer

class Timeout(object):
    def __init__(self, time_or_event):
        if isinstance(time_or_event, Number):
            self.event = Event()
            self.timer = Timer(time_or_event, self.event.set)
        else:
            self.event = time_or_event
            self.timer = None

    def __enter__(self):
        if self.timer:
            self.timer.start()
        return self.event

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.timer:
            self.timer.cancel()
            self.timer.join()

def verify(MC, GA, client_data_hash):
    credential_data = MC.auth_data.credential_data
    GA.verify(client_data_hash, credential_data.public_key)

import struct

@pytest.fixture(scope="session")
def device():
    dev = Device()
    return dev

@pytest.fixture(scope="module")
def info(device):
    return device.client()._backend.info

@pytest.fixture(scope="module")
def MCRes(device, *args):
    return device.doMC(*args)

@pytest.fixture(scope="module")
def resetdevice(device):
    device.reset()
    return device

@pytest.fixture(scope="module")
def GARes(device, MCRes, *args):
    res = device.doGA(allow_list=[
            {"id": MCRes['res'].attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ], *args)

    assertions = res['res'].get_assertions()
    for a in assertions:
        verify(MCRes['res'].attestation_object, a, res['req']['client_data'].hash)
    return res

@pytest.fixture(scope="module")
def MCRes_DC(device, *args):
    return device.doMC(rk=True, *args)

@pytest.fixture(scope="module")
def GARes_DC(device, MCRes_DC, *args):
    res = device.GA(allow_list=[
            {"id": MCRes_DC['res'].attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ], *args)
    verify(MCRes_DC['res'].attestation_object, res['res'], res['req']['client_data_hash'])

    return res

@pytest.fixture(scope="module")
def RegRes(resetdevice, *args):
    res = resetdevice.doMC(ctap1=True, *args)
    att = FidoU2FAttestation()
    att.verify(res['res'].attestation_object.att_stmt, res['res'].attestation_object.auth_data, res['req']['client_data'].hash)
    return res


@pytest.fixture(scope="module")
def AuthRes(device, RegRes, *args):
    res = device.doGA(ctap1=True, allow_list=[
            {"id": RegRes['res'].attestation_object.auth_data.credential_data.credential_id, "type": "public-key"}
        ], *args)
    aut_data = res['res'].get_response(0)
    m = aut_data.response.authenticator_data.rp_id_hash + aut_data.response.authenticator_data.flags.to_bytes(1, 'big') + aut_data.response.authenticator_data.counter.to_bytes(4, 'big') + aut_data.response.client_data.hash
    ES256(RegRes['res'].attestation_object.auth_data.credential_data.public_key).verify(m, aut_data.response.signature)
    return aut_data

@pytest.fixture(scope="class")
def client_pin(resetdevice):
    return ClientPin(resetdevice.client()._backend.ctap2)


# ---------------------------------------------------------------------------
# CCID (ISO 7816) card fixtures — OATH / OTP / container tests.
#
# The fapico2-emulation binary dials 127.0.0.1:35963 at start-up; the relay
# (tests/harness/ccid_relay.py, started alongside the emulator) accepts that
# connection and exposes the client port 35970. This fixture speaks the same
# length-prefixed frame protocol and mimics the pyscard card/connection API
# used by tests/pico-fido (card.connection.transmit / card.connection.reconnect).
# ---------------------------------------------------------------------------

import socket as _socket
import struct as _struct
import threading as _threading

CCID_CLIENT_PORT = 35970


class _CcidConnection:
    def __init__(self, sock):
        self._sock = sock
        self._last_select = None
        self._lock = _threading.Lock()

    def _recv_exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("CCID connection closed")
            buf += chunk
        return bytes(buf)

    def _transmit_bytes(self, payload):
        with self._lock:
            self._sock.sendall(_struct.pack(">H", len(payload)) + payload)
            (length,) = _struct.unpack(">H", self._recv_exact(2))
            return self._recv_exact(length)

    def transmit(self, apdu):
        """pyscard-style transmit: returns (data_list, sw1, sw2)."""
        apdu = bytes(apdu)
        # Remember the most recent SELECT-by-AID so reconnect() can redo it.
        if len(apdu) >= 7 and apdu[1] == 0xA4:
            self._last_select = apdu
        body = self._transmit_bytes(apdu)
        if len(body) < 2:
            return [], body[0] if body else 0x6F, body[-1] if body else 0x00
        return list(body[:-2]), body[-2], body[-1]

    def reconnect(self):
        """ISO reset: re-issue the last SELECT (clears the app's security
        state, which is what the suite uses reconnect() for)."""
        if self._last_select is not None:
            self._transmit_bytes(self._last_select)

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass


class _CcidCard:
    def __init__(self, sock):
        self.connection = _CcidConnection(sock)


@pytest.fixture(scope="session")
def ccid_card():
    try:
        sock = _socket.create_connection(("127.0.0.1", CCID_CLIENT_PORT), timeout=3)
    except OSError:
        pytest.skip("CCID relay not available on port %d" % CCID_CLIENT_PORT)
    sock.settimeout(15)
    card = _CcidCard(sock)
    yield card
    card.connection.close()


class _OpenPgpReader:
    """Raw-APDU reader adapter for the OpenPGP suite (OpenPGP_Card calls
    reader.send_cmd(cmd) and expects response + SW bytes back)."""

    def __init__(self, ccid_card):
        self._ccid = ccid_card

    def send_cmd(self, cmd):
        data, sw1, sw2 = self._ccid.connection.transmit(bytes(cmd))
        return bytes(data) + bytes([sw1, sw2])

    def reset_device(self):
        self._ccid.connection.reconnect()

    def ccid_power_off(self):
        pass


@pytest.fixture(scope="session")
def card(ccid_card):
    """OpenPGP suite fixture (mirrors the C repo root conftest card())."""
    from openpgp_card import OpenPGP_Card

    c = OpenPGP_Card(_OpenPgpReader(ccid_card))
    c.cmd_select_openpgp()
    yield c


# --- US-912 factory-PIN gate -------------------------------------------------
#
# The card refuses PSO:SIGN / PSO:DECIPHER / GENKEY / TERMINATE DF while the
# factory PINs (PW1=123456, PW3=12345678) are still in force; the gate lifts
# only after BOTH have been changed via CHANGE REFERENCE DATA. Suites that
# exercise those gated ops lift it with the helpers below and restore a
# factory card afterwards (TERMINATE DF + ACTIVATE FILE re-arms it).

GATE_PW1 = b"246813"
GATE_PW3 = b"86429753"


def lift_factory_pin_gate(card):
    """Move PW1/PW3 off the factory defaults (idempotent)."""
    from card_const import FACTORY_PASSPHRASE_PW1, FACTORY_PASSPHRASE_PW3
    try:
        # Factory-first: a successful factory verify burns no retry counter.
        card.cmd_verify(3, FACTORY_PASSPHRASE_PW3)
    except ValueError:
        card.cmd_verify(3, GATE_PW3)
        card.cmd_verify(1, GATE_PW1)
    else:
        card.cmd_change_reference_data(1, FACTORY_PASSPHRASE_PW1 + GATE_PW1)
        card.cmd_change_reference_data(3, FACTORY_PASSPHRASE_PW3 + GATE_PW3)


def restore_factory_card(card):
    """TERMINATE DF + ACTIVATE FILE: wipes personalization, factory PINs back
    (and re-arms the US-912 gate). Only call while the gate is lifted."""
    from openpgp_card import iso7816_compose
    reader = card._OpenPGP_Card__reader
    card.cmd_verify(3, GATE_PW3)
    for ins in (0xE6, 0x44):  # TERMINATE DF, ACTIVATE FILE
        resp = reader.send_cmd(iso7816_compose(ins, 0x00, 0x00, b""))
        assert resp[-2:] == b"\x90\x00", "factory restore failed: %02X%02X" % (
            resp[-2], resp[-1])


@pytest.fixture(scope="module")
def pin_gate_lifted(card):
    """US-912: module-scoped card with the factory-PIN gate lifted; a factory
    card is restored afterwards so downstream modules see factory state."""
    lift_factory_pin_gate(card)
    yield card
    restore_factory_card(card)


@pytest.fixture(scope="function")
def pin_gate_lifted_once(card):
    """US-912: like pin_gate_lifted, but per-test (mixed modules)."""
    lift_factory_pin_gate(card)
    yield card
    restore_factory_card(card)


# --- OATH session authentication -------------------------------------------
#
# The applet provisions a documented default access code on every path that can
# end up without one -- both boots (`OathApp::boot_in_place`) and the factory
# reset (`reset_state`) -- so "no access code" is not a reachable state
# (`apps/oath/src/oath_core.rs::provision_default_access_code`,
# `DEFAULT_ACCESS_CODE = b"123456"`). Consequence for a host driver: a fresh
# session is UNVALIDATED and every credential command answers 0x6982 until
# VALIDATE runs.
#
# This is the handshake BOTH first-party clients already run, and it is why the
# applet can afford to keep the lockout: `yubikit/oath.py` decides from the
# SELECT response alone (`_has_key = self._challenge is not None`) and picoforge
# from `info.password_set()`, then each answers the `74` challenge with
# HMAC-SHA1 of the access code. The harness runs the same three steps rather
# than assuming the applet grants itself.

OATH_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]
OATH_DEFAULT_ACCESS_CODE = b"123456"
OATH_TAG_DEVICE_ID = 0x71
OATH_TAG_CHALLENGE = 0x74
OATH_TAG_RESPONSE = 0x75
OATH_INS_VALIDATE = 0xA3

import hmac as _hmac
import hashlib as _hashlib


def select_oath_aid(ccid_card):
    """SELECT the OATH applet; returns the response body (TLVs, no SW)."""
    resp, sw1, sw2 = ccid_card.connection.transmit(
        [0x00, 0xA4, 0x04, 0x00, 0x00, 0x00, len(OATH_AID)] + OATH_AID + [0x00, 0x00]
    )
    assert [sw1, sw2] == [0x90, 0x00], "OATH SELECT failed: %02X%02X" % (sw1, sw2)
    return resp


def oath_select_challenge(select_body):
    """The `74` challenge value out of a SELECT response, or None.

    The applet serves it only while an access code is on file -- which, since
    the default-code provisioning, is always.
    """
    i = 0
    while i + 1 < len(select_body):
        tag, ln = select_body[i], select_body[i + 1]
        if tag == OATH_TAG_CHALLENGE:
            return bytes(select_body[i + 2:i + 2 + ln])
        i += 2 + ln
    return None


def oath_derive_access_key(password, device_id):
    """`PBKDF2-HMAC-SHA1(password, device_id, 1000, 16)` — the client derivation.

    Byte-identical to picoforge `derive_access_key` and `yubikit/oath.py`
    `_derive_key`. The device **never** sees the password: it stores this
    derived key, so HMACing with the raw password validates against nothing a
    real client sends.
    """
    return _hashlib.pbkdf2_hmac("sha1", password, device_id, 1000, 16)


def oath_select_device_id(select_body):
    """The `71` device-id TLV out of a SELECT response — the PBKDF2 salt."""
    i = 0
    while i + 1 < len(select_body):
        tag, ln = select_body[i], select_body[i + 1]
        if tag == OATH_TAG_DEVICE_ID:
            return bytes(select_body[i + 2:i + 2 + ln])
        i += 2 + ln
    return None


def authenticate_oath(ccid_card, code=OATH_DEFAULT_ACCESS_CODE):
    """SELECT + VALIDATE, i.e. the client flow both first-party clients use.

    Mirrors ykman/yubikit and picoforge: read the challenge off the SELECT
    response, answer it with HMAC-SHA1 of the **derived** access key (INS 0xA3,
    `74` challenge + `75` proof), and every credential command is served until
    the next host-issued SELECT drops the grant again.

    The salt is the device-id from the same SELECT response — the `71` TLV the
    applet documents as "the PBKDF2 salt a host uses for the access key".
    """
    # SELECT picks up the challenge; VALIDATE answers it. Same two steps the
    # clients take, so a test that calls this is exercising a reachable path.
    sel = select_oath_aid(ccid_card)
    chal = oath_select_challenge(sel)
    assert chal is not None and len(chal) == 8, (
        "OATH SELECT served no VALIDATE challenge: %s" % (chal,)
    )
    salt = oath_select_device_id(sel)
    assert salt is not None and len(salt) == 8, (
        "OATH SELECT served no 71 device-id TLV: %s" % (sel,)
    )
    mac = _hmac.new(oath_derive_access_key(code, salt), chal, _hashlib.sha1).digest()
    data = [OATH_TAG_CHALLENGE, len(chal)] + list(chal) \
        + [OATH_TAG_RESPONSE, len(mac)] + list(mac)
    resp, sw1, sw2 = ccid_card.connection.transmit(
        [0x00, OATH_INS_VALIDATE, 0x00, 0x00, len(data)] + data + [0x00, 0x00]
    )
    assert [sw1, sw2] == [0x90, 0x00], "OATH VALIDATE failed: %02X%02X" % (sw1, sw2)
    return resp


@pytest.fixture(scope="class")
def select_oath(ccid_card):
    select_oath_aid(ccid_card)
    return ccid_card


@pytest.fixture(scope="class")
def oath_session(reset_oath):
    """A re-virginized OATH applet with an authenticated (validated) session."""
    authenticate_oath(reset_oath)  # mirrors the client flow: SELECT + VALIDATE
    return reset_oath


@pytest.fixture(scope="class")
def reset_oath(select_oath):
    # Re-virginize the OATH applet before each class: the management app
    # factory RESET (INS 0x1E, presence auto-acks in the emulator; the US-711
    # factory_wipe hook clears OATH durable state) and then the applet's own
    # RESET. **This is test isolation, not a workaround** — that distinction
    # used to be blurred, and it mattered.
    #
    # The previous comment here called it a "US-901 shim" and explained it as
    # necessary because "once anything is provisioned, SELECT leaves the OATH
    # session locked and every credential command is refused with 6982". That
    # was true, and it is why the whole suite was **blind** to the defect: every
    # OATH test began by re-virginizing, so none of them ever held a credential
    # across a SELECT -- which is the only state picoforge and ykman reach. A
    # narrower version of the gap then reopened, in the other direction: with
    # "no access code" no longer a reachable state (the applet provisions
    # `DEFAULT_ACCESS_CODE` on boot and on reset), every session is locked and
    # the fixture has to authenticate. What the fixture must NOT do is
    # authenticate on the tests whose subject is the lockout --
    # `test_070_oath.py::test_noauth` and the red-team refusals take
    # `reset_oath` itself, deliberately.
    #
    # US-132 (PICOForge-COMPAT): OATH RESET (04/DE/AD) is NOT in that list any
    # more — its US-903 session gate was removed so the reference client's
    # bare, unlocked Reset reaches the applet. The 0xDE/0xAD magic and the
    # user-presence grant are the only two gates it still has.
    # (docs/tasks/us132-oath-reset-picocompat.md)
    #
    # This fixture deliberately leaves the session UNVALIDATED: the applet's
    # RESET re-provisions the default access code, so a client that wants the
    # table must run the SELECT + VALIDATE handshake — `oath_session`, or
    # `authenticate_oath()` mid-test.
    mgmt_aid = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17]
    resp, sw1, sw2 = select_oath.connection.transmit(
        [0x00, 0xA4, 0x04, 0x00, len(mgmt_aid)] + mgmt_aid
    )
    assert [sw1, sw2] == [0x90, 0x00], "mgmt SELECT failed: %02X%02X" % (sw1, sw2)
    resp, sw1, sw2 = select_oath.connection.transmit(
        [0x00, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    )
    assert [sw1, sw2] == [0x90, 0x00], "mgmt RESET failed: %02X%02X" % (sw1, sw2)
    resp, sw1, sw2 = select_oath.connection.transmit(
        [0x00, 0xA4, 0x04, 0x00, 0x00, 0x00, 0x07]
        + [0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]
        + [0x00, 0x00]
    )
    assert [sw1, sw2] == [0x90, 0x00], "OATH SELECT failed: %02X%02X" % (sw1, sw2)
    resp, sw1, sw2 = select_oath.connection.transmit(
        [0x00, 0x04, 0xDE, 0xAD, 0x00, 0x00, 0x00, 0x00, 0x00]
    )
    assert [sw1, sw2] == [0x90, 0x00], "OATH RESET failed: %02X%02X" % (sw1, sw2)
    return select_oath
