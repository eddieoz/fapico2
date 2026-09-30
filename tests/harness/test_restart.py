"""Harness-level restart acceptance tests for US-322 (FX-410).

These tests manage their own emulation-binary processes: register a
credential, SIGTERM the emulator, restart it with the same
FAPICO2_KEYSTORE, and prove getAssertion still succeeds. A corrupt-file
drill verifies the emulator refuses to silently reset (FX-409).

Runs against a private HID port (FAPICO2_TEST_HID_PORT, default 35961) so
it can coexist with the suite's shared emulator on 35962.

The raw CTAP-HID client below speaks the transport by hand, so it must
tolerate the CTAPHID keepalive (0xBB) frame that dab5780/FX-402 made the
emulator emit for CTAP2 makeCredential/getAssertion BEFORE the real CBOR
reply: those keepalives postdate this test, and ``Emu._cbor`` skips them to
reach the 0x90 CBOR response (python-fido2 does the same natively).
"""

import hashlib
import hmac
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from fido2.cbor import decode as cbor_decode, encode as cbor_encode

REPO = Path(__file__).resolve().parents[2]
DEFAULT_BIN = REPO / "target/x86_64-unknown-linux-gnu/debug/fapico2-emulation"
HOST = "127.0.0.1"
REPORT_SIZE = 64


def _bin() -> Path:
    return Path(os.environ.get("FAPICO2_EMULATION_BIN", DEFAULT_BIN))


def _port() -> int:
    return int(os.environ.get("FAPICO2_TEST_HID_PORT", "35961"))


# Dial target for direct-spawn emulators that need no CCID at all: an
# unbound port keeps their one-shot startup dial off the shared
# run_tests.sh relay (35963) — a dial there would replace the shared
# emulator's slot and wedge every other CCID consumer. See the port map
# in tests/harness/ccid_relay.py.
DEAD_CCID_PORT = 35973


class Emu:
    """One emulation-binary process + a raw CTAPHID-over-TCP client.

    The restart matrix passes per-row private paths/port; the three original
    tests use the single ``keystore_path`` form (defaults unchanged).
    """

    def __init__(
        self,
        keystore_path: Path,
        hid_port: int | None = None,
        partition_path: Path | None = None,
        piv_path: Path | None = None,
    ):
        self.keystore_path = keystore_path
        self.hid_port = hid_port
        self.partition_path = partition_path
        self.piv_path = piv_path
        self.proc = None
        self.sock = None
        self.cid = None

    def start(self):
        hid_port = self.hid_port if self.hid_port is not None else _port()
        env = dict(os.environ)
        env["FAPICO2_KEYSTORE"] = str(self.keystore_path)
        env["FAPICO2_HID_PORT"] = str(hid_port)
        # Emu itself is HID-only: default the one-shot CCID dial to a dead
        # port unless the caller opted into a private relay by setting
        # FAPICO2_CCID_PORT first (CcidEmu._env, the openpgp/redteam/boot
        # suites). The default dial target (35963) is the shared
        # run_tests.sh relay under bare ./run_tests.sh — a dial there
        # would steal the shared emulator's slot.
        env.setdefault("FAPICO2_CCID_PORT", str(DEAD_CCID_PORT))
        if self.partition_path is not None:
            env["FAPICO2_SECURE_PARTITION"] = str(self.partition_path)
        if self.piv_path is not None:
            env["FAPICO2_PIV_KEYSTORE"] = str(self.piv_path)
        self.proc = subprocess.Popen(
            [str(_bin())],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                self.sock = socket.create_connection((HOST, hid_port), timeout=1)
                break
            except OSError:
                if self.proc.poll() is not None:
                    raise RuntimeError(f"emulator exited early: {self.proc.returncode}")
                time.sleep(0.1)
        else:
            raise RuntimeError("emulator did not come up in time")
        self._init_handshake()

    def stop(self, sig=signal.SIGTERM):
        if self.sock:
            self.sock.close()
            self.sock = None
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(sig)
            self.proc.wait(timeout=5)
        self.proc = None

    # -- raw CTAPHID ---------------------------------------------------

    def _send_frame(self, frame: bytes):
        self.sock.sendall(len(frame).to_bytes(2, "big") + frame)

    def _recv_frame(self) -> bytes:
        size = int.from_bytes(self._recv_exact(2), "big")
        return self._recv_exact(size)

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise OSError("connection closed by emulator")
            buf += chunk
        return bytes(buf)

    def _init_handshake(self):
        nonce = b"\x11" * 8
        payload = nonce
        self.cid = b"\xff\xff\xff\xff"
        self._send_frame(self.cid + bytes([0x86]) + len(payload).to_bytes(2, "big") + payload.ljust(REPORT_SIZE - 7, b"\x00"))
        resp = self._recv_frame()
        assert resp[4] == 0x86, "INIT response expected"
        assert resp[7:15] == nonce, "INIT nonce mismatch"
        self.cid = resp[15:19]

    def _cbor(self, payload: bytes) -> bytes:
        out = bytearray()
        out += self.cid + bytes([0x90 | 0x10]) + len(payload).to_bytes(2, "big")
        out += payload[:57].ljust(REPORT_SIZE - 7, b"\x00")
        self._send_frame(bytes(out))
        offset = 57
        seq = 0
        while offset < len(payload):
            chunk = payload[offset : offset + 59]
            self._send_frame(self.cid + bytes([seq]) + chunk.ljust(REPORT_SIZE - 5, b"\x00"))
            offset += 59
            seq += 1
        # collect response: the CTAP2 makeCredential/getAssertion paths emit a
        # CTAPHID keepalive (0xBB) BEFORE the CBOR reply (FX-402); skip any
        # keepalives until the 0x90 CBOR response arrives. A 0xBF error frame
        # means the command itself failed — surface it with a clear error.
        while True:
            first = self._recv_frame()
            if first[4] == 0xBF:
                raise AssertionError(
                    f"CTAP-HID error frame (0x{first[7]:02x}); expected CBOR response"
                )
            if first[4] == 0xBB:  # keepalive (UP NEEDED)
                continue
            assert first[4] == 0x90, f"expected CBOR response, got {first[4]:02x}"
            break
        total = int.from_bytes(first[5:7], "big")
        data = bytes(first[7:])
        while len(data) < total:
            cont = self._recv_frame()
            data += cont[5:]
        return data[:total]

    def ctap(self, command: int, body: bytes = b"") -> bytes:
        return self._cbor(bytes([command]) + body)


@pytest.fixture()
def keystore_path(tmp_path):
    return tmp_path / "restart_keystore.cbor"


def _make_credential(emu: Emu) -> bytes:
    client_data_hash = os.urandom(32)
    req = cbor_encode(
        {
            1: client_data_hash,
            2: {"id": "example.com", "name": "Example RP"},
            3: {"id": b"user_id", "name": "A. User"},
            4: [{"type": "public-key", "alg": -7}],
            7: {"rk": True},
        }
    )
    resp = emu.ctap(0x01, req)
    assert resp[0] == 0x00, f"makeCredential failed: {resp[0]}"
    obj = cbor_decode(resp[1:])
    auth_data = obj[2]
    # attested credential data: rpIdHash(32) flags(1) count(4) aaguid(16) idLen(2) id
    cred_len = int.from_bytes(auth_data[53:55], "big")
    return auth_data[55 : 55 + cred_len]


def _get_assertion(emu: Emu) -> bytes:
    """Returns the asserted credential id."""
    req = cbor_encode({1: "example.com", 2: os.urandom(32)})
    resp = emu.ctap(0x02, req)
    assert resp[0] == 0x00, f"getAssertion failed: {resp[0]}"
    obj = cbor_decode(resp[1:])
    return obj[1]["id"]  # credentialId


def test_register_survives_emulator_restart(keystore_path):
    emu = Emu(keystore_path)
    emu.start()
    try:
        cred_id = _make_credential(emu)
        auth1 = _get_assertion(emu)
        assert auth1 is not None
    finally:
        emu.stop(signal.SIGTERM)

    # Restart with the same keystore.
    emu.start()
    try:
        auth2 = _get_assertion(emu)
        assert auth2 == cred_id, "same credential must be asserted after restart"
    finally:
        emu.stop()


def test_corrupt_keystore_is_refused(keystore_path):
    emu = Emu(keystore_path)
    emu.start()
    try:
        _make_credential(emu)
    finally:
        emu.stop()

    # Corrupt the snapshot.
    data = keystore_path.read_bytes()
    keystore_path.write_bytes(data[: len(data) // 2])

    # A fresh emulator must refuse to silently reset (exit code 2, FX-409).
    emu2 = Emu(keystore_path)
    with pytest.raises((RuntimeError, OSError)):
        emu2.start()
    assert emu2.proc is not None
    assert emu2.proc.returncode == 2, "corrupt keystore must produce exit code 2"


# -- CTAP2 PIN protocol v1 (mirrors installed python-fido2 PinProtocolV1) ----
# The emulator's getInfo advertises pinUvAuthProtocols [1, 2]; this test pins
# v1: enc_key == hmac_key == SHA256(ECDH_x_coordinate); AES-256-CBC (IV=0, no
# padding); pinUvAuthParam = HMAC-SHA256(hmac_key, data)[:16]. Subcommand
# numbering is THIS stack's (== fido2 ClientPin.CMD): 0x02 getKeyAgreement,
# 0x05 getPinToken (legacy), 0x03 setPIN, 0x01 getPinRetries.


def _pin_cose_key(client_sk):
    pn = client_sk.public_key().public_numbers()
    return {
        1: 2,
        3: -25,  # ECDH_ES_HKDF_256 ("although NOT actually used" per the spec)
        -1: 1,  # P-256
        -2: pn.x.to_bytes(32, "big"),
        -3: pn.y.to_bytes(32, "big"),
    }


def _pin_shared_secret_v1(client_sk, auth_x, auth_y):
    """v1 shared secret = SHA256(ECDH x-coordinate); enc_key == hmac_key."""
    auth_pk = ec.EllipticCurvePublicNumbers(
        int.from_bytes(auth_x, "big"), int.from_bytes(auth_y, "big"), ec.SECP256R1()
    ).public_key(default_backend())
    raw = client_sk.exchange(ec.ECDH(), auth_pk)  # x-coordinate, 32 bytes
    return hashlib.sha256(raw).digest()


def _pin_encrypt_v1(key, plaintext):
    c = (
        Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16), backend=default_backend())
        .encryptor()
    )
    return c.update(plaintext) + c.finalize()


def _pin_hmac16(key, data):
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()[:16]


def _set_pin(emu: Emu, pin: str):
    """Set a PIN via authenticatorClientPIN (CTAP 0x06), protocol v1.

    Returns (client_sk, shared_secret): the authenticator's ECDH hkey is
    persistent, so the same client key re-derives the same shared secret
    after a restart — reused for the wrong-PIN verification attempt below.
    """
    client_sk = ec.generate_private_key(ec.SECP256R1(), default_backend())
    # getKeyAgreement (sub 0x02) → the authenticator's COSE key-agreement key.
    resp = emu.ctap(0x06, cbor_encode({1: 1, 2: 0x02}))
    assert resp[0] == 0x00, f"getKeyAgreement failed: {resp[0]:02x}"
    ka = cbor_decode(resp[1:])[1]  # COSE key-agreement map
    shared = _pin_shared_secret_v1(client_sk, ka[-2], ka[-3])
    # setPIN (sub 0x03): newPinEnc + pinUvAuthParam (no token is consumed).
    new_pin_enc = _pin_encrypt_v1(shared, pin.encode().ljust(64, b"\x00"))
    pin_uv_param = _pin_hmac16(shared, new_pin_enc)
    resp = emu.ctap(
        0x06,
        cbor_encode(
            {1: 1, 2: 0x03, 3: _pin_cose_key(client_sk), 4: pin_uv_param, 5: new_pin_enc}
        ),
    )
    assert resp[0] == 0x00, f"setPIN failed: {resp[0]:02x}"
    return client_sk, shared


def _get_pin_retries(emu: Emu) -> int:
    resp = emu.ctap(0x06, cbor_encode({1: 1, 2: 0x01}))
    assert resp[0] == 0x00, f"getPinRetries failed: {resp[0]:02x}"
    return cbor_decode(resp[1:])[3]


def _wrong_pin_get_pin_token(emu: Emu, client_sk, shared) -> int:
    """Legacy getPinToken (sub 0x05) with a WRONG encrypted pin hash.

    Returns the CTAP2 status byte (non-zero = rejected). On a mismatch the
    firmware decrements the persisted retry budget before comparing — the
    exact path the restart test measures in step (e).
    """
    wrong_hash = hashlib.sha256(b"definitely-not-the-pin").digest()[:16]
    pin_hash_enc = _pin_encrypt_v1(shared, wrong_hash)
    resp = emu.ctap(
        0x06,
        cbor_encode({1: 1, 2: 0x05, 3: _pin_cose_key(client_sk), 6: pin_hash_enc}),
    )
    return resp[0]


def _assert_pin_survived(emu: Emu, client_sk, shared):
    """Post-restart PIN checks, shared by the PIN restart test and matrix row.

    (d) clientPin is advertised without re-registration; (e) a wrong-PIN
    verification attempt decrements the persisted retry budget.
    """
    info = cbor_decode(emu.ctap(0x04, b"")[1:])
    assert info[4].get("clientPin") is True, "clientPin must survive the restart"
    before = _get_pin_retries(emu)
    status = _wrong_pin_get_pin_token(emu, client_sk, shared)
    assert status != 0x00, f"wrong PIN must be rejected, got ok (0x{status:02x})"
    after = _get_pin_retries(emu)
    assert after == before - 1, f"retries must decrement {before} -> {after}"


def test_pin_survives_emulator_restart(keystore_path):
    emu = Emu(keystore_path)
    emu.start()
    try:
        # (b) set a PIN via authenticatorClientPIN (CTAP 0x06), protocol v1.
        client_sk, shared = _set_pin(emu, "12345678")
        # A freshly set PIN resets the retry budget to the max (8).
        assert _get_pin_retries(emu) == 8, "a new PIN must reset retries to 8"
    finally:
        emu.stop(signal.SIGTERM)

    # (c) restart with the same keystore.
    emu.start()
    try:
        # (d) clientPin is advertised without re-registration; (e) a wrong-PIN
        # verification attempt decrements the persisted budget.
        _assert_pin_survived(emu, client_sk, shared)
    finally:
        emu.stop()


# ---------------------------------------------------------------------------
# Restart matrix (US-429 / SECURE-PERSIST Phase C).
#
# Proves every app's durable state survives a SIGTERM + restart with the same
# private paths. The CCID rows (OATH / OTP / mgmt) share the emulator's FIXED
# CCID dial port (the DEDICATED dial-in 35974 below — not the shared harness
# 35963, which the run_tests.sh relay holds under bare ./run_tests.sh), so one
# emulator instance runs at a time: the relay
# (tests/harness/ccid_relay.py) must be listening BEFORE the emulator starts,
# else the emulator degrades to FIDO-only and never receives CCID APDUs. We
# therefore manage our own relay + emulator + client here instead of the
# session-scoped conftest ``ccid_card`` fixture (which cannot be restarted
# with per-row private paths).
# ---------------------------------------------------------------------------

MATRIX_HID_PORT = 35965  # private HID port shared by the (sequential) rows


def _crc16(data: bytes) -> int:
    """CRC-16 (init 0xFFFF, poly 0x8408) — mirrors the C-parity OTP helper."""
    crc = 0xFFFF
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0x8408 if crc & 1 else 0)
    return crc & 0xFFFF


class _CcidClient:
    """Raw ISO 7816-4 APDU client over the relay's length-prefixed CCID frame.

    Frame protocol (both directions): ``[u16 BE length] + body``. A single
    ``0x04`` byte powers the card on and returns the ATR.
    """

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._atr = None

    def _send(self, payload: bytes):
        self._sock.sendall(len(payload).to_bytes(2, "big") + payload)

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise OSError("CCID connection closed")
            buf += chunk
        return bytes(buf)

    def _recv_frame(self) -> bytes:
        length = int.from_bytes(self._recv_exact(2), "big")
        return self._recv_exact(length)

    def power_on(self) -> bytes:
        self._send(b"\x04")
        self._atr = self._recv_frame()
        return self._atr

    def apdu(self, cla: int, ins: int, p1: int = 0, p2: int = 0,
             data: bytes = b"") -> tuple[bytes, int]:
        """Send one APDU; return (body, sw16)."""
        apdu = bytes([cla, ins, p1 & 0xFF, p2 & 0xFF, len(data)]) + data
        self._send(apdu)
        resp = self._recv_frame()
        sw1, sw2 = resp[-2], resp[-1]
        return resp[:-2], (sw1 << 8) | sw2

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass


class CcidEmu:
    """One emulation-binary process + CCID relay + a raw CCID client.

    ``start()`` brings up the relay first (it must be listening on the fixed
    CCID dial port before the emulator dials it in), then the emulator, then a
    test client on the relay's client port, and powers the card on. ``stop()``
    tears the whole trio down so a fresh ``start()`` can re-run the restart
    half of a row with the same private paths.
    """

    RELAY = REPO / "tests" / "harness" / "ccid_relay.py"
    # DEDICATED relay ports (dial-in / client), disjoint from the shared
    # run_tests.sh pair (35963/35970) and from the sibling suites — see the
    # port map in tests/harness/ccid_relay.py. The emulator is pointed at the
    # private dial-in via FAPICO2_CCID_PORT so the suite also runs under bare
    # ./run_tests.sh default discovery.
    RELAY_CCID_PORT = 35974  # the emulator dials in here (FAPICO2_CCID_PORT)
    CCID_CLIENT_PORT = 35982  # this test connects here

    def __init__(self, paths: dict, hid_port: int):
        self.paths = paths
        self.hid_port = hid_port
        self.proc = None
        self.relay = None
        self.client = None
        self.sock = None

    def _env(self) -> dict:
        env = dict(os.environ)
        env["FAPICO2_KEYSTORE"] = str(self.paths["keystore"])
        env["FAPICO2_SECURE_PARTITION"] = str(self.paths["partition"])
        env["FAPICO2_PIV_KEYSTORE"] = str(self.paths["piv"])
        env["FAPICO2_HID_PORT"] = str(self.hid_port)
        # Dedicated CCID dial-in: the private relay holds RELAY_CCID_PORT,
        # not the shared harness dial-in 35963.
        env["FAPICO2_CCID_PORT"] = str(self.RELAY_CCID_PORT)
        return env

    def start(self):
        try:
            self._start_relay()
            self.proc = subprocess.Popen(
                [str(_bin())],
                env=self._env(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.sock = self._connect_client()
            self.client = _CcidClient(self.sock)
            self.client.power_on()
        except Exception:
            # A mid-start failure (relay never READY, early emulator exit,
            # connect timeout, power_on error) must not leak the relay or
            # emulator: stop() is safe on a partially-started instance (every
            # attribute is init'd to None in __init__ and guarded in stop()),
            # then the original exception re-raises unchanged.
            self.stop()
            raise

    def _start_relay(self):
        self.relay = subprocess.Popen(
            [sys.executable, str(self.RELAY),
             "--ccid-port", str(self.RELAY_CCID_PORT),
             "--client-port", str(self.CCID_CLIENT_PORT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        deadline = time.time() + 10
        line = ""
        while time.time() < deadline:
            line = self.relay.stdout.readline()
            if "READY" in line:
                return
            if self.relay.poll() is not None:
                raise RuntimeError(f"relay exited early: {self.relay.returncode} {line!r}")
        raise RuntimeError(f"relay did not become READY: {line!r}")

    def _connect_client(self):
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                return socket.create_connection((HOST, self.CCID_CLIENT_PORT), timeout=1)
            except OSError:
                if self.proc.poll() is not None:
                    raise RuntimeError(f"emulator exited early: {self.proc.returncode}")
                time.sleep(0.1)
        raise RuntimeError("CCID client did not connect in time")

    def stop(self, sig=signal.SIGTERM):
        if self.client:
            self.client.close()
            self.client = None
        if self.sock:
            self.sock.close()
            self.sock = None
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(sig)
            self.proc.wait(timeout=5)
        self.proc = None
        if self.relay:
            if self.relay.poll() is None:
                self.relay.terminate()
                try:
                    self.relay.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.relay.kill()
            self.relay = None


OATH_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]
OTP_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01]
MGMT_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17]


def _ccid_select(card: _CcidClient, aid: list[int]) -> bytes:
    """SELECT-by-AID; host SELECT resets the app's security state."""
    body, sw = card.apdu(0x00, 0xA4, 0x04, 0x00, data=bytes(aid))
    assert sw == 0x9000, f"SELECT AID {aid!r} failed: SW={sw:04x}"
    return body


def _private_paths(tmp_path, app: str) -> dict:
    return {
        "keystore": tmp_path / f"ks_{app}.cbor",
        "partition": tmp_path / f"part_{app}.bin",
        "piv": tmp_path / f"piv_{app}.cbor",
    }


def _run_fido_credential(paths: dict):
    emu = Emu(paths["keystore"], hid_port=MATRIX_HID_PORT,
              partition_path=paths["partition"], piv_path=paths["piv"])
    emu.start()
    try:
        cred_id = _make_credential(emu)
        assert _get_assertion(emu) is not None
    finally:
        emu.stop(signal.SIGTERM)
    emu.start()
    try:
        auth2 = _get_assertion(emu)
        assert auth2 == cred_id, "resident credential must be asserted after restart"
    finally:
        emu.stop()


def _run_fido_pin(paths: dict):
    emu = Emu(paths["keystore"], hid_port=MATRIX_HID_PORT,
              partition_path=paths["partition"], piv_path=paths["piv"])
    emu.start()
    try:
        client_sk, shared = _set_pin(emu, "12345678")
        assert _get_pin_retries(emu) == 8, "a new PIN must reset retries to 8"
    finally:
        emu.stop(signal.SIGTERM)
    emu.start()
    try:
        _assert_pin_survived(emu, client_sk, shared)
    finally:
        emu.stop()


def _run_oath(paths: dict):
    # SEC-HARDEN Phase A (US-901/903): a non-virgin app boots and SELECTs
    # unvalidated, so the post-restart LIST needs a validated session. The
    # flow therefore also sets an access code (SET_CODE) before the restart
    # and re-validates (VALIDATE against the challenge the app serves on
    # SELECT once a code exists) before LIST — the same fail-closed
    # semantics the C-parity suite (test_070 test_noauth) exercises.
    oath_key = b"kaka-secret-key"
    emu = CcidEmu(paths, MATRIX_HID_PORT)
    emu.start()
    try:
        _ccid_select(emu.client, OATH_AID)
        # PUT one credential: name "kaka" + a 22-byte HMAC-SHA1 key.
        key = bytes([0x21, 0x06]) + bytes([0x0B] * 20)
        put_data = bytes([0x71, 0x04, 0x6B, 0x61, 0x6B, 0x61, 0x73, 0x16]) + key
        _, sw = emu.client.apdu(0x00, 0x01, 0x00, 0x00, data=put_data)
        assert sw == 0x9000, f"OATH PUT failed: SW={sw:04x}"
        # SET_CODE (device-key variant): key + challenge + response proof.
        chal = bytes(8)
        mac = hmac.new(oath_key, chal, hashlib.sha1).digest()[:20]
        setcode = (
            bytes([0x73, len(oath_key) + 1, 0x21]) + oath_key
            + bytes([0x74, len(chal)]) + chal
            + bytes([0x75, len(mac)]) + mac
        )
        _, sw = emu.client.apdu(0x00, 0x03, 0x00, 0x00, data=setcode)
        assert sw == 0x9000, f"OATH SET_CODE failed: SW={sw:04x}"
    finally:
        emu.stop(signal.SIGTERM)
    emu.start()
    try:
        body = _ccid_select(emu.client, OATH_AID)
        # Re-validate with the access code (US-903 session gate) before LIST.
        i = body.find(bytes([0x74, 8]))
        assert i >= 0, f"no VALIDATE challenge in SELECT response: {body.hex()}"
        chal = body[i + 2 : i + 10]
        mac = hmac.new(oath_key, chal, hashlib.sha1).digest()[:20]
        _, sw = emu.client.apdu(
            0x00,
            0xA3,
            0x00,
            0x00,
            data=bytes([0x74, len(chal)]) + chal + bytes([0x75, len(mac)]) + mac,
        )
        assert sw == 0x9000, f"OATH VALIDATE failed: SW={sw:04x}"
        body, sw = emu.client.apdu(0x00, 0xA1, 0x00, 0x00)
        assert sw == 0x9000, f"OATH LIST failed: SW={sw:04x}"
        entry = bytes([0x72, 0x05, 0x21, 0x6B, 0x61, 0x6B, 0x61])
        assert entry in body, f"OATH entry missing after restart: {body.hex()}"
    finally:
        emu.stop()


def _run_otp(paths: dict):
    emu = CcidEmu(paths, MATRIX_HID_PORT)
    emu.start()
    try:
        _ccid_select(emu.client, OTP_AID)
        # SLOT_CONFIGURE: a 52-byte Yubikey-compatible config (CRC16-checked).
        cfg = bytearray(52)
        cfg[16:22] = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        cfg[22:38] = bytes([0xAA] * 16)
        cfg[38:44] = bytes([0x00] * 6)
        cfg[46] = 0x40
        cfg[47] = 0x22
        crc = _crc16(bytes(cfg[0:50]))
        cfg[50:52] = ((~crc) & 0xFFFF).to_bytes(2, "little")
        _, sw = emu.client.apdu(0x00, 0x01, 0x01, 0x00, data=bytes(cfg))
        assert sw == 0x9000, f"OTP SLOT_CONFIGURE failed: SW={sw:04x}"
        # A configured slot answers a challenge with a 20-byte body.
        body_pre, sw = emu.client.apdu(0x00, 0x01, 0x30, 0x00, data=os.urandom(64))
        assert sw == 0x9000, f"OTP CALCULATE (pre-restart) failed: SW={sw:04x}"
        assert len(body_pre) == 20, (
            f"OTP slot must be configured pre-restart (20-byte HOTP), "
            f"got {len(body_pre)}-byte body: {body_pre.hex()}"
        )
    finally:
        emu.stop(signal.SIGTERM)
    emu.start()
    try:
        _ccid_select(emu.client, OTP_AID)
        body, sw = emu.client.apdu(0x00, 0x01, 0x30, 0x00, data=os.urandom(64))
        assert sw == 0x9000, f"OTP CALCULATE (post-restart) failed: SW={sw:04x}"
        assert len(body) == 20, (
            f"OTP slot must persist after restart (20-byte HOTP), "
            f"got {len(body)}-byte body: {body.hex()}"
        )
    finally:
        emu.stop()


def _run_mgmt(paths: dict):
    emu = CcidEmu(paths, MATRIX_HID_PORT)
    emu.start()
    try:
        _ccid_select(emu.client, MGMT_AID)
        # WRITE_CONFIG: [len=04, TLV 03 02 00 21 = TAG_USB_ENABLED caps 0x0021].
        _, sw = emu.client.apdu(0x00, 0x1C, 0x00, 0x00,
                                data=bytes([0x04, 0x03, 0x02, 0x00, 0x21]))
        assert sw == 0x9000, f"mgmt WRITE_CONFIG failed: SW={sw:04x}"
    finally:
        emu.stop(signal.SIGTERM)
    emu.start()
    try:
        _ccid_select(emu.client, MGMT_AID)
        body, sw = emu.client.apdu(0x00, 0x1D, 0x00, 0x00)
        assert sw == 0x9000, f"mgmt READ_CONFIG failed: SW={sw:04x}"
        assert body == bytes([0x04, 0x03, 0x02, 0x00, 0x21]), (
            f"mgmt config must persist after restart; "
            f"expected 04 03 02 00 21, got {body.hex()}"
        )
    finally:
        emu.stop()


@pytest.mark.parametrize(
    "app",
    [
        pytest.param("fido_hid_credential"),
        pytest.param("fido_hid_pin"),
        pytest.param("oath_ccid"),
        pytest.param("otp_ccid"),
        pytest.param("mgmt_ccid"),
        pytest.param("openpgp_ccid",
                     marks=pytest.mark.skip("restart coverage lands in Phase 7")),
        pytest.param("piv_ccid",
                     marks=pytest.mark.skip("restart coverage lands in Phase 7")),
    ],
)
def test_app_survives_restart(app: str, tmp_path):
    paths = _private_paths(tmp_path, app)
    if app == "fido_hid_credential":
        _run_fido_credential(paths)
    elif app == "fido_hid_pin":
        _run_fido_pin(paths)
    elif app == "oath_ccid":
        _run_oath(paths)
    elif app == "otp_ccid":
        _run_otp(paths)
    elif app == "mgmt_ccid":
        _run_mgmt(paths)
    else:
        pytest.fail(f"unhandled restart-matrix app: {app}")
