"""PIV pytest harness — US-378 (the PIV suite gate).

Brings up ONE fresh ``fapico2-emulation`` + ``ccid_relay`` session per pytest
run, with ``FAPICO2_PIV_KEYSTORE`` pointed at a per-session temp file, and
exposes a selected-PIV-card fixture plus APDU / management-auth / PIN /
data-object / key helpers.

The Rust firmware under test is the single merged emulation binary built with
``--features emulation`` (``target/x86_64-unknown-linux-gnu/debug/
fapico2-emulation``). It dials ``127.0.0.1:35963`` at start-up; the relay
(``tests/harness/ccid_relay.py``) binds that port and exposes the client port
``35970``. Both directions are ``[u16 BE length]``-framed; power-on is a single
``0x04`` byte answered by the ATR.

Reuses the shared harness machinery (``tests/harness/ccid.py``:
``EmulatedCard`` + ``resolve_emulator_binary``) rather than re-implementing the
frame protocol.

Green / red split (recorded in README.md):
* GREEN now (US-371/372/373): status (SELECT/FCI, version, serial, PIN
  lifecycle, management AUTHENTICATE, missing-object 6A82) and data objects
  (GET/PUT DATA incl. long-form lengths, clear, unknown fid, oversize).
* RED until US-374 lands: GEN KEY (0x47), IMPORT (0xFE), GET METADATA (0xF7).
* RED until US-375 lands: slot sign (0x87 to 9a/9c/9d/9e) and ECDH (0x3C).

RED tests fail on plain protocol assertions (an ``assert sw == 0x9000`` that
sees ``0x6D00``/``0x6A81``) — never via a fixture/timeout crash — so the suite
is a live TDD record of the US-374/375 contract.
"""

from __future__ import annotations

import os
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

# --- import the shared harness (tests/harness/ccid.py) -----------------------
HERE = Path(__file__).resolve().parent            # fapico2/tests/piv
TESTS = HERE.parent                               # fapico2/tests
FAPICO2_ROOT = TESTS.parent                       # fapico2
HARNESS = TESTS / "harness"
for _p in (str(HARNESS),):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from ccid import EmulatedCard  # noqa: E402  (harness)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec as _ec  # noqa: E402


# --- ECC helpers (Python-side cross-checks for US-374/375) -------------------
def secp256r1():
    return _ec.SECP256R1()


def secp384r1():
    return _ec.SECP384R1()


def field_size(curve) -> int:
    return (curve.key_size + 7) // 8


def scalar_bytes(d: int, n: int) -> bytes:
    """Big-endian fixed-width private scalar (32 for P-256, 48 for P-384)."""
    return d.to_bytes(n, "big")


def expected_pubkey(d: int, curve) -> bytes:
    """Uncompressed point ``04 || X || Y`` for Q = d*G on `curve`."""
    fs = field_size(curve)
    nums = _ec.derive_private_key(d, curve).public_key().public_numbers()
    return b"\x04" + nums.x.to_bytes(fs, "big") + nums.y.to_bytes(fs, "big")


def assert_point_on_curve(point: bytes, curve) -> None:
    """Raise if `point` is not a valid uncompressed point on `curve`."""
    fs = field_size(curve)
    assert point[0] == 0x04, "point must be 04-prefixed (uncompressed)"
    assert len(point) == 1 + 2 * fs, "point must be 1+2*field bytes, got %d" % len(point)
    x = int.from_bytes(point[1:1 + fs], "big")
    y = int.from_bytes(point[1 + fs:1 + 2 * fs], "big")
    _ec.EllipticCurvePublicNumbers(x, y, curve).public_key()  # validates on-curve


def verify_ecdsa(der_sig: bytes, msg: bytes, pub_point: bytes, curve, hash_alg) -> None:
    """Verify a DER ECDSA signature the card made over ``H(msg)``.

    The card (C `mbedtls_ecdsa_write_signature`) hashes ``msg`` with SHA-256
    (P-256) / SHA-384 (P-384) before signing, so verification re-hashes ``msg``
    with the same digest.
    """
    fs = field_size(curve)
    x = int.from_bytes(pub_point[1:1 + fs], "big")
    y = int.from_bytes(pub_point[1 + fs:1 + 2 * fs], "big")
    pub = _ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    pub.verify(der_sig, msg, _ec.ECDSA(hash_alg))  # raises InvalidSignature on mismatch

# --- transport / ports (FIXED by the harness; see AGENTS.md) -----------------
CCID_PORT = 35963        # emulator dials in here
CLIENT_PORT = 35970      # test clients connect here
RELAY = str(HARNESS / "ccid_relay.py")
PYTHON = sys.executable


def _emulator_binary() -> str:
    """The freshly-built Rust emulation binary (the firmware under test)."""
    target = FAPICO2_ROOT / "target" / "x86_64-unknown-linux-gnu" / "debug" / "fapico2-emulation"
    if target.is_file() and os.access(target, os.X_OK):
        return str(target)
    # Fall back to the harness resolver (build/pico_fido2 symlink, ...).
    from ccid import resolve_emulator_binary
    return resolve_emulator_binary()


def _own_ancestor_pids() -> set:
    """This process's PID plus every ancestor (so orphan cleanup never self-kills)."""
    skip = {os.getpid()}
    pid = os.getpid()
    for _ in range(128):
        try:
            with open("/proc/%d/stat" % pid) as f:
                # field 4 (ppid) follows "(comm)", which may contain spaces/parens.
                ppid = f.read().rsplit(")", 1)[1].split()[1]
            pid = int(ppid)
        except (OSError, IndexError, ValueError):
            break
        if pid <= 1 or pid in skip:
            break
        skip.add(pid)
    return skip


def _pkill(*patterns: str) -> None:
    """Best-effort orphan cleanup that can never signal this harness.

    ``pkill -f PATTERN`` matches any process whose *command line* contains
    PATTERN — including an ancestor ``bash -c`` wrapper that merely mentions the
    name (the classic self-match gotcha). We collect our own PID and the full
    ancestor chain and skip those, so a stray ``fapico2-emulation`` /
    ``ccid_relay.py`` orphan is reaped without risking the tree running this test.
    """
    skip = _own_ancestor_pids()
    for pat in patterns:
        try:
            out = subprocess.run(["pgrep", "-f", pat], stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL)
        except (OSError, FileNotFoundError):
            continue
        for tok in out.stdout.split():
            try:
                pid = int(tok)
            except ValueError:
                continue
            if pid in skip:
                continue
            try:
                os.kill(pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass


# --- PIV protocol constants (C `pico-openpgp/src/openpgp/piv.c` / `files.h`) --
PIV_AID = bytes([0xA0, 0x00, 0x00, 0x03, 0x08])      # C `piv_aid` (5 bytes)

# Algorithm ids (C `piv.c` — pico numbering).
ALGO_3DES = 0x03
ALGO_AES128 = 0x08
ALGO_AES192 = 0x0A
ALGO_AES256 = 0x0C
ALGO_ECCP256 = 0x11
ALGO_ECCP384 = 0x14

# Key slots (C `EF_PIV_KEY_*`).
SLOT_AUTH = 0x9A       # key authentication  -> cert EF_PIV_AUTHENTICATION 0xC105
SLOT_CARDMGM = 0x9B    # card management (mgm)
SLOT_SIG = 0x9C        # signature           -> cert EF_PIV_SIGNATURE 0xC10A
SLOT_KEYMGM = 0x9D     # key management      -> cert EF_PIV_KEY_MANAGEMENT 0xC10B
SLOT_CARDAUTH = 0x9E   # card authentication -> cert EF_PIV_CARD_AUTH 0xC101
# A retired slot no other test populates — used for the sign "no key" case.
RETIRED1 = 0x82        # C `EF_PIV_KEY_RETIRED1`

# PIV data-object file ids (C `files.h` 0xC1xx space).
OBJ_CARD_AUTH = 0xC101
OBJ_CHUID = 0xC102
OBJ_FINGERPRINTS = 0xC103
OBJ_SECURITY = 0xC106
OBJ_CAPABILITY = 0xC107
OBJ_FACIAL = 0xC108
OBJ_PRINTED = 0xC109
OBJ_AUTHENTICATION = 0xC105
OBJ_SIGNATURE = 0xC10A
OBJ_KEY_MANAGEMENT = 0xC10B

# Pin / touch policy values (C `piv.c`).
PINPOLICY_DEFAULT = 0
PINPOLICY_NEVER = 1
PINPOLICY_ONCE = 2
PINPOLICY_ALWAYS = 3
TOUCHPOLICY_NEVER = 1
TOUCHPOLICY_ALWAYS = 2

# Origin (C `piv.c` ORIGIN_*).
ORIGIN_GENERATED = 0x01
ORIGIN_IMPORTED = 0x02

# Management-key single-challenge defaults (C `piv_management_key_default`,
# AES-192, 24 bytes 0x01..0x08 x3).
DEFAULT_MGM_KEY = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] * 3)

# Status words (C `pico-keys-sdk/src/apdu.h`).
SW_OK = 0x9000
SW_WRONG_LENGTH = 0x6700
SW_WRONG_DATA = 0x6700
SW_MEMORY_FAILURE = 0x6581
SW_FUNC_NOT_SUPPORTED = 0x6A81
SW_INCORRECT_PARAMS = 0x6A80
SW_FILE_NOT_FOUND = 0x6A82
SW_INCORRECT_P1P2 = 0x6A86
SW_REFERENCE_NOT_FOUND = 0x6A88
SW_WRONG_P1P2 = 0x6B00
SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982
SW_PIN_BLOCKED = 0x6983
SW_DATA_INVALID = 0x6984
SW_INS_NOT_SUPPORTED = 0x6D00


# --- wire helpers -------------------------------------------------------------
def pin_wire(pin: str) -> bytes:
    """PIV 8-byte wire form (ASCII, 0xFF-padded) — C `PIV_PIN_WIRE_SIZE`."""
    b = pin.encode("ascii")[:8]
    return b + b"\xff" * (8 - len(b))


def build_apdu(cla: int, ins: int, p1: int = 0, p2: int = 0,
               data: bytes | None = None, le: int | None = None) -> bytes:
    """Encode a case-2/4 APDU; bodies over 255 use the extended ``00 Hi Lo`` Lc."""
    a = bytearray([cla & 0xFF, ins & 0xFF, p1 & 0xFF, p2 & 0xFF])
    if data:
        if len(data) > 255:
            a += b"\x00" + struct.pack(">H", len(data))
        else:
            a.append(len(data))
        a += bytes(data)
    if le is not None:
        a.append(le & 0xFF)
    return bytes(a)


def tlv_len_form(n: int) -> bytes:
    """C `tlv_format_len`: <128 short, <256 ``81 xx``, else ``82 hi lo``."""
    if n < 128:
        return bytes([n])
    if n < 256:
        return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def aes_ecb(key: bytes, block: bytes, encrypt: bool = True) -> bytes:
    """Single-block AES ECB (the mgm key cipher) via `cryptography`."""
    c = Cipher(algorithms.AES(key), modes.ECB())
    op = c.encryptor() if encrypt else c.decryptor()
    return op.update(block) + op.finalize()


def parse_53_value(data: bytes) -> bytes:
    """Extract the object content from a GET DATA ``53 <len> <content>`` body."""
    assert data[0] == 0x53, "GET DATA must answer 53 <len> <content>, got %s" % data[:2].hex()
    n, off = data[1], 2
    if n == 0x81:
        n, off = data[2], 3
    elif n == 0x82:
        n, off = (data[2] << 8) | data[3], 4
    return data[off:off + n]


def parse_metadata(data: bytes) -> dict:
    """Parse a GET METADATA key-slot response into its fields.

    Layout (C `cmd_get_metadata`): ``01 01 <alg> 02 02 <pinpol> <touch>
    03 01 <origin> 04 <len> 86 <ptlen> <uncompressed point>``.
    """
    out: dict = {}
    i = 0
    while i < len(data):
        tag = data[i]
        ln = data[i + 1]
        val = data[i + 2:i + 2 + ln]
        if tag == 0x01:
            out["algo"] = val[0]
        elif tag == 0x02:
            out["pin_policy"] = val[0]
            out["touch"] = val[1]
        elif tag == 0x03:
            out["origin"] = val[0]
        elif tag == 0x04:
            # val == 86 <ptlen> <point>
            assert val[0] == 0x86, "metadata pubkey not an 86 point: %s" % val[:2].hex()
            out["pubkey"] = val[2:]
        i += 2 + ln
    return out


# --- the session: one relay + one emulator + one client socket ----------------
class PivSession:
    """Owns a relay + emulator + client socket for the PIV app under test.

    ``restart()`` re-launches the relay and emulator against the SAME
    ``FAPICO2_PIV_KEYSTORE`` (the relay exits when the emulator disconnects, so
    both must come back up together) and re-establishes the client + SELECT.
    """

    def __init__(self, emulator_bin: str, keystore: str, select: bool = True) -> None:
        self.bin = emulator_bin
        self.keystore = keystore
        self._select_on_start = select
        self.relay: subprocess.Popen | None = None
        self.emu: subprocess.Popen | None = None
        self.sock: socket.socket | None = None
        self.card: EmulatedCard | None = None
        _pkill("fapico2-emulation", "ccid_relay.py")
        time.sleep(0.4)
        self._start()

    # -- lifecycle ------------------------------------------------------------
    def _start(self) -> None:
        self.relay = subprocess.Popen(
            [PYTHON, RELAY, "--ccid-port", str(CCID_PORT), "--client-port", str(CLIENT_PORT)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self._wait_ready(self.relay)
        env = dict(os.environ)
        env["FAPICO2_PIV_KEYSTORE"] = self.keystore
        self.emu = subprocess.Popen(
            [self.bin], env=env, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        time.sleep(1.1)  # emulator dials 35963 at start-up
        self.sock = socket.create_connection(("127.0.0.1", CLIENT_PORT), timeout=5)
        self.sock.settimeout(20)
        self.card = EmulatedCard(self.sock)
        self.card.power_on()
        if self._select_on_start:
            self.select()

    def _wait_ready(self, proc: subprocess.Popen, timeout: float = 15.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = proc.stdout.readline()
            if b"READY" in line:
                return
            if not line and proc.poll() is not None:
                raise RuntimeError("relay exited before READY (rc=%s)" % proc.poll())
        raise TimeoutError("ccid_relay did not become ready within %.0fs" % timeout)

    def stop(self) -> None:
        if self.emu is not None and self.emu.poll() is None:
            self.emu.terminate()
            try:
                self.emu.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.emu.kill()
        if self.card is not None:
            self.card.close()
        if self.relay is not None and self.relay.poll() is None:
            self.relay.terminate()
            try:
                self.relay.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.relay.kill()
        self.emu = self.relay = self.card = self.sock = None

    def restart(self) -> None:
        """Stop relay+emulator, bring both back up against the same keystore."""
        self.stop()
        _pkill("fapico2-emulation", "ccid_relay.py")
        time.sleep(0.4)
        self._start()

    def __enter__(self) -> "PivSession":
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- APDU primitives ------------------------------------------------------
    @property
    def atr(self) -> bytes:
        return self.card.atr

    def apdu_raw(self, payload: bytes) -> tuple[bytes, int, int]:
        resp = self.card.transmit(bytes(payload))
        return resp[:-2], resp[-2], resp[-1]

    def apdu(self, cla: int, ins: int, p1: int = 0, p2: int = 0,
             data: bytes | None = None, le: int | None = None) -> tuple[bytes, int, int]:
        return self.apdu_raw(build_apdu(cla, ins, p1, p2, data, le))

    @staticmethod
    def sw(result: tuple[bytes, int, int]) -> int:
        return (result[1] << 8) | result[2]

    # -- PIV commands ---------------------------------------------------------
    def select(self) -> int:
        """SELECT PIV AID (``00 A4 04 00``) -> FCI blob + 9000 (clears session)."""
        return self.sw(self.apdu(0x00, 0xA4, 0x04, 0x00, PIV_AID))

    def get_version(self) -> tuple[bytes, int]:
        d, s1, s2 = self.apdu(0x00, 0xFD, 0x00, 0x00)
        return d, self.sw((d, s1, s2))

    def get_serial(self) -> tuple[bytes, int]:
        d, s1, s2 = self.apdu(0x00, 0xF8, 0x00, 0x00)
        return d, self.sw((d, s1, s2))

    def mgm_auth(self, key: bytes = DEFAULT_MGM_KEY, algo: int = ALGO_AES192) -> int:
        """Management-key single-challenge AUTHENTICATE (0x87/0x9B).

        Issue ``7C 02 81 00`` (card answers the 16-byte challenge), then complete
        with the challenge AES-ECB-encrypted under the mgm key in ``82``. Returns
        the completion SW (0x9000 on success).
        """
        d, s1, s2 = self.apdu(0x00, 0x87, algo, SLOT_CARDMGM, bytes([0x7C, 0x02, 0x81, 0x00]))
        if (s1, s2) != (0x90, 0x00):
            return (s1 << 8) | s2
        if d[:4] != bytes([0x7C, 0x12, 0x81, 0x10]):
            raise AssertionError("mgm challenge TLV shape: %s" % d[:6].hex())
        challenge = d[4:20]
        ct = aes_ecb(key, challenge, encrypt=True)
        _, s1, s2 = self.apdu(0x00, 0x87, algo, SLOT_CARDMGM,
                              bytes([0x7C, 0x12, 0x82, 0x10]) + ct)
        return (s1 << 8) | s2

    # -- PIN ------------------------------------------------------------------
    def query_pin(self) -> int:
        """VERIFY with no data (0x20 0x00 0x80) -> 63Cx / 9000 / 6983."""
        return self.sw(self.apdu(0x00, 0x20, 0x00, 0x80))

    def verify_pin(self, pin: str) -> int:
        return self.sw(self.apdu(0x00, 0x20, 0x00, 0x80, pin_wire(pin)))

    def logout_pin(self) -> int:
        return self.sw(self.apdu(0x00, 0x20, 0xFF, 0x80))

    def reset_retries(self, puk: str, new_pin: str) -> int:
        """RESET RETRIES (0x2C): data = puk(8) || new_pin(8); unblocks the PIN."""
        return self.sw(self.apdu(0x00, 0x2C, 0x00, 0x80, pin_wire(puk) + pin_wire(new_pin)))

    # -- data objects (GET/PUT DATA) -----------------------------------------
    @staticmethod
    def _object_id(fid: int) -> bytes:
        return bytes([0x5C, 0x03, 0x5F, 0xC1, fid & 0xFF])

    def get_object(self, fid: int) -> tuple[bytes, int]:
        d, s1, s2 = self.apdu(0x00, 0xCB, 0x3F, 0xFF, self._object_id(fid))
        return d, self.sw((d, s1, s2))

    def get_object_value(self, fid: int) -> tuple[bytes, int]:
        """GET DATA returning just the object content (the 53 value)."""
        data, sw = self.get_object(fid)
        if sw != SW_OK:
            return b"", sw
        return parse_53_value(data), sw

    @staticmethod
    def _put_body(fid: int, data: bytes) -> bytes:
        return (bytes([0x5C, 0x03, 0x5F, 0xC1, fid & 0xFF, 0x53])
                + tlv_len_form(len(data)) + bytes(data))

    def put_object(self, fid: int, data: bytes) -> int:
        return self.sw(self.apdu(0x00, 0xDB, 0x3F, 0xFF, self._put_body(fid, data)))

    def clear_object(self, fid: int) -> int:
        return self.put_object(fid, b"")

    # -- keys (US-374/375) ----------------------------------------------------
    def gen_key(self, slot: int, algo: int, pin_policy: int | None = None,
                touch: int | None = None) -> tuple[bytes, int]:
        """GEN KEY (0x47): data = ``AC <n> 80 01 <alg> [AA 01 pp] [AB 01 tp]``."""
        inner = [0x80, 0x01, algo]
        if pin_policy is not None:
            inner += [0xAA, 0x01, pin_policy]
        if touch is not None:
            inner += [0xAB, 0x01, touch]
        data = bytes([0xAC, len(inner)] + inner)
        d, s1, s2 = self.apdu(0x00, 0x47, 0x00, slot, data)
        return d, self.sw((d, s1, s2))

    def import_key(self, slot: int, algo: int, scalar: bytes,
                   pin_policy: int | None = None, touch: int | None = None) -> int:
        """IMPORT (0xFE): P1=algo, P2=slot, data = ``06 <n> <scalar> [AA][AB]``."""
        data = bytearray([0x06, len(scalar)])
        data += bytes(scalar)
        if pin_policy is not None:
            data.extend([0xAA, 0x01, pin_policy])
        if touch is not None:
            data.extend([0xAB, 0x01, touch])
        return self.sw(self.apdu(0x00, 0xFE, algo, slot, bytes(data)))

    def get_metadata(self, slot: int) -> tuple[bytes, int]:
        d, s1, s2 = self.apdu(0x00, 0xF7, 0x00, slot)
        return d, self.sw((d, s1, s2))

    def slot_sign(self, slot: int, algo: int, msg: bytes) -> tuple[bytes, int]:
        """Slot sign (0x87 to a key slot): data = ``7C <n> 81 <msg>``."""
        body = bytes([0x7C, len(msg) + 2, 0x81, len(msg)]) + bytes(msg)
        d, s1, s2 = self.apdu(0x00, 0x87, algo, slot, body)
        return d, self.sw((d, s1, s2))

    def ecdh(self, slot: int, algo: int, host_pub: bytes) -> tuple[bytes, int]:
        """ECDH (0x3C, ADR-0001 addition): data = ``7C <n> 81 <host pubkey>``."""
        body = bytes([0x7C, len(host_pub) + 2, 0x81, len(host_pub)]) + bytes(host_pub)
        d, s1, s2 = self.apdu(0x00, 0x3C, algo, slot, body)
        return d, self.sw((d, s1, s2))


# --- fixtures -----------------------------------------------------------------
@pytest.fixture(scope="session")
def piv_keystore(tmp_path_factory) -> str:
    """Per-session keystore file (fresh -> factory defaults, 3 PIN retries)."""
    d = tmp_path_factory.mktemp("piv_keystore")
    return str(d / "fapico2_piv_keystore.cbor")


@pytest.fixture(scope="session")
def piv(piv_keystore: str) -> PivSession:
    """One fresh emulator + relay session for the whole PIV run (PIV selected)."""
    session = PivSession(emulator_bin=_emulator_binary(), keystore=piv_keystore)
    yield session
    session.stop()
    _pkill("fapico2-emulation", "ccid_relay.py")


@pytest.fixture(autouse=True)
def _select_piv(piv: PivSession):
    """Re-SELECT PIV before every test -> clean session state (no stale mgm/PIN).

    Persistent state (data objects, imported keys, PIN retry counters) survives
    the SELECT — tests that need a specific object/key establish it themselves.
    """
    piv.select()
    yield
