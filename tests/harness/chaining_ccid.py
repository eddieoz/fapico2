"""Private CCID relay + emulator for US-181 (`PICOForge-COMPAT`) command chaining.

Why a **private** relay and not the shared one `run_openpgp_tests.sh` starts
(which defaults to `tests/openpgp/`, where `test_openpgp_chaining.py` lives):

1. **This test writes card state.** It stores a >255-byte DO in the cardholder
   certificate slot and reads it back. Under the shared relay it would share
   one emulator and one keystore with the whole OpenPGP suite, and
   `tests/openpgp/card_test_check_card.py` inspects DOs. Writing a 512-byte
   cardholder certificate into a card the rest of the suite is using is a
   cross-test dependency nobody asked for — and the OpenPGP suite is already
   order-sensitive, so the failure would surface as an unrelated test
   failing.
2. **The stale-binary trap is worse on a shared port.** `run_openpgp_tests.sh`
   refuses to start if 35963 is already listening, because a leftover
   emulator would otherwise hold the port, the freshly-built one would die on
   `AddrInUse`, and pytest would silently report a full green run against a
   binary that is not on disk. This harness therefore carries the same
   guard *itself* (see `ChainingEmu.__enter__`) rather than relying on the
   wrapper — because this test is equally happy to run under a bare
   `pytest tests/openpgp/` with no wrapper at all, and in that case the
   wrapper's guard is not there.

**Every APDU this file emits is transcribed from the PicoForge client**, not
from the firmware, and carries the `file:line`. Same rule, same reason, as
`rescue_ccid.py`: a test built from the device's own constants cannot fail
when the device and the client disagree, which on a single-consumer
compatibility surface is the only failure mode that matters.
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

REPO = Path(__file__).resolve().parents[2]

#: Private relay ports, disjoint from every other entry in the port map in
#: `tests/harness/ccid_relay.py` (which must be updated when these move).
#: Dial-in is the port the emulator connects to; client is the port the test
#: connects to.
DIAL_PORT = 36011
CLIENT_PORT = 36012
#: A private HID port so this test can never displace the shared listener.
HID_PORT = 36111

# ---------------------------------------------------------------------------
# Client-side constants, transcribed from `picoforge/`
# ---------------------------------------------------------------------------

#: `CLA_CHAIN = 0x10` (`picoforge/src/hal/apdu/mod.rs:26`) — the chain bit,
#: CLA b4. `send_chained` sets it on every fragment but the last
#: (`picoforge/src/hal/transport/ccid.rs:123`).
CLA_CHAIN = 0x10

#: `CLA_ISO` (`picoforge/src/hal/apdu/mod.rs:25`).
CLA_ISO = 0x00

#: `CHAIN_CHUNK = 255` (`picoforge/src/hal/transport/ccid.rs:22`) — the
#: fragment size. Every fragment `send_chained` emits carries exactly this
#: many data bytes.
CHAIN_CHUNK = 255

#: `INS_PUT_DATA` for OpenPGP is `0xDA` (INS 0xDA is PUT DATA in OpenPGP card
#: spec v3.4 §7.2.5; the vendored opcard maps it in
#: `vendor/opcard/src/command.rs`). P1/P2 are unused by the spec and are sent
#: as 0 by the client's own `Apdu` construction.
INS_PUT_DATA = 0xDA

#: OpenPGP cardholder certificate DO, `7F 21` (spec §4.4.3.9; opcard's
#: `PutDataObject::CardHolderCertificate`). A large certificate is the
#: realistic >255-byte `PUT DATA` this story exists for.
TAG_CARDHOLDER_CERT = (0x7F, 0x21)

#: `INS_GET_DATA` = 0xCA, P1/P2 = the DO tag (`00 CA 7F 21 00`, Le = 256).
INS_GET_DATA = 0xCA

#: OpenPGP AID, RID D2 76 00 01 24 01 (spec §4.2.1) — the same six bytes
#: `openpgp_card.cmd_select_openpgp` selects with.
OPENPGP_AID = bytes.fromhex("D27600012401")

#: Factory PW3 (`vendor/opcard/src/state.rs:35` `DEFAULT_ADMIN_PIN`). The
#: cardholder certificate is an Admin-permission DO
#: (`vendor/opcard/src/command/data.rs:926-930`), so a `PUT DATA` of one
#: needs PW3 verified first.
FACTORY_PW3 = b"12345678"


def select_openpgp() -> bytes:
    """`00 A4 04 00 06 <AID>` — no Le, exactly as the suite's own SELECT."""
    return bytes([0x00, 0xA4, 0x04, 0x00, len(OPENPGP_AID)]) + OPENPGP_AID


def verify_pw3(pin: bytes = FACTORY_PW3) -> bytes:
    """`00 20 00 83 08 <pin>` — VERIFY, P1 = 00, **P2 = 0x83**.

    The trap: it is P2, not P1, that names the password, and P2 is `0x83`,
    not `3`. `PasswordMode::try_from` accepts only `0x81` (PW1 sign), `0x82`
    (PW1 other) and `0x83` (PW3)
    (`vendor/opcard/src/command.rs:248-258`), so `00 20 00 03 …` — the
    encoding that reads correctly — is answered `6A86`.
    """
    return bytes([0x00, 0x20, 0x00, 0x83, len(pin)]) + pin


def do_tlv(tag: tuple[int, int], value: bytes) -> bytes:
    """`TAG_HI TAG_LO <len> <value>` with the minimal BER length.

    Two-byte tag (the `b1 & 0x1f == 0x1f` form opcard's TLV reader requires,
    `vendor/opcard/src/tlv.rs:41-46`) and a length wide enough for `value`.
    """
    out = bytearray([tag[0], tag[1]])
    n = len(value)
    if n < 0x80:
        out.append(n)
    elif n < 0x100:
        out += bytes([0x81, n])
    else:
        out += bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    return bytes(out + value)


def write_apdu(ins: int, p1: int, p2: int, data: bytes, chained: bool) -> bytes:
    """`cla ins p1 p2 <Lc> <data>`, matching `Apdu::write`.

    `chained` sets CLA b4. This is the exact shape `send_chained` puts on the
    wire for both a fragment (`ccid.rs:121-130`) and the tail
    (`ccid.rs:135-142`, via `Apdu::write`, which sends no Le).
    """
    cla = CLA_ISO | (CLA_CHAIN if chained else 0)
    assert len(data) <= 255, "the client's fragments are short-form; use send_chained"
    return bytes([cla, ins, p1, p2, len(data)]) + data


def send_chained(ins: int, p1: int, p2: int, body: bytes) -> list[bytes]:
    """Split `body` into the exact APDU list `send_chained` would transmit.

    Transcribed from `picoforge/src/hal/transport/ccid.rs:115-144`:

    * `body.len() <= CHAIN_CHUNK` short-circuits to one unchained
      `transceive_full` — no fragment at all (`:116-118`).
    * `while data.len() - i > CHAIN_CHUNK` emits one `cla|0x10` fragment of
      exactly `CHAIN_CHUNK` bytes (`:121-131`).
    * the remainder goes out as an ordinary APDU with the original class
      (`:135-142`).

    The caller asserts `9000` on every one of them, because `send_chained`
    returns `Err` on the first fragment that does not (`:129-131`).
    """
    if len(body) <= CHAIN_CHUNK:
        return [write_apdu(ins, p1, p2, body, chained=False)]
    apdus = []
    i = 0
    while len(body) - i > CHAIN_CHUNK:
        apdus.append(write_apdu(ins, p1, p2, body[i : i + CHAIN_CHUNK], chained=True))
        i += CHAIN_CHUNK
    apdus.append(write_apdu(ins, p1, p2, body[i:], chained=False))
    return apdus


def split(resp: bytes) -> tuple[bytes, int]:
    """Split an APDU response into `(data, sw)`, the SW as one int."""
    assert len(resp) >= 2, f"response must carry a status word: {resp.hex()}"
    return resp[:-2], (resp[-2] << 8) | resp[-1]


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("CCID connection closed")
        buf += chunk
    return bytes(buf)


def frame(sock: socket.socket, payload: bytes) -> bytes:
    """One `[u16 BE length] + body` frame, both directions."""
    sock.sendall(struct.pack(">H", len(payload)) + payload)
    (length,) = struct.unpack(">H", _recv_exact(sock, 2))
    return _recv_exact(sock, length)


def _wait_relay_line(proc: subprocess.Popen, needle: str, timeout: float) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        if needle in line:
            return
    raise AssertionError(f"ccid relay did not report {needle!r} within {timeout}s")


def port_is_listening(port: int) -> bool:
    """True if something is already bound to `port` on loopback.

    `ss` is used rather than a connect attempt because a connect attempt to a
    listening relay would *succeed* and be indistinguishable from our own
    relay being up.
    """
    import subprocess as sp

    try:
        out = sp.run(["ss", "-ltn"], capture_output=True, text=True, timeout=5)
    except (OSError, sp.TimeoutExpired):
        return False
    return f":{port} " in out.stdout or out.stdout.rstrip().endswith(f":{port}")


class ChainingEmu:
    """A private CCID relay + one emulation binary, driven over ISO 7816-4.

    Modelled on `rescue_ccid.RescueEmu`, with the stale-port guard that
    `RescueEmu` does **not** have. Every durable file (keystore, partition,
    PIV store, PHY record) is private to this instance, so a write in one test
    cannot be seen by another.
    """

    def __init__(self, tmp_path: Path, log_path: Path | None = None):
        self.tmp_path = tmp_path
        self.log_path = log_path
        self.relay = None
        self.emulator = None
        self.client = None
        self._log = None

    def __enter__(self) -> "ChainingEmu":
        # The guard. A leftover emulator holding the dial port would make the
        # one we start below die on AddrInUse, and every assertion in this
        # file would then be about *that* binary. Failing loudly here is the
        # only way the failure is attributable.
        if port_is_listening(DIAL_PORT) or port_is_listening(CLIENT_PORT):
            raise AssertionError(
                f"port {DIAL_PORT}/{CLIENT_PORT} is already listening before this "
                f"test started. A stale fapico2-emulation or ccid_relay is holding "
                f"it; the emulator this test starts would die on AddrInUse and the "
                f"assertions would then silently describe the STALE binary instead "
                f"of the one on disk. Find it with:  ss -ltnp | grep -E "
                f"'({DIAL_PORT}|{CLIENT_PORT})'  and kill it before re-running."
            )

        keystore = self.tmp_path / "chaining_keystore.cbor"
        partition = self.tmp_path / "chaining_partition.bin"
        piv = self.tmp_path / "chaining_piv.cbor"
        phy = self.tmp_path / "chaining_phy.bin"

        self.relay = subprocess.Popen(
            [sys.executable, str(REPO / "tests" / "harness" / "ccid_relay.py"),
             "--ccid-port", str(DIAL_PORT),
             "--client-port", str(CLIENT_PORT)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        _wait_relay_line(self.relay, "READY", timeout=10)

        env = dict(os.environ)
        env["FAPICO2_KEYSTORE"] = str(keystore)
        env["FAPICO2_SECURE_PARTITION"] = str(partition)
        env["FAPICO2_PIV_KEYSTORE"] = str(piv)
        env["FAPICO2_RESCUE_PHY"] = str(phy)
        env["FAPICO2_CCID_PORT"] = str(DIAL_PORT)
        env["FAPICO2_HID_PORT"] = str(HID_PORT)

        if self.log_path is not None:
            self._log = self.log_path.open("w+")
            stdout = stderr = self._log
        else:
            stdout = stderr = subprocess.DEVNULL
        self.emulator = subprocess.Popen(
            [str(REPO / "target" / "x86_64-unknown-linux-gnu" / "debug" / "fapico2-emulation")],
            env=env, stdout=stdout, stderr=stderr,
        )
        _wait_relay_line(self.relay, "emulator connected", timeout=15)
        self.client = socket.create_connection(("127.0.0.1", CLIENT_PORT), timeout=5)
        self.client.settimeout(30)
        _wait_relay_line(self.relay, "[client] test client connected", timeout=15)
        # Power-on must answer with the device ATR before an XfrBlock is
        # served.
        atr = frame(self.client, b"\x04")
        assert atr[:1] == b"\x3b", f"unexpected ATR: {atr.hex()}"
        return self

    def __exit__(self, *exc) -> None:
        if self.client is not None:
            self.client.close()
            self.client = None
        if self.emulator is not None and self.emulator.poll() is None:
            self.emulator.send_signal(signal.SIGTERM)
            try:
                self.emulator.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.emulator.kill()
                self.emulator.wait(timeout=5)
        self.emulator = None
        if self.relay is not None:
            try:
                self.relay.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.relay.kill()
                self.relay.wait(timeout=5)
            self.relay = None
        if self._log is not None:
            self._log.close()
            self._log = None

    # -- card operations -------------------------------------------------

    def send(self, apdu: bytes) -> tuple[bytes, int]:
        """Transmit one APDU and return `(data, sw)`. No `61xx` following."""
        return split(frame(self.client, apdu))

    def send_chained(self, ins: int, p1: int, p2: int, body: bytes) -> list[int]:
        """Run `body` through the client's `send_chained` loop.

        Asserts `9000` on **every** fragment, because the client returns
        `Err` on the first one that is not (`ccid.rs:129-131`) — so a card
        that answered anything else would make the client give up rather than
        complete the write, and the failure would be indistinguishable from a
        card bug. Returns the per-fragment status words for the test to
        report.
        """
        sws = []
        for apdu in send_chained(ins, p1, p2, body):
            _, sw = self.send(apdu)
            sws.append(sw)
        return sws

    def get_data(self, tag: tuple[int, int]) -> bytes:
        """`00 CA <tag_hi> <tag_lo> 00`, following `61xx` with GET RESPONSE.

        A >255-byte DO does not fit one response, so the `61xx` /
        `GET RESPONSE` (INS 0xC0) dance is mandatory here; it is the same
        contract `transceive_paged` implements
        (`picoforge/src/hal/transport/ccid.rs:90-111`).
        """
        data, sw = self.send(bytes([CLA_ISO, INS_GET_DATA, tag[0], tag[1], 0x00]))
        if sw == 0x9000:
            return data
        assert sw & 0xFF00 == 0x6100, f"GET DATA answered {sw:04X}"
        out = bytearray(data)
        le = sw & 0xFF
        while True:
            le = 256 if le == 0 else le
            more, sw = self.send(bytes([CLA_ISO, 0xC0, 0x00, 0x00, min(le, 255)]))
            out += more
            if sw == 0x9000:
                return bytes(out)
            assert sw & 0xFF00 == 0x6100, f"GET RESPONSE answered {sw:04X}"
            le = sw & 0xFF

    def log(self) -> str:
        if self._log is None:
            return ""
        self._log.flush()
        self._log.seek(0)
        return self._log.read()
