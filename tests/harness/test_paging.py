"""US-180 (PICOForge-COMPAT Phase J): the `61xx` / `6Cxx` paging contract.

**This is a contract document that happens to be executable.** The EPIC's
commit line for the story is `test(harness): paging contract across all
applets` — there is no implementation to land here, only the statement of
what the device already does when a host asks for fewer bytes than the
answer is long. The docstring below is the part a future reader needs; the
test is the enforcement.

PicoForge drives this over `picoforge/src/hal/transport/ccid.rs:90-111`
(`transceive_paged`): on `6Cxx` it resends the *same* command with
`Le = xx` before consuming any data; on `61xx` it appends the page and
issues a continuation — `INS 0xC0` (GET RESPONSE) generally, `INS 0xA5`
(YKOATH SEND REMAINING) for OATH, via `transceive_oath` at
`ccid.rs:86-88`. The status-word predicates are exact
(`picoforge/src/hal/apdu/mod.rs:105-112`): `more_data()` is
`sw & 0xFF00 == 0x6100`, `wrong_le()` is `sw & 0xFF00 == 0x6C00`. Nothing
else drives the loop, so those two shapes and nothing else are the whole
client-side contract.

---------------------------------------------------------------------------
The contract on this device
---------------------------------------------------------------------------

**`6Cxx` is never emitted — anywhere, by any applet.** Not one construction
site in `apps/`, `platform/` or `firmware/`; the only `0x6C` literals in
the tree are the CCID message-type constants `PC_TO_RDR_GET_PARAMETERS`
(`platform/src/ccid.rs:63`) and their tests. That is *correct*, not an
omission: `6Cxx` means "I will not send more than `Le` bytes; resend with a
bigger `Le`", and no applet on this device is ever willing to say it. Each
one either sends its whole reply in one exchange or pages the remainder
with `61xx` — so there is never a `6Cxx` to emit. `paged_responses_honour_6c_and_61`
asserts that absence as a real contract, because the day a `6Cxx` *does*
appear it means an applet started refusing to over-deliver, which changes
what a host has to implement. Read the failure message before "fixing" it.

**`61xx` is emitted by exactly two applets**, and they page for different
reasons:

| applet | pages? | `Le` honoured? | continuation | why |
|---|---|---|---|---|
| **OpenPGP** | **yes** | **yes** | `0xC0` GET RESPONSE | the reference implementation — `apps/openpgp/src/device_shell.rs:556-578` |
| **OATH** | **yes**, `CALCULATE ALL` only | **no** | `0xA5` SEND REMAINING | chunks at its own cap; see below |
| `mgmt` | no | no | — | `READ CONFIG` is 29 B; nothing to page |
| `otp` | no | no | — | nothing to page; a factory card has no slot (`9000`, empty body) |
| `piv` | no | no | — | **the one gap** — see below |
| `vendor_led` | no | no | — | 17 B (`apps/vendor_led/src/lib.rs:115-120`) |
| `rescue` | no | no | — | ≤ 20 B; CLA `0x80`, not the ISO `0x00` applets |

**OpenPGP honours `Le` exactly.** `OpenPgpApp::run` stages the whole
composed reply in `self.scratch` and then serves `min(Le, available)` per
exchange, answering `61XX` with the remaining count while more pends
(`device_shell.rs:556-578`; the doc comment at `:514-528` names the
regression it fixed — gpg's short-`Le` `00 CA 00 6E 00` met the full
270-byte wire reply and scd's `le + 2` buffer truncated it). A short `Le` of
`0x00` and an *absent* `Le` field both normalise to 256
(`device_shell.rs:565`), which is the ISO reading and what gpg's scd
assumes.

**OATH chunks at 2036 and ignores `Le`.** `OATH_CHUNK_MAX = 2036`
(`apps/oath/src/oath_core.rs:229`) is the C firmware's own one-exchange body
cap, and the arithmetic checks out in the C tree:
`USB_BUFFER_SIZE 2048` (`pico-keys-sdk/src/usb/usb.h:121`) −
`CCID_MSG_DATA_OFFSET 10` (`pico-keys-sdk/src/usb/ccid/ccid.c:58`) =
`CCID_MAX_XFR_BLOCK_DATA_SIZE 2038` (`ccid.c:60`), which
`driver_exec_finished_cont_ccid` passes to `apdu_limit_response` at
`ccid.c:345`; that function's `ne = max_size - 2` (`apdu.c:326-347`) is the
2036. It is C parity, not a defect: the host's `Le` cannot make the C card
send more in one exchange either, so a client that honours `Le` gets
`min(Le, 2036)` from a conformant card. The only OATH command that pages is
`CALCULATE ALL` (`cmd_calculate_all`, `oath_core.rs:1634-1694`, and
`cmd_send_remaining` at `:1696-1716`); `LIST` and `CALCULATE` answer in one
exchange whatever `Le` says — see the OATH block of the test, which asserts
that rather than pretending otherwise.

The OATH `MAX_RESPONSE` overflow the EPIC ties to US-705 is a *different*
problem and is already handled: `cmd_list` is overflow-aware and answers
`6A84` rather than truncating into a garbage trailing SW
(`oath_core.rs:1714-1745`, tests at `apps/oath/tests/device_oath.rs:562`
and `:664`). This test does not re-cover it.

---------------------------------------------------------------------------
PIV — the one genuine gap
---------------------------------------------------------------------------

`PivApp::cmd_get_data` (`apps/piv/src/lib.rs:751-791`) writes
`53 <len> <object>` straight into the response buffer and returns `9000`.
With a maximal `MAX_OBJECT_SIZE` object (2048 B, `lib.rs:55`) that is
`1 + 3 + 2048 = 2052` bytes in a *single* exchange, with **no** `61xx`, no
`0xC0`, and `Le` ignored entirely — including `Le = 1`. This test pins that
behaviour explicitly and names it as a limitation rather than leaving it
implicit; see the PIV block for the reasoning on why the fix is not in this
story.

The device's other non-ISO status word is `6F00` — the transport-level
fail-closed answer for an aborted CCID bulk transfer and for a persist
failure under durable-before-ack (`firmware/src/tasks.rs:225-241` and
`:352-358`; `platform/src/ccid.rs:54`). It is SW-only and is not part of
this story's status-word list, which is a gap in the EPIC's text, not in
the device.
"""

from __future__ import annotations

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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from harness.rescue_ccid import frame

REPO = Path(__file__).resolve().parents[2]

# ---------------------------------------------------------------------------
# Private relay ports (dial-in / client) + a private HID listener, disjoint
# from every other entry in the port map in `tests/harness/ccid_relay.py`
# (US-180). Never the shared 35963/35970 pair: bare `./run_tests.sh` starts
# a shared emulator against that relay, and a second dial there would
# displace its slot for every other CCID consumer in the run.
# ---------------------------------------------------------------------------
RELAY_CCID_PORT = 36009  # the emulator dials in here (FAPICO2_CCID_PORT)
RELAY_CLIENT_PORT = 36010  # this test connects here
HID_PORT = 36109  # private; nothing else may listen on it

# ---------------------------------------------------------------------------
# AIDs (each app's own `aid()`; the dispatcher's SELECT-by-AID path,
# `platform/src/dispatch.rs:147-188`).
# ---------------------------------------------------------------------------
OPENPGP_AID = bytes.fromhex("D27600012401")       # openpgp/src/device_shell.rs:29
OATH_AID = bytes.fromhex("A0000005272101")      # oath/src/oath.rs:389

# The device provisions a default OATH access code on boot, so every credential
# command needs the same SELECT + VALIDATE handshake both first-party clients
# perform. Same two steps yubikit and picoforge take; see `conftest.py`'s
# `authenticate_oath` for the relay-transport twin.
OATH_DEFAULT_ACCESS_CODE = b"123456"


def _oath_device_id(select_body: bytes) -> bytes:
    i = 0
    while i + 1 < len(select_body):
        tag, ln = select_body[i], select_body[i + 1]
        if tag == 0x71:
            return select_body[i + 2:i + 2 + ln]
        i += 2 + ln
    raise AssertionError(f"OATH SELECT served no 71 device-id: {select_body.hex()}")


def _oath_challenge(select_body: bytes) -> bytes:
    i = 0
    while i + 1 < len(select_body):
        tag, ln = select_body[i], select_body[i + 1]
        if tag == 0x74:
            return select_body[i + 2:i + 2 + ln]
        i += 2 + ln
    raise AssertionError(f"OATH SELECT served no challenge: {select_body.hex()}")


def authenticate_oath(emu) -> None:
    """SELECT the OATH applet and VALIDATE with the default access code.

    The device stores `PBKDF2-HMAC-SHA1(password, device_id, 1000, 16)` and the
    salt is the `71` device-id TLV from this same SELECT — the derivation both
    clients perform before they ever send a proof.
    """
    sel = emu.select(OATH_AID)
    chal = _oath_challenge(sel)
    device_id = _oath_device_id(sel)
    key = hashlib.pbkdf2_hmac("sha1", OATH_DEFAULT_ACCESS_CODE, device_id, 1000, 16)
    mac = hmac.new(key, chal, hashlib.sha1).digest()
    data = bytes([0x74, len(chal)]) + chal + bytes([0x75, len(mac)]) + mac
    _, sw = emu.transmit(bytes([0x00, 0xA3, 0x00, 0x00, len(data)]) + data)
    assert sw == 0x9000, f"OATH VALIDATE failed: SW={sw:04X}"
OTP_AID = bytes.fromhex("A0000005272001")       # oath/src/otp.rs:955
MGMT_AID = bytes.fromhex("A000000527471117")    # mgmt/src/lib.rs:43
PIV_AID = bytes.fromhex("A000000308")           # piv/src/lib.rs:30
LED_AID = bytes.fromhex("F000000001")                 # vendor_led/src/lib.rs:115
#: `RESCUE_AID` (`picoforge/src/hal/rescue/constants.rs:106`). Rescue is the
#: one applet on CLA `0x80`, not the ISO `0x00` the others use.
RESCUE_AID = bytes.fromhex("A0583FC19B7E4F21")

#: `OATH_CHUNK_MAX` (`apps/oath/src/oath_core.rs:229`) — the C CCID one-exchange
#: body cap, not a host-chosen window. See the module docstring.
OATH_CHUNK_MAX = 2036

#: `MAX_OBJECT_SIZE` (`apps/piv/src/lib.rs:55`).
PIV_MAX_OBJECT_SIZE = 2048
#: C `piv_management_key_default` (`apps/piv/src/lib.rs:189-192`): 0x01..0x08
#: repeated three times, AES-192, touch ALWAYS (the touch check is
#: `#ifndef ENABLE_EMULATION` in C, so the emulation path skips it —
#: `apps/piv/src/lib.rs:521-522`).
PIV_DEFAULT_MGM_KEY = bytes([0x01, 0x02, 0x03, 0x04,
                             0x05, 0x06, 0x07, 0x08]) * 3
#: `PIV_ALGO_AES192` (`apps/piv/src/lib.rs:77`) and `KEY_CARDMGM` (`:84`).
PIV_ALGO_AES192 = 0x0A
PIV_KEY_CARDMGM = 0x9B


# ---------------------------------------------------------------------------
# APDU builders.
#
# `ccid.py:EmulatedCard.send_apdu` always writes a 1-byte Lc, so it cannot
# express a 5-byte case-2 APDU (the framing this story is entirely about) —
# a GET DATA with a short `Le` is the *canonical* paging request and must go
# out as `CLA INS P1 P2 Le`. These build the raw bytes and the card helper
# below drives them through `transmit`-equivalent framing.
# ---------------------------------------------------------------------------


def case1(cla: int, ins: int, p1: int = 0, p2: int = 0) -> bytes:
    """Four-byte case-1 APDU: no Lc, **no Le**."""
    return bytes([cla, ins, p1 & 0xFF, p2 & 0xFF])


def case2(cla: int, ins: int, p1: int, p2: int, le: int) -> bytes:
    """Case-2 APDU with an explicit `Le`.

    `le = 0` is the ISO short form for "256" and is passed as a literal
    `0x00` byte — never widened. `le > 255` uses the extended `00 xx xx`
    form, which is how this test asks for a genuinely unconstrained read.
    """
    if le < 256:
        return bytes([cla, ins, p1 & 0xFF, p2 & 0xFF, le & 0xFF])
    return bytes([cla, ins, p1 & 0xFF, p2 & 0xFF, 0x00]) + le.to_bytes(2, "big")


def case3(cla: int, ins: int, p1: int, p2: int, data: bytes, le: int | None = None) -> bytes:
    """Case-3 (optionally case-4) APDU: `Lc` + body [+ `Le`].

    `le` is encoded the same way as in [`case2`], so `le = 0` is a literal
    trailing `0x00` — the "Le = 256" form a conformant reader uses.

    A body over 255 bytes uses the extended `00 <hi> <lo> Lc` form. Both
    PIV (`parse_data`, `apps/piv/src/lib.rs:852-865`) and OATH
    (`parse_apdu`, `apps/oath/src/oath_core.rs:1069-1096`) accept the
    extended encoding, so the PIV PUT DATA below is framed the ISO way
    rather than leaning on a harness-only extension.
    """
    if len(data) < 256:
        apdu = bytearray([cla, ins, p1 & 0xFF, p2 & 0xFF, len(data)])
    else:
        apdu = bytearray([cla, ins, p1 & 0xFF, p2 & 0xFF, 0x00])
        apdu += len(data).to_bytes(2, "big")
    apdu += data
    if le is not None:
        if le < 256:
            apdu.append(le & 0xFF)
        else:
            apdu += bytes([0x00]) + le.to_bytes(2, "big")
    return bytes(apdu)


def _listen_ports() -> set[int]:
    """Ports with a LISTEN socket, via `ss -ltn`.

    The stale-port trap is real and fatal to trust. A leftover relay or
    emulator from an earlier run keeps the dial-in port bound; the new relay
    then dies on `bind`, the new emulator panics on its HID `bind` with
    `AddrInUse` (see `firmware/src/emul_main.rs:476`), and the suite dies in
    a fixture teardown with neither process cleaned up — which is how the
    *next* run inherits a stale port and reports results for a binary that
    is no longer on disk. Reading this *before* anything starts turns that
    cascade into one message that names the port.
    """
    try:
        out = subprocess.run(["ss", "-ltn"], capture_output=True, text=True,
                             timeout=10).stdout
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        pytest.skip(f"cannot enumerate listening ports ({exc}); stale-port guard unavailable")
    ports: set[int] = set()
    for line in out.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 4:
            try:
                ports.add(int(fields[3].rsplit(":", 1)[-1]))
            except ValueError:
                continue
    return ports


def _assert_ports_free(ports: tuple[int, ...]) -> None:
    busy = sorted(p for p in ports if p in _listen_ports())
    assert not busy, (
        f"port(s) {busy} already have a LISTEN socket. A leftover relay or "
        f"emulator from an earlier run is holding them; this test's emulator "
        f"would either refuse to bind or silently drive a stale binary. "
        f"Check `ss -ltnp | grep -E 'ccid_relay|fapico2-emulation'`, kill it, "
        f"and re-run. Ports reserved for this file: {list(ports)}."
    )


class PagingEmu:
    """One private CCID relay + one emulation binary + a raw ISO 7816 client.

    Modelled on `tests/harness/rescue_ccid.py` (the newest and most careful
    harness in the tree) rather than `ccid.py:EmulatorSession`, for two
    reasons: every durable path is private to this instance so the test's
    writes cannot be seen by another suite, and the ports are explicit so
    bare `./run_tests.sh` default discovery cannot have this emulator steal
    the shared relay's slot.
    """

    RELAY = REPO / "tests" / "harness" / "ccid_relay.py"
    BINARY = REPO / "target" / "x86_64-unknown-linux-gnu" / "debug" / "fapico2-emulation"

    def __init__(self, store: Path, log_path: Path):
        self.store = store
        self.log_path = log_path
        self.relay: subprocess.Popen | None = None
        self.emulator: subprocess.Popen | None = None
        self.sock: socket.socket | None = None
        self._log = None

    # -- lifecycle ---------------------------------------------------

    def __enter__(self) -> "PagingEmu":
        # Loud, before anything binds: see `_assert_ports_free`.
        _assert_ports_free((RELAY_CCID_PORT, RELAY_CLIENT_PORT, HID_PORT))

        self.relay = subprocess.Popen(
            [sys.executable, str(self.RELAY),
             "--ccid-port", str(RELAY_CCID_PORT),
             "--client-port", str(RELAY_CLIENT_PORT)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        self._wait_relay("READY")

        env = dict(os.environ)
        env["FAPICO2_KEYSTORE"] = str(self.store / "paging_keystore.cbor")
        env["FAPICO2_SECURE_PARTITION"] = str(self.store / "paging_partition.bin")
        env["FAPICO2_PIV_KEYSTORE"] = str(self.store / "paging_piv.cbor")
        env["FAPICO2_RESCUE_PHY"] = str(self.store / "paging_phy.bin")
        env["FAPICO2_CCID_PORT"] = str(RELAY_CCID_PORT)
        env["FAPICO2_HID_PORT"] = str(HID_PORT)

        self._log = self.log_path.open("w+")
        self.emulator = subprocess.Popen(
            [str(self.BINARY)], env=env, stdout=self._log, stderr=self._log,
        )
        # The relay must see *this* emulator's dial before any APDU is
        # framed, or the client would talk into a slot nobody serves.
        self._wait_relay("emulator connected")
        self.sock = socket.create_connection(("127.0.0.1", RELAY_CLIENT_PORT), timeout=5)
        self.sock.settimeout(30)
        self._wait_relay("[client] test client connected")
        atr = self.send(b"\x04")
        assert atr[:1] == b"\x3b", f"unexpected ATR: {atr.hex()}"
        return self

    def __exit__(self, *exc) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None
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

    def _wait_relay(self, needle: str, timeout: float = 15) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self.relay.stdout.readline()
            if not line:
                break
            if needle in line:
                return
        raise AssertionError(f"ccid relay did not report {needle!r} within {timeout}s")

    # -- card operations ---------------------------------------------

    def transmit(self, apdu: bytes) -> tuple[bytes, int]:
        """One APDU exchange; returns `(data, sw16)`.

        `rescue_ccid.frame` is the same `[u16 BE length] + body` framing every
        other suite uses, reused rather than re-derived.
        """
        resp = frame(self.sock, apdu)
        assert len(resp) >= 2, f"reply must carry a status word: {resp.hex()}"
        return resp[:-2], (resp[-2] << 8) | resp[-1]

    def send(self, payload: bytes) -> bytes:
        """Raw framed round-trip, used for the ATR power-on byte."""
        return frame(self.sock, payload)

    def select(self, aid: bytes, p2: int = 0x00) -> bytes:
        """SELECT-by-AID through the dispatcher's ordinary AID path."""
        data, sw = self.transmit(bytes([0x00, 0xA4, 0x04, p2, len(aid)]) + aid)
        assert sw == 0x9000, f"SELECT {aid.hex()} failed: SW={sw:04X}"
        return data

    def log(self) -> str:
        self._log.flush()
        self._log.seek(0)
        return self._log.read()


@pytest.fixture(scope="module")
def emu(tmp_path_factory):
    """Module-scoped: one emulator, one relay, one private store.

    A module-scoped fixture (rather than one per test) keeps the OpenPGP DO
    6E, the OATH table and the PIV object in a single card image, which is
    what lets the test compare a paged read against an unconstrained one on
    the same state.
    """
    store = tmp_path_factory.mktemp("paging_store")
    log_path = tmp_path_factory.mktemp("paging_log") / "emulator.log"
    with PagingEmu(store, log_path) as card:
        yield card


# ---------------------------------------------------------------------------
# Small helpers used by the applet blocks below.
# ---------------------------------------------------------------------------


def _drain(card: PagingEmu, first: bytes, cont_ins: int, le: int,
           limit: int = 32) -> tuple[bytes, list[int]]:
    """Append `first`, then follow `61xx` pages with `cont_ins` until `9000`.

    Returns `(concatenated body, per-exchange SW list)`. The SW list is
    returned rather than discarded because the *sequence* of status words is
    part of what this story pins: every intermediate page must be `61xx`
    carrying the exact undelivered remainder, and only the last may be
    `9000`.
    """
    out = bytearray(first)
    sws: list[int] = []
    for _ in range(limit):
        data, sw = card.transmit(case2(0x00, cont_ins, 0x00, 0x00, le))
        sws.append(sw)
        # Append **before** the 9000 check: the terminating exchange still
        # carries the tail of the body. A 61xx page is by definition not
        # the last one, but a 9000 page is data-bearing — dropping it here
        # silently truncates the reassembly by up to `le` bytes.
        out += data
        if sw == 0x9000:
            return bytes(out), sws
        assert (sw & 0xFF00) == 0x6100, (
            f"continuation INS {cont_ins:02X} answered {sw:04X}; expected a "
            f"61xx continuation page or a terminating 9000"
        )
    raise AssertionError(f"INS {cont_ins:02X} paging did not terminate within {limit} exchanges")


def _first_diff(a: bytes, b: bytes) -> str:
    """Where two reassemblies diverge, without raising on a length-only diff.

    A plain `next(... for ... if x != y)` inside an assert *message* raises
    StopIteration the moment one side is a prefix of the other — which is
    the most likely way this comparison fails, so the message must not
    blow up exactly when it is needed.
    """
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return f"{i} ({x:02X} vs {y:02X})"
    return f"none — one is a prefix of the other (lengths {len(a)} vs {len(b)})"


def _aes_ecb(key: bytes, block: bytes) -> bytes:
    """Single-block AES-ECB — `crypto::mgm_crypt` over `PIV_ALGO_AES192`
    (`apps/piv/src/crypto.rs` `block_crypt`: one block, ECB, no IV)."""
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


# ---------------------------------------------------------------------------
# The test.
#
# One test, four blocks, because the EPIC names one RED and because the four
# blocks share one card image: the OpenPGP baseline is read on the same
# state the paged read is compared against, and the OATH stream is started
# with the same table the expected body is computed from.
# ---------------------------------------------------------------------------


def test_paged_responses_honour_6c_and_61(emu):
    # `seen_6c` accumulates every (label, Le, SW) the sweep produced so the
    # 6Cxx assertion can name the exact call that broke the contract.
    seen_6c: list[str] = []

    def note(label: str, le: int, sw: int) -> None:
        if (sw & 0xFF00) == 0x6C00:
            seen_6c.append(f"{label} with Le={le:02X} answered {sw:04X}")

    # =====================================================================
    # Block 1 — OpenPGP: the reference implementation. `Le` is honoured.
    # =====================================================================
    #
    # The carrier is GET DATA of the Application Related Data DO (0x6E),
    # which on a factory card is 270 bytes — the largest reply the OpenPGP
    # app composes, and the exact one named in the S723-REPAIR comment at
    # `apps/openpgp/src/device_shell.rs:514-528`: gpg's short-Le
    # `00 CA 00 6E 00` used to meet all 272 wire bytes (270 + SW) and scd's
    # `le + 2` buffer truncated them.
    emu.select(OPENPGP_AID)

    # The unconstrained read, used as the oracle every page is compared
    # against: extended `Le = 0xFFFF`, which `serve` clamps to "whatever is
    # staged" and answers `9000` in one exchange.
    full, sw = emu.transmit(case2(0x00, 0xCA, 0x00, 0x6E, 0xFFFF))
    assert sw == 0x9000, f"unconstrained GET DATA 6E must be one clean exchange, got {sw:04X}"
    assert len(full) == 270, (
        f"Application Related Data DO is {len(full)} bytes, expected 270. A "
        f"change here is a deliberate DO change (a UIF, say), not a paging "
        f"regression — but the numbers below are derived from it, so re-read "
        f"them before updating."
    )
    assert len(full) > 256, "the whole point of this block: the DO does not fit one short exchange"

    # Le = 256 (the literal `0x00` form) → exactly 256 bytes + 61xx with
    # the exact remainder in SW2.
    data, sw = emu.transmit(case2(0x00, 0xCA, 0x00, 0x6E, 0x00))
    note("openpgp GET DATA 6E", 0x00, sw)
    assert data == full[:256], "Le = 256 must return the first 256 bytes verbatim"
    assert sw == 0x610E, f"expected 610E (14 undelivered), got {sw:04X}"
    assert sw & 0xFF == len(full) - 256, "SW2 must be the exact undelivered remainder"

    # Le = 1 — the most extreme short read, and the clearest demonstration
    # that OpenPGP clamps to Le instead of over-delivering.
    data, sw = emu.transmit(case2(0x00, 0xCA, 0x00, 0x6E, 0x01))
    note("openpgp GET DATA 6E", 0x01, sw)
    assert data == full[:1]
    assert sw == 0x61FF, (
        f"Le = 1 must yield 1 byte + 61FF, got {len(data)} bytes / {sw:04X}. "
        f"`serve` saturates the remainder at 0xFF when it exceeds 255 "
        f"(device_shell.rs:572-574) — 269 undelivered is exactly that case."
    )

    # Le = 64 → page the whole DO with GET RESPONSE (INS 0xC0), which is the
    # continuation PicoForge issues for every non-OATH applet
    # (`picoforge/src/hal/transport/ccid.rs:101-105`).
    first, sw = emu.transmit(case2(0x00, 0xCA, 0x00, 0x6E, 0x40))
    note("openpgp GET DATA 6E", 0x40, sw)
    assert first == full[:64]
    assert (sw & 0xFF00) == 0x6100 and sw & 0xFF == 206, f"expected 61CE, got {sw:04X}"

    paged, sws = _drain(emu, first, 0xC0, 0x40)
    assert paged == full, (
        f"paged reassembly differs from the unconstrained read: "
        f"{len(paged)} paged bytes vs {len(full)} unconstrained; first "
        f"divergence at offset "
        f"{_first_diff(paged, full)}"
    )
    # 270 = 64 (GET DATA, 61CE) + 64 (618E) + 64 (614E) + 64 (610E) + 14
    # (9000). `_drain` starts *after* the GET DATA exchange, so its first
    # status is the second page.
    assert sws == [0x618E, 0x614E, 0x610E, 0x9000], (
        f"unexpected page status sequence: {[f'{s:04X}' for s in sws]}"
    )

    # `le == 0` normalises to 256 (`device_shell.rs:565`) — and so does
    # an *absent* Le field. Both are checked here, because gpg's scd relies on
    # it: a four-byte GET RESPONSE must serve 256 bytes, not zero. Arm the
    # stream with the most extreme first page (Le = 1, so 269 pends) so the
    # 256 is unambiguous.
    _, sw = emu.transmit(case2(0x00, 0xCA, 0x00, 0x6E, 0x01))
    assert (sw & 0xFF00) == 0x6100
    data, sw = emu.transmit(case1(0x00, 0xC0))
    assert len(data) == 256, (
        f"a GET RESPONSE with no Le field must serve 256 bytes (le == 0 → 256), "
        f"got {len(data)}"
    )
    assert (sw & 0xFF00) == 0x6100
    tail, sw = emu.transmit(case2(0x00, 0xC0, 0x00, 0x00, 0x00))
    assert sw == 0x9000 and len(tail) == 13, f"tail: {len(tail)} bytes / {sw:04X}"
    assert full[:1] + data + tail == full

    # A GET RESPONSE with nothing staged is an empty 9000, not a 6A86 —
    # `run` skips re-dispatching for INS 0xC0 (`device_shell.rs:539-541`)
    # and `serve` sees an empty remainder. Upstream vpicc parity.
    data, sw = emu.transmit(case2(0x00, 0xC0, 0x00, 0x00, 0x40))
    assert (data, sw) == (b"", 0x9000), f"drained GET RESPONSE: {data.hex()} / {sw:04X}"

    # =====================================================================
    # Block 2 — OATH: pages, but at its own cap, not at `Le`.
    # =====================================================================
    authenticate_oath(emu)

    # 32 TOTP/SHA1 credentials. Each CALC ALL entry is
    # `71 <len> <name> 75 15 06 <20-byte HMAC>` = 65 bytes, so 32 of them
    # are 2080 — just over the 2036 one-exchange cap. That is the smallest
    # table that crosses it, and it crosses *mid-entry*: the first exchange
    # carries 31 whole entries (2015 B) plus 21 bytes of the 32nd, and the
    # `0xA5` follow-up the remaining 44. (The applet's own chunk-boundary
    # behaviour is covered exhaustively, at entry-aligned and unaligned
    # boundaries, at `apps/oath/tests/device_oath.rs:562` and `:664`.)
    creds: list[tuple[bytes, bytes]] = []
    for i in range(32):
        name = f"cred-{i:035}".encode()
        secret = f"secret-{i:024}".encode()
        body = (bytes([0x71, len(name)]) + name
                + bytes([0x73, 2 + len(secret), 0x21, 0x06]) + secret)
        _, sw = emu.transmit(case3(0x00, 0x01, 0x00, 0x00, body))
        assert sw == 0x9000, f"PUT credential {i} failed: {sw:04X}"
        creds.append((name, secret))

    challenge = bytes([1, 2, 3, 4, 5, 6, 7, 8])
    calc_all = case3(0x00, 0xA4, 0x00, 0x00, bytes([0x74, 8]) + challenge, le=0x00)

    first, sw = emu.transmit(calc_all)
    note("oath CALCULATE ALL", 0x00, sw)
    assert len(first) == OATH_CHUNK_MAX, (
        f"first CALC ALL exchange is {len(first)} bytes; OATH_CHUNK_MAX is "
        f"{OATH_CHUNK_MAX} (`oath_core.rs:229`). Le was 0x00 (256) and was "
        f"correctly ignored — see the Le-ignored assertion below."
    )
    assert sw == 0x612C, f"expected 612C (44 undelivered), got {sw:04X}"

    rest, sw = emu.transmit(case2(0x00, 0xA5, 0x00, 0x00, 0x00))
    note("oath SEND REMAINING", 0x00, sw)
    assert sw == 0x9000 and len(rest) == 44, f"A5 page: {len(rest)} bytes / {sw:04X}"

    # The reassembled body, recomputed here from the secrets rather than
    # compared against the device's own first chunk, so a device that pages
    # the *right* number of wrong bytes still fails.
    expected = bytearray()
    for name, secret in creds:
        expected += bytes([0x71, len(name)]) + name
        expected += bytes([0x75, 21, 0x06]) + hmac.new(secret, challenge, hashlib.sha1).digest()
    assert len(expected) == 32 * 65 == 2080
    assert first + rest == bytes(expected), "OATH chunked stream is not the full body"

    # **OATH does not honour `Le`.** Asserted as behaviour, not excused: the
    # 2036 cap is the C firmware's own one-exchange body cap (see the module
    # docstring for the `ccid.c:58-60` → `apdu.c:326-347` arithmetic), so a
    # conformant card in this family returns `min(Le, 2036)` here and
    # PicoForge's `transceive_paged` copes: it appends whatever arrives and
    # follows the `61xx`. Saying "OATH honours Le" would be false and would
    # make this test lie about the device.
    first2, sw2 = emu.transmit(case3(0x00, 0xA4, 0x00, 0x00,
                                      bytes([0x74, 8]) + challenge, le=0x40))
    note("oath CALCULATE ALL", 0x40, sw2)
    assert len(first2) == OATH_CHUNK_MAX and sw2 == 0x612C, (
        f"Le = 64 must NOT shrink the OATH chunk: got {len(first2)} bytes / {sw2:04X}"
    )
    emu.transmit(case2(0x00, 0xA5, 0x00, 0x00, 0x00))  # drain, keep the card clean

    # The stream is consumed, not restarted: a further 0xA5 is an error
    # (`oath_core.rs:1696-1704`, a story decision over the C transport's
    # silent empty 9000).
    _, sw = emu.transmit(case2(0x00, 0xA5, 0x00, 0x00, 0x00))
    note("oath SEND REMAINING (no pending)", 0x00, sw)
    assert sw == 0x6985, f"0xA5 with no pending stream must be 6985, got {sw:04X}"

    # OATH LIST does **not** page: it answers in one exchange whatever `Le`
    # says (1376 bytes for this 32-credential table). Recorded because the
    # PicoForge client's own doc comment claims OATH "paginates LIST /
    # CALCULATE ALL" (`ccid.rs:81-85`); on this device LIST simply never
    # reaches a 61xx, and the client's generic loop handles that fine. The
    # case that *would* overflow — a table too large for `MAX_RESPONSE` — is
    # answered `6A84` by the overflow-aware `cmd_list`
    # (`oath_core.rs:1714-1745`), not truncated.
    data, sw = emu.transmit(case2(0x00, 0xA1, 0x00, 0x00, 0x01))
    note("oath LIST", 0x01, sw)
    assert sw == 0x9000 and len(data) == 32 * 43, (
        f"OATH LIST answered {len(data)} bytes / {sw:04X}; expected the whole "
        f"{32 * 43}-byte body in one exchange with no paging"
    )

    # =====================================================================
    # Block 3 — the other five applets: no `61xx`, no `6Cxx`, and the
    # largest reply each one can produce.
    # =====================================================================
    #
    # `mgmt` READ CONFIG (INS 0x1D, `apps/mgmt/src/lib.rs:153`) is the
    # management applet's biggest read; `vendor_led` GET (INS 0x11,
    # `apps/vendor_led/src/lib.rs:120`) its only read; Rescue READ
    # SecureBootStatus (`80 1E 02 00 00`) its largest at 20 bytes. All three
    # APDUs are transcribed from the *client*, not from this firmware, per
    # the discipline in `rescue_ccid.py` — the Rescue one is the exact byte
    # string at `tests/harness/rescue_ccid.py:59-67` (`READ_SECURE_BOOT`).
    # (Note `rescue_ccid.py`'s own citation, `ops.rs:288-292`, points at the
    # PhyConfig read in the current client, not SecureBootStatus; the bytes
    # are what the client actually sends, which is the part that matters.)
    # Every probe below is a case-4 APDU with **no request body** and a
    # varying `Le` — i.e. exactly the request shape a paging client makes,
    # so a `6Cxx` would be the natural answer and its absence is meaningful.
    # The AID travels with its probe because the dispatcher holds ONE
    # current selection: probing mgmt and then LED without re-selecting
    # between them would send the mgmt APDUs to whichever applet was
    # selected last.
    probes: list[tuple[str, bytes, int, list[bytes]]] = [
        ("mgmt READ CONFIG", MGMT_AID, 0x00,
         [case3(0x00, 0x1D, 0x00, 0x00, b"", le) for le in (0x01, 0x00, 0x40, 0xFF)]),
        # OTP's read commands all hang off INS 0x01 with P1 selecting the
        # operation (`apps/oath/src/otp.rs:964-1010`); P1 0x14 is EXTENDED
        # STATUS, the one that returns a data block. A factory card has no
        # configured slot, so the honest expected reply here is `9000` with
        # an *empty* body — the point of the row is that the command is a
        # valid read and still never answers `61xx` or `6Cxx`.
        ("otp EXTENDED STATUS (INS 01 P1 14)", OTP_AID, 0x00,
         [case3(0x00, 0x01, 0x14, 0x00, b"", le) for le in (0x01, 0x00, 0x40, 0xFF)]),
        ("vendor_led GET", LED_AID, 0x04,
         [case3(0x00, 0x11, 0x00, 0x00, b"", le) for le in (0x01, 0x00, 0x40, 0xFF)]),
        # Rescue is CLA `0x80`; every other applet here is `0x00`.
        ("rescue READ SecureBootStatus", RESCUE_AID, 0x04,
         [case3(0x80, 0x1E, 0x02, 0x00, b"", le) for le in (0x01, 0x00, 0x40, 0xFF)]),
    ]

    max_len: dict[str, int] = {}
    for label, aid, p2, apdus in probes:
        emu.select(aid, p2=p2)
        for apdu in apdus:
            data, sw = emu.transmit(apdu)
            note(label, apdu[-1], sw)
            assert (sw & 0xFF00) != 0x6100, (
                f"{label} returned 61xx ({sw:04X}) with no pending stream. "
                f"Only OpenPGP (61xx + INS 0xC0) and OATH CALC ALL "
                f"(61xx + INS 0xA5) page on this device; a 61xx from any "
                f"other applet would strand PicoForge's `transceive_paged` "
                f"on a continuation INS that applet does not implement."
            )
            max_len[label] = max(max_len.get(label, 0), len(data))

    # Each row's largest reply, unchanged whatever `Le` says. These are the
    # numbers the module docstring's table quotes. `otp` is 0 because a
    # factory card has no slot to report on — asserted as `9000` so the row
    # cannot silently become an error SW that proves nothing.
    assert max_len["mgmt READ CONFIG"] == 29, max_len
    assert max_len["vendor_led GET"] == 17, max_len
    assert max_len["rescue READ SecureBootStatus"] == 20, max_len
    assert max_len["otp EXTENDED STATUS (INS 01 P1 14)"] == 0, max_len

    # =====================================================================
    # Block 4 — PIV: the one real gap, pinned.
    # =====================================================================
    emu.select(PIV_AID)
    # Management-key single challenge (`apps/piv/src/lib.rs:608-652`):
    # `7C 02 81 00` issues a plaintext challenge, `7C 12 82 10 <enc>` answers
    # it. The key is the C factory default (see PIV_DEFAULT_MGM_KEY).
    data, sw = emu.transmit(case3(0x00, 0x87, PIV_ALGO_AES192, PIV_KEY_CARDMGM,
                                  bytes([0x7C, 0x02, 0x81, 0x00])))
    assert sw == 0x9000 and data[:4] == bytes([0x7C, 0x12, 0x81, 0x10]), \
        f"PIV mgmt challenge: {data.hex()} / {sw:04X}"
    witness = bytes([0x7C, 0x12, 0x82, 0x10]) + _aes_ecb(PIV_DEFAULT_MGM_KEY, data[4:20])
    _, sw = emu.transmit(case3(0x00, 0x87, PIV_ALGO_AES192, PIV_KEY_CARDMGM, witness))
    assert sw == 0x9000, f"PIV mgmt authenticate failed: {sw:04X}"

    obj = bytes((i * 7 + 3) & 0xFF for i in range(PIV_MAX_OBJECT_SIZE))
    put_body = (bytes([0x5C, 0x03, 0x5F, 0xC1, 0x01,
                       0x53, 0x82, PIV_MAX_OBJECT_SIZE >> 8, PIV_MAX_OBJECT_SIZE & 0xFF]) + obj)
    _, sw = emu.transmit(case3(0x00, 0xDB, 0x3F, 0xFF, put_body))
    assert sw == 0x9000, f"PIV PUT DATA 2048 failed: {sw:04X}"

    # `cmd_get_data` (`apps/piv/src/lib.rs:751-791`) pushes
    # `53 <len> <object>` into the response and returns `9000`. It reads no
    # `Le` and stages no remainder, so the whole object goes out in one
    # exchange: 1 tag + 3 length bytes + 2048 = 2052.
    #
    # **This is a documented limitation, pinned deliberately.** It is
    # ISO-nonconformant in the same way OATH's fixed 2036 is — but unlike
    # OATH, 2036 is the C card's own cap and 2052 is not. On the C
    # `pico-keys-sdk` the same GET DATA *does* page, like every other applet:
    # `apdu_process`'s INS 0xC0 branch plus `apdu_next` / `apdu_limit_response`
    # (`pico-keys-sdk/src/apdu.c:175-235`, `:301-347`) are a transport-level
    # seam that every applet's response passes through, so the C PIV never
    # had to think about it. Only the OpenPGP and OATH applets here re-implemented
    # that seam; PIV, mgmt, otp, vendor_led and rescue all bypass it.
    #
    # The fix is deliberately NOT in this story. US-180's commit line is
    # `test(harness): paging contract across all applets`; adding `61xx` to
    # PIV is a behaviour change to `apps/piv/src/lib.rs` that also needs a
    # client-side decision (PicoForge's generic continuation is INS `0xC0`,
    # which `cmd_get_data` does not currently answer, and PIV's SELECT
    # clears `current_idx`-adjacent state that a staged reply would have to
    # survive). It belongs with the US-181 chaining work. Until then this
    # assertion is the record: if it ever starts failing, PIV grew paging
    # and this test should be rewritten to *require* it, not relaxed.
    expected_get = bytes([0x53, 0x82, PIV_MAX_OBJECT_SIZE >> 8, PIV_MAX_OBJECT_SIZE & 0xFF]) + obj
    for le in (0x00, 0x40, 0x01, 0xFF):
        data, sw = emu.transmit(case3(0x00, 0xCB, 0x3F, 0xFF,
                                      bytes([0x5C, 0x03, 0x5F, 0xC1, 0x01]), le=le))
        note("piv GET DATA 5FC101", le, sw)
        assert sw == 0x9000, f"PIV GET DATA must stay SW 9000 today, got {sw:04X}"
        assert (sw & 0xFF00) != 0x6100, (
            "PIV GET DATA started paging. That is the fix this test was "
            "pinning the absence of; the expected behaviour changes with it."
        )
        assert data == expected_get, (
            f"PIV GET DATA with Le={le:02X} returned {len(data)} bytes; the "
            f"pinned no-paging contract is {len(expected_get)} bytes in one "
            f"exchange. A short read here is a real defect: the host asked "
            f"for at most {le if le else 256} bytes and the object round-trip "
            f"cannot be reassembled (PIV has no continuation INS)."
        )

    # =====================================================================
    # The 6Cxx contract.
    # =====================================================================
    #
    # A `6Cxx` is not a bug on this device; it would be a *change of
    # behaviour*. It means "I will not send more than Le — resend with a
    # bigger Le", and every applet here instead either sends its whole reply
    # (mgmt/otp/vendor_led/rescue/piv) or stages a page (OpenPGP/OATH). If
    # one starts refusing, a host has to grow the `6Cxx` branch of
    # `transceive_paged` and — more importantly — the applet has started
    # holding a response it did not hold before, which is a real design
    # change to review. So: read the failure, do not blanket-allow it.
    assert not seen_6c, (
        "6Cxx appeared on this device:\n  " + "\n  ".join(seen_6c) + "\n"
        "No applet in this tree constructs a 6Cxx (the only 0x6C literals are "
        "the CCID message-type constants at platform/src/ccid.rs:63). This is "
        "a behaviour change worth understanding, not automatically a bug: it "
        "means an applet began refusing to over-deliver past Le and now "
        "expects PicoForge's `transceive_paged` 6Cxx branch "
        "(picoforge/src/hal/transport/ccid.rs:95-99) to resend the command."
    )
