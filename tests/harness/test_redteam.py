"""US-923: red-team regression suite — the EPIC SEC-HARDEN gate (Phase F).

Every case replays one attack executed against the live device during the
authorized red-team assessment (2026-09-22,
``redteam/out/ASSESSMENT_REPORT.md``) against the emulation binary, and
asserts the attack is REFUSED on the fixed (US-901–US-922) build.

TDD red/green (controller decision, binding): the *red* evidence for each
case is the assessment record — the attack verifiably succeeded against the
pre-fix device (the report's evidence column). No fix is reverted to
re-create a literal red; each case documents its red citation below and in
its docstring, and green is the emulator run of this suite.

Case → finding mapping (assessment-report IDs R1–R12):

=============  ==========================  =====================  ============
Case           Attack (report table #)     Finding(s)             Emulation
=============  ==========================  =====================  ============
dump           #2 OATH unauth LIST +       R2 (session            active
               CALC_ALL                    self-grant)
tamper         #4 PUT overwrite, #5        R1 (unauth RESET),     active
               DELETE, #6 unauth RESET     R2
ga-no-pin      #12 raw-CBOR GA without     R3 (UP stub),          active
               the PIN token + wave-2      R10 (PIN verifier
               forged pinUvAuthParam       budget)
u2f-presence   #14 silent REGISTER, #15    R3 (UP stub)           skipped
               AUTHENTICATE w/o touch                             (parity)
mgmt-presence  #18 WRITE_CONFIG / RESET    R11 (presence-latch    skipped
               without presence            harvest)               (parity)
ccid-wedge     US-920 stall sequence       R11 (CCID park DoS)    skipped
                                                                  (parity)
forged-slot    #17 forged format-v2 slot   R6 (plaintext store,   active
               with attacker ``fido.hkey`` CRC-only)
=============  ==========================  =====================  ============

The three skipped cases cannot be replayed as refusals against the
emulation binary *by construction* — not because the fixes regressed:

- **u2f-presence / mgmt-presence**: the emulation build's user-presence
  source auto-acks (``apps/fido/src/app.rs`` ``process_u2f`` passes
  ``|| true``; ``apps/mgmt/src/lib.rs`` ``default_user_present()`` returns
  ``true`` on host builds), so the attack gets SW=9000 in emulation
  regardless of the device fail-closed default. The device gates live in
  ``apps/fido/src/u2f.rs`` (US-908: no grant ⇒ no signature, no key-handle
  minting) and ``apps/mgmt/src/lib.rs`` (US-906/US-921 bound presence
  service); their unit tests cover the refusal. Physical-presence attacks
  are the US-924 hardware BDD run's scope (the RP2350 has the button).
- **ccid-wedge**: the US-920 reassembler + park timeout are wired only in
  the device serve loop (``firmware/src/tasks.rs``); the emulation binary's
  TCP CCID path (``platform/src/emulation.rs`` ``read_ccid`` +
  ``firmware/src/emul_main.rs``) has no stale-partial drop, so a stalled
  partial frame wedges the emulator's CCID decode permanently. Empirically
  confirmed against this build (probe run 2026-09-24: no reply to a valid
  SELECT after the stall, two attempts over 8 s).

Each skipped case keeps its full attack description and finding-ID
citation here so the regression intent survives the deferral.

Like the sibling harness suites, every test manages its own CCID relay +
emulator instance with private keystore/partition paths, so cases are
independent. The relay binds DEDICATED ports (35964 dial-in / 35972 client,
below) so the suite also runs under bare ``./run_tests.sh`` default
discovery, where the shared relay already holds the harness ports
(35963/35970) — the emulator is pointed at the private dial-in via
``FAPICO2_CCID_PORT``.
"""

import contextlib
import os
import signal
import socket
import struct
import subprocess
import sys
import time
import zlib
from pathlib import Path

import pytest

from harness.test_restart import Emu

REPO = Path(__file__).resolve().parents[2]
RELAY_CCID_PORT = 35964  # the emulator dials in here (FAPICO2_CCID_PORT)
RELAY_CLIENT_PORT = 35972  # this test connects here

# Dial target for the direct-spawn emulators that need no CCID at all
# (forged-slot refusal, CTAPHID-only GA): an unbound port keeps them
# FIDO-only so their one-shot dial never steals the shared relay's
# emulator slot under bare ./run_tests.sh (the shared emulator dials
# 35963 once at startup, no retry).
DEAD_CCID_PORT = 35973

# Private HID ports (35961/35962/35966 are taken by the sibling suites).
HID_PORT_DUMP = 35967
HID_PORT_TAMPER = 35968
HID_PORT_GA = 35969

SW_SEC_STATUS = b"\x69\x82"  # 0x6982 SECURITY_STATUS_NOT_SATISFIED
SW_OK = b"\x90\x00"


def _emulation_bin() -> Path:
    return Path(
        os.environ.get(
            "FAPICO2_EMULATION_BIN",
            str(REPO / "target/x86_64-unknown-linux-gnu/debug/fapico2-emulation"),
        )
    )

# --- OATH (YKOATH) -----------------------------------------------------
OATH_AID = bytes.fromhex("A0000005272101")

TAG_NAME = 0x71
TAG_KEY = 0x73
TAG_CHALLENGE = 0x74
INS_PUT = 0x01
INS_DELETE = 0x02
INS_RESET = 0x04
INS_LIST = 0xA1
INS_CALC_ALL = 0xA4

VICTIM_NAME = b"GitHub:eddieoz"  # the credential destroyed live (report #6)
ATTACKER_SECRET = b"attacker-planted-key-123456"  # 26 bytes
# key TLV value: 0x21 = TOTP | SHA-1, 0x06 = 6 digits, then the secret.
VICTIM_KEY = b"\x21\x06" + b"\x0b" * 20


def _oath_apdu(ins, p1=0, p2=0, data=b""):
    """Short-APDU OATH command (harness framing, tests/harness parity)."""
    return bytes([0x00, ins, p1, p2, len(data)]) + data


def _put_tlv(name, key):
    return bytes([TAG_NAME, len(name)]) + name + bytes([TAG_KEY, len(key)]) + key


SELECT_OATH = bytes([0x00, 0xA4, 0x04, 0x00, len(OATH_AID)]) + OATH_AID
CALC_ALL_CHAL = bytes([TAG_CHALLENGE, 8]) + bytes(8)


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("CCID connection closed")
        buf += chunk
    return bytes(buf)


def _ccid(sock, payload):
    """One [u16 BE length] framed exchange; returns the response body."""
    sock.sendall(struct.pack(">H", len(payload)) + payload)
    (length,) = struct.unpack(">H", _recv_exact(sock, 2))
    return _recv_exact(sock, length)


def _sw(resp):
    return resp[-2:]


def _wait_relay_line(proc, needle, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        if needle in line:
            return
    raise AssertionError(f"ccid relay did not report {needle!r} within {timeout}s")


class _Relay:
    """The harness CCID relay on the dedicated red-team ports."""

    def __init__(self):
        self.proc = subprocess.Popen(
            [
                sys.executable,
                str(REPO / "tests" / "harness" / "ccid_relay.py"),
                "--ccid-port",
                str(RELAY_CCID_PORT),
                "--client-port",
                str(RELAY_CLIENT_PORT),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        _wait_relay_line(self.proc, "READY", timeout=10)

    def stop(self):
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        self.proc = None


@contextlib.contextmanager
def _redteam_device(tmp_path, monkeypatch, tag, hid_port):
    """Private relay + emulator + relayed CCID client for one case."""
    monkeypatch.setenv("FAPICO2_KEYSTORE", str(tmp_path / f"{tag}_keystore.cbor"))
    monkeypatch.setenv(
        "FAPICO2_SECURE_PARTITION", str(tmp_path / f"{tag}_partition.bin")
    )
    monkeypatch.setenv("FAPICO2_PIV_KEYSTORE", str(tmp_path / f"{tag}_piv.cbor"))
    # Dedicated CCID dial-in (Emu.start copies os.environ): the private
    # relay holds RELAY_CCID_PORT, not the shared harness dial-in 35963.
    monkeypatch.setenv("FAPICO2_CCID_PORT", str(RELAY_CCID_PORT))
    relay = _Relay()
    client = None
    emu = Emu(tmp_path / f"{tag}_keystore.cbor", hid_port=hid_port)
    try:
        emu.start()
        _wait_relay_line(relay.proc, "[ccid] emulator connected", 15)
        client = socket.create_connection(("127.0.0.1", RELAY_CLIENT_PORT), timeout=3)
        client.settimeout(15)
        _wait_relay_line(relay.proc, "[client] test client connected", 15)
        yield client
    finally:
        emu.stop(signal.SIGTERM)
        if client is not None:
            client.close()
        relay.stop()


def _plant_victim_credential(client):
    """Setup: plant a victim credential through the *virgin* grant.

    The landed US-901 rule deliberately keeps the C-firmware parity: an app
    with no access code, no OTP PIN and no credentials is grantable so a
    legitimate user can provision it. This is the documented design
    allowance (see the US-923 report), not a regression; the attacks under
    test are the credential *dump/tamper/wipe* against a seeded store.
    """
    assert _sw(_ccid(client, SELECT_OATH)) == SW_OK
    put = _oath_apdu(INS_PUT, data=_put_tlv(VICTIM_NAME, VICTIM_KEY))
    assert _sw(_ccid(client, put)) == SW_OK
    # Control: in the (still-validated) planting session the credential is
    # readable — the refusals below are the session gate, not a broken app.
    listed = _ccid(client, _oath_apdu(INS_LIST))
    assert _sw(listed) == SW_OK and VICTIM_NAME in listed, listed.hex()
    # A host-issued SELECT recomputes the session grant (US-901): with a
    # credential on file the app is non-virgin, so the fresh session is
    # UNvalidated — the state every attacker session below replays.
    assert _sw(_ccid(client, SELECT_OATH)) == SW_OK


def test_oath_unauth_dump_refused(tmp_path, monkeypatch):
    """R2 — OATH credential dump refused from an unvalidated session.

    Attack (report #2, ``oath_attack2.py``): a fresh OATH SELECT started a
    session pre-validated when no access code was configured, so LIST
    (INS 0xA1) dumped every stored credential name and CALC_ALL (INS 0xA4)
    emitted the live TOTP/HOTP digests of all of them — ``kaka`` and
    ``GitHub:eddieoz`` were dumped with codes saved to
    ``redteam/out/oath_codes_dump.bin``.

    Red: report R2 (oath.rs self-granting sessions) + evidence row #2.
    Green: US-901 makes every non-virgin session start unvalidated, so
    both dump commands must answer 6982 before touching any credential.
    """
    with _redteam_device(tmp_path, monkeypatch, "rt_dump", HID_PORT_DUMP) as client:
        _plant_victim_credential(client)
        resp = _ccid(client, _oath_apdu(INS_LIST))
        assert _sw(resp) == SW_SEC_STATUS, f"unauth LIST dumped credentials: {resp.hex()}"
        resp = _ccid(client, _oath_apdu(INS_CALC_ALL, data=CALC_ALL_CHAL))
        assert _sw(resp) == SW_SEC_STATUS, f"unauth CALC_ALL dumped digests: {resp.hex()}"


def test_oath_unauth_tamper_refused(tmp_path, monkeypatch):
    """R1 + R2 — OATH overwrite, DELETE and unauthenticated RESET refused.

    Attacks (report rows #4/#5/#6, ``oath_storage2.py``/``oath_storage.py``):
    from the self-granted session the attacker overwrote a credential's
    secret (PUT, SW=9000), invalidated it (DELETE, SW=9000) and — worst —
    wiped the whole table with one unauthenticated ``00 04 DE AD`` RESET
    (SW=9000; all credentials destroyed, user-authorized destructive test).

    Red: report R1 (``cmd_reset`` missing the validated gate) + rows
    #4/#5/#6. Green: US-902/US-901 keep the fresh session unvalidated and
    US-903 gates RESET on the session BEFORE presence, so all three must
    answer 6982 and nothing may be erased or rewritten.
    """
    with _redteam_device(tmp_path, monkeypatch, "rt_tamper", HID_PORT_TAMPER) as client:
        _plant_victim_credential(client)
        # Overwrite (corrupt) — attacker secret over the victim's key.
        resp = _ccid(
            client, _oath_apdu(INS_PUT, data=_put_tlv(VICTIM_NAME, ATTACKER_SECRET))
        )
        assert _sw(resp) == SW_SEC_STATUS, f"unauth PUT overwrote a credential: {resp.hex()}"
        # Invalidate.
        resp = _ccid(
            client, _oath_apdu(INS_DELETE, data=bytes([TAG_NAME, len(VICTIM_NAME)]) + VICTIM_NAME)
        )
        assert _sw(resp) == SW_SEC_STATUS, f"unauth DELETE destroyed a credential: {resp.hex()}"
        # Wipe — the single worst APDU of the assessment. The session gate
        # fires before the presence gate, so this is a pure-session refusal
        # even though the emulation presence source would auto-ack.
        resp = _ccid(client, _oath_apdu(INS_RESET, p1=0xDE, p2=0xAD))
        assert _sw(resp) == SW_SEC_STATUS, f"unauth RESET wiped the store: {resp.hex()}"


def test_forged_v2_slot_refused(tmp_path, monkeypatch):
    """R6 — a forged format-v2 secure-store slot never boots.

    Attack (report rows #16/#17, ``store_forge.py``): the secure partition
    was plaintext flash guarded by CRC-32 only, so an evil-maid/flash-dump
    attacker recomputed the CRC over a forged format-v2 slot image carrying
    an attacker-controlled ``fido.hkey`` (``out/forged_secure_slot_primary.bin``)
    and it booted as LoadPrimary — full keystore control.

    Red: report R6 + rows #16/#17. Green: US-915/US-917 (encrypt-then-MAC
    format v3, AEAD record wraps) make a v2 image — even a structurally
    valid one with a recomputed CRC — unbootable: the emulator refuses with
    exit code 2 ("legacy v2 or forged; refusing to boot (US-915)") and the
    forged slot is never loaded nor migrated.
    """
    # The attacker's recomputed-CRC v2 image: [PS2F][count][entries][crc32],
    # every field little-endian (platform/src/secure_store.rs layout) —
    # structurally valid, CRC recomputed, attacker-controlled fido.hkey.
    entries = [
        (b"fido.hkey", b"\xc7" * 32),  # the attacker's "hkey" (report: scalar c7b2f6c5…)
        (b"oath.kaka", b"\x0b" * 20),  # attacker replanting wiped credentials
    ]
    img = bytearray(b"PS2F")
    img += len(entries).to_bytes(4, "little")
    for key, val in entries:
        img += len(key).to_bytes(4, "little") + key
        img += len(val).to_bytes(4, "little") + val
    img += zlib.crc32(bytes(img)).to_bytes(4, "little")

    partition = tmp_path / "forge_partition.bin"
    monkeypatch.setenv("FAPICO2_SECURE_PARTITION", str(partition))
    monkeypatch.setenv(
        "FAPICO2_PIV_KEYSTORE", str(tmp_path / "forge_piv.cbor")
    )
    # The transport init (HID listener bind) runs BEFORE the partition
    # check, so the refusing emulator needs a free HID port of its own.
    monkeypatch.setenv("FAPICO2_HID_PORT", "35971")
    # ...and a dead CCID dial target (see DEAD_CCID_PORT) so its one-shot
    # dial never steals the shared relay's emulator slot.
    monkeypatch.setenv("FAPICO2_CCID_PORT", str(DEAD_CCID_PORT))
    partition.write_bytes(bytes(img))

    # Spawn the emulator directly (stderr captured) so the refusal is
    # pinned to the US-915 boot decision, not any other early exit.
    env = dict(os.environ)
    env["FAPICO2_KEYSTORE"] = str(tmp_path / "forge_keystore.cbor")
    proc = subprocess.Popen(
        [str(_emulation_bin())],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
    )
    try:
        out, _ = proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    assert proc.returncode == 2, (
        f"forged v2 slot must be refused with exit code 2, got "
        f"{proc.returncode}; output:\n{out[-2000:]}"
    )
    assert "refusing to boot" in out, (
        "exit 2 must be the US-915 legacy/forged-image refusal"
    )
    # The forgery was never adopted: the partition file must not have been
    # re-sealed into v3 (the attacker's bytes survive untouched on disk).
    assert partition.read_bytes() == bytes(img), "forged slot was migrated/sealed"


def test_ctap2_ga_without_pin_refused(tmp_path, monkeypatch):
    """R3/R10 — raw-CBOR getAssertion without the PIN token is refused.

    Attack (report row #12, ``ctap_raw_ga.py``; wave-2 forged-pinUvAuthParam
    probe): a hostile host speaks raw CTAP2 CBOR straight over CTAPHID and
    asks for an assertion with no PIN token — silent authentication without
    user verification. The pre-fix device refused this (a genuine pass:
    "refused correctly — PIN enforced"), and the wave-2 probes confirmed
    forged pinUvAuthParams hit PIN_AUTH_INVALID with a durable budget.

    Red: report "What held up" #2 + wave-2 matrix; guarded by R3 (UP stub)
    and R10 (PIN verifier). Green: US-910's salted stretched PIN verifier +
    the PUAT gate (apps/fido/src/app.rs get_assertion) must keep both
    refusals: PUAT_REQUIRED for the token-less request, PIN_AUTH_INVALID
    for the forged pinUvAuthParam.
    """
    monkeypatch.setenv("FAPICO2_SECURE_PARTITION", str(tmp_path / "rt_ga_partition.bin"))
    monkeypatch.setenv("FAPICO2_PIV_KEYSTORE", str(tmp_path / "rt_ga_piv.cbor"))
    # CTAPHID-only case: a dead CCID dial target (see DEAD_CCID_PORT) keeps
    # this private emulator from stealing the shared relay's slot.
    monkeypatch.setenv("FAPICO2_CCID_PORT", str(DEAD_CCID_PORT))
    emu = Emu(tmp_path / "rt_ga_keystore.cbor", hid_port=HID_PORT_GA)

    from fido2.ctap import CtapError
    from fido2.ctap2 import Ctap2, ClientPin
    from fido2.hid import CtapHidDevice
    from fido2.hid.base import CtapHidConnection, HidDescriptor

    class _PrivatePortConnection(CtapHidConnection):
        """python-fido2 bridge to a private-port emulator (hid_emul parity)."""

        def __init__(self, port):
            self.handle = socket.create_connection(("127.0.0.1", port))

        def write_packet(self, packet):
            self.handle.sendall(len(packet).to_bytes(2, "big") + packet)

        def read_packet(self):
            size = int.from_bytes(self._recv_exact(2), "big")
            data = self._recv_exact(size)
            if len(data) != size:
                raise OSError("short read")
            return data

        def _recv_exact(self, n):
            buf = bytearray()
            while len(buf) < n:
                chunk = self.handle.recv(n - len(buf))
                if not chunk:
                    raise OSError("connection closed by emulator")
                buf += chunk
            return bytes(buf)

        def close(self):
            self.handle.close()

    emu.start()
    conn = None
    try:
        conn = _PrivatePortConnection(HID_PORT_GA)
        dev = CtapHidDevice(
            HidDescriptor(None, 0x00, 0x00, 64, 64, "fapico2", "AAAAAA"), conn
        )
        ctap2 = Ctap2(dev)
        # Setup: enroll a PIN exactly as the device owner had (the live
        # device held an enrolled PIN during attacks #12/#13).
        cp = ClientPin(ctap2)
        cp.set_pin("24681357")

        # Attack 1: raw-CBOR GA demanding user verification with no PIN
        # token — the silent-authentication shape.
        with pytest.raises(CtapError) as err:
            ctap2.get_assertion(
                "example.com", os.urandom(32), options={"uv": True}
            )
        assert err.value.code == CtapError.ERR.PUAT_REQUIRED, (
            f"GA without a PIN token must be PUAT_REQUIRED, got {err.value.code}"
        )

        # Attack 2: forged pinUvAuthParam (wave-2) — refused, and the
        # durable attempt budget (US-909) records it.
        with pytest.raises(CtapError) as err:
            ctap2.get_assertion(
                "example.com",
                os.urandom(32),
                options={"uv": True},
                pin_uv_param=b"\x00" * 32,
                pin_uv_protocol=1,
            )
        assert err.value.code == CtapError.ERR.PIN_AUTH_INVALID, (
            f"forged pinUvAuthParam must be PIN_AUTH_INVALID, got {err.value.code}"
        )

        # Control: with a genuine PIN token the GA path works end-to-end —
        # the refusals above are the missing/forged token, not a broken
        # GA path (no resident credentials ⇒ NO_CREDENTIALS after the gate).
        token_cp = ClientPin(ctap2)
        token = token_cp.get_pin_token("24681357")
        client_hash = os.urandom(32)
        with pytest.raises(CtapError) as err:
            ctap2.get_assertion(
                "example.com",
                client_hash,
                options={"uv": True},
                pin_uv_param=token_cp.protocol.authenticate(token, client_hash),
                pin_uv_protocol=token_cp.protocol.VERSION,
            )
        assert err.value.code == CtapError.ERR.NO_CREDENTIALS, (
            f"GA with a genuine PIN token must pass the PUAT gate "
            f"(NO_CREDENTIALS expected), got {err.value.code}"
        )
    finally:
        emu.stop(signal.SIGTERM)
        if conn is not None:
            conn.close()


def test_u2f_register_auth_without_presence_refused(tmp_path, monkeypatch):
    """R3 — U2F REGISTER/AUTHENTICATE with zero touches must never sign.

    Attacks (report rows #14/#15, ``mitm_ctap.py``): over the CTAP1/U2F
    path — which had no gate at all — REGISTER silently planted a
    credential for an attacker-chosen appId and AUTHENTICATE completed with
    zero touches while claiming UP=0x01, including a CTAPHID-level MITM
    challenge rewrite (``out/u2f_auth.json``).

    Red: report R3 (UP stub, device_core.rs/u2f.rs) + rows #14/#15.
    Green (US-908): no presence grant ⇒ no key-handle minting and no
    signature — REGISTER answers SW_CONDITIONS_NOT_SATISFIED and
    AUTHENTICATE answers the CTAP1 NOT_PRESENT byte.

    DEFERRED to US-924 (hardware BDD): the emulation build's presence
    source auto-acks (apps/fido/src/app.rs process_u2f passes ``|| true``;
    the emulator has no button), so this attack cannot be replayed as a
    refusal in the emulator — the device build's fail-closed default is
    covered by apps/fido/tests/u2f_presence.rs.
    """
    pytest.skip(
        "emulation parity: the emulation presence source auto-acks, so the "
        "U2F silent-register/auth attacks succeed by construction in the "
        "emulator; US-908's refusal is unit-covered (u2f_presence.rs) and "
        "replayed on hardware by US-924 (R3, report rows #14/#15)"
    )


def test_mgmt_write_config_reset_without_presence_refused(tmp_path, monkeypatch):
    """R11 — mgmt WRITE_CONFIG/RESET without the physical button.

    Attack (report row #18, ``recon_device.py``; the R11 presence-latch
    harvest): a hostile host loops WRITE_CONFIG (INS 0x1C) and factory
    RESET (INS 0x1E) waiting to steal a user's button press meant for an
    unrelated FIDO touch. The live device failed closed (6985) — a pass the
    US-906/US-921 work turned into bound, single-use, tag-matched grants.

    Red: report "What held up" #1 + R11 (presence-latch race). Green
    (US-906/US-921): a grant requires a press edge bound to THIS pending
    command tag; a press with nothing pending never arms.

    DEFERRED to US-924 (hardware BDD): the emulation build's mgmt presence
    default auto-acks (apps/mgmt/src/lib.rs default_user_present() returns
    true on host builds), so the attack cannot be replayed as a refusal in
    the emulator; the grant discipline is unit-covered by US-906/US-921.
    """
    pytest.skip(
        "emulation parity: mgmt presence auto-acks on host builds, so "
        "WRITE_CONFIG/RESET without a button press succeed by construction "
        "in the emulator; replayed on hardware by US-924 (R11, report "
        "row #18)"
    )


def test_ccid_wedge_recovery(tmp_path, monkeypatch):
    """R11 — a stalled CCID bulk-OUT must not wedge the transport.

    Attack (report R11, ``tasks.rs:75-88,303-324``): one aborted CCID
    message — a partial bulk-OUT the host never finishes — parked the
    device transport forever ("would park it until replug"); a valid
    command after the stall got no reply.

    Red: report R11. Green (US-920): a partial message older than the park
    window (2 s) is dropped and the state resyncs, so a fresh SELECT after
    the stall assembles and replies.

    DEFERRED: the US-920 reassembler is wired only in the device serve
    loop (firmware/src/tasks.rs); the emulation binary's TCP CCID path
    (platform/src/emulation.rs read_ccid) keeps the stale partial at the
    buffer head forever, so the emulator wedges (probed empirically against
    this build: no reply after the stall, two attempts). The device-side
    resync is unit-covered by firmware/src/ccid_reasm.rs.
    """
    pytest.skip(
        "emulation parity: the US-920 park-timeout resync is device-serve-"
        "loop only; the emulation TCP CCID path has no stale-partial drop "
        "and wedges on the stall. Unit-covered by ccid_reasm.rs; replayed "
        "on hardware by US-924 (R11)"
    )
