"""US-171/US-172 (EPIC `PICOForge-COMPAT`) — the backup seed, driven through
the CLI tool's own library over the emulated CTAP-HID transport.

`scripts/backup_fido.py` is a standalone host tool (imported here by path, the
house pattern of `tests/harness/test_docs_gate.py`). This file drives its
library functions against the `fapico2-emulation` binary exactly the way the
CLI would: MSE channel establishment, EXPORT/LOAD under ChaCha20-Poly1305,
FINALIZE, and the BIP-39 layer that turns the 32-byte seed into the 24-word
phrase a user writes on paper.

## What this file proves

* **The wire dialect, byte-exact.** `load_request_is_a_byte_exact_transcription`
  pins a *fixed* host key into the MSE handshake (monkeypatching
  `ec.generate_private_key`), so the test can independently recompute the
  channel key (HKDF over the device's point), the AEAD blob, and therefore the
  **exact request bytes** — and the firmware answers `0x00` to precisely those
  bytes. A transcription error in the script (wrong AAD, wrong HKDF info, a
  re-encoded CBOR params) would fail the tag or the status here, because the
  expected bytes are computed by the test, not by the code under test.
* **Restore → export round-trips losslessly**, over a live device.
* **FINALIZE is the boundary the firmware claims it is**: after it, EXPORT
  answers `0x30` but LOAD still works — the seed goes in, it just never comes
  back out.
* **The BIP-39 layer matches the client's own renderer.** The two vectors below
  were verified against the `bip39` 2.2.2 Rust crate — the crate picoforge
  (`Cargo.toml:34`) renders the phrase with — not against this Python. Both
  directions are checked.
* **Client-side refusals fire before any wire traffic**: length, wordlist and
  checksum gates are pure functions of the phrase.

## What this file does NOT prove — read before citing it

* **[EMU].** No RP2350, no USB, no CCID. The keystore is the emulator's.
* **Not the touch gate.** The emulation path auto-acks presence, so every
  gated call here runs on its *accepting* side. A firmware that dropped the
  touch requirement from EXPORT/LOAD/FINALIZE entirely would leave this file
  green; the gate's teeth are pinned in `apps/fido/tests/vendor_backup.rs`
  (`export_falls_back_to_a_touch_when_there_is_no_pin` and siblings), not here.
* **Not the CLI's argparse layer.** The suite deliberately drives the library
  with an explicit device object: a development machine can have *real* boards
  enumerated beside the emulator, so a test that ran `main()` would have to
  pick a device, and device picking is exactly what must not be guessed. The
  CLI is a thin shell (arg parsing, prompts, prose-to-stderr) over the flows
  proven here.
* **Not a no-seed EXPORT on every store.** `export_on_a_seedless_board…`
  *skips* unless `STATE` reports `has_seed: false` — the emulator's keystore
  is wiped by `run_tests.sh` at the start of a run but not by a bare pytest
  invocation, so that initial state is genuinely nondeterministic. The skip is
  the honest form; do not "fix" it into an assertion.

## State leaks across tests — the file order is load-bearing

The emulator is session-scoped and its keystore persists across test
functions. Two leaks are handled here, not avoided: earlier files leave a
**PIN** on the board (cleared by the module-scoped reset — see
`_pin_free_board`), and `finalize_permanently_seals…` runs **last** because
FINALIZE's export-window closure is permanent *for the whole pytest session*.
Any test needing an open window must come before it. Do not reorder, and do
not move backup tests from this file into an earlier-numbered one without
re-checking which file runs first.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fido2 import cbor

# tests/pico-fido/test_093_backup.py -> parents[2] == fapico2/. Resolve the
# repo from the test file, never from the CWD (house rule, see
# tests/harness/test_docs_gate.py).
REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "backup_fido.py"


def _load_tool():
    """Import the standalone tool by path (it is not on sys.path)."""
    spec = importlib.util.spec_from_file_location("backup_fido_tool", SCRIPT)
    if spec is None or spec.loader is None:  # pragma: no cover - setup error
        raise RuntimeError(f"cannot load backup tool: {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


bk = _load_tool()

SEED_A = bytes(range(0, 32))  # 00 .. 1f — the first vector's entropy
SEED_B = bytes(range(1, 33))  # 01 .. 20 — the second vector's entropy

PHRASE_FOR_SEED_A = (
    "abandon amount liar amount expire adjust cage candy arch gather drum "
    "bullet absurd math era live bid rhythm alien crouch range attend journey "
    "unaware"
)
PHRASE_FOR_SEED_B = (
    "absurd avoid scissors anxiety gather lottery category door army half "
    "long cage bachelor another expect people blade school educate curtain "
    "scrub monitor lady beyond"
)

# A fixed scalar for the MSE handshake so the test can recompute everything
# the client does. Not a constant anyone should ship; it exists so the
# expected *bytes* can be derived independently of the code under test.
FIXED_HOST_SCALAR = int.from_bytes(
    hashlib.sha256(b"fapico2 backup transcription test").digest(), "big"
)
FIXED_NONCE = b"\xcc" * 12
FIXED_CHANNEL_KEY = b"\xaa" * 32
FIXED_AAD = b"\xbb" * 65

LOAD_HEAD = b"\x41\xa2\x01\x03\x02"  # 0x41 ‖ map(2) ‖ {1: LOAD, 2: params}


@pytest.fixture(scope="module", autouse=True)
def _pin_free_board(resetdevice):
    """The tool rides the tokenless touch path, which exists only PIN-free.

    Earlier files in this suite (`test_010_pin.py` and friends) leave a PIN on
    the shared emulator, and on a PIN-set board the firmware demands a
    pinUvAuthToken for every gated vendor call (AGENTS.md §4) — the gate run
    answered `0x36` where a fresh store answers `0x00`. CTAP2 reset clears the
    PIN (and credentials) but **not** the vendor seed (`reset_from_seed`,
    `device_keystore.rs:2860`), so this costs nothing the backup state depends
    on. This file is the last in the directory; nothing after it needs the PIN
    those files set.
    """
    return resetdevice


@pytest.fixture()
def dev(device):
    """The raw CtapHidDevice behind the session fixture (has .call/.descriptor)."""
    return device.dev


@pytest.fixture()
def fixed_host_key(monkeypatch):
    """Pin the MSE handshake's host key so the test can recompute the channel.

    `ec.generate_private_key` is patched on the *cryptography* module object
    that the tool imported, so the patch is global while it lasts — monkeypatch
    restores it. The emulator holds the session state on its side regardless of
    which host key was used; MSE is last-wins and per-power-cycle.
    """
    key = ec.derive_private_key(FIXED_HOST_SCALAR, ec.SECP256R1())
    monkeypatch.setattr(ec, "generate_private_key", lambda curve: key)
    return key


def _channel_key_independently(host_key, mse_response: bytes) -> tuple[bytes, bytes]:
    """Recompute (channel_key, aad) from the MSE response, without the tool."""
    assert mse_response[0] == 0x00
    value, _rest = cbor.decode_from(mse_response[1:])
    dev_key = value[1]
    device_point = b"\x04" + dev_key[-2] + dev_key[-3]
    z = host_key.exchange(
        ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), device_point)
    )
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=device_point,
    ).derive(z)
    return key, device_point


def _capture_calls(monkeypatch, dev):
    """Record (request, response) pairs through dev.call; undone by monkeypatch."""
    log: list[tuple[bytes, bytes]] = []
    orig = dev.call

    def recording(cmd, data, *a, **kw):
        resp = orig(cmd, data, *a, **kw)
        log.append((bytes(data), bytes(resp)))
        return resp

    monkeypatch.setattr(dev, "call", recording)
    return log


# ---------------------------------------------------------------------------
# STATE / probe
# ---------------------------------------------------------------------------


def test_find_devices_sees_the_emulator_and_reads_state(monkeypatch, dev):
    # The emulator serves ONE HID client; a second connection is answered with
    # "reconnect: cleared session state" and drops the first. The probe must
    # therefore run over the fixture's own connection — list_devices is
    # pointed at it rather than re-enumerating the (already patched) backend.
    monkeypatch.setattr(
        bk.CtapHidDevice, "list_devices", classmethod(lambda cls: [dev])
    )
    devices, _notes = bk.find_devices()
    assert devices, "the emulator must answer the ungated STATE probe"
    _dev, path, state = devices[0]
    assert set(state) == {"sealed", "has_seed", "locked", "unlocked"}
    assert all(isinstance(v, bool) for v in state.values())
    # The harness product name is "Pico-Fido" — inside the family hint.
    assert bk.looks_like_board(bk.product_of(dev))


def test_state_summary_speaks_user_vocabulary():
    open_summary = bk.state_summary({"sealed": False, "has_seed": True, "locked": False, "unlocked": False})
    assert "open" in open_summary and "present" in open_summary
    sealed_summary = bk.state_summary({"sealed": True, "has_seed": True, "locked": False, "unlocked": False})
    assert "CLOSED" in sealed_summary
    locked_summary = bk.state_summary({"sealed": False, "has_seed": False, "locked": True, "unlocked": False})
    assert "engaged" in locked_summary


def test_export_on_a_seedless_board_answers_0x30(dev):
    """EXPORT with nothing to export is refused 0x30 — *when* the store is empty.

    The keystore is wiped by run_tests.sh but not by a bare pytest run, so
    `has_seed` is genuinely nondeterministic here. Skip rather than assert.
    """
    state = bk.read_state(dev)
    if state["has_seed"]:
        pytest.skip("board already has a seed (bare pytest run without a wipe)")
    status, _body = bk._vendor_call(dev, bk.SUB_EXPORT)
    assert status == 0x30


# ---------------------------------------------------------------------------
# BIP-39 — vectors verified against the bip39 2.2.2 crate (picoforge's own
# renderer), both directions.
# ---------------------------------------------------------------------------


def test_seed_to_mnemonic_matches_the_clients_renderer():
    assert bk.seed_to_mnemonic(SEED_A) == PHRASE_FOR_SEED_A
    assert bk.seed_to_mnemonic(SEED_B) == PHRASE_FOR_SEED_B


def test_parse_mnemonic_round_trips_the_same_vectors():
    assert bk.parse_mnemonic(PHRASE_FOR_SEED_A) == SEED_A
    assert bk.parse_mnemonic(PHRASE_FOR_SEED_B) == SEED_B


@pytest.mark.parametrize(
    "bad",
    [
        " ".join(["abandon"] * 23),  # 23 words
        " ".join(["abandon"] * 25),  # 25 words
        "abandon ability able",  # 3 words
        PHRASE_FOR_SEED_A.replace("abandon", "still", 1),  # unknown word first
        PHRASE_FOR_SEED_A.replace("abandon", "zoo", 1),  # unknown word, off-list
        # A checksum breaker: swap one valid word for another valid word.
        PHRASE_FOR_SEED_A.replace("amount", "absurd", 1),
    ],
)
def test_client_side_mnemonic_gates_refuse_before_any_wire(bad):
    with pytest.raises(bk.MnemonicError):
        bk.parse_mnemonic(bad)


def test_mnemonic_gate_tolerates_case_punctuation_and_numbered_cards():
    # The compact numbered-card form the tool strips ordinals for: `1.abandon`.
    # `1. abandon` (with the space) is deliberately NOT a form it accepts —
    # the ordinal strip runs per whitespace-separated token.
    numbered = "\n".join(f"{i + 1}.{w.upper()}," for i, w in enumerate(PHRASE_FOR_SEED_A.split()))
    assert bk.parse_mnemonic(numbered) == SEED_A


# ---------------------------------------------------------------------------
# The seed flows, over the wire.
# ---------------------------------------------------------------------------


def test_restore_export_roundtrip_is_lossless(dev, fixed_host_key):
    bk.restore_seed(dev, SEED_A)
    assert bk.read_state(dev)["has_seed"] is True
    assert bk.export_seed(dev) == SEED_A


def test_load_request_is_a_byte_exact_transcription(monkeypatch, dev, fixed_host_key):
    """The LOAD request is exactly what an independent client computes.

    The expected bytes are derived here from the fixed host key, the MSE
    response and the injected nonce — the tool's own sealing/HKDF code is not
    consulted. The firmware answering `0x00` to those exact bytes is the
    transcription proof; a re-encoded params or a wrong AAD would 0x27.
    """
    log = _capture_calls(monkeypatch, dev)
    bk.restore_seed(dev, SEED_B, nonce=FIXED_NONCE)

    mse = [(req, resp) for req, resp in log if req[:4] == b"\x41\xa2\x01\x01"]
    loads = [(req, resp) for req, resp in log if req[:5] == LOAD_HEAD]
    assert mse, "an MSE request must precede the LOAD"
    assert loads, "the LOAD request must appear on the wire"

    key, aad = _channel_key_independently(fixed_host_key, mse[-1][1])
    blob = FIXED_NONCE + ChaCha20Poly1305(key).encrypt(FIXED_NONCE, SEED_B, aad)
    expected_request = LOAD_HEAD + cbor.encode({1: blob})
    # The firmware accepted exactly these bytes — same length, same tail.
    assert loads[-1][0] == expected_request
    assert loads[-1][1][0] == 0x00
    # Blob framing: nonce(12) ‖ ct(32) ‖ tag(16) under a 0x58 0x3C head.
    assert len(blob) == 60 and blob[:12] == FIXED_NONCE


def test_export_response_opens_independently(monkeypatch, dev, fixed_host_key):
    """EXPORT's sealed blob opens with a key recomputed by the test alone."""
    bk.restore_seed(dev, SEED_A)
    log = _capture_calls(monkeypatch, dev)
    seed = bk.export_seed(dev)
    assert seed == SEED_A
    mse = [(req, resp) for req, resp in log if req[:4] == b"\x41\xa2\x01\x01"]
    key, aad = _channel_key_independently(fixed_host_key, mse[-1][1])
    # EXPORT carries no params: the request head is map-of-1 (`0xA1`), and
    # the response body is `{1: bstr(blob)}` — `0x00` status, then the map.
    exports = [(req, resp) for req, resp in log if req[:4] == b"\x41\xa1\x01\x02"]
    assert exports, "the EXPORT request must appear on the wire"
    value, _rest = cbor.decode_from(exports[-1][1][1:])
    plain = ChaCha20Poly1305(key).decrypt(value[1][:12], value[1][12:], aad)
    assert plain == SEED_A


def test_the_macd_request_builder_is_transcribed_from_the_client():
    """`_build_request`'s token branch: HMAC over the **raw wire** params.

    The tool is touch-only, so this branch never fires in the flows — it is
    kept as executable dialect documentation (the token path is what a PIN
    client would send). Pinned here so it cannot rot silently: the message is
    `FF×32 ‖ 0x41 ‖ sub ‖ cbor(params-as-sent)` truncated to 16 bytes.
    """
    token = bytes(range(32))
    params = {1: b"\x11" * 60}
    params_bytes = cbor.encode(params)
    import hmac as _hmac

    expected_mac = _hmac.new(token, b"\xff" * 32 + b"\x41\x03" + params_bytes, hashlib.sha256).digest()[:16]
    expected = (
        b"\x41\xa4\x01\x03\x02" + params_bytes + b"\x03\x01\x04\x50" + expected_mac
    )
    assert bk._build_request(3, params, token=token) == expected


# ---------------------------------------------------------------------------
# FINALIZE — runs LAST: the export window it closes stays closed for the
# whole pytest session (see the module docstring).
# ---------------------------------------------------------------------------


def test_finalize_permanently_seals_but_load_still_works(dev, fixed_host_key):
    bk.finalize(dev)
    assert bk.read_state(dev)["sealed"] is True

    # EXPORT is now refused 0x30, whatever the store holds.
    with pytest.raises(bk.BackupError) as exc:
        bk.export_seed(dev)
    assert exc.value.status == 0x30

    # LOAD still works: the seed goes in even after the window is closed.
    bk.restore_seed(dev, SEED_B)
    assert bk.read_state(dev)["has_seed"] is True
    assert bk.read_state(dev)["sealed"] is True
