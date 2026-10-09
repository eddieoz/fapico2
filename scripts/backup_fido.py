#!/usr/bin/env python3
"""backup_fido — back up and restore the fapico2 board's vendor master seed as a
24-word BIP-39 phrase.

The board already speaks the whole protocol; this tool is only the client. On
the CTAP2 vendor channel (`0x41`, the RS-Key channel — `apps/fido/src/
vendor_backup.rs`) it drives:

    MSE (1)      ungated ephemeral-ECDH channel establishment
    EXPORT (2)   the 32-byte master seed, sealed under that channel (touch)
    LOAD (3)     install a host-supplied seed (touch)
    FINALIZE (4) permanently close the export window (touch)
    STATE (5)    ungated `{sealed, has_seed, locked, unlocked}`

The wire dialect is picoforge's (../picoforge/src/hal/fido/backup.rs): the
channel key is `HKDF-SHA256(salt=b"", ikm=z, info=device_point, L=32)`, the
AEAD is ChaCha20-Poly1305 with the device's uncompressed point as AAD, and a
blob is `nonce(12) ‖ ct ‖ tag(16)` with a sender-chosen nonce in both
directions. The phrase is plain BIP-39 over the 32-byte seed — `from_entropy`
semantics, no passphrase — so a phrase this tool prints is the same phrase
picoforge renders for the same seed.

# What this tool does NOT do — read before relying on it

The seed this backs up is the board's **vendor** master seed, the one the
`0x41` channel manages (the soft-lock key material and picoforge's Backup
screen). It is **not** the FIDO credential root — passkeys derive from
`device_random` (`device_keystore.rs`, `stateless::master_from_device_random`)
and are non-exportable by design. Restoring a phrase gives a replacement board
its vendor seed; **it does not bring passkeys back**, and no tool can.

# Safety rules this tool enforces on its own

* The phrase travels by **hidden prompt (TTY), stdin piped/redirected, or
  `--file` — never as an argv or environment value**, so it stays out of shell
  history and `/proc/*/cmdline`.
* `export` writes the phrase, and **only** the phrase, to stdout (prose goes to
  stderr), so `backup_fido.py export | pass insert ...` stores exactly the
  words. `--out FILE` writes a 0600 file whose content is the phrase and a
  newline, and refuses to overwrite.
* `restore` validates the BIP-39 checksum client-side **before any wire
  traffic**, confirms before overwriting an existing seed by naming what is
  destroyed, and `restore --generate` installs first and prints the phrase
  only after the install succeeded — no phrase on screen that is not on the
  board.
* `finalize` is permanent and refuses piped/non-TTY runs unless `--yes` is
  passed; on a terminal it requires typing FINALIZE.
* Gated calls print a "touch now" prompt naming the device — without it, a
  tokenless EXPORT/LOAD/FINALIZE looks like a hung terminal until a human
  presses the button on the right board.

# Devices

The CLI probes HID devices with the ungated `STATE` as a **liveness** check —
a probe that cannot by itself identify a board. The firmware answers on VID/PID
`1050:0407`, the Yubico identity, *deliberately*, so VID/PID says nothing and
the product string is only a hint (the shipped build reports "The BLOCO
Community fapico2"; a stored rescue-WRITE can override it). The authoritative
discriminator is the **MSE handshake**: on a device whose `0x41` is the CTAP
2.0 preview credentialManagement command — a YubiKey's reading — the MSE
sub-command maps to a preview-credMgmt sub-command that demands pinUvAuth, so
an unauthenticated MSE there answers an error status rather than a board's
`0x00` plus COSE key, and every mutating command stops there with that message.
(This is reasoned from the client dialects, not measured against a YubiKey —
none was on the bus when this was written; the probe carries no MAC, so no
counter is charged either way.) A lone candidate whose product name lacks
"pico" earns a caution; when more than one device answers at all, the tool
refuses and asks for `--device PATH` instead of guessing.

# Interpreters

Verified on the two generations present on the dev machine (the API surface
used is `CtapHidDevice.call/list_devices`, `fido2.cbor`, `fido2.hid.CTAPHID`,
and PyCA's P-256 / HKDF / ChaCha20-Poly1305):

* the test venv: fido2 2.2.1, cryptography 50.0.1 (what the suites run on);
* system python3: fido2 1.2.0, cryptography 44.0.3.

Both are outside each other's declared ranges; this tool sticks to the surface
they share and changes to it should be checked against both.

Usage:
    backup_fido.py status
    backup_fido.py export [--out FILE]
    backup_fido.py restore [--file F | --generate] [--yes]
    backup_fido.py finalize [--yes]
    backup_fido.py [--device PATH] ...
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import os
import secrets
import sys

import fido2.cbor as cbor
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fido2.hid import CTAPHID, CtapHidDevice

# ---------------------------------------------------------------------------
# Wire constants — the client's own (`picoforge/src/hal/fido/constants.rs`).
# ---------------------------------------------------------------------------

# The RS-Key vendor command: CTAP2 opcode 0x41, payload first byte on the wire.
VENDOR_CMD = 0x41

SUB_MSE = 0x01
SUB_EXPORT = 0x02
SUB_LOAD = 0x03
SUB_FINALIZE = 0x04
SUB_STATE = 0x05

MASTER_SEED_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16

CTAP2_OK = 0x00

# CTAP2 status bytes this channel answers, mapped to what the user should do.
# All verified against apps/fido/src/vendor_backup.rs: 0x30 is EXPORT on a
# sealed OR seedless board (the client's own error table merges the two),
# 0x3B is the presence gate, 0x33/0x34 exist on the token path (this tool is
# touch-only, so seeing them means the command itself went wrong, not a PIN
# attempt), and 0x3D/0x02 both mean the single-slot MSE channel was re-keyed
# or never established — the remediation for both is to re-run the operation.
STATUS_HELP = {
    0x02: "no key-agreement channel — another client talked to the board, or the "
    "handshake was skipped. Re-run the command.",
    0x30: "the export window is closed, or the board has no seed. `status` tells "
    "you which.",
    0x33: "the board rejected the command's authentication. This flow never sends "
    "a PIN token, so no counter was charged by you — this looks like a bug or "
    "another client interfering; retrying is safe.",
    0x34: "PIN authorization is blocked on the board (three bad attempts by some "
    "other PIN-token client). Unlock it by entering the correct PIN with your "
    "FIDO client, then retry.",
    0x36: "the board has a PIN set, and a PIN-set board requires a PIN token for "
    "this command — which this touch-only tool deliberately never asks for. "
    "Use PicoForge (it mints the token), or clear the PIN: a CTAP2 reset "
    "removes the PIN and the passkeys but NOT the vendor seed, so a reset "
    "followed by this tool is lossless for the seed.",
    0x3B: "no touch was detected. Run the command again and press the button on "
    "the named board when prompted.",
    0x3D: "the sealed blob failed to open — the key-agreement channel was re-keyed "
    "by another client mid-operation. Re-run the command.",
}


class BackupError(Exception):
    """A refusal from the board or the tool, with the CTAP2 status if any."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class MnemonicError(ValueError):
    """The phrase is not a valid 24-word BIP-39 phrase for this tool."""


# ---------------------------------------------------------------------------
# The `0x41` wire layer.
#
# The MAC is taken over the RAW WIRE BYTES of `subCommandParams`
# (`vendor41::verify_mac` captures a span, deliberately), so the params value
# is encoded exactly once and spliced verbatim into the outer map — decoding
# and re-encoding it would produce different bytes and fail with 0x33. The
# token path is not used by this tool (it is touch-only; PIN-token flows are
# picoforge's), but `_build_request` carries it because it is the executable
# form of the dialect, and test_093 pins the construction byte-exactly.
# ---------------------------------------------------------------------------


def _vendor_mac(token: bytes, sub: int, params_bytes: bytes) -> bytes:
    """`HMAC-SHA256(token, 0xFF*32 ‖ 0x41 ‖ sub ‖ cbor(params))[:16]`."""
    message = b"\xff" * 32 + bytes([VENDOR_CMD, sub]) + params_bytes
    return hmac.new(token, message, hashlib.sha256).digest()[:16]


def _build_request(sub: int, params: dict | None, token: bytes | None = None) -> bytes:
    """Assemble `0x41 ‖ cbor({1: sub, 2: params?, 3: 1, 4: mac?})` by hand.

    Token-less requests carry only `{1: sub, 2: params?}` — that is the touch
    path, and the firmware refuses a token-less request that *declares* auth
    fields it cannot verify. `sub` values 1..5 serialize as single-byte CBOR
    unsigneds, and the 16-byte MAC as a definite-length bstr (`0x50`), which
    is why the heads can be assembled directly.
    """
    params_bytes = cbor.encode(params) if params is not None else b""
    pairs: list[bytes] = [b"\x01", bytes([sub])]
    if params is not None:
        pairs += [b"\x02", params_bytes]
    if token is not None:
        pairs += [b"\x03", b"\x01", b"\x04", b"\x50" + _vendor_mac(token, sub, params_bytes)]
    head = bytes([0xA0 | len(pairs) // 2])
    return bytes([VENDOR_CMD]) + head + b"".join(pairs)


def _vendor_call(dev, sub: int, params: dict | None = None) -> tuple[int, bytes]:
    """Send an ungated (touch-fallback) `0x41` request; return (status, body).

    `dev.call` blocks on CTAPHID keepalives while the board's presence window
    is open, so a touch-gated request simply waits for the human.
    """
    reply = dev.call(CTAPHID.CBOR, _build_request(sub, params))
    if not reply:
        raise BackupError("empty response from the board")
    return reply[0], reply[1:]


# ---------------------------------------------------------------------------
# STATE (5) — ungated, and the device probe.
# ---------------------------------------------------------------------------


def read_state(dev) -> dict[str, bool]:
    """`STATE`: `{1: sealed, 2: has_seed, 3: locked, 4: unlocked}`."""
    status, body = _vendor_call(dev, SUB_STATE)
    if status != CTAP2_OK:
        raise BackupError(f"STATE answered 0x{status:02X}", status)
    value, _rest = cbor.decode_from(body)
    if not isinstance(value, dict):
        raise BackupError("STATE response is not a CBOR map")
    return {
        "sealed": bool(value.get(1, False)),
        "has_seed": bool(value.get(2, False)),
        "locked": bool(value.get(3, False)),
        "unlocked": bool(value.get(4, False)),
    }


def state_summary(state: dict[str, bool]) -> str:
    """The flags in the user's vocabulary, not the protocol's.

    `unlocked` is omitted on purpose: the CLI cannot unlock (that is
    PicoForge's lock-release screen) and the field reads as a problem after
    every power cycle when no lock is engaged.
    """
    lines = [
        f"  seed:          {'present' if state['has_seed'] else 'absent'}",
        f"  export window: {'CLOSED' if state['sealed'] else 'open'}",
        f"  lock:          {'engaged' if state['locked'] else 'not engaged'}",
    ]
    if state["locked"]:
        lines.append(
            "  (a locked board is released from PicoForge's Lock screen; this "
            "tool cannot unlock it)"
        )
    return "\n".join(lines)


def product_of(dev) -> str | None:
    """The HID descriptor's product string, or None.

    `fapico2` builds as *"The BLOCO Community fapico2"* (`platform/src/usb.rs`)
    and the emulator harness reports *"Pico-Fido"* (`tests/harness/hid_emul.py`),
    so a "pico" substring covers both. It is a **hint, not a gate**: the stored
    product name is overridable at enumeration, and a renamed board must not be
    locked out.
    """
    return getattr(getattr(dev, "descriptor", None), "product_name", None)


def looks_like_board(product: str | None) -> bool:
    return product is None or "pico" in product.lower()


def find_devices(want_path: str | None = None):
    """Probe HID devices with ungated STATE; return the boards that answer.

    Returns `(devices, notes)` — the answering boards as `(dev, path, state)`
    triples, and a line per board that was seen but did not answer.

    **STATE is a liveness probe only, and the board makes it an imperfect
    one on purpose:** the firmware answers `0x41` on VID/PID `1050:0407`,
    the Yubico identity, so VID/PID cannot discriminate anything, and
    anything that speaks CTAPHID is worth probing. The *authoritative*
    check is the MSE handshake — on this channel a non-board's `0x41` is
    preview credentialManagement, whose sub-commands demand pinUvAuth
    and answer an error where a board answers `0x00` with a COSE key —
    so every mutating command fails fast there (see `_mse_handshake`).
    A product name without "pico" in it earns a caution, not a refusal.
    """
    devices = []
    notes = []
    try:
        candidates = list(CtapHidDevice.list_devices())
    except OSError as exc:
        return [], [f"could not enumerate HID devices ({exc})"]
    for dev in candidates:
        path = str(getattr(dev.descriptor, "path", None))
        if want_path is not None and path != want_path:
            continue
        try:
            state = read_state(dev)
        except BackupError as exc:
            notes.append(f"  {path or '(no path)'}: no answer ({exc})")
            continue
        except OSError as exc:
            notes.append(f"  {path or '(no path)'}: could not open ({exc})")
            continue
        if not looks_like_board(product_of(dev)):
            notes.append(
                f"  {path}: identifies as '{product_of(dev)}' — not a "
                "fapico2-family product name; picked only if that is your board"
            )
        devices.append((dev, path, state))
    return devices, notes


# ---------------------------------------------------------------------------
# MSE (1) — the ephemeral-ECDH channel.
# ---------------------------------------------------------------------------


def _mse_handshake(dev) -> tuple[bytes, bytes]:
    """Run MSE; return (channel_key, aad) — aad is the device's 65-byte point.

    The response's COSE key is parsed **by label, never positionally** (the
    firmware emits the map in the client's BTreeMap order, `-3, -2, -1, 1, 3`),
    and each coordinate must be a 32-byte string.
    """
    host_key = ec.generate_private_key(ec.SECP256R1())
    pub = host_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    cose = {1: 2, 3: -25, -1: 1, -2: pub[1:33], -3: pub[33:65]}
    status, body = _vendor_call(dev, SUB_MSE, {1: cose})
    if status != CTAP2_OK:
        raise BackupError(
            f"MSE answered 0x{status:02X} — this does not look like a "
            "fapico2 board (is the device a YubiKey or another FIDO key that "
            "reads 0x41 as credentialManagement?)",
            status,
        )
    value, _rest = cbor.decode_from(body)
    if not isinstance(value, dict) or not isinstance(value.get(1), dict):
        raise BackupError(
            "MSE response has no device COSE key — this does not look like "
            "a fapico2 board's MSE answer"
        )
    dev_key = value[1]
    x, y = dev_key.get(-2), dev_key.get(-3)
    if not (isinstance(x, bytes) and len(x) == 32 and isinstance(y, bytes) and len(y) == 32):
        raise BackupError(
            "MSE device key is not a well-formed P-256 point — this does not "
            "look like a fapico2 board's MSE answer"
        )
    device_point = b"\x04" + x + y
    z = host_key.exchange(
        ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), device_point)
    )
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=MASTER_SEED_LEN,
        salt=b"",
        info=device_point,
    ).derive(z)
    return key, device_point


# ---------------------------------------------------------------------------
# The AEAD — `nonce(12) ‖ ct ‖ tag(16)`, AAD = the device's point.
# ---------------------------------------------------------------------------


def _open_seed(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise BackupError("sealed blob is too short to hold a nonce and tag")
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    try:
        plain = ChaCha20Poly1305(key).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        raise BackupError("the sealed seed failed to authenticate") from exc
    if len(plain) != MASTER_SEED_LEN:
        raise BackupError(f"exported seed is {len(plain)} bytes, expected 32")
    return plain


def _seal_blob(key: bytes, seed: bytes, aad: bytes, nonce: bytes | None = None):
    """Seal the seed; return (blob, nonce). `nonce` is injectable for tests."""
    if nonce is None:
        nonce = secrets.token_bytes(NONCE_LEN)
    ct = ChaCha20Poly1305(key).encrypt(nonce, seed, aad)
    return nonce + ct, nonce


# ---------------------------------------------------------------------------
# BIP-39 — `from_entropy` semantics, no passphrase. The wordlist is the file
# beside this script (provenance in its header); correctness is pinned by
# published vectors in tests/pico-fido/test_093_backup.py, both directions.
# ---------------------------------------------------------------------------

BIP39_ENGLISH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bip39_english.txt")
_WORDLIST_CACHE: list[str] | None = None


def load_wordlist(path: str | None = None) -> list[str]:
    global _WORDLIST_CACHE
    if path is not None:
        return _read_wordlist(path)
    if _WORDLIST_CACHE is None:
        _WORDLIST_CACHE = _read_wordlist(BIP39_ENGLISH)
    return _WORDLIST_CACHE


def _read_wordlist(path: str) -> list[str]:
    words = [
        line.strip()
        for line in open(path, encoding="utf-8")
        if line.strip() and not line.strip().startswith("#")
    ]
    if len(words) != 2048 or len(set(words)) != 2048:
        raise MnemonicError(f"wordlist has {len(words)} entries, expected 2048 unique")
    return words


def seed_to_mnemonic(seed: bytes, wordlist: list[str] | None = None) -> str:
    """32 bytes → 24 words. The checksum is SHA-256's first 8 bits.

    BIP-39 takes `CS = ENT/32` bits of `SHA256(entropy)` — for 256-bit
    entropy that is the digest's entire first byte, so the shift here is
    none on purpose: a `>> 24` would take the top two bits of a byte and
    make every checksum look correct.
    """
    if len(seed) != MASTER_SEED_LEN:
        raise MnemonicError(f"seed is {len(seed)} bytes, expected 32")
    wl = wordlist or load_wordlist()
    bits = "".join(f"{b:08b}" for b in seed)
    checksum = hashlib.sha256(seed).digest()[0]
    bits += f"{checksum:08b}"
    return " ".join(wl[int(bits[i * 11 : (i + 1) * 11], 2)] for i in range(24))


def parse_mnemonic(text: str, wordlist: list[str] | None = None) -> bytes:
    """A pasted/transcribed phrase → its 32 bytes of entropy.

    Tolerates what a human actually produces: a BOM (password-manager
    export), any whitespace (tabs, several spaces), upper case (the wordlist
    is lowercase-only), trailing punctuation, and a compact numbered paper
    card (`1.abandon 2.ability …` — the ordinal only strips when it is glued
    to the word; a spaced-out numbering produces 48 tokens and is refused
    with a length error, deliberately, because half of it being lost would
    be worse). Errors name the offending position and word and never echo
    the phrase back.
    """
    wl = wordlist or load_wordlist()
    tokens = [t.casefold().strip(".,;:!?") for t in text.replace("\ufeff", "").split()]
    tokens = [_strip_ordinal(t) for t in tokens]
    if not tokens:
        raise MnemonicError("no words given")
    if len(tokens) != 24:
        raise MnemonicError(
            f"{len(tokens)} words given — this tool handles the 24-word phrase "
            "this board exports"
        )
    for position, token in enumerate(tokens, start=1):
        if token not in wl:
            raise MnemonicError(
                f"word {position} '{token}' is not in the BIP-39 wordlist — "
                "check punctuation and spelling"
            )
    indices = [wl.index(t) for t in tokens]
    bits = "".join(f"{i:011b}" for i in indices)
    entropy = bytes(int(bits[i * 8 : (i + 1) * 8], 2) for i in range(32))
    checksum = int(bits[256:264], 2)
    if checksum != hashlib.sha256(entropy).digest()[0]:
        raise MnemonicError(
            "checksum mismatch — at least one word is wrong (or mistyped); "
            "the phrase is not valid BIP-39"
        )
    return entropy


def _strip_ordinal(token: str) -> str:
    """`1.abandon` → `abandon`; a bare `1.` is left alone to fail loudly."""
    head, sep, tail = token.partition(".")
    if sep and head.isdigit() and tail:
        return tail
    return token


# ---------------------------------------------------------------------------
# The four flows. `touch_prompt` is called before every gated wire command so
# the CLI can put "Touch the button on … now" on the user's stderr — without
# it a tokenless request reads as a hung terminal until a human acts.
# ---------------------------------------------------------------------------


def export_seed(dev, touch_prompt=lambda: None) -> bytes:
    """MSE + EXPORT → the 32-byte seed. Raises BackupError with the status."""
    touch_prompt()
    key, aad = _mse_handshake(dev)
    status, body = _vendor_call(dev, SUB_EXPORT)
    if status != CTAP2_OK:
        raise BackupError(f"EXPORT answered 0x{status:02X}", status)
    value, _rest = cbor.decode_from(body)
    if not isinstance(value, dict) or not isinstance(value.get(1), bytes):
        raise BackupError("EXPORT response has no sealed seed")
    return _open_seed(key, value[1], aad)


def restore_seed(dev, seed: bytes, touch_prompt=lambda: None, nonce: bytes | None = None) -> None:
    """MSE + LOAD. Installs the seed; works even on a sealed board."""
    touch_prompt()
    key, aad = _mse_handshake(dev)
    blob, _ = _seal_blob(key, seed, aad, nonce)
    status, _body = _vendor_call(dev, SUB_LOAD, {1: blob})
    if status != CTAP2_OK:
        raise BackupError(f"LOAD answered 0x{status:02X}", status)


def finalize(dev, touch_prompt=lambda: None) -> None:
    """FINALIZE. Permanently closes the export window; idempotent on the board."""
    touch_prompt()
    status, _body = _vendor_call(dev, SUB_FINALIZE)
    if status != CTAP2_OK:
        raise BackupError(f"FINALIZE answered 0x{status:02X}", status)


def generate_seed() -> bytes:
    """32 bytes from the OS CSPRNG — the `--generate` provisioning path."""
    return secrets.token_bytes(MASTER_SEED_LEN)


# ---------------------------------------------------------------------------
# CLI. Rule of surface: stdout carries the phrase and only the phrase; every
# word a human reads goes to stderr.
# ---------------------------------------------------------------------------


def _prose(message: str) -> None:
    print(message, file=sys.stderr)


def _is_tty() -> bool:
    return sys.stdin.isatty()


def _confirm(token: str, question: str, assume_yes: bool) -> bool:
    """`--yes` is the only non-interactive path: piped stdin does NOT confirm."""
    if assume_yes:
        return True
    if not _is_tty():
        _prose("refusing to proceed without a terminal (piped stdin) — pass --yes to force")
        return False
    answer = input(f"{question} Type {token} to proceed: ").strip()
    return answer == token


def _read_phrase(file=None) -> str:
    """The phrase enters by hidden prompt, stdin, or --file — never argv."""
    if file is not None:
        with open(file, encoding="utf-8") as f:
            return f.read()
    if _is_tty():
        return getpass.getpass("Enter the 24-word phrase (hidden input): ")
    return sys.stdin.readline()


def _touch_prompt_for(path: str):
    def prompt():
        _prose(f"Touch the button on the fapico2 board at {path} now…")

    return prompt


def _select_device(want_path: str | None):
    devices, notes = find_devices(want_path)
    for note in notes:
        _prose(note)
    if want_path is not None:
        matching = [d for d in devices if d[1] == want_path]
        if not matching:
            _prose(f"no board answering at {want_path}.")
            raise BackupError("no board found")
        dev, path, _state = matching[0]
    elif not devices:
        _prose(
            "no fapico2 board found. Checklist:\n"
            "  - is it plugged in?\n"
            "  - do the udev rules apply (a stock Ubuntu host binds only "
            "2E8A:10FF — see scripts/fix_usb_identity.py)?\n"
            "  - close Yubico Authenticator / ykman (exclusive HID open)"
        )
        raise BackupError("no board found")
    elif len(devices) > 1:
        _prose("more than one board answers — pick one with --device PATH:")
        for _dev, path, state in devices:
            _prose(f"  {path} (product: {product_of(_dev) or 'unknown'}):")
            _prose("\n".join("  " + line for line in state_summary(state).splitlines()))
        raise BackupError("several boards answer; --device PATH is required")
    else:
        dev, path, _state = devices[0]
    product = product_of(dev)
    _prose(
        f"using board at {path}"
        + (f" (product: {product})" if product else "")
    )
    return dev, path


def cmd_status(args) -> int:
    dev, path = _select_device(args.device)
    product = product_of(dev)
    _prose(f"board at {path} (product: {product or 'unknown'}):")
    state = read_state(dev)
    _prose(state_summary(state))
    if not looks_like_board(product):
        _prose(
            "caution: this device does not identify as a fapico2-family "
            "board. STATE is only a liveness probe — if this is a YubiKey or "
            "another authenticator, these values are meaningless."
        )
    if state["has_seed"] and not state["sealed"]:
        _prose(
            "the seed on this board can still be exported by anyone who gets "
            "hold of it — run finalize when you are done."
        )
    return 0


def cmd_export(args) -> int:
    dev, path = _select_device(args.device)
    state = read_state(dev)
    if not state["has_seed"]:
        _prose("this board has no seed to export. Provision one with `restore --generate`.")
        return 1
    if state["sealed"]:
        _prose(
            "this board's export window is permanently closed — the seed cannot "
            "be exported again. Restore the phrase onto a replacement board instead."
        )
        return 1
    seed = export_seed(dev, _touch_prompt_for(path))
    phrase = seed_to_mnemonic(seed)
    if args.out:
        if os.path.exists(args.out):
            _prose(f"refusing to overwrite existing {args.out}")
            return 1
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(phrase + "\n")
        _prose(f"24 words written to {args.out} (permissions 0600). Write them on paper as well.")
    else:
        print(phrase)
    _prose(
        "Anyone holding this phrase holds the seed. Store it offline.\n"
        "The export window is still open — run `finalize` to close it for good."
    )
    return 0


def cmd_restore(args) -> int:
    if args.generate:
        seed = generate_seed()
        phrase = seed_to_mnemonic(seed)
        _prose("A fresh phrase was drawn from the OS random generator.")
    else:
        try:
            seed = parse_mnemonic(_read_phrase(args.file))
        except MnemonicError as exc:
            _prose(f"not a valid phrase: {exc}")
            return 2
        phrase = None
    dev, path = _select_device(args.device)
    state = read_state(dev)
    if state["has_seed"]:
        _prose(
            "This board already has a seed. Restoring replaces it PERMANENTLY: "
            "the current seed cannot be recovered unless you have ITS 24-word "
            "phrase — this tool cannot read it back for you, and it may be sealed."
        )
        if not _confirm("RESTORE", "Replace the seed on this board?", args.yes):
            return 1
    if state["sealed"]:
        _prose(
            "Note: this board's export window is closed, so the seed you are "
            "installing can never be exported from it again — this phrase will "
            "be its only copy."
        )
    restore_seed(dev, seed, _touch_prompt_for(path))
    after = read_state(dev)
    _prose("Seed installed. Board now reports:")
    _prose(state_summary(after))
    if args.generate:
        print(phrase)
    _prose(
        "Reminder: CTAP2 reset does NOT clear this seed — `finalize`, not "
        "reset, is what closes the export door before you hand the board over."
    )
    return 0


def cmd_finalize(args) -> int:
    dev, path = _select_device(args.device)
    state = read_state(dev)
    if state["sealed"]:
        _prose("The export window on this board is already closed. Nothing to do.")
        return 0
    if not _confirm(
        "FINALIZE",
        "Close the export window on this board permanently? Nothing is erased, "
        "but the seed can never be exported again.",
        args.yes,
    ):
        return 1
    finalize(dev, _touch_prompt_for(path))
    _prose(
        "The export window on this board is now closed forever. Nothing was "
        "erased — the seed and all passkeys remain on the board. Any copy of "
        "the 24-word phrase, on paper or elsewhere, remains a full working "
        "key forever."
    )
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="backup_fido.py",
        description=(
            "Back up / restore the fapico2 board's vendor master seed as a "
            "24-word BIP-39 phrase."
        ),
    )
    parser.add_argument("--device", help="select a board by HID path (required when several answer)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="read the board's seed state (no touch, no PIN)")

    export_parser = sub.add_parser("export", help="print the seed as 24 words (touch)")
    export_parser.add_argument(
        "--out", metavar="FILE", help="write the phrase to FILE (0600) instead of stdout"
    )

    restore_parser = sub.add_parser("restore", help="install a seed from a phrase (touch)")
    restore_parser.add_argument(
        "--file", metavar="F", help="read the phrase from a file instead of the prompt/stdin"
    )
    restore_parser.add_argument(
        "--generate", action="store_true", help="draw a fresh seed, install it, print its phrase"
    )
    restore_parser.add_argument("--yes", action="store_true", help="skip the overwrite confirmation")

    finalize_parser = sub.add_parser("finalize", help="permanently close the export window (touch)")
    finalize_parser.add_argument("--yes", action="store_true", help="skip the typed confirmation")

    args = parser.parse_args(argv)
    try:
        return {
            "status": cmd_status,
            "export": cmd_export,
            "restore": cmd_restore,
            "finalize": cmd_finalize,
        }[args.command](args)
    except BackupError as exc:
        _prose(f"error: {exc}")
        if exc.status is not None:
            _prose(STATUS_HELP.get(exc.status, f"status 0x{exc.status:02X}"))
        return 1
    except KeyboardInterrupt:
        _prose("\naborted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
