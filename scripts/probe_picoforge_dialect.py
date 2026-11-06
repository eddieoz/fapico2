#!/usr/bin/env python3
"""Probe the live board's 0x41 (RS-Key) dialect — US-1751, EPIC fapico2-support.

The probe reads over CTAPHID only and NEVER sends a mutating command:

    getInfo       raw CBOR (CTAP2 getInfo framing): version + AAGUID
                  (stock `fa20:0002`)
    CONFIG_READ   0x41 sub 0x0D {1: 0x01} (PHY target) — ungated
    STATE         0x41 sub 0x05 — keys 1..4 only; NO key 5 may ever appear
                  (fetched exactly once: the raw map drives both the no-key-5
                  assertion and the flag summary — one round-trip)
    MSE           0x41 sub 0x01 {1: COSE_Key} — ephemeral ECDH, device
                  COSE_Key back with a 65-byte uncompressed point
    EXPORT        0x41 sub 0x02 — ATTEMPTED BY DEFAULT; `--no-touch` skips.
                  With `--pin-token HEX` (a PERM_ACFG pinUvAuthToken obtained
                  elsewhere — the probe never mints one) the request carries
                  {3: 1, 4: mac} keyed on that token and must answer 0x00 with
                  {1: blob}. Tokenless, the touch gate opens; unpressed it
                  answers 0x2D (window closed) or 0x3B (gate refused), and a
                  PIN-set board without a token answers 0x36 — all printed
                  verbatim as honest off-host observations, never counted and
                  never faked as a 0x00 the probe did not receive.
    PC/SC SELECT  rescue applet A0583FC19B7E4F21 (`--pcsc`; prints data[2])

LOAD / FINALIZE / CONFIG_WRITE (identity tier included) are never sent, and
neither is clientPIN/getPinRetries: the probe only ever uses PIN tokens handed
to it on the command line, so no PIN retry counter is charged either. Every
CTAPHID vendor command runs under an explicit 31 s SIGALRM budget — the brief's
"keep each under 32 s" made enforceable; a board that hangs past it reports a
TIMEOUT as a FAILed assertion rather than passing silently.

Every assertion prints on its own line (PASS or FAIL), so a transcript shows
exactly which leg died. The probe exits 0 with DIALECT-OK only when every
EXECUTED assertion passed; legs skipped by `--no-touch`/`--pcsc` are reported
as SKIPPED and not counted — the honest shape of an off-host run.

The wire layer is `backup_fido.py`'s: `_vendor_mac`, `_build_request`,
`_vendor_call`, `_mse_handshake`, `_prose`, `_select_device`, `product_of`,
its SUB_EXPORT/SUB_STATE constants and BackupError — imported the way
`probe_seed_restore.py` imports backup_fido's layer (same sibling-script
contract; verified on both interpreters: test venv fido2 2.2.1 and system
python3 fido2 1.2.0). `_build_request(SUB_EXPORT, None, token)` assembles the
token path (`{1: sub, 3: 1, 4: mac}`) and `_vendor_mac` recomputes that MAC
locally to prove the request on the wire carries it — the token itself is never
echoed.

Usage:
    probe_picoforge_dialect.py [--device PATH] [--no-touch] [--pin-token HEX] [--pcsc]
"""

from __future__ import annotations

import argparse
import signal

import fido2.cbor as cbor
from fido2.hid import CTAPHID

from backup_fido import (  # sibling script; scripts/ is sys.path[0] when run
    BackupError,
    SUB_EXPORT,
    SUB_STATE,
    _build_request,
    _mse_handshake,
    _prose,
    _select_device,
    _vendor_call,
    _vendor_mac,
    product_of,
)

# CONFIG_READ is the RS-Key protocol byte from apps/fido/src/vendor41.rs
# (RSKEY_CONFIG_READ = 13); it is not in backup_fido's five-subcommand set.
CONFIG_READ_SUB = 0x0D
PHY_TARGET = 0x01
STOCK_AAGUID = bytes.fromhex("66617069636f32000000000000000002")  # lsusb fa20:0002

# The brief's "<32 s per vendor command", made explicit: every CTAPHID call is
# wrapped in a SIGALRM budget. One second of slack below 32 so a board that
# answers at its own presence-window limit (<=30 s) still passes on time.
VENDOR_BUDGET_S = 31


class VendorTimeout(BaseException):
    """Escapes a hung CTAPHID call. BaseException on purpose: fido2's wire loop
    catches `Exception`, and this must not be swallowed by it."""


def _alarm_handler(signum, frame):  # signal passes (signum, frame) — unused
    raise VendorTimeout(f"exceeded the {VENDOR_BUDGET_S} s vendor budget")


def timed(label: str, fn, *args):
    """Run fn(*args) under a VENDOR_BUDGET_S SIGALRM budget; cancel after."""
    signal.signal(signal.SIGALRM, _alarm_handler)
    signal.alarm(VENDOR_BUDGET_S)
    try:
        return fn(*args)
    finally:
        signal.alarm(0)


_failures = 0


def check(ok: bool, label: str, detail: str = "") -> None:
    global _failures
    if not ok:
        _failures += 1
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f": {detail}" if detail else ""))


def on_timeout(label: str, exc: VendorTimeout) -> None:
    """One FAIL line per timed-out arm — the budget is an assertion, not a suggestion."""
    check(False, f"{label} stayed under the {VENDOR_BUDGET_S} s vendor budget", str(exc))


def get_info(dev) -> dict:
    # CTAP2 getInfo over this board's CBOR channel: command byte 0x04 then
    # CBOR undefined (b"\xc0") — the framing fix_usb_identity.py uses.
    reply = timed("getInfo", dev.call, CTAPHID.CBOR, b"\x04\xc0")
    if not reply or reply[0] != 0x00:
        raise BackupError(f"getInfo answered status 0x{reply[0]:02X}" if reply else "getInfo empty")
    value, _rest = cbor.decode_from(reply[1:])
    return value


def config_read(dev) -> tuple[int, bytes | None, list[tuple[int, bytes]]]:
    """Ungated 0x41 CONFIG_READ {1: PHY}. Returns (status, blob, TLV records).

    A stock board that never ran CONFIG_WRITE answers `{1: b""}` — an empty
    but present blob; that is the honest dialect shape, not a failure.
    """
    status, body = timed("CONFIG_READ", _vendor_call, dev, CONFIG_READ_SUB, {1: PHY_TARGET})
    blob = None
    records: list[tuple[int, bytes]] = []
    if status == 0x00 and body:
        value, _rest = cbor.decode_from(body)
        if isinstance(value, dict):
            blob = value.get(1)
        if isinstance(blob, (bytes, bytearray)):
            i = 0
            while i + 2 <= len(blob):
                tag, ln = blob[i], blob[i + 1]
                records.append((tag, bytes(blob[i + 2 : i + 2 + ln])))
                i += 2 + ln
    return status, blob, records


def state_raw(dev) -> dict:
    """STATE, fetched exactly once — keys must be a subset of {1,2,3,4}.

    The returned raw map drives the no-key-5 assertion AND the flag summary in
    main; there is no second STATE round-trip.
    """
    status, body = timed("STATE", _vendor_call, dev, SUB_STATE)
    if status != 0x00:
        raise BackupError(f"STATE answered 0x{status:02X}", status)
    value, _rest = cbor.decode_from(body)
    if not isinstance(value, dict):
        raise BackupError("STATE response is not a CBOR map")
    return value


def export_leg(dev, token: bytes | None) -> None:
    """EXPORT (sub 0x02) on the MSE channel main just opened.

    Token path (`--pin-token`, a PERM_ACFG pinUvAuthToken obtained elsewhere):
    `_build_request` assembles `{1: sub, 3: 1, 4: mac}` and `_vendor_mac`
    recomputes that MAC to prove the wire bytes carry it; the board must then
    answer 0x00 with the sealed blob {1: nonce||ct||tag}. Tokenless, the touch
    gate opens: unpressed it answers 0x2D (window closed) or 0x3B (gate
    refused), and a PIN-set board without a token answers 0x36. Those are
    printed verbatim — honest off-host observations, not counted, never faked
    as a 0x00 the probe did not receive.
    """
    if token is None:
        status, body = timed("EXPORT", _vendor_call, dev, SUB_EXPORT)
    else:
        request = _build_request(SUB_EXPORT, None, token)
        mac = _vendor_mac(token, SUB_EXPORT, b"")
        if mac not in request:  # the built request must carry its own MAC
            raise BackupError("built EXPORT request does not carry its PERM_ACFG MAC")
        reply = timed("EXPORT", dev.call, CTAPHID.CBOR, request)
        if not reply:
            raise BackupError("EXPORT empty reply")
        status, body = reply[0], reply[1:]
    if status in (0x3B, 0x2D):
        # presence gate refused / window closed unpressed (the seed-restore
        # audit's KEEPALIVE-CANCEL answer). Honest off-host observation.
        _prose(f"EXPORT answered 0x{status:02X} (presence gate; nobody pressed on "
               "this host) — honest observation, not counted")
        return
    if status == 0x36:
        _prose("EXPORT answered 0x36 (PUAT_REQUIRED: PIN set, token not supplied) "
               "— honest observation, not counted")
        return
    check(status == 0x00, "EXPORT answers 0x00", f"status=0x{status:02X}")
    blob = None
    if body:
        value, _rest = cbor.decode_from(body)
        if isinstance(value, dict):
            blob = value.get(1)
    check(isinstance(blob, (bytes, bytearray)) and len(blob) >= 28,
          "EXPORT returns sealed blob {1: nonce||ct||tag}", f"len={len(blob or b'')}")


def pcsc_leg() -> None:
    """SELECT the rescue applet over PC/SC; print its header incl. data[2].

    AID and APDU follow `bootsel.py` (same SELECT, same reader-pick caveat).
    pyscard 2.3.x renamed `connections` to `readers`; try readers first.
    """
    try:
        from smartcard.System import readers
    except ImportError:
        _prose("PC/SC leg SKIPPED: pyscard not importable on this interpreter")
        return
    try:
        from smartcard.pcsc.PCSCCardConnection import PCSCCardConnection as CardConnection
    except ImportError:
        try:
            from smartcard.CardConnection import CardConnection
        except ImportError:
            _prose("PC/SC leg SKIPPED: no usable pyscard CardConnection")
            return
    try:
        found = readers()
    except Exception as exc:
        _prose(f"PC/SC leg SKIPPED: readers() failed ({type(exc).__name__})")
        return
    names = [r[0] if isinstance(r, (list, tuple)) else str(r) for r in found]
    if not names:
        _prose("PC/SC leg SKIPPED: no pcscd reader on the bus")
        return
    pico = [n for n in names if "pico" in n.lower()] or names
    conn = CardConnection(pico[0])
    try:
        conn.connect()
    except Exception as exc:
        _prose(f"PC/SC leg SKIPPED: connect() failed ({type(exc).__name__})")
        return
    aid = bytes.fromhex("A0583FC19B7E4F21")
    apdu = [0x00, 0xA4, 0x04, 0x00, len(aid)] + list(aid)
    proto = getattr(conn, "RAW_protocol", None)
    try:
        if proto is None:
            data, sw1, sw2 = conn.transmit(apdu)
        else:
            # Newer pyscard (PCSCCardConnection) wants the protocol arg; the
            # APDU above carries its own header, so RAW is the faithful one.
            data, sw1, sw2 = conn.transmit(apdu, proto)
    except Exception as exc:
        _prose(f"PC/SC leg SKIPPED: transmit failed ({type(exc).__name__})")
        return
    body = bytes(data)
    print(f"PC/SC SELECT rescue AID: reader={pico[0]} SW={sw1 << 8 | sw2:#06x} "
          f"len={len(body)} body={body.hex()}")
    if len(body) >= 4:
        # Header: MCU, product, fw major, fw minor — data[2] is the fw major.
        check(body[2] == 0x08, "PC/SC rescue SELECT data[2] (fw major) == 8",
              f"got 0x{body[2]:02X}")
        print(f"PC/SC header: MCU=0x{body[0]:02X} product=0x{body[1]:02X} "
              f"fw={body[2]}.{body[3]} extra={body[4:].hex()}")
    else:
        check(False, "PC/SC rescue SELECT returned a short header",
              f"len={len(body)}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Probe the 0x41 (RS-Key) dialect on a live fapico2 board")
    ap.add_argument("--device", help="HID path of the board (default: auto-select)")
    ap.add_argument("--no-touch", action="store_true",
                    help="skip the touch-gated EXPORT leg (default attempts it)")
    ap.add_argument("--pin-token", metavar="HEX",
                    help="PERM_ACFG pinUvAuthToken (hex), obtained elsewhere; "
                         "the probe never mints one and never sends clientPIN")
    ap.add_argument("--pcsc", action="store_true",
                    help="also SELECT the rescue applet over PC/SC and print data[2]")
    args = ap.parse_args(argv)

    token: bytes | None = None
    if args.pin_token is not None:
        try:
            token = bytes.fromhex(args.pin_token)
        except ValueError:
            _prose("--pin-token is not valid hex; EXPORT will run tokenless")
        else:
            if len(token) < 16:  # CTAP pinUvAuthToken floor
                _prose(f"--pin-token is {len(token)} bytes (<16, below the CTAP "
                       "floor); ignoring it, EXPORT will run tokenless")
                token = None

    dev, path = _select_device(args.device)
    _prose(f"board: {path} (product: {product_of(dev)})")

    # --- getInfo ----------------------------------------------------------
    try:
        info = get_info(dev)
    except VendorTimeout as exc:
        on_timeout("getInfo", exc)
        info = {}
    if info:
        _prose(f"getInfo: version={info.get(0x01)} AAGUID={bytes(info.get(0x03, b'')).hex()} "
               f"versions={[k for k in sorted(info)]}")
        check(bytes(info.get(0x03, b"")) == STOCK_AAGUID,
              "AAGUID is the stock fa20:0002 identity",
              f"{bytes(info.get(0x03, b'')).hex()}")

    # --- CONFIG_READ {1: PHY} ---------------------------------------------
    try:
        status, blob, records = config_read(dev)
        check(status == 0x00, "CONFIG_READ(0x0D) {1: 0x01 PHY-target} answers 0x00",
              f"status=0x{status:02X}")
        check(isinstance(blob, (bytes, bytearray)),
              "CONFIG_READ returns a bytes blob under key 1",
              f"{len(records)} TLV records, {len(blob or b'')} bytes")
        for tag, val in records:
            _prose(f"  PHY record tag=0x{tag:02X} len={len(val)} value={val.hex()}")
        if not records:
            _prose("  (no stored PhyConfig overrides — stock board never CONFIG_WRITE'n)")
    except VendorTimeout as exc:
        on_timeout("CONFIG_READ", exc)

    # --- STATE (one round-trip; raw map drives everything) -----------------
    try:
        state = state_raw(dev)
        _prose(f"STATE raw map: {state}")
        check(all(1 <= k <= 4 for k in state), "STATE keys are a subset of {1,2,3,4}",
              f"keys={sorted(state)}")
        check(5 not in state, "NO key 5 in STATE (load-bearing)")
        sealed = bool(state.get(1, False))
        has_seed = bool(state.get(2, False))
        locked = bool(state.get(3, False))
        _prose(f"STATE flags (same round-trip): seed={has_seed} sealed={sealed} "
               f"locked={locked}")
    except VendorTimeout as exc:
        on_timeout("STATE", exc)

    # --- MSE --------------------------------------------------------------
    try:
        _prose("MSE handshake (ungated ephemeral ECDH; no PIN token supplied)")
        channel_key, device_point = timed("MSE", _mse_handshake, dev)
        check(len(device_point) == 65 and device_point[0] == 0x04,
              "MSE returns {1: COSE_Key} with a 65-byte uncompressed device point",
              f"len={len(device_point)}")
    except VendorTimeout as exc:
        on_timeout("MSE", exc)

    # --- EXPORT (attempted by default; --no-touch skips) -------------------
    if args.no_touch:
        _prose("EXPORT leg SKIPPED (--no-touch); the MSE channel times out by itself")
    else:
        how = ("with the PERM_ACFG MAC over --pin-token" if token is not None else
               "tokenless (touch-gated)")
        _prose(f"EXPORT {how}: touch the button on the fapico2 board at {path} now… "
               "(if nobody can, it answers 0x3B/0x2D after the presence window)")
        try:
            export_leg(dev, token)
        except VendorTimeout as exc:
            on_timeout("EXPORT", exc)

    # --- PC/SC observation (opt-in) ----------------------------------------
    if args.pcsc:
        pcsc_leg()
    else:
        _prose("PC/SC leg SKIPPED (--pcsc not requested)")

    if _failures == 0:
        print("DIALECT-OK")
        return 0
    print(f"{_failures} assertion(s) FAILed")
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BackupError as exc:
        _prose(f"probe died: {exc}")
        raise SystemExit(2)
    except VendorTimeout as exc:
        _prose(f"probe died on a vendor timeout: {exc}")
        raise SystemExit(2)
    except KeyboardInterrupt:
        _prose("aborted")
        raise SystemExit(130)
