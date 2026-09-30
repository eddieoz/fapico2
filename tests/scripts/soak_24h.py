#!/usr/bin/env python3
"""S-731-2: 24-hour soak test for fapico2 firmware (US-385).

Host-driven over USB, exercising FIDO (register-once at start, then U2F
authenticate-only per round — or getInfo-only if the start register
failed), OATH CALCULATE, and OpenPGP PSO:SIGN every
5 minutes for 288 rounds (24 hours). Monitors lsusb identity, operation
latency drift, and device wedge conditions.

Rewrite history (S-731-2, fixes the 2026-09-18 failed attempt):
  * OpenPGP SELECT bytes: the old script sent ``00 A4 04 04`` (P2=0x04) —
    the firmware OpenPGP app rejected it with SW 6A86 on every one of the
    144 rounds of the previous attempt. Correct SELECT by AID is
    ``00 A4 04 00`` + AID D2 76 00 01 24 01 (P2=0x00), verified against
    the proven P7-C6/P7-C7 APDUs.
  * OpenPGP leg is now a real sign: SELECT -> VERIFY PW1 (P2=0x81,
    factory 123456) -> PSO:SIGN. The PW1 (0x81) authorisation is consumed
    by each PSO:SIGN, so VERIFY precedes EVERY sign. A verify failure is
    never retried (retry burn protection): the leg is disabled for that
    round and recorded. The digest is round-salted: Ed25519 is
    deterministic, so the brief's "fixed digest" and "non-repeating
    signature" cannot both hold — salted digest keeps the non-repeating
    wedge check meaningful.
  * Transport: pyscard/pcscd is gone (pcscd cannot negotiate this board,
    and pcscd must stay down anyway). OATH + OpenPGP legs use pyusb
    raw-CCID (tests/scripts/ccid_usb.py, proven P7-C7/P7-D1 transport);
    FIDO uses python-fido2 over HID.
  * FIDO hardening (DARK-BOOT-1 revision): no PIN anywhere (get_pin_token
    is never called; credMgmt/authenticatorConfig are never touched). The
    leg is REGISTER-ONCE + AUTHENTICATE-ONLY: one U2F credential is
    registered at soak start (key handle kept in a scratch file next to
    the log) and every round then only CTAP1-authenticates against that
    handle — signing plus the transactional signature-counter bump. A
    per-round register is impossible on the 16-entry secure store
    (DARK-BOOT-1: the 32-entry variant dark-boots on hardware; 288
    leaked non-resident U2F creds ≈ 73 keystore parts, far beyond the
    store), so the soak would wedge by construction. The counter is
    logged per round and must be non-decreasing across rounds. If the
    start-time register fails (capacity), the leg falls back to
    getInfo-only and records the degradation honestly in the log header.
    One-strike downgrade (S-731-2 review): if the stored handle's FIRST
    authenticate is CTAP-rejected (stale handle — e.g. factory reset or
    reflash wiped the credential), the whole run downgrades to
    getInfo-only instead of burning 288 rounds on a dead handle;
    transport-level failures stay device-level (stop rule).
  * OATH: the OATH keystore was empty (LIST -> 9000, no creds), so the
    soak provisions the deterministic P7-B1/P7-D1 suite credential
    ("kaka" TOTP) once at start and validates the first CALCULATE against
    the published suite vector before round 1. Each round then CALCULATEs
    TOTP with a fresh time-based challenge.
  * Loop resilience: every leg runs in a forked child with a watchdog
    (a hang cannot stall the loop again — the previous attempt blocked
    for ~2 h at round 145 then died on [Errno 5]). A per-leg failure
    marks the round FAIL but the loop continues. A device-level failure
    (re-enumeration loss, USB I/O error, leg hang) triggers the stop
    rule: retry the round 3x, then abort with a summary.

Usage:
    python3 soak_24h.py [--rounds N] [--interval SECONDS] [--dry-run]
        [--output FILE] [--start-round N]

Options:
    --rounds N       Total rounds to run (default 288 for 24h)
    --interval SEC   Seconds between rounds (default 300 = 5 min)
    --dry-run        Run one round and exit (for testing the script itself)
    --output FILE    Log file path (default: soak_<timestamp>.log)
    --start-round N  Start from this round number (for resuming after crash)

Pass criteria:
    - All rounds complete without error
    - No re-enumeration loss (lsusb identity check passes every round)
    - No wedge conditions (operations complete in bounded time)
    - Memory stable (no growth signal via operation latency drift)
"""

import sys
import os
import time
import hashlib
import hmac as hmac_mod
import multiprocessing
import subprocess
import argparse
import json
import datetime
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ccid_usb import Ccid  # noqa: E402  (pyusb raw-CCID, proven P7 transport)

# Suppress [gb_*] GreenBoost telemetry lines that pollute Python stdout
import re
GB_PATTERN = re.compile(r'\[gb_\d+\].*')

LEG_TIMEOUT_S = 40          # per-leg watchdog
DEVICE_RETRIES = 3          # stop rule: retry the round 3x, then abort


def filter_gb(text):
    """Filter out [gb_*] GreenBoost telemetry lines."""
    if isinstance(text, bytes):
        text = text.decode('utf-8', errors='replace')
    return '\n'.join(line for line in text.split('\n') if not GB_PATTERN.match(line))


class SoakTestError(Exception):
    """Soak test error with round context."""
    def __init__(self, message, round_num=None, details=None):
        super().__init__(message)
        self.round_num = round_num
        self.details = details or {}


class LegError(SoakTestError):
    """Per-leg failure (APDU-level): the round FAILS, the loop continues."""


class DeviceLevelError(SoakTestError):
    """Device-level failure (USB/transport/enumeration): triggers the stop
    rule — retry the round connection 3x, then abort with a summary."""


class Logger:
    """Logger that writes to both file and stdout."""

    def __init__(self, path):
        self.path = path
        self.file = open(path, 'w')
        print(f"Logging to {path}")

    def _emit(self, level, msg):
        ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        line = f"[{ts}] {level}: {msg}"
        self.file.write(line + '\n')
        self.file.flush()
        print(line, flush=True)

    def info(self, msg):
        self._emit("INFO", msg)

    def warn(self, msg):
        self._emit("WARN", msg)

    def error(self, msg):
        self._emit("ERROR", msg)

    def round_result(self, round_num, status, elapsed_ms, details=None):
        ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        detail_str = json.dumps(details or {}) if details else '{}'
        line = f"[{ts}] ROUND {round_num}: {status} ({elapsed_ms:.0f}ms) {detail_str}"
        self.file.write(line + '\n')
        self.file.flush()

    def close(self):
        self.file.close()


def run_lsusb_check(logger, expected_vid="fa20", expected_pid="0002"):
    """Check that the device is enumerated with the correct identity."""
    try:
        result = subprocess.run(
            ['lsusb'],
            capture_output=True, text=True, timeout=15
        )
        output = filter_gb(result.stdout)

        if f"{expected_vid}:{expected_pid}" not in output:
            raise DeviceLevelError(
                f"Device identity check failed. Expected {expected_vid}:{expected_pid}")

        if 'fapico2' not in output.lower():
            logger.warn("lsusb shows VID:PID but no 'fapico2' product name")

    except subprocess.TimeoutExpired:
        raise DeviceLevelError("lsusb timed out (15s)")
    except FileNotFoundError:
        raise DeviceLevelError("lsusb command not found")

    return True


# ---------------------------------------------------------------------------
# Leg worker: every leg runs in a forked child with a watchdog so a hung
# transport cannot stall the loop (the 2026-09-18 attempt blocked ~2 h).
# ---------------------------------------------------------------------------

def _leg_worker(q, fn, args):
    """Run one leg in the child; report (kind, payload) via the queue."""
    try:
        q.put(("ok", fn(*args)))
    except DeviceLevelError as e:
        q.put(("dev", str(e)))
    except LegError as e:
        q.put(("leg", str(e)))
    except Exception as e:
        q.put(("err", "%s: %s" % (type(e).__name__, e)))


def _classify_transport_exc(e):
    """Transport/USB-level exceptions are device-level; anything else a leg
    failure. usb.core.USBError and OSError ([Errno 5] I/O error) are the
    observed device-level classes; ccid_usb raises RuntimeError on CCID
    status errors."""
    if isinstance(e, SoakTestError):
        return e
    if isinstance(e, (OSError, RuntimeError)):
        return DeviceLevelError("transport: %s: %s" % (type(e).__name__, e))
    return LegError("%s: %s" % (type(e).__name__, e))


def run_leg_with_watchdog(fn, args, timeout, logger, label):
    """Run one leg under a watchdog; returns the leg result dict."""
    ctx = multiprocessing.get_context("fork")
    q = ctx.SimpleQueue()
    p = ctx.Process(target=_leg_worker, args=(q, fn, args))
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.terminate()
        p.join(5)
        raise DeviceLevelError(f"{label} hung > {timeout}s (watchdog)")
    if p.exitcode != 0:
        raise DeviceLevelError(f"{label} worker died (exitcode={p.exitcode})")
    kind, payload = q.get()
    if kind == "dev":
        raise DeviceLevelError(f"{label}: {payload}")
    if kind in ("leg", "err"):
        raise LegError(f"{label}: {payload}")
    return payload


# ---------------------------------------------------------------------------
# FIDO leg — REGISTER-ONCE (soak start) + AUTHENTICATE-ONLY per round.
#
# DARK-BOOT-1: the device secure store is 16 entries (the 32-entry variant
# dark-boots on hardware — MSPLIM/stack squeeze). A U2F register leaks a
# non-resident credential into the keystore snapshot forever (invisible to
# credMgmt), so a register-per-round soak (288 rounds) would exhaust the
# store by construction (~73 keystore parts) regardless of capacity. The
# leg therefore registers ONE U2F credential at soak start (key handle
# persisted in a scratch file next to the log) and every round only
# CTAP1-authenticates against that handle: real signing plus the
# transactional signature-counter bump. If the start-time register fails
# (capacity), the leg degrades to getInfo-only, recorded honestly in the
# log header.
# ---------------------------------------------------------------------------

FIDO_CHASH = b"\x33" * 32          # client param (registration)
FIDO_APP_ID = b"\xa0" * 32         # U2F app param (as in the earlier rounds)


def register_fido(logger, output_path):
    """One-time U2F registration at soak start. Returns the key handle as
    hex, or `None` when the register failed (CTAP error, e.g. capacity) —
    the caller then runs the leg getInfo-only for the whole run. The key
    handle lives in `<output>.kh` next to the log so a resumed run
    (--start-round) reuses it instead of consuming another store slot."""
    from fido2.hid import CtapHidDevice
    from fido2.ctap2 import Ctap2
    from fido2.ctap import CtapError
    from fido2.ctap1 import Ctap1

    kh_path = output_path + ".kh"
    if os.path.exists(kh_path):
        with open(kh_path) as f:
            kh_hex = f.read().strip()
        if kh_hex and len(kh_hex) % 2 == 0:
            logger.info(f"FIDO register-once: reusing key handle from "
                        f"{kh_path} ({len(kh_hex) // 2} B; resume — a "
                        "re-register would consume another store slot)")
            return kh_hex
        logger.warn(f"FIDO register-once: {kh_path} is corrupt; "
                    "registering anew")

    try:
        devices = list(CtapHidDevice.list_devices())
        if not devices:
            raise DeviceLevelError("No FIDO2 HID device found")
        dev = devices[0]
        try:
            info = Ctap2(dev).get_info()
            if 'FIDO_2_1' not in info.versions:
                raise LegError(f"Unexpected versions: {info.versions}")
            reg = Ctap1(dev).register(FIDO_CHASH, FIDO_APP_ID)
            kh = reg.key_handle
        finally:
            try:
                dev.close()
            except Exception:
                pass
    except CtapError as e:
        logger.error(f"FIDO register-once FAILED (CTAP error 0x{e.code:02X}): "
                     "the FIDO leg degrades to getInfo-only for the whole "
                     "run (nothing to sign against). Recorded honestly in "
                     "this header.")
        return None
    except (OSError, RuntimeError) as e:
        raise DeviceLevelError("FIDO registration transport: %s: %s"
                               % (type(e).__name__, e))

    with open(kh_path, "w") as f:
        f.write(kh.hex())
    logger.info(f"FIDO register-once: U2F credential registered, key handle "
                f"({len(kh)} B) saved to {kh_path}")
    return kh.hex()


def _fido_leg_impl(round_num, kh_hex, prev_counter):
    from fido2.hid import CtapHidDevice
    from fido2.ctap2 import Ctap2
    from fido2.ctap import CtapError
    from fido2.ctap1 import Ctap1

    devices = list(CtapHidDevice.list_devices())
    if not devices:
        raise DeviceLevelError("No FIDO2 HID device found")

    dev = devices[0]
    try:
        ctap = Ctap2(dev)
        info_start = time.time()
        info = ctap.get_info()
        info_elapsed = (time.time() - info_start) * 1000
        if 'FIDO_2_1' not in info.versions:
            raise LegError(f"Unexpected versions: {info.versions}")

        counter = None
        auth_ms = 0.0
        if kh_hex is None:
            # Start-time register failed: getInfo-only degradation.
            mode = "getinfo_only"
        else:
            c1 = Ctap1(dev)
            kh = bytes.fromhex(kh_hex)
            # Round-salted challenge: keeps the signature non-repeating.
            chal = hashlib.sha256(
                b"fapico2 u2f soak auth %d" % round_num).digest()
            t0 = time.time()
            try:
                auth = c1.authenticate(chal, FIDO_APP_ID, kh)
            except CtapError as e:
                # One-strike downgrade (S-731-2 review Minor 2): the stored
                # handle's authenticate was rejected by the card at the CTAP
                # level (e.g. WrongData after a factory reset/reflash wiped
                # the credential) — a dead handle. Report it so the main
                # loop downgrades the WHOLE run to getInfo-only instead of
                # burning 288 rounds on it. Transport-level failures
                # (OSError/RuntimeError) stay device-level (stop rule).
                return {
                    "mode": "dead_handle",
                    "ctap_error": e.code,
                    "info_ms": info_elapsed,
                    "auth_ms": (time.time() - t0) * 1000,
                    "counter": None,
                    "total_ms": (time.time() - info_start) * 1000 + 0.0,
                }
            auth_ms = (time.time() - t0) * 1000
            # Reply: user_presence(1) || counter(4, big-endian) || signature.
            if not auth[0] & 0x01:
                raise LegError("U2F authenticate: user-presence bit clear "
                               "(0x%02X)" % auth[0])
            counter = int.from_bytes(auth[1:5], "big")
            # Stability signal: the per-credential counter must never
            # decrease across rounds (US-425: the durable-before-ack gate
            # guarantees the signed counter is the durable one).
            if prev_counter is not None and counter < prev_counter:
                raise LegError(
                    "U2F auth counter DECREASED: %d < %d (signature-counter "
                    "regression — possible rollback/wedge)"
                    % (counter, prev_counter))
            mode = "u2f_auth"
    except (OSError, RuntimeError) as e:
        raise DeviceLevelError("FIDO HID transport: %s: %s"
                               % (type(e).__name__, e))
    finally:
        try:
            dev.close()
        except Exception:
            pass

    return {
        "mode": mode,
        "info_ms": info_elapsed,
        "auth_ms": auth_ms,
        "counter": counter,
        "total_ms": (time.time() - info_start) * 1000 + 0.0,
    }


# ---------------------------------------------------------------------------
# CCID helpers (raw-CCID transport for OATH + OpenPGP)
# ---------------------------------------------------------------------------

def _x(c, apdu):
    """Transmit one APDU, return (body, (sw1, sw2))."""
    resp = c.transmit(bytes(apdu))
    if len(resp) < 2:
        raise DeviceLevelError("empty card response: %r" % (resp,))
    return resp[:-2], (resp[-2], resp[-1])


def _sw(sw):
    return "%02X%02X" % (sw[0], sw[1])


# --- OATH leg ---------------------------------------------------------------

OATH_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]
OATH_INS_CALCULATE = 0xA2
OATH_INS_LIST = 0xA1
OATH_INS_PUT = 0x01
TAG_NAME = 0x71
TAG_RESPONSE = 0x75
TAG_T_RESPONSE = 0x76

# Deterministic P7-B1/P7-D1 suite credential: "kaka" TOTP sha1,
# key 21 06 + 20x0B; CALCULATE with challenge 00..01 must produce the
# published full-digest vector (validated at soak start, before round 1).
OATH_SUITE_KEY = bytes([0x21, 0x06]) + bytes([0x0B] * 20)
OATH_SUITE_NAME = b"kaka"
OATH_SUITE_VECTOR = bytes([
    0x75, 0x15, 0x06,
    0xB3, 0x99, 0xBD, 0xFC, 0x9D, 0x05, 0xD1, 0x2A,
    0xC4, 0x35, 0xC4, 0xC8, 0xD6, 0xCB, 0xD2, 0x47,
    0xC4, 0x0A, 0x30, 0xF1])


def _oath_select(c):
    # C-harness SELECT framing (tests/conftest.py select_oath) — verbatim
    # P7-D1 APDU bytes.
    sel = [0x00, 0xA4, 0x04, 0x00, 0x00, 0x00, len(OATH_AID)] + OATH_AID + [0x00, 0x00]
    body, sw = _x(c, sel)
    if sw != (0x90, 0x00):
        raise LegError(f"OATH SELECT failed: {_sw(sw)}")
    return body


def _oath_apdu(c, ins, p1, p2, data=None):
    # C-harness framing (tests/pico-fido/utils.py send_apdu) — verbatim
    # P7-D1 APDU bytes.
    base = [0x00, ins, p1, p2]
    if data:
        base += [0x00, 0x00, len(data)] + list(data)
    return _x(c, base + [0x00, 0x00])


def _oath_calculate(c, name, challenge):
    data = [TAG_NAME, len(name)] + list(name) + [0x74, 8] + list(challenge)
    return _oath_apdu(c, OATH_INS_CALCULATE, 0, 0, data)


def provision_oath(logger):
    """One-time: SELECT, LIST; PUT the suite credential if absent; validate
    the suite vector. Raises LegError on any mismatch (fail fast, not
    silently 288 broken rounds)."""
    from usb.core import USBError  # noqa: F401 (classification via OSError)

    c = Ccid()
    try:
        c.power_on()
        _oath_select(c)
        body, sw = _oath_apdu(c, OATH_INS_LIST, 0, 0)
        if sw != (0x90, 0x00):
            raise LegError(f"OATH LIST failed: {_sw(sw)} (no PIN is set on "
                           "the OATH app; locked list would be 6982)")
        names = []
        i = 0
        while i + 1 < len(body):
            if body[i] == 0x72:  # TAG_NAME_LIST: 72 <len> <type> <name...>
                n = body[i + 1]
                names.append(bytes(body[i + 3:i + 2 + n]))
                i += 2 + n
            else:
                break
        logger.info(f"OATH provisioning: LIST -> {len(names)} credential(s): "
                    + ", ".join(n.decode(errors="replace") for n in names))
        if OATH_SUITE_NAME not in names:
            put_data = ([TAG_NAME, len(OATH_SUITE_NAME)] + list(OATH_SUITE_NAME)
                        + [0x73, len(OATH_SUITE_KEY)] + list(OATH_SUITE_KEY))
            body, sw = _oath_apdu(c, OATH_INS_PUT, 0, 0, put_data)
            if sw != (0x90, 0x00):
                raise LegError(f"OATH PUT 'kaka' failed: {_sw(sw)}")
            logger.info("OATH provisioning: PUT 'kaka' TOTP (suite key) OK")
        else:
            logger.info("OATH provisioning: 'kaka' already present")

        # Suite-vector validation (challenge 00 00 00 00 00 00 00 01)
        body, sw = _oath_calculate(
            c, OATH_SUITE_NAME, bytes(7) + b"\x01")
        if sw != (0x90, 0x00):
            raise LegError(f"OATH suite-vector CALCULATE failed: {_sw(sw)}")
        if bytes(body) != OATH_SUITE_VECTOR:
            raise LegError("OATH suite vector mismatch: got %s, expected %s"
                           % (bytes(body).hex(" "), OATH_SUITE_VECTOR.hex(" ")))
        logger.info("OATH provisioning: suite vector validated "
                    "(B399BD...30F1)")
    except (OSError, RuntimeError) as e:
        raise DeviceLevelError("OATH provisioning transport: %s: %s"
                               % (type(e).__name__, e))
    finally:
        try:
            c.close()
        except Exception:
            pass


def _oath_leg_impl(round_num, prev_challenge_hex, prev_digest):
    start = time.time()
    c = Ccid()
    try:
        c.power_on()
        _oath_select(c)
        # CALCULATE TOTP with a fresh time-based challenge
        challenge = int(time.time()).to_bytes(8, "big")
        body, sw = _oath_calculate(c, OATH_SUITE_NAME, challenge)
        if sw != (0x90, 0x00):
            raise LegError(f"OATH CALCULATE failed: {_sw(sw)}")
        digest = bytes(body)
        if len(digest) < 3 or digest[0] != TAG_RESPONSE:
            raise LegError(f"OATH CALCULATE body malformed: {digest.hex(' ')}")
        # Wedge check: a different challenge yielding the previous digest is
        # a stale/repeat response. (The same challenge twice — a same-second
        # collision at short smoke intervals — is legitimately identical.)
        if (prev_digest is not None and prev_challenge_hex is not None
                and digest == prev_digest
                and challenge.hex() != prev_challenge_hex):
            raise LegError("OATH CALCULATE returned the previous digest for a "
                           "different challenge (stale/repeat — possible wedge)")
    except (OSError, RuntimeError) as e:
        raise DeviceLevelError("OATH transport: %s: %s"
                               % (type(e).__name__, e))
    finally:
        try:
            c.close()
        except Exception:
            pass
    return {
        "challenge_hex": challenge.hex(),
        "digest_hex": digest.hex(" "),
        "total_ms": (time.time() - start) * 1000,
    }


# --- OpenPGP leg -------------------------------------------------------------

OPENPGP_AID = bytes([0xD2, 0x76, 0x00, 0x01, 0x24, 0x01])
FACTORY_PW1 = b"123456"  # PW1 for signing (P2=0x81), factory value


def _pgp_sign_once(c, digest):
    """VERIFY PW1 (P2=0x81) + PSO:SIGN — the verify is consumed by each
    PSO:SIGN, so this pair is atomic per signature."""
    ver = bytes.fromhex("0020008106") + FACTORY_PW1  # 00 20 00 81 06 31..
    body, sw = _x(c, ver)
    if sw != (0x90, 0x00):
        # NEVER retry a failed verify — a wrong-PIN probe burns a retry.
        raise LegError(f"PW1 VERIFY failed: {_sw(sw)} (no retry, leg "
                       "disabled for this round)")
    pso = bytes.fromhex("002A9E9A237C2280") + digest + b"\x00"
    body, sw = _x(c, pso)
    if sw != (0x90, 0x00):
        raise LegError(f"PSO:SIGN failed: {_sw(sw)}")
    sig = bytes(body)
    if len(sig) != 64:
        raise LegError(f"PSO:SIGN returned {len(sig)} bytes (expected 64)")
    return sig


def _openpgp_leg_impl(round_num, prev_sig):
    start = time.time()
    c = Ccid()
    try:
        c.power_on()
        sel = bytes.fromhex("00A4040006") + OPENPGP_AID  # P2=0x00 (6A86 fix)
        body, sw = _x(c, sel)
        if sw != (0x90, 0x00):
            raise LegError(f"OpenPGP SELECT failed: {_sw(sw)}")
        # Round-salted digest: Ed25519 is deterministic, so a fixed digest
        # would repeat signatures byte-for-byte; the salt keeps the
        # non-repeating check meaningful.
        digest = hashlib.sha256(
            b"fapico2 OpenPGP soak round %d" % round_num).digest()
        sig = _pgp_sign_once(c, digest)
        if prev_sig is not None and sig == prev_sig:
            raise LegError("PSO:SIGN signature repeated from a previous "
                           "round (stale response — possible wedge)")
    except (OSError, RuntimeError) as e:
        raise DeviceLevelError("OpenPGP transport: %s: %s"
                               % (type(e).__name__, e))
    finally:
        try:
            c.close()
        except Exception:
            pass
    return {"sig_hex": sig.hex(" ")[:32] + "...",
            "total_ms": (time.time() - start) * 1000}


def check_wedge(logger):
    """Check for device wedge conditions (basic USB communication)."""
    try:
        result = subprocess.run(
            ['lsusb'],
            capture_output=True, text=True, timeout=10
        )
        if 'fapico2' not in filter_gb(result.stdout).lower():
            raise DeviceLevelError("Device disappeared from lsusb during wedge check")
    except subprocess.TimeoutExpired:
        raise DeviceLevelError("lsusb timed out during wedge check - possible USB wedge")


def pcscd_status():
    """Return the current pcscd active state string (diagnostic)."""
    try:
        r = subprocess.run(['systemctl', 'is-active', 'pcscd'],
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except Exception as e:
        return "unknown(%s)" % e


def main():
    parser = argparse.ArgumentParser(description='fapico2 24-hour soak test')
    parser.add_argument('--rounds', type=int, default=288, help='Total rounds (default 288)')
    parser.add_argument('--interval', type=int, default=300, help='Interval between rounds in seconds (default 300)')
    parser.add_argument('--dry-run', action='store_true', help='Run one round and exit')
    parser.add_argument('--output', type=str, default=None, help='Log file path')
    parser.add_argument('--start-round', type=int, default=1, help='Starting round number')
    parser.add_argument('--skip-oath-provision', action='store_true',
                        help='skip the one-time OATH suite provisioning check')
    args = parser.parse_args()

    # Set up logging
    if not args.output:
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        args.output = f"soak_{ts}.log"

    logger = Logger(args.output)
    expected_end = datetime.datetime.now() + datetime.timedelta(
        seconds=args.rounds * args.interval)
    logger.info(f"Soak test starting: {args.rounds} rounds, interval={args.interval}s")
    logger.info(f"Output: {args.output}")
    logger.info(f"Expected completion: {expected_end.strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("=" * 60)
    logger.info("WARNING (24h run preconditions):")
    logger.info("  - pcscd must NOT be restarted during the soak (it would")
    logger.info("    steal the CCID device from the raw-CCID client).")
    logger.info("  - The board must NOT be unplugged/replugged.")
    logger.info("  - No gpg/scdaemon client may touch the device.")
    logger.info("=" * 60)
    logger.info(f"pcscd state at start: {pcscd_status()} "
                "(must stay inactive for the whole run)")

    # Pre-flight checks
    logger.info("Pre-flight: checking device identity...")
    run_lsusb_check(logger)
    logger.info("Pre-flight: device identity OK "
                "(fa20:0002 The BLOCO Community fapico2)")

    try:
        import fido2.hid  # noqa: F401
        logger.info("Dependency check: python-fido2 OK")
    except ImportError:
        logger.error("Dependency check: python-fido2 NOT installed")
    try:
        import usb.core  # noqa: F401
        logger.info("Dependency check: pyusb (raw-CCID) OK")
    except ImportError:
        logger.error("Dependency check: pyusb NOT installed")

    # One-time OATH provisioning + suite-vector validation
    if not args.skip_oath_provision:
        logger.info("Pre-flight: OATH provisioning + suite-vector validation...")
        try:
            provision_oath(logger)
        except Exception as e:
            logger.error(f"OATH provisioning failed: {e}")
            logger.info("SOAK TEST FAILED (provisioning) — aborting before round 1")
            logger.close()
            return 1
    else:
        logger.warn("Pre-flight: OATH provisioning SKIPPED (--skip-oath-provision)")

    # One-time FIDO registration (register-once, DARK-BOOT-1): the per-round
    # register of the previous design would exhaust the 16-entry secure
    # store by construction. On register failure the leg degrades to
    # getInfo-only for the whole run (recorded in the log header above).
    logger.info("Pre-flight: FIDO register-once (U2F credential)...")
    try:
        fido_kh_hex = register_fido(logger, args.output)
    except DeviceLevelError as e:
        logger.error(f"FIDO register-once failed at transport level: {e}")
        logger.info("SOAK TEST FAILED (FIDO registration) — aborting before round 1")
        logger.close()
        return 1

    # Main soak loop
    round_num = args.start_round - 1
    success_count = 0
    fail_count = 0
    leg_counts = {"fido": 0, "fido_getinfo": 0, "oath": 0, "pgp": 0,
                  "pgp_disabled": 0}
    device_retries = 0
    stop_rule_events = []
    latency_history = []
    prev_oath_challenge = None
    prev_oath_digest = None
    prev_pgp_sig = None
    prev_fido_counter = None
    fido_degradation_noted = fido_kh_hex is None
    aborted = False

    try:
        while round_num < args.rounds:
            round_num += 1

            round_start = time.time()
            round_errors = []
            round_detail = {}

            # Step 0: retry loop for device-level failures (stop rule)
            attempt = 0
            round_done = False
            while not round_done:
                attempt += 1
                try:
                    logger.info(f"Starting round {round_num}/{args.rounds}"
                                + (f" (device retry {attempt}/{DEVICE_RETRIES})"
                                   if attempt > 1 else ""))

                    # Step 1: lsusb identity check
                    run_lsusb_check(logger)

                    # Step 2: FIDO leg (authenticate-only against the
                    # soak-start credential; getInfo-only when the
                    # start-time register failed or the handle went stale)
                    try:
                        fido_result = run_leg_with_watchdog(
                            _fido_leg_impl,
                            (round_num, fido_kh_hex, prev_fido_counter),
                            LEG_TIMEOUT_S, logger, "FIDO")
                        if fido_result["mode"] == "dead_handle":
                            # One-strike downgrade (S-731-2 review Minor 2):
                            # the stored handle's FIRST authenticate was
                            # CTAP-rejected (stale handle — e.g. factory
                            # reset/reflash wiped the credential). Downgrade
                            # the whole run to getInfo-only NOW instead of
                            # burning 288 rounds on a dead handle; the round
                            # itself still counts (getInfo was exercised).
                            fido_kh_hex = None
                            leg_counts["fido_getinfo"] += 1
                            logger.warn(
                                "FIDO DEGRADATION: the stored key handle's "
                                "authenticate was rejected by the card "
                                "(CTAP error 0x%02X) — stale handle (factory "
                                "reset/reflash?). ONE-STRIKE downgrade: the "
                                "whole run continues getInfo-only; recorded "
                                "honestly in this log."
                                % fido_result.get("ctap_error", 0))
                            logger.info(
                                f"Round {round_num}: FIDO OK "
                                f"({fido_result['info_ms']:.0f}ms info, "
                                "mode=getinfo_only after stale-handle "
                                "downgrade)")
                            round_detail["fido"] = "getinfo_only"
                        elif fido_result["mode"] == "getinfo_only":
                            leg_counts["fido_getinfo"] += 1
                            if not fido_degradation_noted:
                                logger.warn(
                                    "FIDO DEGRADATION: the start-time U2F "
                                    "register failed (see header); the leg "
                                    "runs getInfo-only for the whole run.")
                                fido_degradation_noted = True
                            logger.info(
                                f"Round {round_num}: FIDO OK "
                                f"({fido_result['info_ms']:.0f}ms info, "
                                f"mode={fido_result['mode']})")
                            round_detail["fido"] = fido_result["mode"]
                        else:
                            leg_counts["fido"] += 1
                            if fido_result.get("counter") is not None:
                                prev_fido_counter = fido_result["counter"]
                            logger.info(
                                f"Round {round_num}: FIDO OK "
                                f"({fido_result['info_ms']:.0f}ms info, "
                                f"mode={fido_result['mode']}"
                                + (f", counter={fido_result['counter']}"
                                   if fido_result.get("counter") is not None
                                   else "")
                                + ")")
                            round_detail["fido"] = fido_result["mode"]
                    except LegError as e:
                        round_errors.append(f"FIDO: {e}")
                        logger.error(f"Round {round_num}: FIDO failed - {e}")

                    # Step 3: OATH CALCULATE
                    try:
                        oath_result = run_leg_with_watchdog(
                            _oath_leg_impl,
                            (round_num, prev_oath_challenge, prev_oath_digest),
                            LEG_TIMEOUT_S, logger, "OATH")
                        leg_counts["oath"] += 1
                        prev_oath_challenge = oath_result.get("challenge_hex")
                        prev_oath_digest = oath_result.get("digest_hex")
                        logger.info(f"Round {round_num}: OATH OK "
                                    f"({oath_result['total_ms']:.0f}ms)")
                    except LegError as e:
                        round_errors.append(f"OATH: {e}")
                        logger.error(f"Round {round_num}: OATH failed - {e}")

                    # Step 4: OpenPGP sign
                    try:
                        pgp_result = run_leg_with_watchdog(
                            _openpgp_leg_impl, (round_num, prev_pgp_sig),
                            LEG_TIMEOUT_S, logger, "OpenPGP")
                        leg_counts["pgp"] += 1
                        prev_pgp_sig = pgp_result["sig_hex"]
                        logger.info(f"Round {round_num}: OpenPGP OK "
                                    f"(sig {pgp_result['sig_hex']})")
                    except LegError as e:
                        round_errors.append(f"OpenPGP: {e}")
                        logger.error(f"Round {round_num}: OpenPGP failed - {e}")
                        if "VERIFY failed" in str(e):
                            leg_counts["pgp_disabled"] += 1

                    # Step 5: Wedge check
                    check_wedge(logger)

                    round_done = True
                    device_retries = 0

                except DeviceLevelError as e:
                    device_retries += 1
                    msg = (f"Round {round_num}: device-level failure "
                           f"(attempt {device_retries}/{DEVICE_RETRIES}): {e} "
                           f"[pcscd={pcscd_status()}]")
                    stop_rule_events.append(msg)
                    logger.error(msg)
                    if device_retries >= DEVICE_RETRIES:
                        logger.error(
                            f"STOP RULE: {DEVICE_RETRIES} consecutive "
                            "device-level failures — aborting soak with "
                            "summary (device absent, wedged, or re-"
                            "enumeration loss).")
                        aborted = True
                        break
                    logger.warn(f"Retrying round {round_num} after "
                                f"{2 * device_retries}s backoff...")
                    time.sleep(2 * device_retries)

            if aborted:
                fail_count += 1  # the round never completed
                break

            # Record results
            elapsed_ms = (time.time() - round_start) * 1000
            latency_history.append(elapsed_ms)

            if round_errors:
                fail_count += 1
                logger.round_result(round_num, "FAIL", elapsed_ms,
                                    {"errors": round_errors, "legs": leg_counts})
            else:
                success_count += 1
                logger.round_result(round_num, "PASS", elapsed_ms,
                                    {"legs": round_detail})

            # Dry run exits after one round
            if args.dry_run:
                logger.info("Dry run complete")
                break

            # Wait for next interval (minus time spent in this round)
            wait_time = max(0, args.interval - (time.time() - round_start))
            if wait_time > 0 and round_num < args.rounds:
                logger.info(f"Waiting {wait_time:.0f}s until next round...")
                time.sleep(wait_time)

    except KeyboardInterrupt:
        logger.info("Soak test interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error in soak loop: {e}")
        traceback.print_exc()
        aborted = True
    finally:
        # Final summary (self-contained: the log is the evidence)
        total_elapsed = (time.time() - round_start) if 'round_start' in locals() else 0

        logger.info("=" * 60)
        logger.info("SOAK TEST SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Rounds completed: {success_count + fail_count}")
        logger.info(f"Successful rounds: {success_count}")
        logger.info(f"Failed rounds: {fail_count}")
        logger.info(f"Leg passes: FIDO auth={leg_counts['fido']} "
                    f"(getInfo-only rounds: {leg_counts['fido_getinfo']}), "
                    f"OATH={leg_counts['oath']}, OpenPGP sign={leg_counts['pgp']}")
        logger.info(f"OpenPGP verify-failures (leg disabled that round, "
                    f"no retry): {leg_counts['pgp_disabled']}")
        logger.info(f"Stop-rule events: {len(stop_rule_events)}")
        for ev in stop_rule_events:
            logger.info(f"  stop-rule: {ev}")
        logger.info(f"Total elapsed: {total_elapsed:.0f}s ({total_elapsed/3600:.1f}h)")
        if aborted:
            logger.info("Ended by STOP RULE (device-level failure) or "
                        "unexpected error — soak is INCOMPLETE.")

        if latency_history:
            avg_latency = sum(latency_history) / len(latency_history)
            logger.info(f"Average round latency: {avg_latency:.0f}ms")

            if len(latency_history) > 10:
                first_half = latency_history[:len(latency_history)//2]
                second_half = latency_history[len(latency_history)//2:]
                avg_first = sum(first_half) / len(first_half)
                avg_second = sum(second_half) / len(second_half)

                if avg_second > avg_first * 1.5:
                    logger.warn(f"Latency drift detected: first half "
                                f"{avg_first:.0f}ms vs second half {avg_second:.0f}ms")
                    logger.warn("This may indicate memory growth - investigate")
                else:
                    logger.info("No significant latency drift detected "
                                "(memory appears stable)")

        if not aborted and fail_count == 0 and success_count > 0:
            logger.info("=" * 60)
            logger.info("SOAK TEST PASSED")
            logger.info("=" * 60)
            result = "PASS"
        else:
            logger.info("=" * 60)
            logger.info("SOAK TEST FAILED")
            logger.info("=" * 60)
            result = "FAIL"

        logger.close()
        return 0 if result == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
