#!/usr/bin/env python3
"""Shared support for the P7 OATH ceremonies (US-130, PICOForge-COMPAT).

Three ceremony scripts drive the same YKOATH SELECT FCI: `p7_b1_oath.py`
(pcscd/pyscard), and `p7_d1_oath.py` / `p7_d2_oath.py` (pyusb raw-CCID). The
two facts that used to be copy-pasted into all three — the expected SELECT FCI
and the transport to drive it over — now live here, once, so a change to either
cannot rot in two places at once.

# The device-id (US-130)

The `0x71` TAG_NAME TLV in the SELECT FCI is the OATH **device-id**, not a
human-readable applet name. It is what a host feeds to PBKDF2 to derive the
access key, so it is a *per-unit secret-adjacent salt*, and the firmware
derives it from the OTP chip-id:

    device_id = SHA-256(chipid.to_be_bytes())[..8]

**This module must track the firmware.** The hash is
`fapico2_platform::ckey::serial_hash`; the truncation is
`fapico2_oath::oath_core::device_id_from_chipid` (apps/oath/src/oath_core.rs);
the stand-in chip-id is `fapico2_platform::usb_ident::EMULATION_CHIPID`
(`0x6661_7069_636F_3200`, US-103/R12). If any of those change, THIS is the one
place to change — do **not** re-spell the expected bytes as a literal. That is
precisely the bug US-130 removed: a hardcoded fleet-wide FCI prefix that a
derivation change silently invalidates, failing with an opaque hex dump instead
of naming its cause.

# Why the value gate is conditional

On real silicon the device-id is the *unit's own* chip-id, which the host
cannot know. So the FCI gate is split:

* **Structural — always, every transport.** The FCI is exactly
  `79 03 04 03 00` + `71 08 <8 bytes>` + optionally `74 08 <8 bytes>`, in that
  order, with nothing trailing. Tag order, both length bytes and the total
  length are all pinned. This is a real gate on hardware.
* **Value — only when the chip-id is known** (`--emul`, or `--chipid`). The 8
  device-id bytes must equal `device_id_from_chipid(chipid)`. This is what
  catches a regression to a shared constant, and it is the half CI can run.
"""
from __future__ import annotations

import atexit
import os
import subprocess
import sys
import tempfile
from hashlib import sha256

# --- the chip-derived device-id (see the module docstring) -------------------

#: Fixed stand-in chip-id, big-endian. Host/emulation builds have no OTP row;
#: it is the SAME value the USB `iSerialNumber` and the management `TAG_SERIAL`
#: derive from, so every derived identity in the emulation path agrees.
EMULATION_CHIPID = b"\x66\x61\x70\x69\x63\x6f\x32\x00"  # 0x6661_7069_636F_3200

#: SELECT FCI tags/lengths the OATH applet emits, fixed by the YKOATH shape.
_VERSION_TLV = bytes([0x79, 3, 4, 3, 0])
_DEVICE_ID_LEN = 8
#: Everything the SELECT FCI starts with, up to (not including) the device-id.
FCI_HEAD = _VERSION_TLV + bytes([0x71, _DEVICE_ID_LEN])
DEVICE_ID_LEN = _DEVICE_ID_LEN
_CHALLENGE_TLV = bytes([0x74, 8])  # tag + length, always


def device_id_from_chipid(chipid: bytes) -> bytes:
    """The 8-byte OATH device-id the firmware reports for `chipid`.

    `chipid` is the 8 big-endian chip-id bytes. Mirrors
    `fapico2_oath::oath_core::device_id_from_chipid`; see the module docstring
    for the firmware symbols this must track.
    """
    assert len(chipid) == 8, "chip-id is 8 big-endian bytes: %r" % (chipid,)
    return sha256(chipid).digest()[:_DEVICE_ID_LEN]


def fci_prefix(chipid: bytes) -> bytes:
    """The expected SELECT FCI for a known `chipid`: version + device-id TLVs."""
    return _VERSION_TLV + bytes([0x71, _DEVICE_ID_LEN]) + device_id_from_chipid(chipid)


def check_fci(body: bytes, sw, chipid: bytes | None = None) -> tuple[bool, str]:
    """Validate an OATH SELECT response body. Returns `(ok, failure_detail)`.

    `chipid` enables the value gate; pass `None` on real hardware, where the
    unit's chip-id is unknowable to the host.
    """
    if sw != (0x90, 0x00):
        return False, "sw %02X%02X != 9000" % (sw[0], sw[1])

    # --- structural gate: shape is fixed on every transport ---------------
    head = FCI_HEAD
    if not body.startswith(head):
        return False, "FCI does not start with %s" % head.hex(" ")
    n = len(head) + _DEVICE_ID_LEN
    if len(body) == n:
        pass                                   # no access code -> no challenge
    elif (body[n:n + 2] == _CHALLENGE_TLV and len(body) == n + 2 + 8):
        pass                                   # access code -> 8-byte challenge
    else:
        return False, "FCI tail is neither absent nor a single 74 08 TLV: %s" % (
            body[n:].hex(" ") or "<empty>")

    # --- value gate: only when the chip-id is known ----------------------
    if chipid is not None:
        want = device_id_from_chipid(chipid)
        got = body[len(_VERSION_TLV) + 2:len(_VERSION_TLV) + 2 + _DEVICE_ID_LEN]
        if got != want:
            return False, ("device-id %s != SHA-256(chipid)[:8] %s — a shared "
                           "constant is exactly the US-130 regression"
                           % (got.hex(" "), want.hex(" ")))
    return True, ""


#: Management applet AID (`fapico2_mgmt::MANAGEMENT_AID`). Its `READ_CONFIG`
#: (INS 0x1D) response carries `TAG_SERIAL` (0x02) — the 4-byte device-bound
#: value `serial_from_chipid(chipid)` = `usb_ident::serial_hash4(chipid)`.
MGMT_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17]
INS_READ_CONFIG = 0x1D
_TAG_SERIAL = 0x02

#: `apps/mgmt/src/lib.rs:368` — `serial[0] &= !0xFC`, "force 8-digit serial,
#: per C". The management applet masks the top two bits of the first serial
#: byte, so the OATH device-id and the management TAG_SERIAL agree on the low
#: 2 bits of byte 0, not on all 8 bits of it. Comparing the raw values would
#: fail against correct firmware, so the mask is applied here — and named, so
#: a future change to either side is visible rather than mysterious.
MGMT_SERIAL_MASK0 = 0x03


def check_device_id_vs_mgmt_serial(device_id: bytes, dev) -> tuple[bool, str]:
    """Assert the OATH device-id and the management `TAG_SERIAL` agree.

    Both are the same device-bound hash of the same chip-id: the OATH TLV
    widens `serial_hash4` from 4 to 8 bytes (`apps/mgmt/src/lib.rs:75`,
    `platform/src/usb_ident.rs:121`, `apps/oath/src/oath_core.rs`
    `device_id_from_chipid`). So on **real silicon the host learns 3 bytes of
    the chip-id's hash from a second applet** and can check that the OATH salt
    is device-bound without ever knowing the chip-id — which is the gap the
    optional `--chipid` value gate leaves on hardware.

    The management applet is re-SELECTed back to OATH afterwards: this SELECTs
    the management AID, and the dispatcher keeps that applet current until the
    next SELECT, so without it every later OATH command in the ceremony would
    be answered by the wrong app.

    Returns `(ok, detail)`.
    """
    oath_aid = bytes([0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01])
    sel = [0x00, 0xA4, 0x04, 0x00, 0x00, 0x00, len(MGMT_AID)] + MGMT_AID + [0x00, 0x00]
    body, sw = dev.x(sel)
    if sw == (0x90, 0x00):
        cfg, csw = dev.x([0x00, INS_READ_CONFIG, 0x00, 0x00, 0x00, 0x00])
    else:
        cfg, csw = b"", sw
    # Always hand the applet back to OATH, whatever happened above.
    dev.x([0x00, 0xA4, 0x04, 0x00, 0x00, 0x00, len(oath_aid)] + list(oath_aid)
          + [0x00, 0x00])

    if csw != (0x90, 0x00):
        return False, "management READ_CONFIG failed: sw %02X%02X" % csw
    i = cfg.find(bytes([_TAG_SERIAL, 4]))
    if i < 0 or i + 6 > len(cfg):
        return False, "management config carries no 4-byte TAG_SERIAL: %s" % cfg.hex(" ")
    serial = cfg[i + 2:i + 6]
    # The overall-length byte precedes the TLV stream, so `find` on the tag is
    # safe here but the *value* must be read at the tag's own offset — which it
    # is: `i` indexes the tag, `i+2` its value.
    want = bytes([device_id[0] & MGMT_SERIAL_MASK0]) + device_id[1:4]
    if serial != want:
        return False, ("OATH device-id %s does not extend the management "
                       "TAG_SERIAL %s (masked: %s) — the salt is not this unit's "
                       "device-bound hash (US-130)"
                       % (device_id.hex(" "), serial.hex(" "), want.hex(" ")))
    return True, ""


# --- emulation transport ----------------------------------------------------

#: Repo root (tests/scripts -> tests -> repo).
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _rust_emulation_binary() -> str:
    """The **Rust** emulation binary, resolved explicitly and staleness-checked.

    `EmulatorSession.resolve_emulator_binary` searches `cwd/build/pico_fico2`
    and `~/Projects/git/pico/pico-fido2/build/pico_fico2` *before* the Rust
    path — and both can exist on a dev box. Left alone it silently drives the
    C binary, which is the wrong subject for a Rust-firmware gate and would
    report a stale SELECT FCI as a verdict on this tree. So: name the binary.

    Staleness is the other half of that hazard. `target/` survives across
    checkouts, so a binary built before the change under test will happily run
    and report green (or red) for a tree it was not built from. Any local
    modification newer than the binary therefore refuses rather than lying.
    A *clean* tree older than its `target/` is fine and common — cargo decides
    that, not this check.
    """
    found = None
    override = os.environ.get("FAPICO2_EMULATION_BIN")
    if override:
        # An explicit override is authoritative: if it does not resolve, say so
        # rather than quietly falling through to some other binary.
        if os.path.isfile(override) and os.access(override, os.X_OK):
            found = override
        else:
            raise FileNotFoundError(
                "FAPICO2_EMULATION_BIN=%s is not an executable file" % override)
    else:
        for candidate in (
                os.path.join(_REPO, "target", "x86_64-unknown-linux-gnu", "debug",
                             "fapico2-emulation"),
                os.path.join(_REPO, "target", "x86_64-unknown-linux-gnu", "release",
                             "fapico2-emulation")):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                found = candidate
                break
    if found is None:
        raise FileNotFoundError(
            "fapico2-emulation binary not built. Run:\n"
            "  cargo build -p fapico2-firmware --bin fapico2-emulation \\\n"
            "      --no-default-features --features emulation "
            "--target x86_64-unknown-linux-gnu\n"
            "or point FAPICO2_EMULATION_BIN at it.")

    binary_mtime = os.path.getmtime(found)
    newest = None
    for root, dirs, files in os.walk(_REPO):
        dirs[:] = [d for d in dirs
                   if d not in ("target", ".git", "vendor", "docs", "tests")]
        for name in files:
            if name.endswith((".rs", ".toml", ".lock")):
                m = os.path.getmtime(os.path.join(root, name))
                if newest is None or m > newest:
                    newest = m
    if newest is not None and binary_mtime < newest:
        raise RuntimeError(
            "stale emulation binary: %s is older than the newest source file in "
            "%s. A stale target/ would make this gate report on a tree it was not "
            "built from. Rebuild:\n"
            "  cargo build -p fapico2-firmware --bin fapico2-emulation \\\n"
            "      --no-default-features --features emulation "
            "--target x86_64-unknown-linux-gnu" % (found, _REPO))
    return found


class EmulDev:
    """OATH applet device over the fapico2 emulation binary (host TCP).

    Wiring is the harness's own, unchanged: the emulator dials
    127.0.0.1:35963; `tests/harness/ccid_relay.py` accepts that dial-in and
    exposes the client port 35970; `EmulatorSession` (tests/harness/ccid.py)
    launches the binary and connects a client. This is the same transport
    `run_all_tests.sh` builds and drives, and the one `p7_c6_openpgp.py --emul`
    already uses — so the OATH ceremonies gain a runnable transport without a
    second relay, a second port map, or a second binary.

    A fresh temp keystore is used (`FAPICO2_KEYSTORE`, honoured by
    `emul_main.rs`), so the card starts factory-fresh on every run.
    """

    def __init__(self) -> None:
        harness = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "harness")
        if harness not in sys.path:
            sys.path.insert(0, harness)
        from ccid import EmulatorSession

        # The binary is resolved and validated BEFORE the relay is spawned, so
        # the most likely failure cannot leak a child at all.
        binary = _rust_emulation_binary()

        self._relay = subprocess.Popen(
            [sys.executable, os.path.join(harness, "ccid_relay.py")],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        # Register teardown IMMEDIATELY after the spawn, before anything else
        # that can raise. An earlier revision registered it as the last
        # statement of __init__, so every failure between here and there — the
        # READY wait, the emulator start — orphaned a relay still holding
        # 127.0.0.1:35963/35970. The next run then died with a misleading
        # "did not report READY", i.e. one run's failure became the next run's.
        atexit.register(self.close)
        self._session = None

        try:
            self.keystore = os.path.join(
                tempfile.mkdtemp(prefix="fapico2-p7-oath-"), "keystore.cbor")
            os.environ["FAPICO2_KEYSTORE"] = self.keystore
            # US-915: the emulator refuses to boot on a stale/forged partition
            # and never re-seeds, so a per-run partition file is what makes
            # this factory-fresh. (run_tests.sh does the same for its shared
            # instance.)
            os.environ["FAPICO2_SECURE_PARTITION"] = os.path.join(
                tempfile.mkdtemp(prefix="fapico2-p7-oath-"), "partition.bin")
            # Wait for the relay to bind 35963/35970 before the emulator dials in.
            ready = False
            for _ in range(50):
                line = self._relay.stdout.readline().decode(errors="replace")
                if "READY" in line:
                    ready = True
                    break
                if not line:
                    break
            if not ready:
                raise RuntimeError("ccid relay did not report READY")
            self._session = EmulatorSession(binary=binary)
            self._card = self._session.start()
        except BaseException:
            # Belt and braces: atexit also fires on an uncaught exception, but
            # an explicit close keeps the ports free immediately for whatever
            # runs next in the same shell.
            self.close()
            raise
        self.chipid = EMULATION_CHIPID

    def x(self, apdu):
        """Transmit an APDU, return `(body, (sw1, sw2))`.

        Named `x` to match the ceremony `Dev` classes exactly, so this is a
        drop-in transport: the phase functions are byte-for-byte the ones that
        run on hardware.
        """
        resp = self._card.transmit(bytes(apdu))
        assert len(resp) >= 2, "empty card response"
        return resp[:-2], (resp[-2], resp[-1])

    #: Alias, so callers written against the pyscard/pyusb `Dev` shape and
    #: against `p7_c6_openpgp.py`'s `EmulDev` both work unchanged.
    transmit = x

    def close(self) -> None:
        if getattr(self, "_session", None) is not None:
            try:
                self._session.stop()
            except Exception:
                pass
            self._session = None
        if self._relay and self._relay.poll() is None:
            self._relay.terminate()


def chipid_arg(argv: list[str]) -> bytes | None:
    """Parse `--chipid 0xHEXBE`; `None` when absent or unparsable.

    An unparsable value is a hard error rather than a silent "no value gate" —
    quietly dropping the check an operator asked for is how a gate rots.
    """
    if "--chipid" not in argv:
        return None
    i = argv.index("--chipid")
    if i + 1 >= len(argv):
        raise SystemExit("--chipid needs a value, e.g. --chipid 0x66617069636f3200")
    raw = bytes.fromhex(argv[i + 1].removeprefix("0x").removeprefix("0X"))
    if len(raw) != 8:
        raise SystemExit("--chipid must be 8 big-endian bytes (16 hex digits), got %d"
                         % len(raw))
    return raw


def open_dev(argv: list[str], hardware_dev):
    """Build the ceremony device: `--emul` uses the emulator, else hardware.

    Returns `(dev, chipid)`. The chip-id enables the FCI *value* gate — it is
    known for the emulator (the fixed stand-in) and for hardware only when the
    operator supplies `--chipid`.
    """
    emul = "--emul" in argv
    chipid = chipid_arg(argv)
    if emul and chipid is not None:
        # Nonsensical: the emulator's device-id is the stand-in's by
        # construction, so a different chip-id could only ever fail. Silently
        # preferring either one would make the gate's subject ambiguous.
        raise SystemExit("--emul and --chipid are mutually exclusive: the "
                         "emulation binary derives the device-id from the fixed "
                         "EMULATION_CHIPID stand-in. Use --emul alone, or drop "
                         "--emul and pass --chipid for real hardware.")
    if emul:
        dev = EmulDev()
        bind_ceremony_api(dev)
        dev.chipid = EMULATION_CHIPID
        return dev, EMULATION_CHIPID
    dev = hardware_dev()
    # Uniform handle for the FCI value gate: `None` disables it (real hardware
    # with no `--chipid`), which still leaves the structural gate — and the
    # management TAG_SERIAL cross-check, which needs no chip-id at all.
    dev.chipid = chipid
    return dev, chipid


#: YKOATH applet AID (C `oath_aid`).
OATH_AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]


def bind_ceremony_api(dev):
    """Give `dev` the `select()` / `apdu()` the ceremony phases call.

    The framing is verbatim the C harness (`tests/pico-fido/test_070_oath.py`,
    `tests/pico-fido/utils.py send_apdu`) and is byte-identical across all
    three ceremony scripts, so it is written once here instead of three times.
    The hardware `Dev` classes keep their own copies — this only fills the gap
    for a transport that has a raw `x()` and nothing above it.
    """
    def select(self):
        return self.x([0x00, 0xA4, 0x04, 0x00, 0x00, 0x00, len(OATH_AID)]
                      + OATH_AID + [0x00, 0x00])

    def apdu(self, ins, p1, p2, data=None):
        base = [0x00, ins, p1, p2]
        if data:
            base += [0x00, 0x00, len(data)] + list(data)
        return self.x(base + [0x00, 0x00])

    dev.select = select.__get__(dev)
    dev.apdu = apdu.__get__(dev)
    return dev
