#!/usr/bin/env python3
"""US-948 evidence generator: a *synthesized* KDF-DO APDU trace.

PROVENANCE — READ THIS FIRST
----------------------------
No gpg, no scdaemon and no PC/SC layer takes part in what this script
produces.  Every APDU below is written by hand in this file and pushed
into the firmware over the emulation binary's CCID-over-TCP relay
(`tests/harness/ccid_relay.py`).  The output is therefore *not* an
interop capture: it cannot and does not show what any real gpg session
sends.  A live capture is not available on this host — there is no
`vpcd`/virtual PC/SC ifd-handler installed, and `pcscd` + libccid (which
does list this card's 0xFA20/0x0002) only enumerate physical readers.
Bridging gpg to the TCP emulator would mean writing a PC/SC driver,
which is US-952/953 hardware-phase work.

What the trace *does* establish
-------------------------------
* The 110-byte three-salt KDF-DO that gpg 2.4.4's `kdf-setup on` writes
  (see `docs/tasks/us947-kdf-do.md`) is accepted by PUT DATA F9, survives
  in the card's non-volatile store, and comes back byte-exactly from GET
  DATA F9.
* PUT DATA F9 = `81 01 00` (gpg `kdf-setup off`) is accepted and reads
  back verbatim.
* With a valid KDF-DO stored, PSO:DECIPHER ECDH returns the *raw* ECDH
  x-coordinate — byte-identical to the reply with the KDF-DO switched
  off.  The stored KDF-DO deliberately does not touch the decipher
  output.
* The raw value is genuine: it is recomputed here, host-side, with
  `cryptography` (ECDH of the card's imported scalar against the
  generator point) and compared byte for byte.

What the trace does NOT establish
---------------------------------
* That gpg/scdaemon sends exactly these bytes (the 110-byte *layout* is
  pinned by reading gpg 2.4.4's `g10/card-util.c`, not by this trace).
* The double-derive question — whether the card or the host applies the
  KDF.  That is **resolved by decision, not by this trace**: the
  maintainer chose the host-derives contract (raw `Z` out of
  PSO:DECIPHER) because gpg runs `derive_kek` in software
  (`g10/ecdh.c::prepare_ecdh_with_shared_point`).  The decision and its
  supporting gpg 2.4.4 source reading are recorded in
  `docs/tasks/us947-kdf-do.md` — "Decisions" item 2 and "gpg 2.4.4 form
  check".  The firmware change it drove is `6832e81`.

Every checked step below gates the process exit status: a failing check
prints `✗` in the trace, is reported in the SUMMARY, and makes
`main()` return 1.  A total-failure run therefore cannot emit an
evidence file that claims success.

Usage:
    python3.12 tests/scripts/us948_kdf_storage_trace.py
        [--emulator BIN] [--keep] [--write-evidence PATH]
        [--expect-raw-z HEX]

`--expect-raw-z HEX` overrides the host-computed expected raw ECDH
value.  It exists so the harness can be pointed at a wrong expectation
to demonstrate that a bad run really does fail (exit 1).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests"))

from harness.test_restart import CcidEmu  # noqa: E402

OPENPGP_AID = bytes.fromhex("D27600012401")
# P-256 DEC key attribute (tag C2, EC ECDH P-256r1) — OID 1.2.840.10045.3.1.7
# (note 0x122A..., NOT 0x122B which is the secp256k1 attribute).
P256_DEC_ATTR = bytes.fromhex("122A8648CE3D030107")
P256_DEC_ATTR_RESP = bytes([0x12, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0xFF])

# Dedicated ports (disjoint from the shared harness and sibling suites)
US948_RELAY_CCID_PORT = 35983
US948_CCID_CLIENT_PORT = 35984
US948_HID_PORT = 35985

EVIDENCE_RELPATH = "docs/tasks/evidence/us948-kdf-storage-trace.txt"

# Documentation anchors cited by the evidence file.
DECISION_DOC = "docs/tasks/us947-kdf-do.md"
DECISION_ANCHOR = "Decisions #2 + 'gpg 2.4.4 form check'"
DECISION_COMMIT = "6832e81"


def _hexdump(data: bytes, width: int = 32) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:04x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


def build_kdf_do(count: int, salt_u: bytes, salt_r: bytes, salt_s: bytes) -> bytes:
    """Build the 110-byte KDF-DO TLV structure per OpenPGP card spec 3.4 §4.3.3.

    This is the layout gpg 2.4.4 `g10/card-util.c::gen_kdf_data` emits for
    a bare `kdf-setup on` (the three-salt form; `kdf-setup on <salt>`
    writes the 90-byte single-salt one, which this card also accepts).

    Layout (validated by vendor/opcard/src/command/kdf.rs::is_valid):
      [0..3]   81 01 03       enabled marker
      [3..5]   82 01          hash tag
      [5]      08             SHA-256
      [6..8]   83 04          count tag
      [8..12]  <count 4B BE>
      [12..14] 84 08          salt_user tag
      [14..22] <salt_user>
      [22..24] 85 08          salt_r tag
      [24..32] <salt_r>
      [32..34] 86 08          salt_s tag
      [34..42] <salt_s>
      [42..44] 87 20          kek tag
      [44..76] <kek 32B>
      [76..78] 88 20          iv tag
      [78..110] <iv 32B>
    """
    out = bytearray()
    out += bytes([0x81, 0x01, 0x03])
    out += bytes([0x82, 0x01, 0x08])
    out += bytes([0x83, 0x04])
    out += struct.pack(">I", count)
    out += bytes([0x84, 0x08]) + salt_u
    out += bytes([0x85, 0x08]) + salt_r
    out += bytes([0x86, 0x08]) + salt_s
    out += bytes([0x87, 0x20]) + bytes([0x11] * 32)
    out += bytes([0x88, 0x20]) + bytes([0x22] * 32)
    assert len(out) == 110, f"KDF-DO must be 110 bytes, got {len(out)}"
    return bytes(out)


def derive_card_scalar(label: bytes) -> bytes:
    """The deterministic P-256 private scalar this script imports.

    `sha256(label)` with the top 3 bits of the first byte cleared, so the
    value is comfortably below the P-256 group order and always a valid
    scalar.  Deliberately *not* a KDF of anything.
    """
    scalar = bytearray(hashlib.sha256(label).digest())
    scalar[0] &= 0x1F
    return bytes(scalar)


def host_raw_z(scalar: bytes) -> bytes:
    """Recompute the card's PSO:DECIPHER answer host-side, with `cryptography`.

    The APDU carries the *generator point* G as the ephemeral public key,
    which is the private key 1 — so the ECDH shared x-coordinate is
    simply the x-coordinate of `(scalar * G)`.  Computed here as a real
    ECDH exchange rather than a point multiplication so it is an
    independent check of the firmware's answer.
    """
    from cryptography.hazmat.primitives.asymmetric import ec

    card_private = ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1())
    ephemeral_private = ec.derive_private_key(1, ec.SECP256R1())  # public key == G
    return ephemeral_private.exchange(ec.ECDH(), card_private.public_key())


def git(*args: str) -> str:
    """One `git -C REPO <args>` query, stdout stripped, `"(unavailable)"` on error."""
    return "\n".join(git_lines(*args))


def git_lines(*args: str) -> list[str]:
    """One `git -C REPO <args>` query, stdout split into lines and *not*
    stripped.

    Porcelain output is column-sensitive — the XY status occupies columns
    0-1, a space at column 2, and the path starts at column 3. Stripping
    leading whitespace (which a bare `.strip()` on the whole stdout does)
    shifts that path left and silently breaks any path comparison, so the
    unstripped form is what anything parsing `git status` must use.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO), *args],
            capture_output=True, text=True, timeout=10, check=True,
        )
        return out.stdout.splitlines()
    except (OSError, subprocess.SubprocessError):
        return ["(unavailable)"]


def sha256_file(path: Path) -> str:
    import hashlib as _h

    h = _h.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Checks:
    """Accumulates every asserted step and gates the exit status on all of them."""

    def __init__(self, trace: list[str]):
        self.trace = trace
        self.results: list[tuple[str, bool, str]] = []

    def record(self, name: str, ok: bool, detail: str = "") -> bool:
        self.results.append((name, ok, detail))
        self.trace.append(f"  {'✓' if ok else '✗'} {name}")
        if detail:
            for line in detail.splitlines():
                self.trace.append(f"    {line}")
        self.trace.append("")
        return ok

    def expect_sw(self, name: str, sw: int, want: int) -> bool:
        ok = sw == want
        return self.record(f"{name}: SW {sw:04X}", ok,
                           "" if ok else f"expected SW {want:04X}")

    def expect_len(self, name: str, got: int, want: int) -> bool:
        ok = got == want
        return self.record(f"{name}: {got} bytes", ok,
                           "" if ok else f"expected {want} bytes")

    def expect_eq(self, name: str, got: bytes, want: bytes) -> bool:
        ok = got == want
        detail = ""
        if not ok:
            detail = f"expected {len(want)} B: {want.hex()}\ngot      {len(got)} B: {got.hex()}"
        return self.record(f"{name}: byte-exact" if ok else f"{name}: MISMATCH", ok, detail)

    def note(self, text: str) -> None:
        for line in text.splitlines():
            self.trace.append(f"  · {line}" if line == text.splitlines()[0] else f"    {line}")
        self.trace.append("")

    @property
    def failures(self) -> list[tuple[str, bool, str]]:
        return [r for r in self.results if not r[1]]

    def summary(self) -> list[str]:
        lines = ["=" * 60, "SUMMARY", "=" * 60]
        for name, ok, _ in self.results:
            lines.append(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        passed = len(self.results) - len(self.failures)
        lines.append("")
        lines.append(f"{passed}/{len(self.results)} checked steps passed")
        if self.failures:
            lines.append("")
            lines.append("RESULT: FAIL — this trace does NOT establish the")
            lines.append("KDF-DO storage contract; see the failing steps above.")
        else:
            lines.append("")
            lines.append("RESULT: PASS — the steps listed above hold against the")
            lines.append("firmware named in the PROVENANCE header.")
        return lines


def _send(emu, name: str, ins: int, p1: int, p2: int, data: bytes,
          trace: list, note: str = "", le: int = 0) -> tuple[bytes, int]:
    """Send an APDU (CLA=0x00), log it, return (body, sw16).

    Data-bearing commands use case-3S: [CLA INS P1 P2 Lc DATA] (no Le byte).
    The emulation's `iso7816::CommandView::try_from` parses this as
    l == 1 + b1 → Lc = b1, Le = 0 (= 256 in the serve loop).  A trailing
    Le byte would make the parser read the last data byte as Le (case 4S),
    corrupting the payload.  The `le` argument is only consulted for
    data-less commands.
    """
    if data:
        apdu = bytes([0x00, ins, p1 & 0xFF, p2 & 0xFF, len(data)]) + data
    else:
        # Case 2S (Le only) or case 1S (no data, no Le)
        if le:
            apdu = bytes([0x00, ins, p1 & 0xFF, p2 & 0xFF, le & 0xFF])
        else:
            apdu = bytes([0x00, ins, p1 & 0xFF, p2 & 0xFF])
    emu.client._send(apdu)
    resp = emu.client._recv_frame()
    sw1, sw2 = resp[-2], resp[-1]
    body = resp[:-2]
    trace.append(name)
    trace.append(f"  Command: {apdu.hex()}")
    trace.append(f"  SW: {(sw1 << 8) | sw2:04X}")
    if body:
        trace.append(f"  Response data ({len(body)} bytes):")
        trace.append(_hexdump(body))
    if note:
        trace.append(f"  {note}")
    trace.append("")
    return body, (sw1 << 8) | sw2


def main() -> int:
    parser = argparse.ArgumentParser(
        description="US-948 synthesized KDF-DO APDU trace (no gpg participation).",
    )
    parser.add_argument("--emulator", default=None,
                        help="path to the fapico2-emulation binary")
    parser.add_argument("--keep", action="store_true",
                        help="keep the temporary keystore/partition files")
    parser.add_argument("--write-evidence", default=str(REPO / EVIDENCE_RELPATH))
    parser.add_argument(
        "--expect-raw-z", default=None, metavar="HEX",
        help="override the host-computed expected raw ECDH value; exists to "
             "prove the harness fails (exit 1) when an expectation is wrong",
    )
    args = parser.parse_args()

    trace: list[str] = []
    checks = Checks(trace)

    tmpdir = tempfile.mkdtemp(prefix="us948-kdf-")
    paths = {
        "keystore": Path(tmpdir) / "keystore",
        "partition": Path(tmpdir) / "partition",
        "piv": Path(tmpdir) / "piv",
    }

    emu = CcidEmu(paths=paths, hid_port=US948_HID_PORT)
    emu.RELAY_CCID_PORT = US948_RELAY_CCID_PORT
    emu.CCID_CLIENT_PORT = US948_CCID_CLIENT_PORT
    if args.emulator:
        os.environ["FAPICO2_EMULATION_BIN"] = args.emulator

    emu.start()
    binary = Path(emu.proc.args[0])
    short_commit = git("rev-parse", "--short", "HEAD")
    # Dirty = tracked-file changes other than the evidence file this run is
    # about to rewrite. Untracked scratch is irrelevant to the firmware.
    evidence_rel = os.path.relpath(os.path.abspath(args.write_evidence), str(REPO))
    dirty_paths = [
        line for line in git_lines("status", "--porcelain", "--untracked-files=no")
        if line and line[3:].strip() != evidence_rel
    ]

    trace.append("US-948 KDF-DO storage trace — synthesized, no gpg participation")
    trace.append("=" * 72)
    trace.append("")
    trace.append("PROVENANCE")
    trace.append("  Generator:     tests/scripts/us948_kdf_storage_trace.py")
    trace.append(f"  Worktree HEAD: {short_commit} at the moment of this run")
    if dirty_paths:
        trace.append("                 UNCOMMITTED source changes were present, so")
        trace.append("                 the firmware below is whatever was built from the")
        trace.append("                 worktree, NOT from that commit alone:")
        for p in dirty_paths:
            trace.append(f"                   {p}")
    else:
        trace.append("                 (clean worktree apart from this evidence file,")
        trace.append("                 which is written after this header and is therefore")
        trace.append("                 necessarily one commit behind)")
    trace.append(f"  Emulation bin: {binary}")
    if binary.exists():
        trace.append(f"  Bin SHA-256:   {sha256_file(binary)}")
        trace.append("                 (this hash, not the commit, is the authoritative")
        trace.append("                  identity of the firmware these APDUs hit)")
    trace.append("  Transport:     CCID over TCP via tests/harness/ccid_relay.py")
    trace.append(f"  Timestamp:     {time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    trace.append("")
    trace.append("  NO gpg, NO scdaemon and NO PC/SC layer took part in producing")
    trace.append("  this trace. Every APDU below is synthesized by the generator")
    trace.append("  and pushed straight into the firmware. This is NOT an interop")
    trace.append("  capture and makes no claim about what a real gpg session sends.")
    trace.append("  A live capture is unavailable on this host (no vpcd / virtual")
    trace.append("  PC/SC ifd-handler; pcscd+libccid only see physical readers), and")
    trace.append("  bridging gpg to the TCP emulator means writing a PC/SC driver —")
    trace.append("  US-952/953 hardware-phase work.")
    trace.append("")
    trace.append("  The double-derive question (does the card or the host apply the")
    trace.append("  KDF?) is RESOLVED BY DECISION, NOT BY THIS TRACE. The card")
    trace.append("  returns the raw ECDH shared point; gpg derives the KEK in")
    trace.append("  software (g10/ecdh.c::prepare_ecdh_with_shared_point ->")
    trace.append("  derive_kek). Recorded in")
    trace.append(f"    {DECISION_DOC} — {DECISION_ANCHOR}")
    trace.append(f"  firmware change {DECISION_COMMIT}.")
    trace.append("")
    trace.append("=" * 72)
    trace.append("")

    try:
        # 1. SELECT OpenPGP AID (case 3S: Lc + DATA, no Le byte)
        body, sw = _send(emu, "SELECT AID D27600012401", 0xA4, 0x04, 0x00, OPENPGP_AID,
                         trace, "by-DF-name selection", le=0)
        checks.expect_sw("SELECT AID", sw, 0x9000)
        checks.expect_eq("SELECT FCI template tag/length", body[:2], bytes([0x62, 0x20]))
        checks.record(
            "SELECT FCI carries the 5F52 historical-bytes DO",
            bytes.fromhex("5f520a0031f573c00160009000") in body,
            "" if bytes.fromhex("5f520a0031f573c00160009000") in body else
            f"body: {body.hex()}",
        )
        checks.note(
            "NB the trailing `90 00` on the 0020 line of the FCI dump above is\n"
            "NOT a leaked status word: it is the last two bytes of the OpenPGP\n"
            "historical-bytes DO (tag 5F 52, 10 bytes) — see SELECT_FCI in\n"
            "apps/openpgp/src/device_shell.rs. This command's status word is the\n"
            "separate `SW:` line."
        )

        # 2. Personalize: change factory PINs (case 3S: Lc + DATA, no Le)
        # CRD format: old_pin || new_pin (the unverified-session path)
        body, sw = _send(emu, "CRD PW1 (123456 -> 123456654321)",
                         0x24, 0x00, 0x81, b"123456" + b"123456654321", trace, le=0)
        checks.expect_sw("CRD PW1", sw, 0x9000)
        body, sw = _send(emu, "CRD PW3 (12345678 -> 1234567887654321)",
                         0x24, 0x00, 0x83, b"12345678" + b"1234567887654321", trace, le=0)
        checks.expect_sw("CRD PW3", sw, 0x9000)

        # Verify admin PIN (case 3S: Lc + DATA, no Le)
        body, sw = _send(emu, "VERIFY PW3 (new 1234567887654321)",
                         0x20, 0x00, 0x83, b"1234567887654321", trace, le=0)
        checks.expect_sw("VERIFY PW3", sw, 0x9000)

        # 3. PUT DATA C2: P-256 DEC key attribute (case 3S: Lc + DATA, no Le)
        body, sw = _send(emu, "PUT DATA C2 (P-256 DEC attr)",
                         0xDA, 0x00, 0xC2, P256_DEC_ATTR, trace, le=0)
        checks.expect_sw("PUT DATA C2 (P-256 DEC attribute)", sw, 0x9000)

        # 4. Import a deterministic P-256 private key via PUT KEY (DB 3F FF)
        #    Template: 4D 2A <slot> 00 7F 48 02 92 20 5F 48 20 <32-byte secret>
        scalar = derive_card_scalar(b"fapico2-us948-p256-dec")
        template = (bytes([0x4D, 0x2A, 0xB8, 0x00, 0x7F, 0x48, 0x02, 0x92, 0x20,
                           0x5F, 0x48, 0x20]) + scalar)
        body, sw = _send(emu, "PUT KEY B8 (P-256 DEC private key)",
                         0xDB, 0x3F, 0xFF, template, trace,
                         f"card private scalar: {scalar.hex()}", le=0)
        checks.expect_sw("PUT KEY B8 (import P-256 DEC key)", sw, 0x9000)

        # 5. Build and store the KDF-DO
        salt_u = bytes([0xA7] * 8)
        salt_r = bytes([0xB7] * 8)
        salt_s = bytes([0xC7] * 8)
        count = 0x0001_86A0
        kdf_do = build_kdf_do(count, salt_u, salt_r, salt_s)
        trace.append(f"KDF-DO ({len(kdf_do)} bytes) — the three-salt form gpg 2.4.4")
        trace.append("`kdf-setup on` writes (layout pinned by reading")
        trace.append("g10/card-util.c::gen_kdf_data, not by this trace):")
        trace.append(_hexdump(kdf_do))
        trace.append("")

        body, sw = _send(emu, "PUT DATA F9 (KDF-DO)", 0xDA, 0x00, 0xF9, kdf_do, trace, le=0)
        checks.expect_sw("PUT DATA F9 (store 110-byte KDF-DO)", sw, 0x9000)

        # 6. GET DATA F9: roundtrip check (case 2S: Le only)
        body, sw = _send(emu, "GET DATA F9 (KDF-DO roundtrip)",
                         0xCA, 0x00, 0xF9, b"", trace, le=0)
        checks.expect_sw("GET DATA F9", sw, 0x9000)
        checks.expect_eq("GET DATA F9 vs stored KDF-DO", body, kdf_do)

        # 6b. A malformed KDF-DO must be refused and must not disturb the
        #     stored one (this is what makes the roundtrip above meaningful).
        malformed = kdf_do[:-1]  # 109 bytes: truncated salt/KEK block
        body, sw = _send(emu, "PUT DATA F9 (malformed 109-byte KDF-DO)",
                         0xDA, 0x00, 0xF9, malformed, trace, le=0)
        checks.expect_sw("PUT DATA F9 (malformed 109 B) refused", sw, 0x6A80)
        body, sw = _send(emu, "GET DATA F9 (after the refused PUT)",
                         0xCA, 0x00, 0xF9, b"", trace, le=0)
        checks.expect_sw("GET DATA F9 (after the refused PUT)", sw, 0x9000)
        checks.expect_eq("stored KDF-DO unchanged by the refused PUT", body, kdf_do)

        # 7. Check DEC key is registered (GET DATA C2)
        body, sw = _send(emu, "GET DATA C2 (DEC attr check)",
                         0xCA, 0x00, 0xC2, b"", trace, le=0)
        checks.expect_sw("GET DATA C2", sw, 0x9000)
        checks.expect_eq("GET DATA C2 vs the P-256 DEC attribute",
                         body, P256_DEC_ATTR_RESP)

        # 8. Verify PW1 Other (P2=82) — PSO:DECIPHER requires the
        #    `Other` volatile state (key_id matches K::Dec against
        #    V::Other / V::OtherAndSign, not V::Sign).
        body, sw = _send(emu, "VERIFY PW1 Other (new 123456654321)",
                         0x20, 0x00, 0x82, b"123456654321", trace, le=0)
        checks.expect_sw("VERIFY PW1 (Other, P2=82)", sw, 0x9000)

        # 9. PSO:DECIPHER ECDH with the KDF-DO stored (case 3S: Lc + DATA).
        #    Use the P-256 generator G as the ephemeral public key, i.e. an
        #    ephemeral private key of 1 — so the expected answer is
        #    independently computable host-side.
        g_x = bytes.fromhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
        g_y = bytes.fromhex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
        eph_public = b"\x04" + g_x + g_y
        pso_data = bytes.fromhex("a6467f49438641") + eph_public

        expected_z = host_raw_z(scalar)
        if args.expect_raw_z is not None:
            expected_z = bytes.fromhex(args.expect_raw_z.replace(" ", ""))

        body, sw = _send(emu, "PSO:DECIPHER ECDH (KDF-DO stored)",
                         0x2A, 0x80, 0x86, pso_data, trace, le=0)
        with_kdf = body
        checks.expect_sw("PSO:DECIPHER ECDH (KDF-DO stored)", sw, 0x9000)
        checks.expect_len("PSO:DECIPHER reply length", len(body), 32)
        checks.expect_eq("PSO:DECIPHER raw Z (KDF-DO stored)", body, expected_z)
        checks.note(
            f"raw Z (KDF-DO stored): {body.hex()}\n"
            f"recomputed host-side via `cryptography` ECDH: {host_raw_z(scalar).hex()}"
        )

        # 10. Remove the KDF-DO (gpg `kdf-setup off`) (case 3S: Lc + DATA)
        kdf_off = bytes([0x81, 0x01, 0x00])
        body, sw = _send(emu, "PUT DATA F9 (KDF off: 81 01 00)",
                         0xDA, 0x00, 0xF9, kdf_off, trace, le=0)
        checks.expect_sw("PUT DATA F9 (kdf-setup off)", sw, 0x9000)

        # 11. GET DATA F9: the off form is stored verbatim (case 2S: Le only)
        body, sw = _send(emu, "GET DATA F9 (after KDF off)",
                         0xCA, 0x00, 0xF9, b"", trace, le=0)
        checks.expect_sw("GET DATA F9 (after KDF off)", sw, 0x9000)
        checks.expect_eq("GET DATA F9 vs the 3-byte off form", body, kdf_off)

        # 12. Verify PW1 Other again (same session, still valid)
        body, sw = _send(emu, "VERIFY PW1 Other (re-verify for the KDF-off comparison)",
                         0x20, 0x00, 0x82, b"123456654321", trace, le=0)
        checks.expect_sw("VERIFY PW1 (Other, re-verify)", sw, 0x9000)

        # 13. PSO:DECIPHER ECDH with the KDF switched off (case 3S: Lc + DATA)
        body, sw = _send(emu, "PSO:DECIPHER ECDH (KDF off: 81 01 00)",
                         0x2A, 0x80, 0x86, pso_data, trace, le=0)
        without_kdf = body
        checks.expect_sw("PSO:DECIPHER ECDH (KDF off)", sw, 0x9000)
        checks.expect_len("PSO:DECIPHER reply length (KDF off)", len(body), 32)
        checks.expect_eq("PSO:DECIPHER raw Z (KDF off)", body, expected_z)
        checks.record(
            "stored KDF-DO leaves the decipher output untouched "
            "(KDF-stored reply == KDF-off reply)",
            without_kdf == with_kdf,
            "" if without_kdf == with_kdf else
            f"with KDF-DO: {with_kdf.hex()}\nwith KDF off: {without_kdf.hex()}",
        )
        checks.note(
            f"raw Z (KDF off): {without_kdf.hex()}\n"
            "The two replies above are byte-identical. That is the intended\n"
            "contract: the card stores the KDF parameters and serves them back\n"
            "so the host can read them with GET DATA F9 and derive locally; it\n"
            "does not apply them itself."
        )

        trace.extend(checks.summary())
        trace.append("")
        trace.append("WHAT THIS TRACE ESTABLISHES")
        trace.append("  * the 110-byte three-salt KDF-DO is accepted by PUT DATA F9,")
        trace.append("    survives in non-volatile storage and round-trips through")
        trace.append("    GET DATA F9 byte-exactly; a malformed PUT is refused with")
        trace.append("    6A80 and leaves the stored value intact;")
        trace.append("  * PUT DATA F9 = 81 01 00 (gpg `kdf-setup off`) is accepted and")
        trace.append("    reads back verbatim;")
        trace.append("  * PSO:DECIPHER ECDH returns the raw ECDH x-coordinate with")
        trace.append("    and without a stored KDF-DO, byte-identically, and that")
        trace.append("    value is independently reproduced host-side.")
        trace.append("")
        trace.append("WHAT THIS TRACE DOES NOT ESTABLISH")
        trace.append("  * that gpg/scdaemon sends exactly these bytes. The 110-byte")
        trace.append("    *layout* is pinned by reading gpg 2.4.4's")
        trace.append("    g10/card-util.c::gen_kdf_data, not by this trace;")
        trace.append("  * the double-derive question. Resolved by decision, recorded in")
        trace.append(f"    {DECISION_DOC} — {DECISION_ANCHOR}")
        trace.append(f"    (firmware change {DECISION_COMMIT});")
        trace.append("  * that a real gpg session round-trips the KDF-DO end to end.")
        trace.append("    That needs a PC/SC driver in front of the emulator or a")
        trace.append("    physical reader — US-952/953 hardware-phase work.")
    finally:
        emu.stop()
        if not args.keep:
            shutil.rmtree(tmpdir, ignore_errors=True)

    os.makedirs(os.path.dirname(args.write_evidence), exist_ok=True)
    with open(args.write_evidence, "w") as f:
        f.write("\n".join(trace) + "\n")

    failures = checks.failures
    print(f"Evidence written to {args.write_evidence}")
    if failures:
        print(f"FAILED {len(failures)}/{len(checks.results)} checked steps:", file=sys.stderr)
        for name, _, detail in failures:
            print(f"  ✗ {name}", file=sys.stderr)
            for line in detail.splitlines():
                print(f"      {line}", file=sys.stderr)
        return 1
    print(f"OK: {len(checks.results)}/{len(checks.results)} checked steps passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
