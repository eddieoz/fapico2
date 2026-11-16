#!/usr/bin/env python3
"""Hardware-lane isolation gate (US-1906, EPIC HW-LANE-CONSENT).

Host-only, stdlib only (no third-party imports). Pins the boundary between
the repository's two test populations so it cannot rot silently:

  * the EMULATOR GATE — pytest-collected suites under tests/, socket-bound
    to 127.0.0.1:35962, structurally unable to reach a real board;
  * the DEVICE LANES — standalone scripts under redteam/, tests/hardware/,
    tests/soak/ and the tests/scripts device scripts, each wired to the
    first real hidraw/PC-SC/pyusb device on the host, several of them
    deliberately burning PIN retries.

The 2026-11-16 incident (production board PIN-locked and wiped) happened
because nothing in the tree distinguished the two populations. This gate
keeps the distinction enforced:

Rule 1 — guarded inventory.
    Every file on GUARDED must contain a real (non-comment) hw_guard.require
    call, positioned in its first executable region: before the first
    module-level (column 0) device-capable import. Every other .py file
    under redteam/, tests/hardware/ and tests/soak/ must be on EXEMPT with
    a reason — a new device-lane script without the guard fails here rather
    than shipping as one more unguarded hidraw opener. The swept
    directories deliberately do NOT include tests/scripts/ (it holds the
    gate scripts themselves); its device scripts are pinned by list
    membership alone, so a new one there must be added to GUARDED by hand —
    a visible boundary, not an assumed one (see the epic's residuals: the
    scripts/probe_*.py lanes are also outside this gate, on purpose, for
    now).

Rule 2 — collected tests are clean.
    No pytest-collected file (test_*.py / *_test.py under tests/) may
    import — or even name — fido2.pcsc or smartcard, or call .list_devices(
    at all, outside the entries on RULE2_ALLOW (each with a reason). The
    HID shim in tests/conftest.py is the only legitimate list_devices site
    and conftest files are not collected — rule 3 covers conftest.py
    separately.

Rule 3 — the fallback stays closed.
    tests/conftest.py must contain no CtapPcscDevice reference at all. The
    US-1907 removal turned the PC/SC fallback from dead-by-luck into
    refused-by-construction; this rule makes re-introducing it a red gate,
    not a re-armed trap.

Why text, not import
--------------------
Like its sibling gates, this is a source scan, not an execution: importing
a device-lane script to inspect it would run exactly the code the gate
forbids. The scan strips comments and docstrings with a line-preserving
lexer (positions survive, so reports name real lines), which is the same
comment-discipline check_persist_gate.py uses. The residual the epic
records applies here too: an obfuscated enumeration hidden inside an
imported helper called after consent is beyond a name gate.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# --- Rule 1: the guarded inventory ----------------------------------------
# (path, tier note) — the union of US-1903 (redteam/), US-1904 (tests/scripts
# device lane) and US-1905 (tests/hardware/ + tests/soak/), EPIC
# HW-LANE-CONSENT. The tier is documentation: destructive legs also require
# the TTY + typed-YES step, enforced by hw_guard itself.
GUARDED: tuple[tuple[str, str], ...] = (
    # redteam/ — the directory that exists to attack a device
    ("redteam/pin_attack.py", "destructive: deliberate wrong-PIN legs"),
    ("redteam/pin_recover.py", "destructive: PIN counter power-cycle legs"),
    ("redteam/timing.py", "destructive: timed wrong-PIN attempts"),
    ("redteam/hid_fuzz.py", "destructive: HID fuzzing of the live CTAPHID channel"),
    ("redteam/fido_malleability.py", "destructive: FIDO malleability exploits"),
    ("redteam/oath_exploit.py", "destructive: OATH exploit legs"),
    ("redteam/otp_exploit.py", "destructive: OTP exploit legs"),
    ("redteam/pgp_malleability.py", "destructive: OpenPGP malleability exploits"),
    ("redteam/recon.py", "probe: enumerates identity on every interface"),
    ("redteam/reboot_retry.py", "probe: unauthenticated reboot leg"),
    ("redteam/hid_framing.py", "probe: CTAPHID framing"),
    ("redteam/hid_reassembly.py", "probe: CTAPHID reassembly"),
    ("redteam/ctaphid.py", "helper, also executed: raw CTAPHID client"),
    ("redteam/ctap_raw.py", "probe: raw CTAP frames"),
    ("redteam/ctap2_probe.py", "probe: CTAP2 surface"),
    ("redteam/oath_probe.py", "probe: OATH over CCID"),
    ("redteam/otp_probe.py", "probe: OTP over HID"),
    ("redteam/pgp_probe.py", "probe: OpenPGP over CCID"),
    ("redteam/vendor41_probe.py", "probe: RS-Key vendor channel"),
    ("redteam/ccid.py", "helper, also executed: raw CCID client"),
    # tests/scripts — the acceptance-ladder device scripts
    ("tests/scripts/p7_b1_oath.py", "probe: OATH ladder row"),
    ("tests/scripts/p7_c2_ceremony.py", "destructive: ceremony + wrong-PIN legs"),
    ("tests/scripts/p7_c6_openpgp.py", "probe: OpenPGP ladder row"),
    ("tests/scripts/p7_d1_fido.py", "destructive: get_pin_token('1234') burns an attempt per run"),
    ("tests/scripts/p7_d1_mgmt.py", "probe: mgmt applet ladder row"),
    ("tests/scripts/p7_d1_oath.py", "probe: OATH over pyscard"),
    ("tests/scripts/p7_d2_fido.py", "destructive: get_pin_token('1234') burns an attempt per run"),
    ("tests/scripts/p7_d2_mgmt.py", "probe: mgmt over pyusb CCID"),
    ("tests/scripts/p7_d2_oath.py", "probe: OATH over pyusb CCID"),
    ("tests/scripts/p7_d2_preflight.py", "probe: read-only preflight"),
    ("tests/scripts/p7_d2_replug.py", "probe: replug detection"),
    ("tests/scripts/p8_rng_starve.py", "destructive: TRNG starvation on the live board"),
    ("tests/scripts/soak_24h.py", "destructive: 24 h unattended hardware run"),
    ("tests/scripts/s721-5-hardware-test.py", "probe: S-721-5 acceptance run"),
    ("tests/scripts/us933_pull_trace.py", "probe: vendor-channel pull trace"),
    ("tests/scripts/us933_replay.py", "probe: vendor-channel replay"),
    ("tests/scripts/us948_kdf_storage_trace.py", "probe: KDF storage trace"),
    ("tests/scripts/pull_boot_timeline.py", "probe: boot timeline capture"),
    ("tests/scripts/ccid_usb.py", "probe: raw CCID-over-USB APDU client (kernel driver detach)"),
    # tests/hardware — the hardware BDD lane
    ("tests/hardware/redteam_hw_bdd.py", "destructive: N1/N2 forged-pinUvAuth PIN-attack legs"),
    ("tests/hardware/us928_wipe_reprobe.py", "destructive: wipe leg"),
    ("tests/hardware/pso_touch_bdd.py", "probe: presence BDD"),
    ("tests/hardware/us927_prompt_reprobe.py", "probe: touch prompt re-probe"),
    ("tests/hardware/us1301_cycle.py", "probe: REBOOT/BOOTSEL + reflash cycle"),
    ("tests/hardware/boot_time_probe.py", "probe: boot timing (guard under __main__ — imported by test_boot_ladder.py)"),
    ("tests/hardware/store_marker.py", "probe: store marker set/check"),
    ("tests/hardware/probe_preflight.py", "probe: USB bus enumeration"),
    # tests/soak
    ("tests/soak/soak.py", "destructive on --transport usb only (guard is transport-conditional by design, US-1905)"),
)

# Files under the swept directories that open no device and take no guard.
EXEMPT: tuple[tuple[str, str], ...] = (
    ("tests/hardware/test_boot_ladder.py",
     "pure function test of the boot-ladder classifier — opens no device, "
     "pytest-collected on purpose (US-1905)"),
)

# --- Rule 2: collected tests must be clean of real-device machinery --------
# (relative path, RULE2_PATTERNS[0] entry, reason)
RULE2_ALLOW: tuple[tuple[str, str, str], ...] = (
    ("tests/pico-fido/test_093_backup.py", r"\.list_devices\(",
     "a MOCK over the fixture's own connection (setattr with a classmethod "
     "lambda) — never a real enumeration"),
    ("tests/harness/test_conftest_no_fallback.py", r"fido2\.pcsc",
     "the US-1907 poisoner itself: it plants a poisoned sys.modules entry so "
     "a fallback import cannot pass silently"),
    ("tests/scripts/test_gates.py", r"fido2\.pcsc",
     "the mutation harness: its nominated break for rule 3 carries the "
     "forbidden import as a string it writes into a throwaway repo COPY, "
     "never into this tree"),
)

RULE2_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"from\s+fido2\.pcsc\b", "imports fido2.pcsc"),
    (r"import\s+fido2\.pcsc\b", "imports fido2.pcsc"),
    (r"fido2\.pcsc", "names fido2.pcsc"),
    (r"from\s+smartcard\b", "imports smartcard"),
    (r"import\s+smartcard\b", "imports smartcard"),
    (r"\.list_devices\(", "calls .list_devices("),
)

# --- Rule 3: the fallback stays closed -------------------------------------
RULE3_FILE = "tests/conftest.py"
RULE3_PATTERN = "CtapPcscDevice"

# Module-level device-capable imports (column 0 only — lazy function-local
# imports are deliberately allowed: soak.py gates the usb transport inside
# main(), after argument parsing, and that is the sanctioned shape for a
# transport-conditional guard; boot_time_probe.py's guard sits under
# __main__ so pytest can import its pure functions).
RULE1_CONTACT = re.compile(
    r"^(?:from|import)\s+(?:fido2|smartcard|usb|serial|hid|ctaphid|ccid|pyscard|pyusb)\b",
    re.MULTILINE,
)
RULE1_GUARD = re.compile(r"^\s*hw_guard\.require\(", re.MULTILINE)

_DOC_MARKS = ("'''", '"""')


def _strip_comments_and_docstrings(text: str) -> str:
    """Blank out # comments and docstrings, preserving line structure."""
    out_lines: list[str] = []
    in_doc: str | None = None
    for line in text.splitlines():
        if in_doc is None:
            # earliest doc opener on the line (code before it is kept)
            best: tuple[int, str] | None = None
            for d in _DOC_MARKS:
                i = line.find(d)
                if i >= 0 and (best is None or i < best[0]):
                    best = (i, d)
            if best is not None:
                i, d = best
                close = line.find(d, i + 3)
                if close >= 0:  # single-line docstring: blank the whole tail
                    line = line[:i]
                else:
                    in_doc = d
                    line = line[:i]
            idx = line.find("#")
            if idx >= 0:
                line = line[:idx]
        else:
            close = line.find(in_doc)
            if close >= 0:
                line = " " * close  # keep column positions, code after is rare
                in_doc = None
            else:
                line = ""
        out_lines.append(line)
    return "\n".join(out_lines)


def main() -> int:
    offenders: list[str] = []

    # ---- Rule 1 -----------------------------------------------------------
    guarded_names = {path for path, _ in GUARDED}
    for rel, tier in GUARDED:
        path = REPO_ROOT / rel
        if not path.exists():
            offenders.append(
                f"{rel}: listed in the guarded inventory but missing from the tree")
            continue
        stripped = _strip_comments_and_docstrings(
            path.read_text(encoding="utf-8"))
        guard = RULE1_GUARD.search(stripped)
        if guard is None:
            offenders.append(
                f"{rel}: no hw_guard.require call found (inventory tier: {tier})")
            continue
        contact = RULE1_CONTACT.search(stripped)
        if contact is not None and contact.start() < guard.start():
            lineno = stripped[:contact.start()].count("\n") + 1
            offenders.append(
                f"{rel}:{lineno}: module-level device-capable import "
                f"({contact.group(0).strip()}) precedes the hw_guard.require "
                "call; the guard must be the first executable statement (US-1902)")

    swept_files: list[str] = []
    for sub in ("redteam", os.path.join("tests", "hardware"), os.path.join("tests", "soak")):
        d = REPO_ROOT / sub
        for p in sorted(d.glob("*.py")):
            swept_files.append(str(p.relative_to(REPO_ROOT)))
    exempt_names = {path for path, _ in EXEMPT}
    for rel in swept_files:
        if rel not in guarded_names and rel not in exempt_names:
            offenders.append(
                f"{rel}: unlisted .py under the swept directories — add it to "
                "GUARDED with a tier note (it opens a real device) or to EXEMPT "
                "with a reason (it opens none); an unlisted device-lane script "
                "is the incident's original shape")

    # ---- Rule 2 -----------------------------------------------------------
    tests_dir = REPO_ROOT / "tests"
    collected = sorted(
        p for p in tests_dir.rglob("*.py")
        if p.name.startswith("test_") or p.name.endswith("_test.py")
    )
    rule2_allow = {f for f, _pat, _reason in RULE2_ALLOW}
    for p in collected:
        rel = str(p.relative_to(REPO_ROOT))
        stripped = _strip_comments_and_docstrings(
            p.read_text(encoding="utf-8", errors="replace"))
        for lineno, line in enumerate(stripped.splitlines(), 1):
            for pat, label in RULE2_PATTERNS:
                if re.search(pat, line):
                    if rel in rule2_allow:
                        # file-scoped: the harness's nominated-break strings
                        # live as literals in test_gates.py and can match any
                        # of the patterns, not just the documented one
                        continue
                    offenders.append(
                        f"{rel}:{lineno}: collected test {label} — the emulator "
                        "gate never attaches to real hardware (rule 2)")
    for rel, _pat, _reason in RULE2_ALLOW:
        if not (REPO_ROOT / rel).exists():
            offenders.append(f"{rel}: rule-2 allowlist entry names a missing file")

    # ---- Rule 3 -----------------------------------------------------------
    conftest = (REPO_ROOT / RULE3_FILE).read_text(encoding="utf-8")
    if RULE3_PATTERN in conftest:
        for lineno, line in enumerate(conftest.splitlines(), 1):
            if RULE3_PATTERN in line:
                offenders.append(
                    f"{RULE3_FILE}:{lineno}: {RULE3_PATTERN} reference found — the "
                    "PC/SC fallback was removed in US-1907 and must stay removed; "
                    "a hidden fallback re-arms test_010_pin.py on a real board")
                break

    # ---- report -----------------------------------------------------------
    print(f"  guarded inventory: {len(GUARDED)} file(s), exempt: {len(EXEMPT)} "
          f"file(s), collected tests scanned: {len(collected)}")
    for rel, tier in GUARDED:
        print(f"  [GUARD] {rel} [{tier}]")
    for rel, reason in EXEMPT:
        print(f"  [EXEMPT] {rel}: {reason}")
    for rel, _pat, reason in RULE2_ALLOW:
        print(f"  [RULE2-ALLOW] {rel}: {reason}")
    for o in offenders:
        print(f"  [FAIL] {o}")
    if offenders:
        print(
            f"\nRESULT: FAIL ({len(offenders)} isolation violation(s) — a device "
            "lane is unguarded or unlisted, a collected test reaches real-device "
            "machinery, or the conftest PC/SC fallback is back. See EPIC "
            "HW-LANE-CONSENT: docs/tasks/EPIC-hardware-lane-consent.md)"
        )
        return 1
    print("\nRESULT: PASS (hardware-lane isolation gate green)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
