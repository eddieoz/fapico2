#!/usr/bin/env python3
"""Attestation-provisioning gate for SECURE-HARDENING (US-916) + US-175.

Host-only, stdlib only (no third-party imports), comment-aware like
``check_persist_gate.py``. Structural proof that the per-device attestation
identity provisioning (US-916) holds:

    the attestation identity (P-256 key + self-signed cert) is minted ON
    DEVICE from the platform TRNG at first boot and persisted through the
    secure store (``fido.attestation.v1.*`` slots). No repo-committed
    attestation material may ship in the tree or be compiled into an image:

        apps/fido/src/attestation_key.bin  — the old repo static scalar (deleted)
        apps/fido/src/attestation_cert.der — the old repo static cert (deleted)
        include_bytes!                     — must stay out of *code* in
                                            ANY apps/fido/src/**/*.rs module
        the static scalar itself           — the deleted key's raw bytes and
                                            its hex digest must not appear
                                            in ANY apps/fido/src file

If either binary blob reappears anywhere in the tree, ``include_bytes!``
reappears in code anywhere under ``apps/fido/src/`` (US-925 review: scoped
to one file, material re-committed in another module passed), or the static
scalar — raw bytes or its hex digest — reappears in any ``apps/fido/src``
file, the gate trips.

Two attestation identities (US-175)
-----------------------------------

US-175 added a SECOND attestation identity, so everything above now describes
one of two, and the gate's job grew with them: it must not mistake the org
slot for the per-device one, in either direction.

    | | per-device (``US-916``) | organisation (``US-175``) |
    |---|---|---|
    | module | ``apps/fido/src/attestation.rs`` | ``apps/fido/src/vendor_att.rs`` |
    | key + cert | ``fido.attestation.v1.key`` / ``.cert`` — platform ``SecureStore`` slots | vendor snapshot auth-map keys 7 and 8 (``AUTH_KEY_SECRET`` / ``AUTH_KEY_PUBLIC``) |
    | minted | on the device at first boot, from the TRNG | by the HOST, in a PEM/DER file |
    | provisioned via | ``attestation::provision`` (boot path) | ``ATT_IMPORT`` (``SUB_ATT_IMPORT`` = ``0x09``) over the ``0x41`` channel |
    | consumed by | FIDO2 ``makeCredential`` (``packed``) and the U2F register path | the ``0x41`` attestation surface |

The layering rule the EPIC records (US-175) is that org attestation LAYERS ON
the per-device identity and never replaces it: *"a device with no org cert
imported must still mint normal FIDO2 attestations."* The checks below assert
that separation structurally, so the gate holds it even where the behavioural
regression test cannot run:

    distinct storage      — the per-device slot namespace is declared in
                            exactly one place, and the org half of the tree
                            never names it;
    no cross-reach        — ``vendor_att.rs`` does not read the per-device
                            slots, and the per-device modules do not name the
                            ``0x41`` channel or the org slot;
    no FIDO2 substitution — nothing on the ``makeCredential`` / U2F sign path
                            may touch the org credential, so an org cert can
                            never end up in a ``packed`` statement's ``x5c``;
    distinct provisioning — the two entry points are separate functions on
                            separate channels and neither file carries the
                            other's.

Comment-aware (mandatory): Rust line comments (``//``, ``///``, ``//!``)
and block comments (``/* */``, nestable) are stripped BEFORE matching,
because the module docs may mention the deleted files while explaining the
design. A comment-only mention is legal; a code-level occurrence is not.
Ordinary string literal contents are dropped so a name inside a literal is
not treated as code (raw string literals are a documented false-positive
caveat, as in ``check_persist_gate.py``).

Exit status: 0 when the tree is clean (green), 1 otherwise (red, with a
per-file report).

Usage:
    python3 tests/scripts/check_attestation_gate.py [scan-root-dir]

``scan-root-dir`` defaults to the repository root (the parent of the
``tests/`` directory).
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

# tests/scripts/check_attestation_gate.py -> parents[2] == fapico2/
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ROOT = REPO_ROOT

# The repo-committed attestation blobs US-916 deleted. Any re-appearance
# (anywhere in the tree) is a violation: attestation material is minted on
# the device, never committed.
FORBIDDEN_BLOBS = (
    "attestation_key.bin",
    "attestation_cert.der",
)

# The one place include_bytes! is banned from in *code*: every Rust module
# under apps/fido/src (US-925 review — not just attestation.rs).
FIDO_SRC = Path("apps") / "fido" / "src"
INCLUDE_BAN = "include_bytes!"

# US-925: the deleted repo-committed static scalar (EPIC / red-team out
# artifacts, redteam/out/attestation_key.hex). Banned both as raw bytes (a
# re-committed blob, renamed or not) and as its hex digest (a hex literal
# re-embedded in a Rust source).
#
# Why the forbidden value is written down here: a blocklist has to contain the
# thing it forbids. This scalar cannot be a secret any more, and holding it
# costs nothing:
#
#   * it was compiled into a firmware image that anyone could download, so it
#     has been public since before this repository existed;
#   * the red-team round that extracted it rotated it out of the build — the
#     current firmware generates per-device attestation keys from the TRNG
#     (see docs/SECURITY-ASSESSMENT-ROUND2.md §14.1, R4);
#   * every credential that was ever attested under it is therefore forgeable
#     by anyone, which is a fact about the past that cannot be un-published.
#
# So this is a *fingerprint of a known-bad value*, not live key material. The
# gate's job — fail if the bytes or their hex reappear anywhere in the tree —
# is impossible without it, and it is the only reason the value is here.
SCALAR_DIGEST_HEX = "c7b2f6c5b901ffaa8bc977ff98641087fceba59bcc1a738149e90f548e982287"
SCALAR_RAW = bytes.fromhex(SCALAR_DIGEST_HEX)
SCALAR_HEX_NEEDLES = (
    SCALAR_DIGEST_HEX.encode("ascii"),
    SCALAR_DIGEST_HEX.upper().encode("ascii"),
)

# Directories that never hold hand-written source / gate-relevant material.
SKIP_DIRS = {".git", "target", ".test-venv", ".serena", "node_modules", ".cargo"}

# ---------------------------------------------------------------------------
# US-175: the two attestation identities. Every name below is relative to the
# scan root, so the same rules apply whatever root the caller passes.
# ---------------------------------------------------------------------------

# The per-device identity: apps/fido/src/attestation.rs (+ its cert builder).
PER_DEVICE_MOD = Path("apps/fido/src/attestation.rs")
PER_DEVICE_CERT_MOD = Path("apps/fido/src/attestation_cert.rs")

# The organisation identity: apps/fido/src/vendor_att.rs (the 0x41 sub-commands)
# over the storage it reaches through apps/fido/src/vendor_state.rs.
ORG_MOD = Path("apps/fido/src/vendor_att.rs")
ORG_STATE_MOD = Path("apps/fido/src/vendor_state.rs")
ORG_HALF = (
    ORG_MOD,
    ORG_STATE_MOD,
    Path("apps/fido/src/vendor41.rs"),
)

# The per-device slots, and the namespace they live in. Read from the source
# rather than hardcoded so a rename is a one-place edit, then asserted to be
# single-owner (declared in exactly one module) and absent from the org half.
PER_DEVICE_SLOT_CONSTS = ("ATTEST_KEY_SLOT", "ATTEST_CERT_SLOT")
PER_DEVICE_SLOT_NS = "fido.attestation.v1."

# The org half's storage: two numeric auth-map keys, not a slot name. Kept
# distinct from the slot namespace above, so neither half can address the
# other's material.
ORG_AUTH_KEYS = {"AUTH_KEY_SECRET": 7, "AUTH_KEY_PUBLIC": 8}

# Names only the organisation half of the tree may use. Reached by an
# attestation-statement path, an org cert would replace every relying party's
# per-device trust anchor (US-175 layering rule).
ORG_ONLY_NEEDLES = (
    "org_attestation",     # VendorOps accessor / VendorState setter
    "OrgAttestation",      # the imported credential and its view
    "org_chain",           # the DER chain inside the vendor snapshot
    "AUTH_KEY_SECRET",     # vendor snapshot auth-map key 7
    "AUTH_KEY_PUBLIC",     # vendor snapshot auth-map key 8
)

# What the org module must not say about the per-device identity. A `//!` doc
# link naming ATTEST_KEY_SLOT is legal (comments are stripped first); code is
# not.
PER_DEVICE_NEEDLES = (
    "ATTEST_KEY_SLOT",
    "ATTEST_CERT_SLOT",
    "use crate::attestation",
    "crate::attestation::",
)

# ...and the mirror image: the per-device modules must not name the 0x41
# channel or the org slot at all.
PER_DEVICE_BAN = ORG_ONLY_NEEDLES + ("vendor41", "vendor_att")

# The modules that build the FIDO2 attestation statement — the `packed`
# attStmt for makeCredential and the U2F registration response. None of them
# may touch the org credential.
FIDO2_ATTESTATION_PATH = (
    PER_DEVICE_MOD,
    PER_DEVICE_CERT_MOD,
    Path("apps/fido/src/app.rs"),
    Path("apps/fido/src/u2f.rs"),
)

# The two provisioning entry points, and the 0x41 sub-commands that name the
# org one. US-175: ATT_STATE 11 / ATT_CLEAR 10 / ATT_IMPORT 9.
ORG_PROVISION = ("SUB_ATT_IMPORT", "SUB_ATT_CLEAR", "SUB_ATT_STATE")
ORG_PROVISION_ENTRY = "att_import"
PER_DEVICE_PROVISION_ENTRY = "pub fn provision"
ORG_SUB_COMMAND_VALUES = {
    "SUB_ATT_IMPORT": "0x09",
    "SUB_ATT_CLEAR": "0x0A",
    "SUB_ATT_STATE": "0x0B",
}


def strip_comments(src: str) -> str:
    """Strip Rust line and block comments (and ordinary string contents).

    Identical state machine to ``check_persist_gate.py``: line numbers are
    preserved for all ordinary comments and strings, block-comment nesting
    (a Rust extension) is tracked, and ordinary string literal bodies are
    dropped so a ``//`` inside a string is not mistaken for a comment and a
    forbidden name inside a literal is not treated as code. Raw string
    literals (``r#"..."#``) are a documented caveat (no such literal in
    ``attestation.rs``).
    """
    out: list[str] = []
    i = 0
    n = len(src)
    in_line = False
    in_block = 0
    in_string = False
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if in_line:
            if c == "\n":
                in_line = False
                out.append(c)
            i += 1
            continue
        if in_block:
            if c == "/" and nxt == "*":
                in_block += 1
                i += 2
                continue
            if c == "*" and nxt == "/":
                in_block -= 1
                i += 2
                continue
            if c == "\n":
                out.append(c)  # preserve line numbering across multi-line blocks
            i += 1
            continue
        if in_string:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            i += 1
            continue
        if c == "/" and nxt == "/":
            in_line = True
            i += 2
            continue
        if c == "/" and nxt == "*":
            in_block = 1
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _walk(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield Path(dirpath) / name


def _code_lines(root: Path, rel: Path) -> list[tuple[int, str]] | None:
    """Return ``(lineno, code_line)`` for `rel`, comments and string bodies
    stripped, or ``None`` if the file is absent.

    ``None`` is an *offender* at the call site, never a silent pass: a gate
    that cannot see the file it is asserting about must not report green.
    """
    path = root / rel
    if not path.is_file():
        return None
    code = strip_comments(path.read_bytes().decode("utf-8", errors="replace"))
    return list(enumerate(code.splitlines(), 1))


def _decl_line(root: Path, rel: Path, name: str) -> str | None:
    """The first code line in `rel` that declares `name`, or ``None``.

    String-literal *bodies* are dropped by :func:`strip_comments`, so a slot
    name written as ``b"fido.attestation.v1.key"`` comes back as ``b""``.
    Slot-literal checks therefore read the raw bytes (see :func:`_raw`), and
    this helper is for identifier declarations only.
    """
    lines = _code_lines(root, rel)
    if lines is None:
        return None
    for _, line in lines:
        if re.search(rf"\b(?:pub\s+)?const\s+{re.escape(name)}\b", line):
            return line
    return None


def _raw(root: Path, rel: Path) -> str:
    path = root / rel
    if not path.is_file():
        return ""
    return path.read_bytes().decode("utf-8", errors="replace")


def _rel_rust(root: Path, rel_dir: Path) -> list[Path]:
    """Every ``*.rs`` under ``root/rel_dir``, as root-relative sorted paths."""
    d = root / rel_dir
    if not d.is_dir():
        return []
    return sorted(p.relative_to(root) for p in d.rglob("*.rs"))


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else DEFAULT_ROOT
    print(f"scanning: {root}")
    if not root.is_dir():
        print("RESULT: FAIL (scan root missing)")
        return 1

    offenders: list[str] = []

    # 1) The deleted attestation blobs must not exist anywhere in the tree.
    for path in _walk(root):
        if path.name in FORBIDDEN_BLOBS:
            offenders.append(f"blob re-appearance: {path}")

    # 2) US-925: no code-level include_bytes! (or a forbidden blob filename)
    #    in ANY Rust module under apps/fido/src — attestation material
    #    re-committed in another module must not pass. US-925 also bans the
    #    static scalar itself from every apps/fido/src file, raw or as its
    #    hex digest (plain byte scan — kept fast).
    fido_src = root / FIDO_SRC
    if fido_src.is_dir():
        for path in sorted(fido_src.rglob("*.rs")):
            raw = path.read_bytes()
            if SCALAR_RAW in raw:
                offenders.append(f"static scalar bytes: {path.relative_to(root)}")
            for needle in SCALAR_HEX_NEEDLES:
                if needle in raw:
                    offenders.append(f"static scalar hex digest: {path.relative_to(root)}")
            code = strip_comments(raw.decode("utf-8", errors="replace"))
            for lineno, line in enumerate(code.splitlines(), 1):
                if INCLUDE_BAN in line:
                    offenders.append(f"include_bytes! in code: {path.relative_to(root)}:{lineno}")
                if any(name in line for name in FORBIDDEN_BLOBS):
                    offenders.append(
                        f"forbidden blob name in code: {path.relative_to(root)}:{lineno}"
                    )
    else:
        offenders.append(f"missing fido source tree: {FIDO_SRC}")

    # 3) US-175: the two attestation identities live in distinct storage, and
    #    each is declared in exactly one module. A slot name duplicated into
    #    the org half (or vice versa) is the first step towards one identity
    #    overwriting the other.
    for const in PER_DEVICE_SLOT_CONSTS:
        decl = _decl_line(root, PER_DEVICE_MOD, const)
        if decl is None:
            offenders.append(f"per-device slot const not declared: {PER_DEVICE_MOD}:{const}")
        else:
            owners = [
                rel
                for rel in _rel_rust(root, FIDO_SRC)
                if _decl_line(root, rel, const) is not None
            ]
            if owners != [PER_DEVICE_MOD]:
                joined = ", ".join(str(o) for o in owners) or "<none>"
                offenders.append(
                    f"per-device slot {const} declared outside its owner "
                    f"{PER_DEVICE_MOD}: {joined}"
                )
            if PER_DEVICE_SLOT_NS not in _raw(root, PER_DEVICE_MOD):
                offenders.append(
                    f"per-device slot {const} is not in the "
                    f"{PER_DEVICE_SLOT_NS}* namespace: {PER_DEVICE_MOD}"
                )

    for rel in ORG_HALF:
        if _code_lines(root, rel) is None:
            offenders.append(f"missing org-attestation module: {rel}")
            continue
        if PER_DEVICE_SLOT_NS in _raw(root, rel):
            offenders.append(
                f"org half names the per-device slot namespace "
                f"({PER_DEVICE_SLOT_NS}*): {rel}"
            )
        for const in PER_DEVICE_SLOT_CONSTS:
            if _decl_line(root, rel, const) is not None:
                offenders.append(
                    f"org half re-declares the per-device slot {const}: {rel}"
                )

    for const, expected in ORG_AUTH_KEYS.items():
        decl = _decl_line(root, ORG_STATE_MOD, const)
        if decl is None:
            offenders.append(f"org auth-map key not declared: {ORG_STATE_MOD}:{const}")
        elif not re.search(rf"=\s*{expected}\b", decl):
            offenders.append(
                f"org auth-map key {const} is not {expected} (storage collided "
                f"with another snapshot field): {ORG_STATE_MOD}"
            )

    # 4) US-175: neither half reaches the other's storage. The per-device
    #    identity is not an org credential, and the org surface is not a
    #    reader of the per-device slots.
    for rel in (PER_DEVICE_MOD, PER_DEVICE_CERT_MOD):
        lines = _code_lines(root, rel)
        if lines is None:
            continue
        for lineno, line in lines:
            for needle in PER_DEVICE_BAN:
                if needle in line:
                    offenders.append(
                        f"per-device identity reaches the org channel: "
                        f"{rel}:{lineno} ({needle})"
                    )

    org_lines = _code_lines(root, ORG_MOD)
    if org_lines is None:
        pass  # already reported above
    else:
        for lineno, line in org_lines:
            for needle in PER_DEVICE_NEEDLES:
                if needle in line:
                    offenders.append(
                        f"org attestation reaches the per-device identity: "
                        f"{ORG_MOD}:{lineno} ({needle})"
                    )

    # 5) US-175 layering rule: the org credential must never satisfy a FIDO2
    #    attestation statement. On this path it would replace the per-device
    #    cert in every `packed` attStmt's x5c — a device with no org cert
    #    would still answer, so nothing else would notice.
    for rel in FIDO2_ATTESTATION_PATH:
        lines = _code_lines(root, rel)
        if lines is None:
            offenders.append(f"missing FIDO2 attestation-path module: {rel}")
            continue
        for lineno, line in lines:
            for needle in ORG_ONLY_NEEDLES:
                if needle in line:
                    offenders.append(
                        f"org credential reachable from the FIDO2 attestation "
                        f"path: {rel}:{lineno} ({needle})"
                    )

    # 6) US-175: the two provisioning paths are distinguishable in source —
    #    one TRNG-minted at boot, one host-imported over 0x41 — and neither
    #    file carries the other's entry point.
    if org_lines is not None:
        for const in ORG_PROVISION:
            decl = _decl_line(root, ORG_MOD, const)
            want = ORG_SUB_COMMAND_VALUES[const]
            if decl is None:
                offenders.append(f"org sub-command not declared: {ORG_MOD}:{const}")
            elif want not in decl:
                offenders.append(
                    f"org sub-command {const} is not {want}: {ORG_MOD}"
                )
        if any(PER_DEVICE_PROVISION_ENTRY in line for _, line in org_lines):
            offenders.append(
                f"org module re-implements per-device provisioning "
                f"({PER_DEVICE_PROVISION_ENTRY}): {ORG_MOD}"
            )

    for rel in (PER_DEVICE_MOD, PER_DEVICE_CERT_MOD):
        lines = _code_lines(root, rel)
        if lines is None:
            continue
        for lineno, line in lines:
            for needle in ORG_PROVISION + (ORG_PROVISION_ENTRY,):
                if needle in line:
                    offenders.append(
                        f"per-device identity carries the org provisioning path: "
                        f"{rel}:{lineno} ({needle})"
                    )

    per_device_lines = _code_lines(root, PER_DEVICE_MOD)
    if per_device_lines is not None and not any(
        PER_DEVICE_PROVISION_ENTRY in line for _, line in per_device_lines
    ):
        offenders.append(
            f"per-device provisioning entry point missing: "
            f"{PER_DEVICE_MOD} ({PER_DEVICE_PROVISION_ENTRY})"
        )

    for off in offenders:
        print(f"  [FAIL] {off}")
    if offenders:
        n = len(offenders)
        print(
            f"\nRESULT: FAIL ({n} attestation-provisioning violation(s) — "
            "attestation material must be minted on device (US-916), not "
            "committed or include_bytes!-ed; the per-device (US-916) and org "
            "(US-175) identities must stay in separate storage)"
        )
        return 1
    print("  [PASS] no attestation_key.bin / attestation_cert.der blobs in the tree")
    print(f"  [PASS] no code-level include_bytes! / blob name under {FIDO_SRC}/**/*.rs")
    print(f"  [PASS] static scalar absent from {FIDO_SRC} (raw bytes and hex digest)")
    print(
        f"  [PASS] per-device slots single-owner in {PER_DEVICE_MOD} "
        f"({PER_DEVICE_SLOT_NS}*), absent from the org half"
    )
    print(
        f"  [PASS] org storage is the vendor snapshot's auth-map keys "
        f"{'/'.join(str(v) for v in ORG_AUTH_KEYS.values())} "
        f"({ORG_STATE_MOD}), not a per-device slot"
    )
    print(
        "  [PASS] neither half reaches the other's storage ("
        + " / ".join(str(r) for r in (ORG_MOD, PER_DEVICE_MOD, PER_DEVICE_CERT_MOD))
        + ")"
    )
    print(
        "  [PASS] org credential absent from the FIDO2 attestation path "
        "(makeCredential / U2F register)"
    )
    print(
        f"  [PASS] two distinct provisioning paths: {PER_DEVICE_PROVISION_ENTRY} "
        f"({PER_DEVICE_MOD}, TRNG) vs ATT_IMPORT 0x09 ({ORG_MOD}, host over 0x41)"
    )
    print("\nRESULT: PASS (attestation-provisioning gate green)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
