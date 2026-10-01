#!/usr/bin/env python3
"""Reduce whatever `gh attestation download` produced to the SLSA statement.

WHY THIS EXISTS
---------------
The release workflow has to feed `check_release_provenance.py` (US-1063) and
`check_artefact_agreement.py` (US-1064) a build-provenance statement, and the
two things it was told to do were both wrong. It passed `--format jsonl
--output dist/provenance.jsonl`, and this version of `gh` has neither flag:
`gh attestation download` writes ONE file, named after the artefact's digest
(`sha256-<hex>.jsonl`), in the current directory. The step could never have
produced the path its two consumers were told to read.

The second problem is the shape of what comes back, and it is why this is a
script rather than a `cp`. `gh attestation download` does not hand back the
in-toto statement directly; it hands back a Sigstore BUNDLE, in which the
statement sits base64-encoded inside a DSSE envelope. The gates want the
statement. So the two have to be told apart rather than assumed.

Rather than guess which of the shapes a given run will produce, this accepts
all three and says which one it found, in the log, so the run records it:

  1. a bare in-toto/SLSA statement            -> used as-is
  2. one or more JSON lines, first with a
     `predicateType`                          -> used as-is
  3. a Sigstore bundle with `dsseEnvelope`
     -> the base64 `payload` is decoded and used

A bundle with no DSSE payload is REFUSED rather than guessed at: that is a
transparency-log entry or a keyless signature, not a build-provenance
statement, and silently passing something else to a gate that decides whether
to publish is the failure mode this whole release path exists to prevent.

USAGE
-----
    python3 tests/scripts/extract_provenance.py \
        --input sha256-abc123.jsonl --output dist/provenance.json
"""

import argparse
import base64
import json
import sys
import tempfile
from pathlib import Path

# The gates require this exact predicate type; accepting anything else would
# mean this script, not the policy, decided what was being published.
SLSA_PREDICATE = "https://slsa.dev/provenance/v1"


class Refusal(Exception):
    """The input is not a build-provenance statement. The message is the finding."""


def _looks_like_a_statement(doc: object) -> bool:
    return isinstance(doc, dict) and "predicateType" in doc


def _from_bundle(doc: dict) -> dict:
    """The statement inside a Sigstore bundle's DSSE envelope, decoded."""
    envelope = doc.get("dsseEnvelope")
    if not isinstance(envelope, dict):
        raise Refusal(
            "this is a Sigstore bundle with no `dsseEnvelope`, so it carries no "
            "signed statement — a transparency-log entry or a detached "
            "keyless signature, not build provenance. Refusing rather than "
            "handing a gate something it cannot check."
        )
    payload = envelope.get("payload")
    if not isinstance(payload, str) or not payload:
        raise Refusal("the bundle's `dsseEnvelope` has no `payload` to decode")
    try:
        decoded = base64.b64decode(payload, validate=True)
    except Exception as exc:  # noqa: BLE001 - the message is the finding
        raise Refusal(f"the DSSE payload is not valid base64: {exc}") from exc
    try:
        statement = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise Refusal(
            f"the DSSE payload decoded to {len(decoded)} bytes that are not "
            f"JSON: {exc}"
        ) from exc
    if not _looks_like_a_statement(statement):
        raise Refusal(
            "the DSSE payload decoded to JSON with no `predicateType`, so it "
            "is not an in-toto statement."
        )
    return statement


def extract(text: str) -> tuple[dict, str]:
    """Return (statement, which shape it was). Raise Refusal otherwise."""
    text = text.strip()
    if not text:
        raise Refusal("the downloaded file is empty — nothing was attested")

    # 1. A single JSON document: a bare statement, or a bundle.
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        doc = None
    if doc is not None:
        if _looks_like_a_statement(doc):
            return doc, "a bare in-toto statement"
        if isinstance(doc, dict) and "dsseEnvelope" in doc:
            return _from_bundle(doc), "a Sigstore bundle (dsseEnvelope.payload)"
        raise Refusal(
            "the downloaded JSON is neither a build-provenance statement "
            f"(no `predicateType`) nor a Sigstore bundle (no `dsseEnvelope`); "
            f"its top-level keys are {sorted(doc)[:8]}"
        )

    # 2. JSON Lines. gh writes one line per attestation, so the first
    #    line that is a statement is the one to check.
    lines = [ln for ln in text.splitlines() if ln.strip()]
    for n, line in enumerate(lines, start=1):
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError as exc:
            raise Refusal(f"line {n} is neither valid JSON nor part of a "
                          f"statement: {exc}") from exc
        if _looks_like_a_statement(candidate):
            return candidate, f"line {n} of {len(lines)} (jsonl)"
        if isinstance(candidate, dict) and "dsseEnvelope" in candidate:
            return (_from_bundle(candidate),
                    f"line {n} of {len(lines)} (jsonl, Sigstore bundle)")
    raise Refusal(
        f"none of the {len(lines)} JSON lines is a build-provenance statement "
        f"or a Sigstore bundle"
    )


def self_test() -> list[str]:
    """All three accepted shapes, and the refusals."""
    import base64 as b64
    problems: list[str] = []

    statement = {"predicateType": SLSA_PREDICATE,
                 "subject": [{"name": "fapico2.uf2", "digest": {"sha256": "ab"}}]}

    got, how = extract(json.dumps(statement))
    if got != statement or "bare" not in how:
        problems.append(f"a bare statement was not passed through ({how})")

    got, how = extract(json.dumps(statement) + "\n" + json.dumps(statement))
    if got != statement or "jsonl" not in how:
        problems.append(f"a jsonl statement was not passed through ({how})")

    payload = b64.b64encode(json.dumps(statement).encode()).decode()
    bundle = {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
              "dsseEnvelope": {"payload": payload,
                               "payloadType": "application/vnd.in-toto+json"}}
    got, how = extract(json.dumps(bundle))
    if got != statement or "bundle" not in how:
        problems.append(f"a DSSE bundle was not decoded ({how})")

    got, how = extract(json.dumps(bundle) + "\n" + json.dumps(bundle))
    if got != statement or "jsonl" not in how:
        problems.append(f"a jsonl of DSSE bundles was not decoded ({how})")

    # Refusals: the shapes a gate must never be handed silently.
    for name, bad in (
        ("empty file", "   "),
        ("not JSON", "this is not json at all"),
        ("a bundle with no DSSE envelope",
         json.dumps({"mediaType": "x", "verificationMaterial": {}})),
        ("a bundle whose payload is not base64",
         json.dumps({"dsseEnvelope": {"payload": "!!!not base64!!!"}})),
        ("a bundle whose payload is not a statement",
         json.dumps({"dsseEnvelope": {"payload": b64.b64encode(b'"hi"').decode()}})),
    ):
        try:
            extract(bad)
            problems.append(f"{name} was ACCEPTED")
        except Refusal:
            pass
    return problems


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--input", help="the file gh attestation download wrote")
    ap.add_argument("--output", help="where to write the statement (JSON)")
    args = ap.parse_args(argv[1:])

    if not (args.input and args.output):
        print("Reduce a downloaded attestation to a build-provenance statement "
              "(self-test when no paths are given)")
        problems = self_test()
        print("  ACCEPT  bare statement   — passed through unchanged")
        print("  ACCEPT  jsonl statement  — first statement line used")
        print("  ACCEPT  Sigstore bundle  — dsseEnvelope.payload base64-decoded")
        print("  ACCEPT  jsonl of bundles — same, on the first line that matches")
        print("  REFUSE  no statement     — empty, non-JSON, or a bundle with "
              "no DSSE payload")
        if problems:
            print()
            for p in problems:
                print(f"  FAIL: {p}")
            print("\nRESULT: FAIL")
            return 1
        print("\nRESULT: PASS")
        return 0

    try:
        statement, how = extract(Path(args.input).read_text(encoding="utf-8"))
    except (Refusal, OSError) as exc:
        print(f"  REFUSED: {exc}")
        print("\nRESULT: FAIL")
        return 1
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(statement, indent=2) + "\n", encoding="utf-8")
    ptype = statement.get("predicateType")
    if ptype != SLSA_PREDICATE:
        # Not fatal here — the provenance gate is where predicateType is
        # policy — but it belongs in the log either way.
        print(f"  note: predicateType is {ptype!r}; the US-1063 gate requires "
              f"{SLSA_PREDICATE!r}")
    print(f"  read {how}")
    print(f"  predicateType: {ptype}")
    print(f"  wrote {out} ({out.stat().st_size} B)")
    print("\nRESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
