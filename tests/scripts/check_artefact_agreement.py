#!/usr/bin/env python3
"""US-1064: the release fails when the UF2, the SBOM and the attestation disagree.

This is the story that makes the other three non-decorative. US-1062
publishes a component list, US-1063 publishes a signature and a provenance
statement, and neither of those says anything about the *other* one. A
release can easily produce three perfectly valid artefacts that describe
three different builds: the SBOM generated before a rebuild, the signature
over a UF2 that was then replaced, the attestation over yet another. Each
one verifies on its own. Together they are a lie.

So the release gate is pure logic over digests, and it is the half of
Phase 7 that can be — and is — verified here:

  A1  the artefact directory contains fapico2.uf2, sbom.cdx.json and a
      provenance statement. Anything missing is a refusal.
  A2  the UF2's sha256 equals the SBOM's recorded digest for it. The SBOM
      carries a `fapico2-firmware` component; the UF2 is what that
      component is BUILT into, so the release records the image digest
      alongside it and the two are compared here.
  A3  the UF2's sha256 equals the attestation's subject digest, and
      equals the sha256 recorded in the attestation's resolvedDependencies.
  A4  the signature verifies over the UF2 when cosign is available, and
      the signing certificate is the GitHub Actions identity.

Ties to US-1043: ci.yml's reproducible-build ratchet proves the committed
`firmware/fapico2.uf2` is a function of the source, and the release
workflow refuses to publish an artefact that is not that file. This gate
assumes both and checks the thing neither of them can: that the three
published documents describe the same bytes.

Running it
----------

With no arguments (what CI runs on every push) the gate exercises every
rule against committed fixtures in
`tests/scripts/fixtures/agreement/`, including the story's own red — a UF2
mutated after signing — and requires each negative control to be refused.
`--artifacts DIR` is the release mode.

WHAT IS NOT VERIFIED HERE: whether cosign is installed, so A4 is skipped
locally and reported as SKIPPED rather than as a pass. On a release runner
cosign is present (the workflow installs it) and A4 runs for real. A gate
that silently reports "verified" for a check it did not perform is the
decorative-gate failure this epic is about, so the skip is printed.

Stdlib only, Python 3.8+. Exit 0 on PASS, 1 on FAIL.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import certinfo  # noqa: E402  — sibling script, imported by path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "agreement"
UF2_NAME = "fapico2.uf2"
SBOM_NAME = "sbom.cdx.json"
IMAGE_DIGEST_KEY = "cdx:fapico2:uf2:sha256"


EXPECTED_WORKFLOW = ".github/workflows/release.yml"
EXPECTED_REPO = "eddieoz/fapico2"
GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"


def identity_regexp(repo: str, workflow: str) -> str:
    """The Fulcio SAN a keyless signature from THIS workflow must carry."""
    return "^https://github\\.com/" + re.escape(repo) + "/" + re.escape(workflow) + "@"


class Refusal(Exception):
    """A named agreement rule failed. The message is the finding."""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path):
    text = path.read_text(encoding="utf-8")
    # `gh attestation download --format jsonl` emits one statement per line.
    stripped = text.lstrip()
    if stripped.startswith("{") and "\n{" in text.strip():
        first = text.strip().splitlines()[0]
        try:
            return json.loads(first)
        except json.JSONDecodeError:
            pass
    return json.loads(text)


def sbom_image_digest(sbom: dict) -> str:
    """The recorded image digest, from the SBOM's own metadata properties."""
    for prop in sbom.get("metadata", {}).get("properties", []) or []:
        if prop.get("name") == IMAGE_DIGEST_KEY:
            value = str(prop.get("value", "")).strip().lower()
            if re.fullmatch(r"[0-9a-f]{64}", value):
                return value
            raise Refusal(
                f"the SBOM's {IMAGE_DIGEST_KEY} property is {value!r}, which "
                f"is not a sha256. A digest that cannot be compared is not a "
                f"digest."
            )
    raise Refusal(
        f"the SBOM carries no {IMAGE_DIGEST_KEY} property.\n"
        f"  The SBOM lists the crates the image is BUILT FROM; the digest of "
        f"the image itself is a separate fact, and without it the SBOM and "
        f"the UF2 can never be checked against each other. Record it when the "
        f"release artefacts are assembled."
    )


def check_agreement(artifacts: Path, statement: dict, issuer: str | None,
                    cosign: str | None, expected_workflow: str = EXPECTED_WORKFLOW,
                    expected_repo: str = EXPECTED_REPO) -> list[str]:
    """Return a list of notes; raise Refusal on the first broken rule."""
    notes: list[str] = []
    uf2 = artifacts / UF2_NAME
    sbom_path = artifacts / SBOM_NAME
    for path in (uf2, sbom_path):
        if not path.is_file():
            raise Refusal(
                f"{path} is not in the release artefact directory {artifacts}.\n"
                f"  A release publishes the image, its SBOM and its "
                f"provenance together or it publishes nothing; a reader who "
                f"has two of the three cannot check anything."
            )
    if not statement:
        raise Refusal("no provenance statement was supplied to agree with.")

    actual = sha256_file(uf2)
    notes.append(f"UF2 sha256: {actual}")

    # A2 — SBOM <-> UF2
    sbom = load_json(sbom_path)
    recorded = sbom_image_digest(sbom)
    if recorded != actual:
        raise Refusal(
            f"the SBOM records image digest {recorded}, but the UF2 in the "
            f"artefact directory hashes to {actual}.\n"
            f"  Each is internally valid — the SBOM's component set still "
            f"matches a lock file, the UF2 is still a build output — and "
            f"together they describe two different releases. That is the "
            f"failure this gate exists for, and no per-artefact check finds it."
        )
    notes.append(f"SBOM records the same image digest ({recorded})")

    # A3 — attestation <-> UF2
    subjects = statement.get("subject") or []
    if not subjects:
        raise Refusal("the provenance statement has no subject.")
    for s in subjects:
        claimed = (s.get("digest") or {}).get("sha256")
        if claimed != actual:
            raise Refusal(
                f"the attestation's subject digest is {claimed}, but the UF2 "
                f"in the artefact directory hashes to {actual}.\n"
                f"  This is the story's red, verbatim: the UF2 was modified "
                f"after it was signed. `cosign verify-blob` on the published "
                f"file fails, and a release that published it anyway would be "
                f"publishing an artefact nobody signed."
            )
    deps = statement.get("predicate", {}).get("buildDefinition", {}).get(
        "resolvedDependencies", []) or []
    dep_digests = {(d.get("digest") or {}).get("sha256") for d in deps}
    if actual not in dep_digests:
        raise Refusal(
            f"the attestation's resolvedDependencies do not carry the UF2's "
            f"digest ({actual}). Subject and dependency list disagree, so the "
            f"statement does not describe one build."
        )
    notes.append("the attestation's subject and dependency list both carry "
                 "that digest")

    # A4 — the signature, if there is a cosign to ask.
    if cosign is None:
        notes.append("SKIPPED: cosign is not installed here, so the signature "
                     "was NOT verified. This is a skip, not a pass — on a "
                     "release runner cosign is installed by the workflow and "
                     "this check runs for real.")
    else:
        sig = artifacts / f"{UF2_NAME}.sig"
        cert = artifacts / f"{UF2_NAME}.pem"
        if not (sig.is_file() and cert.is_file()):
            raise Refusal(
                f"cosign is available but {sig.name} / {cert.name} are not in "
                f"the artefact directory, so the signature cannot be checked."
            )
        # Both identity arguments are required and neither is optional
        # decoration. cosign 2.2.4 refuses to verify a keyless blob without
        # `--certificate-identity`/`-regexp` at all (found by running it, not
        # by reading the docs), and the two together are the cryptographic
        # half of the `job_workflow_ref` property: the Fulcio certificate
        # carries the workflow that was allowed to mint the identity, so
        # refusing a signature whose identity is not THIS reusable release
        # workflow is the same refusal the statement-level check makes, from
        # the other direction and this time cryptographically.
        r = subprocess.run(
            [cosign, "verify-blob", "--certificate", str(cert),
             "--signature", str(sig), str(uf2),
             "--certificate-oidc-issuer", GITHUB_OIDC_ISSUER,
             "--certificate-identity-regexp", identity_regexp(expected_repo,
                                                              expected_workflow)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            tail = [ln for ln in (r.stderr or r.stdout).splitlines() if ln.strip()]
            raise Refusal(
                f"cosign verify-blob failed on the artefact about to be "
                f"published:\n    " + "\n    ".join(tail[-6:])
            )
        notes.append("cosign verify-blob: the signature is valid and the "
                     "certificate is the GitHub Actions identity")
    if issuer is not None:
        notes.append(f"signing certificate OIDC issuer: {issuer}")
    return notes


def _fixture(name: str) -> Path:
    return FIXTURES / name


def self_test() -> list[str]:
    """Every rule, against the committed fixtures, including the story's red."""
    import tempfile
    problems: list[str] = []
    # `cosign` is deliberately NOT threaded through the fixture self-test. The
    # committed fixtures carry a placeholder signature and a placeholder
    # certificate (both files say so in their first line), so asking cosign
    # to verify them proves nothing and would make the self-test's result
    # depend on whether the host happens to have cosign installed. The real
    # cosign path runs in release mode, where the signature is real; that it
    # is wired up at all is checkable separately and is reported as such.
    with tempfile.TemporaryDirectory() as tmp:
        good = Path(tmp) / "good"
        _materialise(good, mutate_uf2=False)
        try:
            check_agreement(good, load_json(_fixture("provenance.json")),
                            "https://token.actions.githubusercontent.com", None)
        except Refusal as exc:
            problems.append(
                f"the fixture release directory should have been ACCEPTED and "
                f"was refused: {exc}")

        # The story's red: mutate the UF2 after signing. The SBOM's recorded
        # digest is REWRITTEN to match, deliberately: otherwise the SBOM check
        # (A2) fires first and this fixture would only prove that two
        # documents disagree, not that the ATTESTATION is what catches a UF2
        # changed after it was signed. With the SBOM made to agree, A3 is the
        # only rule left standing, and A3 is the one the story names.
        mutated = Path(tmp) / "mutated"
        _materialise(mutated, mutate_uf2=True)
        sbom = load_json(mutated / SBOM_NAME)
        new_digest = sha256_file(mutated / UF2_NAME)
        for prop in sbom["metadata"]["properties"]:
            if prop["name"] == IMAGE_DIGEST_KEY:
                prop["value"] = new_digest
        (mutated / SBOM_NAME).write_text(json.dumps(sbom, indent=2))
        try:
            check_agreement(mutated, load_json(_fixture("provenance.json")),
                            None, None)
            problems.append(
                "a UF2 mutated after signing was ACCEPTED, even with the SBOM "
                "rewritten to match it. This is the US-1064 red, and it "
                "passing means the agreement gate is decorative.")
        except Refusal as exc:
            if "after it was signed" not in str(exc):
                problems.append(
                    f"the mutated-UF2 fixture was refused, but not for the "
                    f"reason it exists to demonstrate: {exc}")

        # A stale SBOM: the image digest is from the previous release.
        stale = Path(tmp) / "stale"
        _materialise(stale, mutate_uf2=False)
        sbom = load_json(stale / SBOM_NAME)
        for prop in sbom["metadata"]["properties"]:
            if prop["name"] == IMAGE_DIGEST_KEY:
                prop["value"] = "00" * 32
        (stale / SBOM_NAME).write_text(json.dumps(sbom, indent=2))
        try:
            check_agreement(stale, load_json(_fixture("provenance.json")),
                            None, None)
            problems.append(
                "an SBOM carrying a stale image digest was ACCEPTED — two "
                "valid documents describing two different releases.")
        except Refusal as exc:
            if "records image digest" not in str(exc):
                problems.append(f"the stale-SBOM fixture was refused for the "
                                f"wrong reason: {exc}")

        # A missing artefact: a release with the image but no SBOM.
        bare = Path(tmp) / "bare"
        _materialise(bare, mutate_uf2=False)
        (bare / SBOM_NAME).unlink()
        try:
            check_agreement(bare, load_json(_fixture("provenance.json")),
                            None, None)
            problems.append("a release with no SBOM attached was ACCEPTED")
        except Refusal:
            pass
    return problems


# The signature and certificate fixtures are WRITTEN, not committed. That is
# not tidiness: `platform/tests/no_signing_key.rs` (US-1081) fails the build
# on any key-shaped filename anywhere in the tree, and it is right to. US-1063
# says the only key this project should ever hold is the future secure-boot
# key, so a committed `*.pem` would contradict the story that introduced this
# gate. The placeholders below are comments; cosign rejects them, which is the
# correct outcome and the reason the self-test does not thread cosign through.
PLACEHOLDER_SIG = (
    "# FIXTURE ONLY - not a signature, written by "
    "check_artefact_agreement.py at run time.\n"
    "# Committed on purpose nowhere: a *.pem in the tree fails US-1081's "
    "no_signing_key test,\n# and a project whose supply-chain story is "
    "'there is no key here' should not ship one.\n"
)
PLACEHOLDER_CERT = (
    "# FIXTURE ONLY - not a certificate. See the note in the .sig file.\n"
)


def _materialise(dest: Path, mutate_uf2: bool) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for name in (UF2_NAME, SBOM_NAME):
        src = _fixture(name)
        if src.is_file():
            shutil.copy2(src, dest / name)
    (dest / f"{UF2_NAME}.sig").write_text(PLACEHOLDER_SIG)
    (dest / f"{UF2_NAME}.pem").write_text(PLACEHOLDER_CERT)
    if mutate_uf2:
        with (dest / UF2_NAME).open("r+b") as fh:
            fh.seek(-1, 2)
            last = fh.read(1)
            fh.seek(-1, 2)
            fh.write(bytes([last[0] ^ 0xFF]))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--artifacts", help="the release artefact directory")
    ap.add_argument("--attestation", help="the provenance statement (json/jsonl)")
    ap.add_argument("--certificate", help="the signing certificate (PEM)")
    ap.add_argument("--expected-repo", default=EXPECTED_REPO,
                    help="owner/name of the repository a release of this "
                         "project may be built from (default: %(default)s)")
    args = ap.parse_args(argv[1:])

    if not args.artifacts:
        print("US-1064 artefact agreement (self-test against committed "
              "fixtures; a real agreement check needs a real release)")
        problems = self_test()
        print("  ACCEPT  good/                 — UF2, SBOM and attestation agree")
        print("  REFUSE  mutated-uf2/          — the UF2 changed after signing "
              "(the story's red)")
        print("  REFUSE  stale-sbom/           — the SBOM records the previous "
              "release's image")
        print("  REFUSE  bare/                 — a release with no SBOM attached")
        cosign = shutil.which("cosign")
        where = cosign or ("NOT INSTALLED — the signature check is SKIPPED, "
                           "not passed")
        print(f"\n  cosign on this host: {where}")
        if problems:
            print()
            for p in problems:
                print(f"  FAIL: {p}")
            print("\nRESULT: FAIL")
            return 1
        print("\nRESULT: PASS")
        return 0

    artifacts = Path(args.artifacts)
    if not args.attestation:
        print(f"FAIL: --attifacts was given without --attestation. There is "
              f"nothing to agree with, and a release that skips the comparison "
              f"is exactly the release this story exists to refuse.")
        print("\nRESULT: FAIL")
        return 1
    statement = load_json(Path(args.attestation))
    issuer = None
    if args.certificate:
        # The issuer lives in an X.509 extension, and the only text form in
        # which that extension is legible is openssl's rendering of it — a
        # raw PEM is base64 and never contains the OID. Searching the PEM
        # directly (as this did) meant `issuer` was always None on a real
        # keyless certificate, and A2/A4 refused every genuine release. See
        # tests/scripts/certinfo.py.
        issuer = certinfo.issuer(Path(args.certificate))
    cosign = shutil.which("cosign")
    print(f"US-1064 artefact agreement — {artifacts}")
    try:
        for note in check_agreement(artifacts, statement, issuer, cosign,
                                    expected_repo=args.expected_repo):
            print(f"  {note}")
    except Refusal as exc:
        print(f"  REFUSED: {exc}")
        print("\nRESULT: FAIL")
        return 1
    print("\nRESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
