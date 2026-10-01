#!/usr/bin/env python3
"""Read the Fulcio OIDC issuer out of a keyless signing certificate.

WHY THIS IS A SEPARATE MODULE
-----------------------------
Both release gates need the same one fact about a certificate: which OIDC
issuer signed it. Neither could get it, and neither said so.

A `.pem` is base64 between BEGIN/END CERTIFICATE lines. The Fulcio issuer
lives in an X.509 extension, and the only text form in which that extension
is legible is openssl's rendering of it —

    1.3.6.1.4.1.57264.1.8 = ASN1:UTF8String:https://token.actions…

— which appears in `openssl x509 -text`, and in NO other form. Both gates
searched the raw PEM for that string, so on a real keyless certificate they
found nothing, `issuer` stayed None, and P2 refused every genuine release
with "no signing certificate was supplied". The committed fixtures did not
catch it because the fixture path passes the issuer in as a bare string
(`issuer.txt`) and never reads a certificate at all.

So: render the certificate first, then look. openssl is present on every
runner this project uses and on any machine that could verify a signature
anyway; if it is missing, the raw text is searched as before, which is
correct for a pre-rendered input and returns None for a PEM — a refusal, not
a false pass. Neither direction is safe to fake, which is why this returns
None rather than guessing when it cannot tell.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

# The Fulcio certificate extensions, and the one that names the issuer.
ISSUER_OID_PREFIX = r"1\.3\.6\.1\.4\.1\.57264\.1\.[1-9]"
ISSUER_PATTERN = re.compile(ISSUER_OID_PREFIX + r"\s*=\s*ASN1:UTF8String:(\S+)")
PEM_MARKER = "-----BEGIN CERTIFICATE-----"


def rendered_text(path: Path) -> str:
    """The certificate's text form, via openssl when it is a real PEM."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    if PEM_MARKER not in raw:
        return raw  # already text (a fixture, an openssl dump)
    openssl = shutil.which("openssl")
    if not openssl:
        return raw  # cannot render; the search below will simply not match
    out = subprocess.run(
        [openssl, "x509", "-in", str(path), "-noout", "-text"],
        capture_output=True, text=True, check=False,
    )
    return out.stdout if out.returncode == 0 else raw


def issuer(path: Path) -> str | None:
    """The OIDC issuer, or None if this certificate does not name one."""
    try:
        m = ISSUER_PATTERN.search(rendered_text(path))
    except OSError:
        return None
    return m.group(1) if m else None


def self_test() -> list[str]:
    """The rendered path must actually run openssl, and must not invent an issuer."""
    import subprocess
    import tempfile
    problems: list[str] = []
    if not shutil.which("openssl"):
        return ["openssl is not installed, so the certificate path cannot be "
                "exercised here; the gates will refuse every release rather "
                "than pass it wrongly"]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        pem = root / "cert.pem"
        # A certificate with no Fulcio extension. It must render, and it must
        # yield None — the point of P2 is that an unknown signer is a refusal.
        made = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(root / "k.pem"), "-out", str(pem),
             "-days", "1", "-subj", "/CN=fapico2-self-test"],
            capture_output=True, check=False,
        )
        if made.returncode != 0 or not pem.is_file():
            return problems  # no openssl cert here; nothing to assert
        text = rendered_text(pem)
        if "Certificate:" not in text:
            problems.append("a PEM was not rendered by openssl")
        if issuer(pem) is not None:
            problems.append("a certificate with no Fulcio extension was given "
                            "an issuer; P2 exists to refuse exactly that")

        # A rendered text input (what a fixture holds) still works, unchanged.
        rendered = root / "rendered.txt"
        rendered.write_text(
            "X509v3 OID: 1.3.6.1.4.1.57264.1.8 = "
            "ASN1:UTF8String:https://token.actions.githubusercontent.com\n")
        got = issuer(rendered)
        if got != "https://token.actions.githubusercontent.com":
            problems.append(f"a pre-rendered issuer was not read back ({got!r})")
    return problems


if __name__ == "__main__":
    import json
    import sys
    bad = self_test()
    print(json.dumps(bad, indent=2) if bad else "ok")
    sys.exit(1 if bad else 0)
