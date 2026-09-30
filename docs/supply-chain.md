# Supply chain (RS-KEY-ADOPT Phase 7, US-1060 – US-1064)

What is in the shipped RP2350 image, where each piece came from, and — the
part that matters — **how much of it anybody has actually read**.

Every number on this page is derived by
[`tests/scripts/check_supply_chain.py`](../tests/scripts/check_supply_chain.py)
on every CI run, and the gate fails if this page and the locked graph disagree.
That is the rule from RS-Key's own `properties.toml` header, quoted in the
epic: *"a hand-written copy of derivable evidence rotted in three of six
fields before a line of code existed; that experiment is not repeated here."*
Nothing below is a promise. It is a measurement with a date on it.

Measured 2026-09-29, on `feat/rskey-adopt` at `288b682`.

---

## The headline, stated plainly

| | count | share |
|---|---:|---:|
| third-party crates cargo-vet sees | **374** | 100% |
| carrying a third-party audit | **62** | **16.6%** |
| partially audited | **1** | 0.3% |
| self-declared exemptions | **311** | **83.2%** |
| of the RP2350 device closure (275 third-party crates), audited | **41** | **14.9%** |
| of the RP2350 device closure, exempt | **234** | 85.1% |
| SBOM components | **382** | the `cargo cyclonedx` component set for `fapico2-firmware`, cross-checked both ways against the locked graph |

**None of the 311 exemptions has been read by a human on this project.** They
exist because `cargo vet init` wrote them, and that is the entire basis.

16.6% is close to RS-Key's own figure (~17%, 243 self-granted exemptions
against 50 third-party-audited crates) and it is nowhere near 100%. It is
printed here so that a reader of this file knows that "we run cargo-vet" means
"we have pinned the dependency set and 16% of it has been read by somebody",
not "we have reviewed our dependencies".

### Where the 62 audited crates come from

Eight third-party audit sets are imported and pinned by
`supply-chain/imports.lock`:

| peer | source |
|---|---|
| mozilla | `mozilla/supply-chain` |
| embark-studios | `EmbarkStudios/rust-ecosystem` (the RustCrypto ecosystem audits) |
| google | `google/supply-chain` |
| zcash | `zcash/rust-ecosystem` |
| bytecode-alliance | `bytecodealliance/wasmtime` |
| actix | `actix/supply-chain` |
| fermyon | `fermyon/spin` |
| isrg | `divviup/libprio-rs` |
| ariel-os | `ariel-os/ariel-os` |

Importing all eight rather than one is worth 47 of the 62 audited crates
(mozilla alone accounts for 15). They are committed into
`supply-chain/audits.toml`, so **CI does not fetch them** — the imports are
refreshed deliberately with `cargo vet import <peer>`, and a build depends on
nothing but the files in this repository.

The one partially-audited crate is `digest 0.10.7`, audited for one criterion
but not another.

---

## The gap cargo-vet cannot see

`vendor/ed448-goldilocks` and `vendor/x448` are `[patch.crates-io]` **path**
replacements, added under S-701-5 because upstream `ed448-goldilocks` pulls the
std-only `hex` crate for its unit tests and so cannot be built `no_std`.
cargo-vet audits by registry identity, so neither crate appears in any audit
list, any exemption, or any count on this page.

They are in the shipped image. They differ from crates.io. No tool in this
pipeline has read them. `check_supply_chain.py` names them on every run so
that this stays a printed fact rather than an absence.

---

## Accepted advisories (deny.toml)

Six RustSec advisories are accepted rather than fixed, each with a stated
reason in `deny.toml` and checked by the gate:

| id | crate | why accepted |
|---|---|---|
| RUSTSEC-2023-0071 | `rsa` 0.9.10 | **Vulnerability** (Marvin attack, non-constant-time RSA). No upstream patch exists. Reaches the image via `trussed-rsa-alloc`. The upstream workaround ("avoid where timing is observable") does not hold for a USB token. |
| RUSTSEC-2021-0127 | `serde_cbor` 0.11.2 | Unmaintained; PIV certificate data objects are CBOR. Note: Mozilla *did* audit 0.11.2, so this one is third-party-audited as well as unmaintained. |
| RUSTSEC-2023-0089 | `atomic-polyfill` | Unmaintained, via `heapless 0.7 -> aead -> aes-gcm -> apps/fido`. No replacement. |
| RUSTSEC-2026-0110 | `bare-metal` | Deprecated, via `cortex-m -> embassy-rp`. Embassy 0.10 has not moved off it. |
| RUSTSEC-2024-0436 | `paste` | Unmaintained, via `pio -> embassy-rp`. Archived. |
| RUSTSEC-2026-0173 | `proc-macro-error2` | Unmaintained, via `pio -> embassy-rp`. Build-time only; also Mozilla-audited. |

The Marvin advisory is the one to read twice. It is a real vulnerability with
no fix, it is in the shipped image, and its timing surface is a USB cable.
Removing it means dropping software RSA, which is a product decision, not a
CI change. It is also downstream of a fact the project already knows and
records elsewhere: RSA **key generation** does not complete on the RP2350
(`AGENTS.md`).

---

## Known divergences

**1. RS-Key's R2 (applet isolation) cannot be expressed as a graph rule here.**
fapico2 builds one trussed `Client` and hands the same service set to every
applet, so which key material an applet can reach is decided by the
service-set split in `platform/src/trusted_backend/`, not by any manifest
edge. `check_crate_graph.py` proves the weaker, real property — applets cannot
import each other's code, and the one crate that does (`fapico2-apps`, the AID
registry) has all five of its edges named — and it prints the limitation on
every run. It does not claim isolation.

**2. CI actions are not all pinned to commit SHAs.** The Phase 7 jobs are
(`EmbarkStudios/cargo-deny-action@3c63498…`, `sigstore/cosign-installer@6f9f17…`,
`actions/attest-build-provenance@4d10147…`). The pre-existing jobs use moving
tags (`actions/checkout@v4`, `dtolnay/rust-toolchain@stable`). RS-Key pins
everything; this repository does not, and rewriting the old jobs is a
different change from a supply-chain story. Recorded, not fixed.

**3. `cargo vet fmt` deletes exemption reasons.** cargo-vet's exemption schema
has a `reason` field and cargo-vet 0.10.2's formatter silently drops it
(verified; transcript in the header of `supply-chain/exemption-reasons.toml`).
The reasons therefore live in a file this repository owns, and the gate does
the pairing.

**4. `wildcards` is "warn", not "deny", in `deny.toml`.** The vendored `opcard`
is crates.io-published, so cargo-deny cannot exempt a path wildcard on it
(`allow-wildcard-paths` covers unpublished path deps only). The rule is
enforced instead by `check_crate_graph.py` G4 over the workspace-owned
manifests, which finds zero.

**5. Multiple versions of 40 crates.** `sha2` 0.9/0.10/0.11, `digest` likewise,
and so on down the tree, because trussed, opcard and our own code pin
different RustCrypto generations. cargo-deny reports each as a warning and
exits 0; `check_crate_graph.py` G5 makes the set a two-directional gate, so
the set cannot change without somebody deciding it should.

**6. The signing and provenance paths are unexercised until a real release.**
US-1063 and US-1064 ship a release workflow whose OIDC and attestation steps
have never run. What HAS been exercised here is the pure logic — the
provenance policy check and the artefact-agreement check, both run against
committed fixtures with negative controls on every push. See
`.superpowers/sdd/report-P7.md`.

---

## Files

| file | what it is |
|---|---|
| `deny.toml` | cargo-deny policy: sources, licences, advisories, duplicates, the `wrappers` allowlist |
| `deny-graph.toml` | the rules cargo-deny has no setting for (R1, R2, G4, G5), read by one gate |
| `supply-chain/config.toml` | cargo-vet config: 312 exemptions + 8 imports |
| `supply-chain/audits.toml` | the imported third-party audits, committed (CI does not fetch) |
| `supply-chain/exemption-reasons.toml` | the stated reason for every exemption; the gate pairs them |
| `supply-chain/sbom.cdx.json` | the CycloneDX 1.5 SBOM generated from the locked graph (US-1062). Regenerate with `cargo cyclonedx --format json --all-features --target all --spec-version 1.5`, move `firmware/fapico2-firmware.cdx.json` to `supply-chain/sbom.cdx.json`, and rewrite the absolute `path+file://` bom-refs to `path+file://./` — the raw output carries the builder's home directory, and `check_sbom.py` fails if one comes back. |
| `tests/scripts/check_crate_graph.py` | US-1060 — the workspace's own edges |
| `tests/scripts/check_supply_chain.py` | US-1061 — vet coverage, exemption reasons, this page's figures |
| `tests/scripts/check_sbom.py` | US-1062 — SBOM ↔ `Cargo.lock` component cross-check |
| `tests/scripts/check_release_provenance.py` | US-1063 — provenance policy (`job_workflow_ref`, issuer, subject digest) |
| `tests/scripts/check_artefact_agreement.py` | US-1064 — UF2 ↔ SBOM ↔ attestation must agree |
