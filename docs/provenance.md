# Provenance audit — fapico2 vs the AGPL reference trees

**Date:** 2026-09-30. **Question:** is fapico2's Rust code an independent
implementation, or a translation of the AGPL-3.0 C trees
(`pico-fido`, `pico-openpgp`, `pico-keys-sdk`)? The answer decides which
licenses fapico2 can carry: a translation is a derivative work and must stay
under the upstream's copyleft; an independent implementation of the same
published protocols is not.

**Method.** Six audit passes, each reading the Rust file and its closest C
counterpart function-by-function, applying one standard: protocol formats,
registry constants, spec-dictated flows and status words are *interface facts*
(nothing an independent implementer could avoid); carried-over comments,
shared function decomposition with C's internal naming, idiosyncratic
non-spec constants, replicated C quirks/bugs, and self-declared porting are
*evidence of derivation*. Every non-CLEAN verdict below cites both sides.

**Reference-tree licenses, verified from their LICENSE files:** `pico-fido`,
`pico-openpgp`, `pico-keys-sdk` and `RS-Key` are **AGPL-3.0** (RS-Key
explicitly -only); `picoforge` is AGPL-3.0 (client only — protocol
interaction creates no derivative); `pico-sdk`, `pico-examples`,
`pico-rng`, `picotool` are BSD-3-Clause. AGENTS.md's "GPLv3 throughout" and
`pico-fido2/README.md`'s "stays GPLv3" are **wrong** — both contradict the
LICENSE files in those trees.

## Verdict summary

| Area | Files | Verdict |
|---|---|---|
| C-flash reader + migration | `platform/src/{cflash,cfs,migration,phy_tlv,fw_manifest}.rs` | **CLEAN-ROOM** (one de-minimis comment to paraphrase) |
| Key derivation / crypto | `platform/src/{ckey,drbg,drbg_seed,boot_key,sha512}.rs` | **CLEAN-ROOM** (interop labels disclosed below) |
| USB transport / APDU dispatch | `platform/src/{ccid,usb,apdu_chain,dispatch,hid_control}.rs`, `apps/fido/src/hid.rs`, `firmware/src/{ctap_hid,ccid_reasm,tasks}.rs` | **CLEAN-ROOM** (every file) |
| Storage / persistence / TRNG | `platform/src/{secure_store,store_v3,persist,persist_sink,trng,entropy_starve}.rs` | **CLEAN-ROOM** — original design, no C counterpart exists |
| CTAP2 command layer | `apps/fido/src/{cbor,ctap2,app,device_core,stateless,u2f}.rs` | **MIXED** — see below |
| OATH / OTP / Management | `apps/oath/src/{oath_core,oath,otp}.rs`, `apps/mgmt/src/lib.rs` | **CLEAN-ROOM** (resolved 2026-09-30 — flagged values are compatibility defaults, see below) |
| OpenPGP app | `apps/openpgp/src/*` | **CLEAN-ROOM** (card logic is vendored LGPL opcard; wrappers original) |
| **PIV app** | `apps/piv/src/{lib,crypto,keystore}.rs` | **DERIVATIVE-EVIDENT** — self-declared translation |

## DERIVATIVE-EVIDENT — must be rewritten before any permissive relicensing

**`apps/piv/` — a self-declared Rust port of AGPL C.** Its own headers say it:
*"Rust port of `pico-openpgp/src/openpgp/piv.c` (GPLv3)"* (`lib.rs:3` —
note the C tree is AGPL, not GPLv3) and *"Ported from … `crypto_utils.c` …
and … `piv.c`"* (`crypto.rs:3`). Every function carries `C <identifier>`
mapping comments, and the port preserves C-authored expression the spec does
not dictate: the SELECT FCI byte-identical including the **"Pico Keys PIV"**
branding string (`piv.c:384-409` ↔ `lib.rs:106-116`); the spend-retry-before-
compare ordering of `pin_check_verifier` (`openpgp.c:1034-1072` ↔
`lib.rs:273-307`); branch-for-branch `authenticate_mgm` including the
non-obvious `SW_EXEC_ERROR`-only-on-valid-state distinction (`piv.c:765-850` ↔
`lib.rs:603-728`); C's idiosyncratic GET DATA validation clause set and
`SW_MEMORY_FAILURE` for unknown FIDs; the `tlv.c` walker's trailing-tag quirk
(labelled "C OATH quirk" in Rust); and — the clearest single artifact —
`crypto_utils.c:40` passes `"DEVICE/ROOT"` with length **12**, accidentally
including the NUL terminator, and `apps/piv/src/crypto.rs:32` reproduces
exactly that artifact with `b"DEVICE/ROOT\0"`.
**Clarification 2026-09-30 (owner):** the PIV crate is a **non-functional
baseline mockup** for a future feature, not a shipped implementation — PIV
serving is deferred post-v1.0.0. **Deletion is excluded: PIV is needed for
PicoForge compatibility.** The remediation path is an independent rewrite of
the mockup's expression while pinning the PicoForge-facing wire surface —
stories US-1109/US-1110 in
[`docs/tasks/EPIC-rewrite-stateless-u2f.md`](tasks/EPIC-rewrite-stateless-u2f.md).
Where US-1109 proves data written by the C firmware must still open, the
replicated KDF interface facts (including the NUL-terminated label length)
move to the disclosure list below rather than being "fixed".

**`apps/fido/src/stateless.rs` — a documented, byte-faithful translation of
pico-fido's stateless U2F key-handle derivation.** The module doc says so
(*"Derivation (C `derive_key`, byte-for-byte)"*, `stateless.rs:16`): the
C idiosyncratic algorithm — 67-byte HKDF-SHA512 self-chaining scratch
(`fido.c:325-346`), MSB-forced path words, `appId ‖ keyHandle[0..32]` HMAC tag
— is reproduced exactly, with comments like *"outk mirrors the C 67-byte
scratch"*. None of this is in any FIDO specification. **Mitigating fact:** the
master key source was changed (HKDF-SHA256 over `device_random` with a
fapico2 label), so the handles are *not* interoperable with C firmware — the
algorithm skeleton was translated but the output is already fapico2-specific,
meaning a re-derivation with its own construction breaks nothing.

## DERIVATIVE-SUSPECT / STRUCTURE-SUSPECT — rewrite the lineage or clear it

- **`apps/fido/src/device_core.rs`** — carries C-internal naming with no spec
  basis (`needs_power_cycle`, `new_pin_mismatches`, `hkey`,
  `MAX_PIN_RETRIES = 8`) and free-choice orderings annotated "C parity"
  (decrement-retries-before-compare; the 3-strike new-PIN power-cycle latch,
  structurally identical to `cbor_client_pin.c:634-642`).
- **`apps/fido/src/u2f.rs`** — builds on the translated `stateless.rs`
  derivation and re-expresses C `cmd_authenticate.c`'s verify path.
- **`apps/fido/src/app.rs::derive_large_blob_key`** (`app.rs:272-277`) —
  reproduces C `credential.c:871-884`'s four-step "SLIP-0022" HMAC chain with
  the same literal labels; no spec defines largeBlobKey derivation, so the
  chain is C-authored. (The sibling hmac-secret chain was *not* carried —
  fapico2 uses its own labels there — which is what the fix looks like.)
- **`apps/fido/src/ctap2.rs`** — defensible as independent (spec + python-fido2
  derived), but two advertising decisions are documented as C parity ("up" not
  advertised; the ES256/EdDSA/ES384/ES512 set).
## RESOLVED 2026-09-30 — OATH / OTP / Management: CLEAN-ROOM

**Owner clarification:** the OATH, OTP and Management applets are
independent implementations; the values the audit had flagged are
**compatibility defaults**, not a port or copy — they are what the
*management* surface must emit to stay interoperable, in the same class as
the format facts below. The audit agrees on the evidence: the expression is
new everywhere checked (different storage, different verifier crypto, a
deliberately *inverted* OTP touch polarity, several documented C-parity
breaks — a copier preserves behavior, this tree traceably does not), the
*"Ported from the C firmware"* lineage headers (`oath/lib.rs:3`,
`mgmt/lib.rs:3`, `otp.rs` US-712 block) were stale first-review text and
were removed, and the three flagged values are interface facts, now recorded
in the disclosure list below:

- `MAX_OTP_COUNTER = 3` and the `serial[0] &= !0xFC` 8-digit serial mask —
  interoperability defaults a client expects, not authorial choices.
- The OathSeal KDF labels (`"DEVICE/ROOT"`, `"PIN/ENC2"`, `"OATH/KEYS"`,
  `"OATH"` magic) — already in the interop disclosure list; a reader of
  C-produced OATH records must reproduce them byte-exactly.

## CLEAN-ROOM areas — with the interop-fact disclosure list

The following are replicated **only** where a reader of C-produced data must
reproduce byte-exact interface facts; they are format data, not expression,
and are listed here for the relicensing record:

- HKDF labels/chain to open C records: `"DEVICE/ROOT"`, `"PIN/VERIFY"`,
  `"PIN/TOKEN"`, `"PIN/ENC"`, `"PIN/ENC2"`, `"OATH/KEYS"`, `"PKOC/*"`
  (`ckey.rs` ↔ `crypto_utils.c`, `oath.c`, `object_crypto_provider.c`);
  keydev record formats; GCM payload layout; PKOR AAD field order.
- C flash format: record header `next|prev|fid|len16`, `0xFFFF` extended
  marker, `0xFFFFFFFF`/`0xEFEFEFEF` sentinels, pool geometry, FID whitelist,
  container magics `PKOC`/`PKOR` with header sizes, the byte-exact 16-byte
  resident policy hash, OpenPGP EF FIDs (`files.h`) and DO payload offsets
  (`cflash.rs`, `cfs.rs`, `migration.rs`, `device_shell.rs`).
- Protocol constants: CCID message types and the gnuk-derived T=1 parameter
  block (the C's own comment attributes it to gnuk), CTAP-HID framing, USB
  class descriptors, ISO 7816-4 SW codes, YKOATH command/tag registry.
- Positive anti-copy markers found repeatedly: the C's `NO-OTP` fallback is
  replaced by fail-closed; C's chain-mismatch `6883` becomes a argued `6700`;
  C's `CTAP1_ERR_INVALID_CHANNEL 0x0b` becomes `0x08`; C's unexplained
  `chain_buf[2038]` becomes a derived `4101`; several C quirks (bogus-appId
  workaround, OTP touch polarity, per-slot access codes) are deliberately
  *not* reproduced. Independent KAT provenance (NIST/FIPS vectors; KATs
  regenerated with Python rather than lifted).

**One hygiene item:** `cfs.rs:7-10` reproduces, nearly line-for-line, the
ASCII record-layout comment diagram from `flash.c:44-47`. De minimis (field
labels are the format's own names), but paraphrase it before relicensing.

**Additional finding 2026-09-30:** `apps/oath/src/otp.rs` (test module,
~2475-2500) contains helpers documented as *"a verbatim port of the reference
client's `pad_challenge` (picoforge `src/hal/applets/otp.rs:452-469`)"* —
picoforge is AGPL-3.0. They are host-test-only and exist to prove interop
against the client's exact padding, which is a legitimate engineering reason,
but "verbatim port of AGPL code" is a provenance fact a relicensing record
must carry: either document them as intentional interop fixtures under the
AGPL's terms, or re-derive the padding independently (the rule is short).
The companion `firmware_trim` helper cites C `otp.c:934-938` as a format rule
(YubiKey trim semantics), which is interface, not expression.

## Consequence for licensing

1. **The tree as a whole cannot be asserted clean-room.** The PIV crate and
   `stateless.rs` are translations by their own admission, and the CTAP2
   PIN-layer naming/orderings put three more files in the suspect column.
   (The OATH/OTP/Management area was resolved to CLEAN-ROOM on 2026-09-30:
   the lineage headers were stale first-review text and are removed, and the
   flagged values are compatibility defaults — see the resolution note.)
2. **RESOLVED 2026-09-30: the workspace now carries the honest label.** The
   sole copyright holder relicensed the tree from `GPL-3.0-or-later` to
   **`AGPL-3.0-or-later`** (LICENSE, all `Cargo.toml` fields, NOTICE,
   README, `deny.toml` allowlist). The derivative portions of the tree are
   compliant under AGPL as they stand; the remaining rewrite work in
   `docs/tasks/EPIC-rewrite-stateless-u2f.md` is code hygiene and the
   prepared path to a permissive license, no longer a compliance
   prerequisite. LGPL-3.0-only opcard remains compatible with AGPL-3.0
   distribution, so the combined firmware carries AGPL end to end. The
   still-unlicensed `vendor/x448` attribution and the SBOM/regeneration
   hygiene are tracked as US-1114.
3. **A permissive license (MIT OR Apache-2.0) is reachable** — everything
   audited clean today is the overwhelming majority of the tree, the two
   evident areas are small (PIV is a deferred, non-functional mockup;
   `stateless.rs` is 189 lines and already non-interoperable with C) — but
   only after:
   (a) independently rewriting `apps/piv` (or dropping it until it earns a
   rewrite), (b) re-deriving `stateless.rs`'s construction and the
   largeBlobKey chain with fapico2's own labels (version the derivation so
   existing credentials keep their keys), (c) replacing the C-parity
   naming/orderings in `device_core.rs`, (d) paraphrasing the
   `cfs.rs` layout diagram, (e) fixing the false NOTICE opcard claim and the
   unlicensed `vendor/x448` attribution found in the parallel license audit.
