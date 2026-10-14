# fapico2-release-alpha-v0.2.0 — Release Notes

**Date:** 2026-10-14 · **Target:** Raspberry Pi Pico 2 (RP2350), USB-connected
**Shipping image:** `fapico2.uf2` — the Release carries the image and GitHub's
own "Source code" archives, and nothing else. The SHA-256 of the image is
recorded per-build, not here: it is stamped in the release SBOM and named in
the `release-manifest.json` attached to the release workflow run, and it is
what the build-provenance attestation covers.

**This is an alpha.** Alpha/beta images keep the debug port available and burn
nothing irreversible into OTP ([ADR 0002](adr/0002-provisioning-policy.md)).

## The headline: Nostr identities on the device (PR #18)

The board now holds up to **8 BIP-340 Nostr identities** — generated, stored
and used entirely on the RP2350. Schnorr event signing and NIP-44 v2
encryption run on the chip; a private key never crosses the wire in either
direction.

A Nostr identity is a publishing identity: non-revocable, recoverable by no
one — the same class of secret as a bitcoin key. The device's existing
posture, on-device generation, AEAD-at-rest under the OTP-derived root and
physical-touch consent, is applied to it without weakening any existing
applet.

**Two transports, one applet:**

- **CCID** — plain APDUs, selected by AID `F0 00 00 00 02`, INS `0x10`–`0x1A`.
- **Vendor HID** — a third USB HID interface (interface 3, usage page
  `0xFF00`), CTAPHID framing with vendor commands `0x40`–`0x4A`, CBOR
  `[idx, arg]` payloads and CBOR `{1: sw, 2?: data}` responses.

**The browser surface** is the separate
[fapico2-nostr-extension](https://github.com/eddieoz/fapico2-nostr-extension)
(Chrome 116+, MV3 + WebHID), which exposes the NIP-07 `window.nostr` API —
sign, NIP-44 encrypt/decrypt, key management — with a per-site, per-action
approval prompt and the physical touch as final consent. Verified end-to-end
against hardware. A Linux user needs
[`platform/udev/70-fapico2-nostr.rules`](../platform/udev/70-fapico2-nostr.rules)
(scoped to the VID, so re-identified boards keep working).

**Consent model.** Three reads are touch-free (`GET_INFO`, `GET_PUBKEY`,
`LIST_KEYS`); every command that uses or changes the private set requires a
physical press, with no config bit to change that. The press consents to the
**identity**, not the opcode: presence tags are `0x4000_0000 ‖ idx` on CCID
and `0x6000_0000 ‖ CID` on HID, disjoint from FIDO's `0x8000_0000`. The gate
survived a dedicated adversarial audit
([`docs/nostr-presence-audit.md`](nostr-presence-audit.md), hardware-verified
2026-10-12) whose two load-bearing fixes are in this release: the domain
check is **exact** (a folded FIDO tag can never arm a Nostr grant), and an
armed grant **dies with its request** (CANCEL and expiry drop it). The HID
arm refuses while parked, it does not queue — the extension does the FIFO on
its side.

**Storage** ([ADR 0005](adr/0005-nostr-key-storage.md)): a third keyregion
domain carved from the **top** of FIDO's range, so every existing passkey
keeps its address. Records are device-bound
(`derive_payload_key(otp_key_1, chipid, NOSTR_PAYLOAD_SECRET)` — no PIN
input), sealed per-record with an AAD binding domain, slot and generation,
and every write runs an occupancy guard: a stale FIDO record in the carved
range refuses `6A84` rather than dying silently.

**Crypto** (`apps/nostr/src/{crypto,nip44}.rs`): BIP-340 signing and NIP-44
v2 on `secp256kfun 0.12.1`, pinned against the BIP-340 reference vectors and
NIP-44's published vector set. The plaintext cap (1,792 B) is derived from
the CCID wire bound against NIP-44's chunk-rounded padding and asserted at
compile time, so the wire cap and the in-band refusal cannot drift. Honest
supply-chain note: `secp256kfun` is self-declared, not human-reviewed — the
cargo-vet record says so explicitly (`supply-chain/config.toml`), and it
carries the applet's signing keys.

## Behaviour changes to know before you flash

- **FIDO2 resident passkeys move 856 → 848.** Eight slots are carved for
  Nostr from the top of FIDO's range; existing records are untouched and
  guarded by the occupancy rule. Measured to refusal at the carved geometry
  ([`docs/capacity.md`](capacity.md)).
- **Management `RESET` now wipes Nostr with everything else** — the CCID
  proxy forwards `factory_wipe`. CTAP2 `authenticatorReset` still spares it.
  "Reset" means what its own documents say.
- **Flash budget raised 1664 → 1680 KiB** in `ci.yml`, with the reason inline
  (the real +28.5 KB delta vs the spike's ~25 KB projection).

## Also in this window: the boot-freeze instrumentation (US-1301…1312)

If a board freezes after a flash or a settings save, the recovery is a
**power cycle with 5 seconds off** — not a reset press, not a re-flash, and
not a fast replug, which leaves the board still frozen
([`docs/boot-freeze.md`](boot-freeze.md)). This release ships the
instrumentation that turns the next report into a measurement, and two fixes
it surfaced:

- **The LED tells the truth at boot**: a countable blink ladder names the
  boot phase a frozen board reached, and the fatal signature (one long
  flash, pause, four short) is distinguishable from a silent freeze
  ([ADR 0004](adr/0004-fatal-boot-recovery-policy.md)).
- **The boot OTP reads retry within a 20 s budget** before refusing, and the
  runtime `sw_lock` write that broke page-0 OTP reads is gone — both were
  false "the OTP key row is unreadable" failures on healthy boards.
- The watchdog was considered and **refused** as a recovery mechanism
  (US-1309/1311/1312); the reasoning is in the epic record.

The trigger itself is **not yet established** — the epic's status is
instrumentation shipped, cause open. Do not attach an SWD probe to
investigate a freeze; on this hardware that alone reproduces it.

## Verifying the download

1. Check out the tag and confirm it names the commit the Release shows.
2. Verify the image against the provenance GitHub minted for it:

   ```bash
   gh attestation verify fapico2.uf2 --repo eddieoz/fapico2
   ```

3. The same digest is in the `release-manifest.json` workflow artifact of the
   release run, cross-checked against the digest stamped into the attached
   SBOM.

The SBOM (`supply-chain/sbom.cdx.json`), the provenance statement and the
release manifest are workflow artifacts, not Release assets — the Release
itself carries the image and the auto-generated source archives.

## Scope and caveats unchanged from v0.1.0

The single UF2 serves one USB composite device (CCID + CTAP HID, now with
the third Nostr vendor-HID interface); applets are selected by AID. The
app-by-app scope, the hardware-acceptance matrix and the provisional-VID
(`fa20:0002`, not USB-IF-registered) note are in
[`docs/release-notes-v1.0.0.md`](release-notes-v1.0.0.md) and
[`docs/hardware-matrix.md`](hardware-matrix.md). The Nostr applet's
user-facing and implementation pages are in the documentation site
(`book/how-to/nostr.md`, `book/features/nostr.md`, served at
<https://eddieoz.github.io/fapico2/>).
