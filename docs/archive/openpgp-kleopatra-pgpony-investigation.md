# OpenPGP: "0000 / test card" and PGPOpony key visibility — root-cause analysis

Two separate reports, analysed 2026-10-05. They have **no common cause**; one is
a firmware field that was never set, the other is a client-side keyring design.

- **Issue 1** — serial shows `0000` / "test card" in Kleopatra and PGPOpony.
  Root cause: `opcard::Options.manufacturer` is left at `[0x00, 0x00]`, the ID the
  OpenPGP card spec reserves for test cards. **Fixed** — now `[0xFF, 0xFE]`, the
  spec's range for a card with a self-generated serial, matching `../pico-fido2`
  and `../RS-Key`.
- **Issue 2** — an imported key is invisible for sign and encrypt in PGPOpony but
  works in Kleopatra. Root cause: **not a firmware defect.** PGPOpony stores a
  freshly-scanned card as identity + fingerprints with no public key attached,
  and excludes unpaired card records from both the signing and the encrypt lists.
  It offers a "Pair with Hardware Key" button; pairing fixes it with no reflash.

Evidence below is quoted from primary sources: the vendored `opcard`, GnuPG
2.4.4, and the PGPony app + core repositories. Client-side line numbers are
pinned to the commits named under each heading.

---

## Issue 1 — the `0000` and the "test card" label are one hard-coded field

### The AID layout, and where our two fields live

The OpenPGP SELECT/GET DATA `4F` response is 16 bytes (spec §4.2.1). opcard
composes it in `vendor/opcard/src/card.rs:536-555`:

```rust
pub fn aid(&self) -> [u8; 16] {
    [
        RID[0], RID[1], RID[2], RID[3], RID[4],   // D2 76 00 01 24
        PIX_APPLICATION[0],                        // 01
        PGP_SMARTCARD_VERSION[0], PGP_SMARTCARD_VERSION[1],  // 03 04
        self.manufacturer[0],                      // AID[8]   <-- 00 00, always
        self.manufacturer[1],                      // AID[9]
        self.serial[0], self.serial[1], self.serial[2], self.serial[3], // AID[10..14]
        PIX_RFU[0], PIX_RFU[1],                    // 00 00
    ]
}
```

So **manufacturer is AID bytes 8–9 and serial is AID bytes 10–13** — the same
split the clients use. `PGPonyCore-Kotlin`
`crypto/card/OpenPgpCard.kt:39-40`:

```kotlin
const val AID_OFFSET_MANUFACTURER = 8   // 2 bytes
const val AID_OFFSET_SERIAL = 10        // 4 bytes
```

### The manufacturer field is never set

`Options::default()` sets it to zeros (`vendor/opcard/src/card.rs:561-564`), with
upstream's own TODO attached:

```rust
impl Default for Options {
    fn default() -> Self {
        // TODO: consider setting a default manufacturer
        Self {
            manufacturer: Default::default(),
            serial: Default::default(),
```

`apps/openpgp/src/device_shell.rs:121-133` overrides the serial only:

```rust
pub fn new(mut client: T) -> Self {
    let mut options = opcard::Options::default();
    options.storage = trussed_core::types::Location::Internal;
    options.serial = Self::provision_serial(&mut client);
```

`options.manufacturer` is `pub` and settable, but **nothing in this repository
ever writes it** — it is dead everywhere in the tree.

### Why that produces exactly "test card"

`0x0000` is one of the two IDs the spec reserves for test cards. Both clients map
it to that literal string.

GnuPG 2.4.4, `scd/app-openpgp.c:329-336`:

```c
      /* 0x0000 and 0xFFFF are defined as test cards per spec,
       * 0xFF00 to 0xFFFE are assigned for use with randomly created
       * serial numbers.  */
    case 0x0000:
    case 0xffff: return "test card";
    default: return (no & 0xff00) == 0xff00? "unmanaged S/N range":"unknown";
```

GnuPG reads the field at `app-openpgp.c:6514`:

```c
      manufacturer = (buffer[8]<<8 | buffer[9]);
```

PGPony, `crypto/card/OpenPgpCard.kt:145-167`:

```kotlin
fun manufacturerName(id: Int): String = when (id) {
    0x0000 -> "Test card"
    ...
    0xFFFF -> "Test card"
    else -> "Manufacturer 0x%04X".format(id)
}
```

Note the same comment: **`0xFF00`–`0xFFFE` is the range the spec assigns to cards
that generate their own serial numbers** — which is exactly what this card does.
`0xFFFE` is the top of that range and is what both references use.

### The "0000" is the manufacturer field, not a run of zeros in the serial

This matters because the two halves are displayed differently. GnuPG prints them
on **separate lines** (`g10/card-util.c:591-593`):

```c
      tty_fprintf (fp, "Manufacturer .....: %s\n", ...);
      tty_fprintf (fp, "Serial number ....: %.8s\n", info.serialno+20);
```

but concatenates them in key listings (`g10/keylist.c:343-351`):

```c
                  /* Example: D2760001240101010001000003470000 */
                  /*                          xxxxyyyyyyyy     */
                  tty_fprintf (fp, "%.*s %.*s", 4, serialno+16, 8, serialno+20);
```

→ `card-no: 0000 XXXXXXXX`. Our own hardware evidence records precisely that
string, `docs/hardware-matrix.md:106`: `card-no: 0000 00000000`,
`manufacturer "test card"`.

The serial half is **not** zero. `provision_serial` draws a packed-BCD value
(`device_shell.rs:753-781`) and persists it. `to_bcd` maps every nibble `% 10`, so
each byte lands in `0x00`–`0x99`. A serial that renders as `0000…` is a
**1-in-4096** coincidence; a manufacturer that renders as `0000` is a certainty.
The reference's `FFFE` is likewise a manufacturer — in `../pico-fido2` the serial
field is separately overwritten from the hardware id.

### The reference value, for comparison

| repo | manufacturer | where |
|---|---|---|
| **`fapico2` (this repo)** | **`0000`** — reserved test card | `vendor/opcard/src/card.rs:564`, never overridden |
| `../pico-fido2` | `FFFE` — unmanaged range | `src/openpgp/openpgp.c:291` |
| `../pico-openpgp` | `FFFE` | `src/openpgp/openpgp.c:291` |
| `../RS-Key` | `FFFE`, or `0006` (Yubico) when impersonating | `crates/rsk-openpgp/src/consts.rs:17-21` |

`../RS-Key` is the only tree that documents the reasoning:

```rust
/// OpenPGP AID manufacturer id (bytes 8-9). `0x0006` = Yubico, used by the
/// `VIDPID=Yubikey5` interop build so hosts show the same vendor as a real
/// YubiKey; `0xFFFE` = the unmanaged/test range for the default RS-Key identity,
/// which is not Yubico. Firmware picks it from the USB VID.
pub const OPGP_MFR_YUBICO: u16 = 0x0006;
pub const OPGP_MFR_UNMANAGED: u16 = 0xFFFE;
```

`../pico-fido2` writes the same value bare, then patches only the serial
(`src/openpgp/openpgp.c:350-355`):

```c
    if ((ef = file_search_by_fid(EF_FULL_AID, NULL, SPECIFY_ANY))) {
        ef->data = openpgp_aid_full;
        memcpy(ef->data + 12, pico_serial.id, 4);
```

### This was a recorded open question, not an oversight

`device_shell.rs:109-116` names it:

> US-934: the AID serial is provisioned here; the manufacturer stays the
> reserved test value `00 00` (OQ-1 — gpg's "test card" display stays truthful
> until the FSFE registration lands).

Introduced in `659c6b3` (2026-09-25). A test pins the value, so changing it is
deliberate work — `apps/openpgp/tests/dispatch.rs:1306-1316`:

```rust
    // Manufacturer keeps the reserved test value 00 00 (OQ-1)…
    assert_eq!(&aid[8..10], &[0x00, 0x00], "manufacturer is the test value");
```

The deferral condition — FSFE vendor registration — has not been met, and the
field is now user-visible on both clients. `0xFFFE` is the honest interim value:
it is the spec's own bucket for a card with a self-generated serial, and it makes
the clients render "unmanaged S/N range" instead of "test card".

**One-line change** (not applied — this is an analysis, and the pinning test
must be updated in the same commit):

```rust
options.manufacturer = [0xFF, 0xFE];
```

---

## Issue 2 — PGPOpony key visibility is a client-side pairing requirement

### Correcting a premise worth stating

PGPOpony (Android) is **`norsehorse-dev/PGPonyAndroid`**, and it is **not** built
on the OpenPGPAndroid library (`org.sufficientlysecure.openpgp`) — that coordinate
returns `numFound: 0` on Maven Central, `repo1.maven.org/maven2/org/sufficientlysecure/`
is 404, and the app's only crypto dependency is BouncyCastle. PGPony has its own
from-scratch OpenPGP card transport, published open for review as
`norsehorse-dev/PGPonyCore-Kotlin`. Line numbers below are pinned to:

- app: `710b96a92ec211aeaacfb261c93c2247ef8d70e8` (versionName `4.6.1`)
- core: `0c09788bda4c208297ae7d1668bdfec10b0f24fd`

(`CardAlgorithmAttributes.kt` and `CardModels.kt` are byte-identical between the
two, so either repo may be cited.)

### Root cause: a scanned card is stored unpaired, and unpaired is filtered out

Importing a card key creates a keyring row that carries **identity and
fingerprints but no public key**. `KeyRepository.kt:1158-1210`
(`importCardKeyInternal`) builds the entity without ever setting
`armoredPublicKey`, whose default is null (`data/PGPKeyEntity.kt:129`):

```kotlin
val entity = PGPKeyEntity(
    fingerprint = primaryFp,
    userID = label,
    isKeyPair = false,
    isCardBacked = true,
    cardSigFingerprint = sigFp, cardDecFingerprint = decFp, cardAuthFingerprint = authFp
)
```

That single field gates **both** lists the user is missing.
`ui/encrypt/EncryptDecryptViewModel.kt:695-721`, with the author's own comment
naming this exact symptom:

```kotlin
    // A freshly-scanned OpenPGP card is stored
    // as identity + fingerprints only (armoredPublicKey == null);
    // there's nothing to encrypt to until the user pairs it with a
    // real public key (import / keyserver / WKD). …
val unrevokedRecipients = allKeys.filter {
    !it.isRevoked && (!it.isCardBacked || it.armoredPublicKey != null)
}
…
val cardSigners = allKeys.filter {
    !it.isRevoked && it.isCardBacked && !it.isKeyPair && it.armoredPublicKey != null
}
val signableKeys = unrevokedKeyPairs + cardSigners
```

and the decrypt picker, `:790`:

```kotlin
val cardDecryptors = allKeys.filter {
    it.isCardBacked && !it.isKeyPair && it.armoredPublicKey != null
}
```

So one null field hides the key from **signing and encryption simultaneously** —
the reported symptom exactly, by design. It is deliberate defensive behaviour:
offering a card contact with no certificate as an encrypt recipient produces a
"no encryption methods" failure.

PGPony ships a UI affordance for precisely this case
(`res/values/strings.xml:735`):

```xml
<string name="import_button_pair_card">Pair with Hardware Key</string>
```

…described as *"Importing will pair this public key with the card so you can
encrypt to it and verify its signatures."* Once paired, `armoredPublicKey` is set
and the key reappears in both lists — **no reflash and no firmware change**.
The same filter appears in `ExchangeViewModel.kt:82`,
`ShareTargetViewModel.kt:219`, `SettingsViewModel.kt:335`, and
`EncryptDecryptViewModel.kt:2803, 3852, 3896`.

### Why Kleopatra is unaffected

GnuPG holds the private key *and* the full certificate in its own keyring. It
never consults a pairing state to decide availability — it already owns the
material, so it just uses the card as a signing engine. PGPony stores no secret
material on the phone, so a card contact is useless until a public key binds to
it. The two clients are not disagreeing about the card; they are applying
different keyring rules to it.

### Card-side hypotheses, tested and cleared

These were the plausible firmware-side suspects. Each is **disproven**:

**Curve support is not the gate.** The client maps only Ed25519/Cv25519 to a
usable algorithm and returns `null` for everything else
(`CardAlgorithmAttributes.kt:84-102`):

```kotlin
startsWith(OID_NIST_P256) -> "NIST P-256" to null
startsWith(OID_SECP256K1) -> "secp256k1" to null
startsWith(OID_BRAINPOOL_P256) -> "brainpoolP256r1" to null
```

That `null` is **display-only**. Slot visibility is decided solely by the DO C5
fingerprint (`CardModels.kt:28`):

```kotlin
val hasKey: Boolean get() = fingerprint != null
```

and `algorithm` is never read by any inclusion filter — `importCardKeyInternal`
even defaults a null algorithm to `ED25519_CV25519` rather than rejecting. A
P-256 card key still shows in the slot list and still imports.

**C5 is never compared against a computed fingerprint.** The card's C5 is stored
verbatim and used only to *find* the owning entity. A fingerprint mismatch on
our side therefore cannot hide a key here — and, notably, `hasKey` reads C5
straight out of GET DATA `6E`, which our firmware fills correctly.

**GET RESPONSE chaining is implemented.** Both our large DOs (Application
Related Data `0x6E` and Algorithm Information `0xFA`, 272 bytes each) exceed a
short APDU. `OpenPgpCardSession.kt:493-530` drains `61xx` correctly and also
handles `6Cxx` wrong-Le:

```kotlin
    while (true) {
        when {
            resp.hasMoreData -> {
                val le = if (resp.sw2 == 0) 256 else resp.sw2
                resp = sendRaw(CommandApdu(cla = 0x00, ins = OpenPgpCard.INS_GET_RESPONSE, …))
```

**DDO shape assumptions do not exist.** `Tlv.findRecursive` (`Tlv.kt:100-116`)
descends into `6E`, `73`, `65`, `7F49`, so C1–C3/C4/C5/CD are found whether nested
under the DDO `73` (YubiKey shape) or flat under `6E` (ours). No vendor branch
anywhere in the card layer.

**PIN gating does not apply.** Slot listing and the import button need no PIN;
PIN is requested at PSO time. Our card reports UIF-disabled + button-present
(`GFM = 7F 74 01 20`), and `confirm_user_presence` returns immediately when UIF
is off.

**Our advertised algorithms match what we accept.** `FA` and the allow-lists are
derived from the same feature set, so there is no advertise-more-than-you-do
mismatch. (RSA *generation* is slow — a documented performance gap, not a
capability lie.)

### One real limitation worth knowing before the fix lands

`CardPGPContentSigner.kt:15-16`:

> ECDSA is not supported here — the card returns r‖s but BC expects DER

If the key on the card is **ECDSA** (NIST P-256/384/521, Brainpool, secp256k1),
PGPony will offer it and then produce a malformed signature. If the key is
Ed25519/Cv25519 this does not apply. Our card returns raw `r‖s` from
`PSO:CDS` by design (US-969/US-970, `docs/known-gate-divergences.md:1318`),
which GnuPG expects but BC does not. So: confirm which algorithm the key uses
before treating a post-pairing signature failure as a regression.

---

## What to do

**Issue 1 — DONE.** `options.manufacturer = [0xFF, 0xFE];` is set in
`OpenPgpApp::new` (`apps/openpgp/src/device_shell.rs`), and the pinning assertion
in `apps/openpgp/tests/dispatch.rs::aid_template_conformance` was updated in the
same commit. Both clients stop saying "test card". `0x0006` (Yubico) would be
wrong — this card is not a Yubico, and misdeclaring a vendor is the masquerade
`../RS-Key` warns about in its threat model. When FSFE registration lands, the
assigned ID replaces `FFFE`.

The change is confined to AID bytes 8–9, so it is **not** a one-way door: the
value is re-derived on every boot, and the persisted serial is untouched. No
factory wipe, no key loss, no host-side stub cleanup (contrast the serial-change
hazard in [`client-compatibility.md`](../client-compatibility.md)).

**Issue 2 — not firmware.** In PGPony, open the keyring and pair the hardware
key with its public key via "Pair with Hardware Key". If the key appears in the
slot list as a card contact named e.g. `"Test card hardware key"` with
`userEmail = "Serial <hex>"` (`KeyRepository.kt:1201-1207`), that confirms the
diagnosis outright — and note that the "Test card" in that label is issue 1
showing up again, so fixing issue 1 also cleans up the label.