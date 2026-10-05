# Device identity

What fapico2 claims to be, where each value comes from, and which of them are
one-way doors. The short version is in [README.md](../README.md); this is the
long one, and it is the document to read before changing a default.

## The block

Four values decide the product's identity. All are resolved at compile time by
`platform/build.rs` and published as `cargo:rustc-env`, then read back and
resolved in `platform/src/identity.rs` with `env!` + `const fn`. Nothing
is read at runtime and nothing is read from flash.

| Value | Where it lands | Default | Override variable |
|---|---|---|---|
| AAGUID | CTAP2.1 getInfo key `0x03`; the leading 16 bytes of every attested credential blob | `66617069636F3200…0002` | `FAPICO2_AAGUID_HEX` |
| Manufacturer | USB `iManufacturer` | `The BLOCO Community` | `FAPICO2_MANUFACTURER` |
| Product | USB `iProduct` | `fapico2` | `FAPICO2_PRODUCT` |
| VID:PID | USB `idVendor` / `idProduct` | `FA20:0002` | `FAPICO2_VID_PID` |

They live in `platform` rather than in an app crate because `platform` is the
only crate every participant depends on: the USB descriptor is built there
(`platform/src/usb.rs`, through the single `identity::usb_ident()` accessor) and
`apps/fido` re-exports `AAGUID` for the CTAP2 layer. A device whose descriptor
and whose getInfo disagreed about a name would be a worse bug than either being
hardcoded.

```bash
# A build aimed at a PicoForge that has not yet been taught fapico2's AAGUID.
FAPICO2_IDENTITY_OVERRIDE_ACK=1 \
FAPICO2_AAGUID_HEX=2479C7BF6B3056839EC80E8171A918B7 cargo build --release -p fapico2-firmware

# A fork publishing under its own name, with a registered VID.
FAPICO2_IDENTITY_OVERRIDE_ACK=1 FAPICO2_MANUFACTURER="Acme" FAPICO2_PRODUCT="Acme Token" \
FAPICO2_VID_PID=1234:5678 cargo build --release -p fapico2-firmware
```

## One source of truth (US-1517)

**The defaults in the table above are the only identity this repository
builds.** `build.sh`, `build-signed.sh` (the release path) and
`build-timeline.sh` set none of the four variables, and
`apps/fido/tests/aaguid_build.rs::no_tracked_build_script_overrides_the_identity`
fails if one of them ever grows an assignment.

**An override takes two variables, and the second one is mandatory.**
`FAPICO2_IDENTITY_OVERRIDE_ACK=1` must accompany any of the four, or the build
**fails** with a message naming what to type. An acknowledged override prints a
`cargo:warning` naming what it changed, on every build.

That is not fussiness. The drift the rule closes was real and invisible: a
`build-custom.sh` — git-ignored, so present in one developer's checkout and in
nobody else's — set `FAPICO2_AAGUID_HEX=89FB94B706C936739B7E30526D968145`,
which is **pico-fido2's own AAGUID**
(`../pico-fido2/src/fido/cbor.c:35`, the first 16 bytes of
`SHA256("Pico FIDO2")`), and also set the Yubico USB strings and VID:PID
`1050:0407`. So `./build.sh` and `./build-custom.sh` produced two images from
one checkout with two identities, and every test in the tree stayed green —
because an override build has always been a *supported* configuration, and the
suite tests the mechanism rather than the policy.

What the drift cost, stated plainly: the AAGUID is the leading 16 bytes of
every attested credential blob, so a device flashed from one and a device
flashed from the other are two authenticators that share no passkeys. A passkey
enrolled on one is invisible to the other. The only record of which image was
which was somebody's flash log.

The escape hatch stays — developing against a PicoForge that has not yet
learned our AAGUID is a real job, and so is a fork shipping under its own name.
It is now a thing you have to say you are doing, twice, in a command line that
gets copied around. `docs/identity.md` and the `platform::identity` module docs
both say so; a build that skips it does not build.

## The fifth build-time parameter: `FAPICO2_FOREIGN_IMAGE_WIPE`

It lives here because it is the same *kind* of thing — a `FAPICO2_*` variable
resolved at build time, with a published default, a hard failure on a bad
value, and a one-line statement of what changing it costs — and because it is
the one an operator is most likely to reach for while they are already in this
file changing their VID.

| Value | Default (device build) | Default (host/emulation) | Override |
|---|---|---|---|
| Wipe the secure store when the running image's hash is not the last-known-good one | **off** | on | `FAPICO2_FOREIGN_IMAGE_WIPE=1` |

**The default does not erase the secure storage.** Your passkeys, OATH
credentials, PIV and OpenPGP data, PIN and FIDO key device survive a firmware
update. That is the intended behaviour and it is what both reference products
do: RS-Key lays its KV store out to survive a reflash *by design*
(`firmware/memory.x:22-27`, regression-tested by
`tests/01_flash_persistence.py:12`) and pico-fido2 has no image check at all.
Neither asks the owner to choose between "secure" and "my credentials still
work tomorrow morning".

**If you want the stricter behaviour, enable it when you build your own
firmware.** An owner who has decided that destroying the store on a
foreign image is the right trade for their device gets exactly that, and
nothing about the default build prevents them from choosing it:

```bash
# A device whose owner wants data-loss-over-implant on a foreign image.
FAPICO2_FOREIGN_IMAGE_WIPE=1 ./build.sh
```

**What the two settings actually do.** The mismatch is always *detected* and
always logged. `=1` then wipes every secure-partition slot before any app
loads. Unset, the foreign image is admitted and the store is kept, and the boot
log says so in those words rather than calling itself a dev build. Measured
difference on hardware: **405 ms** of boot time (`docs/tasks/flash-boot-phase-tables.md`),
of which ~329 ms is generating a fresh P-256 attestation key and ~94 ms is
rewriting the two image slots. A CTAP2 PIN set before a `=1` flash stops
authenticating afterwards and keeps authenticating after an unset one —
checked from the host by `tests/hardware/store_marker.py`, not just from the
firmware's own log.

**This is not a substitute for signed secure boot, and the two are different
axes.** Secure boot is a property of the *device*: burning the RP2350's
one-way `CRIT1.secure_boot_enable` OTP fuse makes the bootrom refuse a
foreign image before any firmware runs, and it cannot be undone
(`secrets/secureboot_fingerprint.txt`, `build-signed.sh`). This variable is a
property of the *build*: it decides what the firmware does when it finds an
image it does not recognise. **If you have burned the fuse, use `=1`** — the
ROM has already stopped the attack, and the wipe is the belt to that braces. If
you have not, the ROM is providing nothing, and the honest summary is that
neither reference product or this one stops a determined implant by default.

## Rules

**A malformed override is a hard build failure, never a silent fallback.** The
build script validates each value and turns a rejection into a `compile_error!`
naming the constant and the reason. This is the same rule US-101 established
for the AAGUID alone, extended to the rest of the block: a typo that quietly
fell back would ship a device claiming an identity nobody asked for, and would
surface to a *user* as a mis-branded product rather than to the build.

**"Unset" means the default. "Set but empty" is an error.** `FAPICO2_PRODUCT=`
is almost always a mistake — a shell template that rendered nothing, a CI
variable that resolved empty, `env VAR=` in a Makefile — and quietly reading
that as "use the default" would ship the identity the operator believed they
had replaced. The empty string reaches the resolver only as the build script's
encoding of "nobody set it", which is why `env!` needs no cfg fork.

**Bounds, and where they come from.** Identity strings are capped at 32 bytes
including the terminator, which is the client's own limit
(`picoforge/src/hal/rescue/ops.rs:456`). The number is stated once, in
`identity::MAX_IDENTITY_STRING`, and `phy_tlv::MAX_NUL_STRING_LEN` and
`vendorff::MAX_IDENTITY_STRING` are checked against it by a `const _:` assert —
three consumers of one wire limit, rather than three restatements of `32` that
could drift.

**`VID:PID` accepts `VVVV:PPPP` and `0xVVVV:0xPPPP`, either case.** A person
copying from `lsusb` writes the first; a person copying from a C header writes
the second. Neither should have to remember which one this build takes.

## The AAGUID specifically

**The default is fapico2's own** — the ASCII bytes of `fapico2`, a NUL,
padding, and a version word of `2`. It reads recognisably in a hex dump and in
`lsusb`/`pcsc_scan` output, which matters when you are telling two tokens apart
in a bag.

**It was RS-Key's until 2026-09-28.** fapico2 borrowed
`2479C7BF6B3056839EC80E8171A918B7` because PicoForge exact-matches getInfo key
`0x03` against a three-entry device-profile table, and without a match the
device falls through to the pico-fido profile — the one profile under which the
app does **not** offer OpenPGP, hiding a fully working applet. The borrow was
always meant to be temporary (EPIC `PICOForge-COMPAT` §3.2, risk R-3).

The borrowed value remains reachable as a build override, and that is the
supported way to develop against an app that has not caught up. It is not the
default any more.

**Changing the default is a one-way door.** The AAGUID is the leading 16 bytes
of every attested credential data blob, so flipping it invalidates every
existing passkey RP→AAGUID binding on every deployed device. The value is a
named constant with a stated derivation rather than a literal in a table for
exactly this reason: it is one line, and it should look like one line.

**The consequence to plan around:** until PicoForge adds fapico2's AAGUID to
`firmwares/mod.rs`, a *default* build is unclassifiable by the app and lands
back on the pico-fido profile. That is the intended state, not a regression —
the fix is upstream (EPIC §7 item 1), and the override exists so nobody has to
wait for it to keep developing. Anyone flashing a default build to test
PicoForge features should build with the override.

## Runtime names: the PHY record

A product or manufacturer name can also be written **at runtime**, into the PHY
record, through tags `0x09` and `0x0F` — over the Rescue applet (`WRITE
PhyConfig`, INS `0x1C`) or over the FIDO `0x41` `CONFIG_WRITE`. The client reads
them back from `read_phy_config` (`picoforge/src/hal/rescue/ops.rs:346-357`),
which is what fills the device-details screen.

Those two tags had no field in the record until 2026-09-28, so a write was
refused `0x2A` and the client showed a blank product name it could do nothing
about. They are stored now, in both keystores, as the record's first
variable-length members.

**They are deliberately not seeded from the build-time block above.** Every
other field in that record is operator intent: it starts empty and is set by a
deliberate write. A name is different — the build already knows it. Seeding it
would be wrong twice: the record would stop being a record of what somebody
chose, and a firmware upgrade that changed the built-in name would leave every
existing device advertising the *old* one with no way to distinguish that from a
deliberate setting. A field that is empty means "nobody set this", which is
what the client already filters on.

So a firmware that never writes the tags serves its built-in name through the
USB descriptor, and an operator who wants a different one writes it.

## What is *not* in the block

**The serial number.** Derived from the RP2350 OTP chip id (US-103) and
rendered as 8 decimal digits, so it is stable across reboots and distinct per
unit. It is deliberately not configurable: a serial an operator can set to the
same value on two devices would break the thing it exists for. The `libccid`
allowlisting that consequence needs is in
[PC/SC allowlist (libccid)](#pcsc-allowlist-libccid) below.

**Secure-boot state, flash statistics, the CCID interface mask.** Those are
the Rescue applet's, and they are runtime state rather than identity — see
`docs/tasks/rescue-threat-model.md`.

## PC/SC allowlist (libccid)

Because `0xFA20` is **not** a USB-IF-registered vendor ID, macOS and Linux need
libccid's `Info.plist` allowlist edited — it has no wildcard, so the CCID
reader is invisible to `pcscd` until `0xFA20` / `0x0002` are appended to its
`ifdVendorID` / `ifdProductID` / `ifdFriendlyName` arrays, then
`sudo systemctl restart pcscd`. On Debian/Ubuntu `ifd-ccid.bundle` is a symlink
to `/etc/libccid_Info.plist`. CTAP-HID (`usbhid`) is unaffected everywhere.

This is a `pcscd` gate, so it binds any PC/SC application, not just one client;
the reader-ordering hazard that remains after allowlisting is a client bug, not
an identity one — see the README's *PicoForge compatibility* section.

### The VID/PID is writable at runtime, and a value libccid does not know is a silent lockout

The paragraph above is about the **build-time** default. The VID/PID is also
**runtime state**: Rescue `WRITE PhyConfig` (tag `0x00`, APDU `80 1C 01 00 …`)
and the FIDO carrier's `0x41 CONFIG_WRITE` (sub-command `0x0C`) both write it,
and `platform/src/usb.rs:425-437` applies a stored value at USB enumeration in
preference to the build-time constant.

That makes the pair a **one-way door**. Choose a `(VID, PID)` that libccid's
table does not contain and the board stays enumerable over USB while producing
**no CCID reader at all**. Consequences, in order of how badly they mislead:

* **No PC/SC reader**, so the Rescue applet is unreachable — and it is the only
  surface with **no PIN**, so the device has just lost its recovery route.
* **PicoForge does not report an error.** Its Rescue leg is PC/SC-only with no
  fallback (`io.rs:27-40` folds the failure into `log::warn!`), so the badge
  degrades to a yellow **"Online - FIDO"** while every FIDO feature keeps
  working. Passkeys, credentials and accounts are all fine; the one broken thing
  is the invisible one.
* **A reflash does not undo it.** `FAPICO2_FOREIGN_IMAGE_WIPE` defaults to the
  secure store *surviving* a reflash, and `usb.rs` prefers the stored record, so
  reflashing the same image re-enumerates at the same wrong ids.

This is reachable through PicoForge's own Configuration screen, which offers
several presets. On a stock Ubuntu host (libccid 1.5.5) `2E8A` is paired with
`0x10FF` only, so of that vendor's four presets — `2E8A:10FD`, `2E8A:10FE`,
`2E8A:10FF`, `2E8A:0003` — **only `2E8A:10FF` enumerates**. Choosing
`2E8A:10FE` writes cleanly, persists, and strands the device.

**Check before choosing:**

```bash
../pico-fido2/.test-venv/bin/python scripts/fix_usb_identity.py --list-known
```

It prints the pairs the local driver can actually bind, read from the plist
rather than hardcoded, so the advice does not go stale with the driver version.

**Diagnosing a stranded device.** `scripts/fix_usb_identity.py` reads the stored
record over the FIDO carrier — `0x41 CONFIG_READ` (`0x0D`) is ungated, so this
needs no PIN — and warns when the stored pair is unbindable:

```bash
../pico-fido2/.test-venv/bin/python scripts/fix_usb_identity.py
```

**Repairing one** does need the PIN, because `CONFIG_WRITE`'s identity tier
requires a `pinUvAuthToken` carrying `PERM_ACFG`, obtainable only via
`clientPin` sub-command `0x09` (a legacy `getPinToken` token carries no
permissions and is refused):

```bash
../pico-fido2/.test-venv/bin/python scripts/fix_usb_identity.py --set FA20:0002
# then unplug and replug — the change applies at the next enumeration
```

**Why a touch is required to get into this state** (US-1536). Rescue `WRITE`
takes a user-presence grant and answers `0x6985` without one, matching
pico-keys-sdk's `rescue_require_user_presence()` and RS-Key's
`require_presence()` byte for byte. It is a button and **not** a PIN because
this applet is the recovery path: a PIN requirement would mean a forgotten PIN
also forfeits the ability to repair the identity. The gate runs *after* the TLV
walk, so a request this firmware would refuse anyway never spends the touch.
Threat-model R1 is narrowed, not closed — a *deliberate* touch can still pick an
unbindable pair, which is why the pair is worth checking first.

## Changing a default, checklist

1. Change the constant in `platform/src/identity.rs`, not a caller.
2. Update `platform/tests/identity.rs` — it pins the bytes deliberately, so a
   default that moves without the test moving is a red, not a surprise.
3. `cargo test -p fapico2-platform --target x86_64-unknown-linux-gnu` and
   `cargo test -p fapico2-fido --target x86_64-unknown-linux-gnu` (the latter
   includes `aaguid_build.rs`, which builds twice and probes both artifacts).
4. Re-run the size gate: the string constants are `.rodata` and the AAGUID is
   read on the attested-credential path.
5. Say so in the commit message, and if it is the AAGUID, say what it breaks.
