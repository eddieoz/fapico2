# AGENTS.md — fapico2 firmware

Rust reimplementation of a YubiKey-class authenticator for the Raspberry Pi
Pico 2 (RP2350). Not a port of the C `pico-fido2` tree, and it does **not**
use `pico-keys-sdk` — that C SDK has no role here at all.

Most developers work on this inside a `pico/` workspace that checks out
`fapico2` alongside the reference trees listed under
[Reference implementations](#reference-implementations). Paths written as
`../<repo>` refer to those sibling checkouts; upstream URLs are given so this
file is also useful when reading the repository on its own.

---

## Read this before touching CTAP2

### 1. There are two `FidoApp`s. The one you want is usually not in `app.rs`.

```
apps/fido/src/app.rs          FidoApp<K: Keystore>   — HOST ONLY (`#[cfg(feature = "host")]`)
apps/fido/src/device_app.rs   FidoApp               — the RP2350 shell; re-exported as fapico2_fido::FidoApp
apps/fido/src/device_core.rs  the command path      — MC/GA/clientPIN/Reset/credMgmt/largeBlobs
```

The firmware runs `device_app::FidoApp` over `device_core.rs`. `app.rs` is a
**twin**, not the shipped one. Fixing only `app.rs` passes every host test and
changes nothing on hardware — that is not hypothetical; it is how the
credential-management dialect work in PR #3 went partly wrong. Change both, and
`device_core.rs` deserves the hardware proof.

`device_core.rs` is no_std but **host-compiled**, so the device path is
testable: boot a `device_app::FidoApp` with `HostTrng`/`HostSecureStore` and
drive `process_ctap2`. `apps/fido/tests/credmgmt_ctap2_spec.rs::device_twin`
does exactly that.

### 2. This firmware does NOT follow CTAP 2.1 opcodes, and that is deliberate.

`python-fido2` 2.2.1 — the library `ykman` and Yubico Authenticator are built
on — sends:

| command | fido2 2.2.1 | CTAP 2.1 spec |
|---|---|---|
| `authenticatorGetInfo` | `0x04` | `0x03` |
| `authenticatorClientPIN` | `0x06` | `0x04` |
| `authenticatorReset` | `0x07` | `0x05` |
| `authenticatorGetNextAssertion` | `0x08` | `0x06` |
| `authenticatorCredentialManagement` | `0x0A` | `0x08` |

`pico-fido`, `RS-Key` and `picoforge` share this convention. **Do not "fix" it
toward the spec** — that breaks every first-party tool and Yubico's own client.

Before diagnosing any CTAP2 mismatch, read the client's constants rather than
the spec:

```python
from fido2.ctap2.base import Ctap2;      list(Ctap2.CMD)
from fido2.ctap2.credman import CredentialManagement
print(CredentialManagement.CMD.__members__)   # GET_CREDS_METADATA=0x01, ENUMERATE_RPS_BEGIN=0x02
print(CredentialManagement.RESULT.__members__) # RP=0x03, RP_ID_HASH=0x04, TOTAL_RPS=0x05, USER=0x06 ...
```

Note the sub-commands use the **CTAP 2.0** order (metadata first), and the
response keys are **not** the spec's `rp=1, rpID=2, totalRps=7`. This "PicoForge
dialect" is what Yubico's library speaks.

### 3. Host apps read `DeviceInfo` over three interfaces, independently.

Any one failing produces a different symptom, and a green CCID test says
nothing about the other two:

| interface | command | failure symptom |
|---|---|---|
| CCID | management `READ_CONFIG` (`0x1D`) | device unseen / wrong serial |
| FIDO (CTAPHID) | `CTAP_READ_CONFIG` = frame cmd `0x42` | `CTAP2: Not supported`; Slots/Passkeys stuck |
| YubiOTP (feature reports) | `SLOT_YK4_CAPABILITIES` = `0x13` | Slots screen spins forever |

Two traps inside the FIDO path:

- The **CTAPHID INIT version bytes 13..15 carry the YubiKey firmware version**
  (5.4.0), *not* the CTAPHID protocol version. `yubikit.management.
  _ManagementCtapBackend` reads them as `device_version` and gates
  `read_device_info` on `>= 4.1`; below that, `_read_info_ctap` fabricates a
  "YubiKey 3.0 / U2F-only / no serial" record with no FIDO2 bit.
- All three must return the **same** body. They share
  `fapico2_mgmt::default_config_tlv(serial, out)`, fed from
  `platform::usb_ident::serial_hash4(chipid)` — the same value the USB
  descriptor uses.

For the YubiOTP path, return the **bare** blob: `platform::otp_hid::set_report`
already appends `!crc16(data)` (YubiKey convention, residue `0xF0B8`). Adding a
second CRC gives `BadResponseError: Invalid checksum`.

### 4. With a PIN set, the PIN and the button are **always** required. This is deliberate.

On a PIN-set board every operation needs a token *and* a touch: registration
prompts for the PIN, and authentication prompts for it again. Nothing in the
WebAuthn options can switch either off. Read that as three separate decisions
about what getInfo **advertises**, all derived from `pin_state` so they cannot
lie about what the command paths do:

| advertised | value | rule |
|---|---|---|
| `alwaysUv` | `pin_set \|\| config_0x02` | `ctap2::always_uv_advertised` |
| `makeCredUvNotRqd` | `!pin_set && !always_uv` | `ctap2::make_cred_uv_not_rqd` |
| `U2F_V2` in `versions` | `!pin_set` | `ctap2::u2f_v2_advertised` |

**User presence (the touch) is not a function of `userVerification`.** UP is
required for every `authenticatorMakeCredential` whatever `uv` says; both
twins reject `options.up = false` (`device_core.rs`, mirroring
`cbor_make_credential.c:387`). CTAP 2.1 §6.1.3 step 7.2 only lets a client
*skip UV*, never UP. So `userVerification: "discouraged"` must not remove the
button.

**UV (the PIN) is required too, because the device says so.** §6.1.3 makes a
token-less makeCredential an error whenever `makeCredUvNotRqd` is `false`, and
§6.2.2 does the same for getAssertion under `alwaysUv`. Both are derived from
the PIN state for exactly that reason. The reference derives them the same way
(`pico-fido2/src/fido/cbor_get_info.c:95-99`), and the two agree on the wire:

```c
bool alwaysUv = (get_opts() & FIDO2_OPT_AUV) || (file_has_data(ef_pin) && !keydev_unlocked);
CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 4 + !alwaysUv));
if (!alwaysUv) { ... "U2F_V2" ... }
```

Why it is worth holding this line: **every relaxation we have tried has cost
more than it bought.** Advertising `U2F_V2` on a PIN-set board made Chrome
enter a U2F register and abandon the CTAP2 operation outright. Advertising
`alwaysUv: false` while refusing token-less makeCredential, or while serving
token-less assertions, is the same failure one level down — a wire claim the
device does not honour. The rule that has survived is the one the reference
uses: **derive each option from the state it describes, and let the gates and
the advertisement come from the same accessor.** US-1529 and US-1533 are the
two halves of it; the tests in `tests/make_cred_uv_not_rqd.rs`,
`tests/u2f_v2_advertisement.rs` and `tests/uv.rs` exist to keep them so.

Config `0x02` (toggleAlwaysUv) can force `alwaysUv` **on**. It cannot turn it
off on a PIN-set device, and it cannot buy a UV-less assertion — a `false` here
is the claim that no token is needed, and the only state in which that is true
is no PIN. Clearing the PIN clears all three rows at once, coherently.

**One known edge:** `u2f_v2_advertised` keys on `pin_set` alone, so a PIN-less
board with Config `0x02` set would advertise `alwaysUv: true` *and*
`U2F_V2`, where the reference would withhold the latter. It is unreachable
through any client (the toggle needs a `PERM_ACFG` token, which needs a PIN),
and CTAP1 is not servable over `CTAPHID_MSG` yet anyway
(`tests/u2f_v2_advertisement.rs::ctap1_is_not_servable_yet`). Left as recorded
rather than fixed, for the same reason.

### 5. Simpler is better security. Unneeded complexity is the vulnerability.

**State the rule plainly, because it is easy to agree with and hard to apply:
when a design choice trades simplicity for protection, take the simpler one —
unless you can name the attack the complexity stops.**

The device's storage is where this bites hardest, and it has already cost real
capability. Keys for FIDO and OATH share one 24-entry `Rp2350SecureStore`
(`secure_store.rs`, `DEV_MAX_ENTRIES = 24`), so each applet gets roughly half
what it needs: **4 resident FIDO credentials** on a device whose `text` is 800 KB
of a 4 MiB chip. Every credential write rewrites every credential, one corrupt
byte costs the whole set, and `DEVICE_MAX_CREDS = 12` was never reachable —
`other_slots + 2 × parts ≤ 24`, not the 5,952 B payload the constant's own
comment cites. None of that was a security decision. It was three storage
backends accreted without a common shape.

What the complexity bought, concretely: nothing — and it is not even consistent.
`Rp2350SecureStore` seals its image under an OTP-derived root
(`store_v3::derive_store_key(otp_key_1, chipid)`); the trussed littlefs2 at `0x102_000` is an
**unencrypted** filesystem whose key wrapping is each applet's own affair; and the RAM
`EFS`/`VFS` are formatted on every boot. Three backends, three protection stories, one of them
already the thing the other two were built to avoid. One hierarchy was available
from the start.

**How to apply it, in order:**

1. **One record format, one region, one key hierarchy** for every applet that
   holds a key — present and future. A second backend for a new applet is a
   decision that must be argued in writing, not inherited.
2. **Name the attack before adding a mechanism.** "More secure" is not a reason.
   "An attacker with a flash dump can enumerate the credential set without the
   PIN" is a reason, and it is testable.
3. **Prefer the boring mechanism.** One AEAD record with an AAD that binds
   slot, generation and identity beats a bespoke blob format every time.
4. **Complexity you cannot delete, at least measure.** We have shipped three
   separate times now: a RAM filesystem formatted at every boot, an OTP-derived
   store key behind a `fatal_boot` that parks the board, and a flash ratchet set
   above the region where OpenPGP keys live.

**The capacity floor is part of the security case, not a concession to it.** A
design that is maximally secure and stores four keys is not secure, it is
broken — and a user who cannot register a passkey has no reason to keep the
device. Capacity is a security property: an unusable authenticator gets returned,
resold, or left in a drawer. When choosing, name **both** the threat you stop
and the credentials you can still hold, and if the second number is small, the
design is wrong.

**Corollary for reviewers:** "this is how the reference does it" is a real
answer — `../pico-fido`, `../pico-openpgp`, `../pico-hsm` and `../RS-Key` all
ship per-record flash storage with an OTP- or device-rooted key — but it is not
a shortcut past measuring. They also each hold 256 credentials, which is the
part that makes their design the simpler one rather than merely a different one.

### 6. getInfo must contain no CBOR integer wider than 32 bits.

This is not a style rule. It is the whole getInfo response.

`yubikit` — the library behind **Yubico Authenticator on Android and on the
desktop** — decodes CBOR integers with `Cbor.loadInt`, which handles
additional-info `0..26` and throws
`IllegalArgumentException("Unable to load integer")` at `27`. Additional-info
`27` is a **64-bit** unsigned integer, head `0x1B`.

So a single 64-bit value anywhere in getInfo does not degrade one field — it
aborts `Ctap2Session`'s constructor, the response is never handed to the
application, and **every** Passkeys/FIDO screen fails to load. Measured on
hardware: a 519-byte getInfo whose key `0x15` (`vendorPrototypeConfigCommands`)
held six 64-bit ids died at byte offset 381; allowing additional-info 27 decoded
the other 20 keys with no trailing bytes.

`python-fido2` reads 64-bit integers without complaint. **That is why this is
invisible from the Linux side** — `ykman fido info`, the whole emulator suite,
and the repo's own tests all pass while every Yubico client is broken. Do not
treat "python-fido2 is happy" as evidence that a getInfo field is shippable.

**Consequences you will otherwise re-derive the hard way:**

* **Key `0x15` is deliberately not emitted.** The six vendor-prototype ids are
  64-bit because *PicoForge* says so — `VendorConfigCommand::from_u64`
  (`../picoforge/src/hal/fido/constants.rs:487-521`) hardcodes those exact
  values and sends them on write, so they are not ours to narrow. Advertising
  them was never load-bearing: both twins dispatch `authenticatorConfig` `0xFF`
  on the id in key `0x01` of the **request** (`app.rs::cfg_vendor_prototype`,
  `vendorff::PhyCommand::decode`) and neither reads getInfo, and PicoForge's
  write path uses a compile-time enum (`ops.rs:154`) rather than the discovered
  list. A real YubiKey 5 omits `0x15` too.
* **The gate is stated in the client's terms**, not as "key 0x15 must be absent",
  so it catches a 64-bit field appearing anywhere:
  `getinfo_holds_no_integer_wider_than_32_bits` in `apps/fido/tests/getinfo.rs`,
  over **both** encoder paths (`to_cbor` and the no-heap `write_cbor_into` — the
  two are separate code and only one ships).
* A CBOR integer needs a `0x1B` head **iff** its value exceeds `0xFFFF_FFFF`, so
  the test asserts on the decoded value. That is also why `0x0E`
  (`firmwareVersion`) must stay `u32` and stay below `0x1_0000`.

### 7. AID matching is a prefix match, in the C SDK's direction.

Yubico's **Java** `yubikit` selects OATH with an **eight**-byte AID —
`a0 00 00 05 27 21 01 01` (`core/smartcard/AppId.java`, `AppId.OATH`, on both
`main` and the 2.8.0 generation) — while this firmware and
`../pico-fido2/pico-keys-sdk/src/oath.c` both register the seven-byte
`a0 00 00 05 27 21 01`. Exact comparison returns `6A82` from `OathSession`'s
constructor and every OATH screen dies, with Management (whose AID happens to
be eight bytes here) answering fine moments earlier — an asymmetry in the log
that points straight at the length.

**The asymmetry is between Yubico's own two clients.** `ykman`'s *Python*
`yubikit` sends the seven-byte form (`AID.OATH = a0000005272101`), so the Linux
desktop, `ykman fido info` and every test in this repository never saw it. Do
not read "ykman works" as evidence that an AID length is fine — `ykman` is not
the client that failed.

`Dispatcher::find_app` therefore mirrors `main.c:85`: **the registered AID is a
prefix of the request**. The direction matters. RS-Key uses the inverse
(`applet.rs:378`, `app.aid().starts_with(apdu.data)`), which admits truncated
AIDs down to one byte; adopting it would let `00 A4 04 00 01 A0` reach OATH.
`a_shorter_candidate_does_not_select_the_applet` pins the direction.

Prefix matching is unambiguous only while no registered AID is a prefix of
another, which is why `register` rejects **overlap** rather than mere equality
(as `app_exists`, `main.c:56`, does) and why
`no_device_aid_is_a_prefix_of_another` pins the registered set in
`apps/tests/registry.rs`.

---

## A yellow "Online - FIDO" in PicoForge is usually the USB identity, not a bug in the applet

Read this before blaming the Rescue applet, and before blaming `pcscd`. Both
were wrong answers on the board this was written for.

PicoForge's badge is one comparison: `status.method == DeviceMethod::Fido`
(`sidebar.rs:317-327`). `method` becomes `Rescue` **only** if
`rescue::read_device_details()` returns `Ok`, and that path is **PC/SC-only,
with no fallback**. Every failure in it is folded into a `log::warn!`
(`io.rs:35-40`), so the reason never reaches the user — the badge just goes
yellow while every FIDO feature keeps working. Four things produce it, and they
look identical from the UI:

1. **The stored VID/PID is not in libccid's table.** No CCID reader, so no
   rescue leg. This is the one that actually occurred, and it is **ours**: the
   Rescue `WRITE` of the VID/PID applies at enumeration (`usb.rs:425-437`),
   overrides the build-time default, and **survives a reflash**. On a stock
   Ubuntu host `2E8A` is paired only with `0x10FF`, so of the four `2E8A:*`
   presets PicoForge offers, only `2E8A:10FF` binds. `docs/identity.md` has the
   mechanism; `scripts/fix_usb_identity.py` diagnoses (`--list-known`,
   default) and repairs (`--set FA20:0002`) it, the latter over the FIDO carrier
   because PC/SC is exactly what is gone.
2. **`pcscd` churn.** The packaged unit runs `--auto-exit`, so the daemon exits
   the moment the last client disconnects — and PicoForge opens a *fresh*
   connection per operation (`rescue/mod.rs:18-33` opens one per call), so it
   loses the race against the gaps between its own calls. A drop-in at
   `/etc/systemd/system/pcscd.service.d/` with `ExecStart=` cleared and
   `ExecStart=/usr/sbin/pcscd --foreground` removes it.
3. **A `6A82` SELECT failure** — the reader-ordering hazard in the README's
   *PicoForge compatibility* section, where another PC/SC reader is enumerated
   first and every APDU goes to the wrong card.
4. **A genuine applet fault** — `RESCUE PC/SC discovery error: Device Error:
   Rescue Applet not found` or `Rescue read_device_details failed`. Across the
   board this was investigated on, the Rescue SELECT succeeded **215** times
   and "Rescue Applet not found" appeared exactly **once**.

**Discriminate from the log, not from the badge.** The three lines are ordered
and mutually exclusive — read whichever fired:

```
~/.var/app/in.suyogtandel.picoforge/data/picoforge/logs/picoforge.log
  "No Rescue PC/SC device found"          -> the reader is gone   (case 1 or 2)
  "Rescue PC/SC discovery error: ..."     -> SELECT refused / PCSC (case 3 or 4)
  "Rescue read_device_details failed: ..."-> our applet answered non-9000 (case 4)
```

And note that **passkeys working while the badge is yellow proves nothing**:
FIDO runs over CTAPHID/`usbhid` and never touches `pcscd`. That was the
reason case 1 survived as long as it did.

---

## Layout

```
firmware/src/
  main.rs        boot, app construction, USB device, task spawn
  boot.rs        statics (MANAGEMENT_APP, OTP_APP, FIDO_APP…), flash partitions, REBOOT
  tasks.rs       CCID task, CTAP-HID task (CTAPHID framing, presence windows)
  otp_hid.rs     YubiOTP HID frame handler (runs one INS 0x01 OTP APDU)
  ctap_hid.rs    CTAPHID assembler, CID allocator, HID command constants
  emul_main.rs   host emulation binary over TCP sockets (`--features emulation`)
  bin/{bringup,bridge,hwtest}.rs
apps/{fido,oath,openpgp,piv,mgmt,rescue,vendor_led}/
platform/src/
  dispatch.rs    the AID dispatcher every applet registers with
  usb.rs         USB device, composite interfaces, identity from PhyConfig
  otp_hid.rs     YubiOTP transport (report descriptors, feature-report state machine)
  ccid.rs, cflash.rs, cfs.rs, ckey.rs   flash / partition / key-derivation
vendor/
  opcard           OpenPGP card 3.4 (the real implementation; apps/openpgp wraps it)
  ed448-goldilocks, x448, trussed-secp256k1, trussed-brainpool
```

Applet maturity differs a lot — check before assuming: `fido` (~28.6k lines)
and `oath` (6.9k) are deep; `openpgp` (887) is a thin wrapper over
`vendor/opcard`; `mgmt` (997) and `rescue` (1267) are small by design;
`vendor_led` (495) is the PicoForge physical-config channel.

---

## Reference implementations

Use these as the specification of correct behaviour — they are the things
that already work with Yubico software.

- **[pico-fido](https://github.com/polhenarejos/pico-fido)** (C; `../pico-fido`)
  — the reference for FIDO2/U2F/OTP. Authoritative for the CTAP2 wire
  behaviour and the management applet.
- **[RS-Key](https://github.com/TheMaxMur/RS-Key)** (C; `../RS-Key`) — the origin
  of the `0x41` vendor channel (`apps/fido/src/vendor41.rs`) that fapico2 also
  answers.
- **[picoforge](https://github.com/librekeys/picoforge)** (Rust; `../picoforge`)
  — the first-party management GUI. **Its wire dialect is the one Yubico's own
  library also speaks**, so it is the best executable spec for credMgmt:
  `src/hal/fido/{ops.rs,constants.rs}` name every field. Compare against those
  before inventing a layout.

---

## Build, flash, test

**Tag convention ([ADR 0002](docs/adr/0002-provisioning-policy.md)):** release tags carry a `-release` suffix (`vX.Y.Z-release`).
Alpha/beta images keep the debug port available and burn nothing irreversible; `-release` images
are the boundary where the `DEBUG_DISABLE` closure will apply. The repository carries **no tags
yet** — `git tag -l` returns empty as of 2026-10-04 — so the convention binds from the first
one, and no tag is created by ADR 0002.

**Commit messages carry no AI trailers.** Do not add `Co-Authored-By`, a
`Generated with …` line, or any other AI-attribution footer — whatever the
model behind the harness calls itself. ZCode is Claude Code under a different
name, and the co-author habit came across with the code: it was written
unprompted on 2026-09-26, with no instruction anywhere in the harness, the
`commit` skill, or the repo's history to produce it.

97 commits between 2026-09-26 and 2026-10-05 do carry
`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. That is
the artifact, not the convention. Reading `git log` and matching what is
already there is how it spread — copying a trailer out of history is the same
mistake as copying a bug out of a function you were asked to delete. The only
author and committer this repository uses is `eddieoz <eddieoz@pm.me>`.

```bash
./build.sh                     # release UF2 for RP2350 -> firmware/fapico2.uf2
cargo test -p fapico2-fido --target x86_64-unknown-linux-gnu
./run_tests.sh                 # clippy + gates + pytest (needs a pytest interpreter;
                                 # see "The pytest interpreter" below)
./run_tests.sh --suites-only   # just the emulator suites — what ci.yml's pytest-gate runs
```

**The pytest interpreter.** The suites live in this repository (`tests/`) and
their dependencies are declared in `tests/requirements.txt`. `run_tests.sh`
takes the interpreter from `PICO_FIDO2_VENV`, defaulting to the sibling
`../pico-fido2/.test-venv`; to use an in-repo one:

```bash
python -m venv .test-venv
./.test-venv/bin/pip install -r tests/requirements.txt   # needs libpcsclite-dev for pyscard
PICO_FIDO2_VENV=$PWD/.test-venv/bin/python ./run_tests.sh
```

CI builds that venv from `tests/requirements.txt` and passes it the same way.

`build.sh` must produce the UF2 through `firmware/uf2gen.py`. Plain
`elf2uf2` output **silently does nothing** on this bootrom — it lacks the
RP2350-E10 absolute preamble and the embedded PICOBIN partition table
(US-924, found on hardware).

### Getting into BOOTSEL without touching the board

The rescue applet's `REBOOT` puts a running board into USB mass-storage
bootloader. **No auth, no PIN, no button** — `cmd_reboot` only checks
`P2 == 0x00` and the mode in `P1` (`apps/rescue/src/lib.rs:1106`).

```
SELECT AID  A0 58 3F C1 9B 7E 4F 21      (RESCUE_AID, lib.rs:339)
REBOOT      80 1F 01 00 00               P1 = 0x01 BOOTSEL (INS 0x1F, lib.rs:414)
```

Mode is in **P1, not P2**; `P2` must be `0x00` or you get `6B00`. `P1 = 0x00`
is a *normal* reboot, not BOOTSEL.

```python
from smartcard.System import readers
from smartcard.util import toBytes
r = readers()[0]; c = r.createConnection(); c.connect()
c.transmit([0x00,0xA4,0x04,0x00,8] + list(toBytes('A0 58 3F C1 9B 7E 4F 21')))
c.transmit([0x80, 0x1F, 0x01, 0x00, 0x00])          # SW=9000, board leaves the bus
```

```bash
udisksctl mount -b /dev/sdd1          # -> /media/$USER/RP2350 (label RP2350)
cp firmware/fapico2.uf2 /media/$USER/RP2350/
```

Then poll `lsusb` for `1050:0407` — **8 s to ~52 s** is normal (bootrom flash
write, not a hang); wait a full minute before calling it dead.

Gotchas, each of which cost time:

- **Close anything holding the CCID reader first.** Yubico Authenticator and
  `ykman` take an exclusive pcscd connection; with one open the APDU fails
  with `CardConnectionException: Sharing violation. (0x8010000B)`.
- The drive is **often already mounted**; `udisksctl mount` then says
  `AlreadyMounted`. Check `lsblk -o NAME,LABEL,MOUNTPOINT | grep -A1 sdd`.
  `sudo mount` is not available in an agent session.
- **Copying right after REBOOT races the automounter** (`Not a directory`).
  Re-check the mount point first.
- REBOOT(BOOTSEL) is only destructive if you then flash over a **stale secure
  partition** (brick needing `nuke_universal.uf2`). A plain reflash leaves the
  flash-resident store intact.

---

## Hardware warnings

- **Never run this firmware with a SWD debugger attached.** `probe-rs run` /
  `gdb … load; monitor reset` make `OTP_DATA_RAW` reads return `0xFFFFFFFF`,
  which embassy-rp maps to `InvalidPermissions`, which `read_otp_key_1()` reads
  as "no key" — `fatal_boot` fires **before USB is constructed**. The result is
  a false "the OTP key row is unreadable" failure on a perfectly healthy board,
  *including on known-good commits*. Validate detached, over BOOTSEL. Use the
  probe to **read**, never to run.
- RP2350 register maps (getting these wrong caused a bogus "SWD can't read
  OTP"): OTP controller `0x4012_0000`; `OTP_DATA` `0x4013_0000`; `OTP_DATA_RAW`
  `0x4013_4000`; TRNG `0x400F_0000`. `0x400D_8100` is the **RP2040** map and
  reads all zeros here.

---

## Verifying against the real Yubico stack

Host tests are a proxy. For anything user-visible, drive the actual client.
`fido2 2.2.1` is already installed in `../pico-fido2/.test-venv`.

```bash
# ykman is not packaged here; install from a GitHub checkout (it vendors yubikit).
# PyPI is blocked in this environment; GitHub is not.
git clone --depth 1 https://github.com/Yubico/yubikey-manager.git
../pico-fido2/.test-venv/bin/pip install --no-deps ./yubikey-manager
ykman list && ykman fido info && ykman otp info     # all three interfaces
```

`ykman` imports `pskc` at CLI start even for `ykman fido`; stub it on
`PYTHONPATH` rather than reaching for the network.

For the **GUI** (no apt package; building needs GTK4 the host may lack):

```bash
# prebuilt AppImage bundles its own GTK4
curl -sSL -o ya.AppImage https://github.com/azagramac/yubico-authenticator-appimage/releases/download/7.4.1/yubikey-authenticator-7.4.1-x86_64.AppImage
chmod +x ya.AppImage && ./ya.AppImage --appimage-extract
Xvfb :99 -screen 0 1600x1000x24 &
DISPLAY=:99 ./squashfs-root/AppRun &
DISPLAY=:99 import -window root shot.png        # ImageMagick
```

Drive it with python-xlib (`Xlib.ext.xtest.fake_input`) — there is no
`xdotool` here, and `set_input_focus` is `(revert_to, time)` and focuses
`self`, so call it **on the app window**.

### Things that are easy to get wrong when probing by hand

- The CTAP2 opcode is the **first byte of the CBOR payload**; the CTAPHID
  frame command byte is always `TYPE_INIT | 0x10` (`0x90`). Folding the opcode
  into the frame byte yields a silently different command.
- In CTAP2 §6.5.6.3 the **pinUvAuthToken itself is the HMAC key** for
  `pinUvAuthParam`; the HKDF-derived key is only for setPIN/changePIN. The
  firmware agrees — signing with the HKDF key fails.
- A PicoForge credMgmt request omits `subCommandParams` entirely for
  `enumerateRpsBegin` and signs the bare sub-command byte.

## Debugging FIDO/CTAP in a real browser

### `chrome://device-log/` is empty unless Chrome was launched for it

The device log is written only with `--enable-logging`. **The chrome-devtools
MCP browser is launched without it** (check `chrome://version` → Command Line),
so `chrome://device-log/` is *always* empty there and will mislead you into
thinking Chrome saw nothing. That is not evidence of anything.

Launch your own Chrome with logging and drive it over CDP:

```bash
# scripts/drive_logging_chrome.py does exactly this and leaves the log behind.
python3 scripts/drive_logging_chrome.py https://demo.yubico.com/webauthn-technical/registration 200
tail -f /tmp/chrome-wa.log
```

Equivalent flags, if you are driving it yourself:

```bash
/opt/google/chrome/chrome --remote-debugging-port=9333 \
  --user-data-dir=/tmp/chrome-wa-profile --no-first-run --no-default-browser-check \
  --enable-logging --v=1 \
  --vmodule=*/device/fido/*=3,*/webauthn*/*=3,*/web_auth*/*=3,*/authenticator*/*=3,\
*/content/browser/webauth/*=3,*/device_event_log/*=1 \
  --log-file=/tmp/chrome-wa.log --ozone-platform=x11
```

Drive it with a CDP client over the WebSocket (`websockets` is in the system
python3, not the venv; there is no playwright/selenium here). `Page.addScriptToEvaluateOnNewDocument`
installs a hook before page scripts, `Runtime.evaluate` clicks, `Runtime.consoleAPICalled`
streams the hook's `console.log`. Do **not** open a second profile against a
board a ceremony is already using — two Chromes on one key makes every reading
ambiguous.

### The lines that actually decide a FIDO bug

```
device_response_converter.cc:403 -> {1: ["U2F_V2", ...], 4: {...}}   what we advertised
authenticator_request_dialog_model.cc:158 UI step: kCableV2QRCode     QR/hybrid fallback
authenticator_request_dialog_model.cc:158 UI step: kClientPinEntry     PIN prompt shown
ctap2_device_operation.h:91  <- 0x6 {1: 2, 2: 9, 9: 3, 10: "rp"}      PIN leg in flight
ctap2_device_operation.h:188 -> {2: h'...'}                           pinUvAuthToken minted
ctap2_device_operation.h:142 -> (CTAP2 error code 0x15 ...)           and the error, named
make_credential_request_handler.cc:825 Ignoring status 1             CTAP2 abandoned
u2f_register_operation.cc:195 Unexpected status 27264                 CTAP1 was tried (0x6A80)
```

`kCableV2QRCode` is the QR-code popup: it is the *cross-device* dialog step,
not a distinct failure, but on a page that fails it is where the UI is left
parked. `0x15 LIMIT_EXCEEDED` from makeCredential is nearly always a
**parser capacity** bug, not a full store — see §1 on the twin trap and
`apps/fido/src/device_core.rs` for the fixed capacities.

### Hooking the page: observe, never interfere

Hook `navigator.credentials.create`/`get` to capture what the RP asked — the
`authenticatorSelection` and `residentKey` values are what separate a site that
works from one that does not, and they are not visible anywhere else:

```js
console.log('[WA] create uv=' + opts.publicKey.authenticatorSelection.userVerification);
```

**The hook must not throw.** `navigator.credentials.create` returns the
promise *the page itself awaits*, so an exception inside your `.then()`
rejects it: the device succeeds, the authenticator is faultless, and the site
reports "operation timed out or was aborted". This cost an hour once. Wrap the
whole handler in `try/catch` and return the credential untouched. Related:
`credential.response.authenticatorData` is an **ArrayBuffer**, not a view, so
`ad.buffer` is `undefined` — use `new Uint8Array(ad)`.

### What you cannot see from the page

The PIN dialog is browser chrome, not DOM: a page screenshot shows nothing and
`document.querySelector('dialog')` finds nothing. Either read the device log
(`UI step: kClientPinEntry` is the proof the prompt appeared) or ask the person
at the keyboard. The virtual authenticator in DevTools → More tools →
WebAuthn is genuinely useful for isolating *Chrome's* behaviour from the
device's — if it completes a ceremony your board cannot, the defect is yours.

`scripts/probe_*.py` cover the non-browser half: `probe_uv_policy.py` (GetInfo
A/B), `probe_mc_uv_ab.py` (token-less makeCredential and both clientPIN legs),
`probe_clientpin_legs.py` (the real ECDH+PIN handshake, which is the only way to
tell "0x14 MISSING_PARAMETER" from "the leg works"), `probe_u2f_path.py` (the
CTAP1 framing gap).