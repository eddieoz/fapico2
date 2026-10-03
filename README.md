# fapico2

A Rust rewrite of the merged `pico-fido2` firmware on the Trussed +
embassy-rp stack, targeting the Raspberry Pi Pico 2 (RP2350,
`thumbv8m.main-none-eabi`). **One firmware, one binary**: a single UF2 image
serves FIDO2/U2F (CTAP-HID), OpenPGP 3.4, OATH, OTP and Management over one
USB composite device (CCID + CTAP HID), apps selected by AID.

**Status:** FIDO2/U2F, OpenPGP 3.4 and OATH command sets are served on the
RP2350, with hardware acceptance passed for all three; PIV serving is
**deferred** (see the app table). The C `pico-fido2` tree stays frozen but
shippable; all new features land only in Rust.

`firmware/` is the binary crate (USB serve loops, `memory.x`, `uf2gen.py`);
`platform/` the transport, AID dispatcher, TRNG, secure store and C-flash
reader; `apps/` the applet crates.

## Apps and AIDs

| App | Transport | AID | Notes |
|---|---|---|---|
| OpenPGP 3.4 | CCID | `D2 76 00 01 24 01` | full opcard OpenPGP 3.4 command set; hardware-accepted (`docs/hardware-matrix.md` row 1) |
| OATH (YKOATH) | CCID | `A0 00 00 05 27 21 01` | full YKOATH command set; hardware-accepted (`docs/hardware-matrix.md` row 3) |
| OTP | CCID | `A0 00 00 05 27 20 01` | served inside the management app crate |
| Management | CCID | `A0 00 00 05 27 47 11 17` | config, rescue surface, migration passphrase APDU |
| FIDO2/U2F | CTAP HID | n/a (HID, no AID) | full CTAP2.1 command set incl. credProtect/credBlob/hmac-secret, credMgmt, largeBlobs; hardware-accepted (`docs/hardware-matrix.md` row 2) |
| PIV | — | `A0 00 00 03 08` | **deferred — post-v1.0.0**; data still re-seeded by migration |

## Requirements

```bash
rustup target add thumbv8m.main-none-eabi
sudo apt-get install -y gcc-arm-none-eabi   # ARM ELF linker for the device build
# picotool or probe-rs for flashing (optional — UF2 needs neither)
```

The workspace targets `thumbv8m.main-none-eabi` (RP2350 / Pico 2) via
`firmware/.cargo/config.toml`, device feature by default; host builds and tests
run under the host triple with `host`/`emulation`.

## USB identity (provisional)

The firmware enumerates as **`fa20:0002` "The BLOCO Community" "fapico2"**.
Units flashed before the manufacturer rename (2026-09-28) still enumerate as
"EddieOz"; the strings differ, the `fa20:0002` ids do not.

> **Provisional identity note:** `0xFA20` is **not** a USB-IF-registered vendor
> ID; production needs a registered VID. Until then macOS and Linux need
> libccid's `Info.plist` allowlist edited so `pcscd` sees the CCID reader — the
> procedure is in [`docs/identity.md`](docs/identity.md#pcsc-allowlist-libccid).
> CTAP-HID (`usbhid`) is unaffected everywhere.

AAGUID, USB manufacturer/product and VID:PID are one build-time block
(`platform/src/identity.rs`), each with a published default and a
`FAPICO2_*` override; a malformed override is a **hard build failure**, never a
silent fallback. Every build script in this repository sets none of those
variables, so the defaults are the identity this repository builds; an override
additionally requires `FAPICO2_IDENTITY_OVERRIDE_ACK=1` or the build fails
(US-1517). The AAGUID default is fapico2's own; the RS-Key borrow,
the override procedure, the one-way-door warning, and
`FAPICO2_FOREIGN_IMAGE_WIPE` (default: the secure store **survives** a reflash)
are all in [`docs/identity.md`](docs/identity.md).

## PicoForge compatibility

PicoForge's PC/SC client takes the **first** reader `list_readers()` returns — never iterating, filtering by name, or falling back to a second (`picoforge/src/hal/transport/pcsc.rs:37-43`, identically `ccid.rs:38-42`). Where another PC/SC reader is enumerated first, every SELECT — Rescue, vendor LED, Management — goes to the **wrong card**, answers `6A82`, and the client returns `Err("Rescue Applet not found...")` rather than `None` (`pcsc.rs:66-71`): the token is healthy and the client simply talked to a different card. `write_led_config` opens a **fresh PC/SC connection per LED slot** (`picoforge/src/hal/io.rs:199-205`), so the same misordering yields a **silently half-written LED profile with every call reporting success**.

**Mitigation is client-side: keep the token as the only reader on the host, or
report this upstream — it is not fixable from the firmware**, since nothing in
the image changes which reader the client picks. The `0xFA20` / `0x0002`
`libccid_Info.plist` allowlist in [USB identity](#usb-identity-provisional) is a
`pcscd` gate, so it binds any PC/SC application, not just PicoForge.

### AAGUID note

fapico2's default AAGUID is now **fapico2's own** (`66617069636F3200…0002`,
ASCII `fapico2`) rather than the borrowed RS-Key
`2479C7BF6B3056839EC80E8171A918B7` (risk R-3's borrow is over) — but until
PicoForge adds it to `firmwares/mod.rs`, a default build is **unclassifiable by
the app** and lands on the pico-fido profile. Flash with
`FAPICO2_IDENTITY_OVERRIDE_ACK=1 FAPICO2_AAGUID_HEX=2479C7BF6B3056839EC80E8171A918B7`
to test PicoForge features — the acknowledgement is **required** (US-1517), so
an override cannot arrive by accident and quietly make one image serve a
different identity from every other build of this checkout. The block's
`DEFAULT_AAGUID` rules, the one-way-door warning and the
runtime name path live in `platform/src/identity.rs` and
[`docs/identity.md`](docs/identity.md).

## Building

```bash
# Device (release firmware, the size-gate + defmt path) -> RP2350 ELF
cargo build --release --target thumbv8m.main-none-eabi

# Host (the workspace default target is the device one; override it)
cargo test --target x86_64-unknown-linux-gnu --exclude fapico2-firmware

# Emulation: CCID + HID over TCP sockets, driving the same app stacks
cargo build -p fapico2-firmware --no-default-features --features emulation

# Lint
cargo clippy --target x86_64-unknown-linux-gnu --exclude fapico2-firmware --all-targets -- -D warnings
cargo clippy --target thumbv8m.main-none-eabi -- -D warnings
```

The device build links an `arm-none-eabi` ELF at
`target/thumbv8m.main-none-eabi/release/fapico2-firmware` (text ≤ 3.5 MiB gate,
CI-enforced; measured against the C baseline in `docs/size-report.md`). The
image is trimmed via cargo features, not code edits: `emulation` swaps the
transports for host TCP sockets, and per-app `device`/`host`/`virt` features
mean an app crate absent from `firmware`'s `device` list is absent from the ELF.

## Flashing (RP2350 / Pico 2, BOOTSEL)

Full procedures (both firmwares, recovery paths) live in
[`docs/bootsel.md`](docs/bootsel.md). Summary:

1. Build the release firmware and convert it, then copy and reboot:

   ```bash
   ./build.sh                       # build + generate firmware/fapico2.uf2
   cp firmware/fapico2.uf2 /media/<user>/RP2350/
   ```

   `build.sh` is the supported local path; `./build-signed.sh` produces a
   signed image instead. No build output is committed — CI produces the
   release artifact from source. (`elf2uf2-rs` hardcodes the RP2040 UF2 family
   id, so the repo ships `firmware/uf2gen.py`; `picotool uf2 convert` works
   too.)

2. Get the board into BOOTSEL — **physical BOOTSEL + RESET**: hold BOOTSEL
   while plugging in, or hold BOOTSEL and tap RESET. The `RP2350` drive mounts
   at `/media/<user>/RP2350/`. (The C `pico-fido2` firmware also accepts
   `scripts/bootsel.py --bootsel` for a programmatic rescue APDU with no
   button press; the Rust build is physical-BOOTSEL only.)

The device enumerates as a composite CCID + CTAP-HID gadget, `fa20:0002`
"The BLOCO Community" "fapico2": OpenPGP/OATH/OTP/Management over CCID
(`pcscd`), FIDO2/U2F over HID.

## Migration from C firmware (first Rust boot)

On the first boot after cutover from the C `pico-fido2` firmware the Rust image
detects the C data partition and **re-seeds the Rust keystore from it** (read-only, idempotent).

- **Silent (no user input):** FIDO keydev + resident credentials, OATH
  credentials, OTP slots, Management `EF_DEV_CONF`, PIV objects (re-seeded,
  serving deferred), OpenPGP public keys / certs / DOs / PIN hashes.
- **One-time PW1/PIN step:** OpenPGP **private keys** and PIN-wrapped FIDO
  keydevs need the passphrase **once**, via the migration management APDU. A
  wrong passphrase ⇒ `NEEDS_PASSPHRASE` (constant-time); C retry counters are
  untouched, the C region being read-only throughout.
- **Not migratable:** the vendor ChaChaPoly keydev (`EF_KEY_DEV_ENC 0xCC01`).

Byte formats, derivations and per-class verdicts:
[`us413-migration-feasibility.md`](docs/migration-feasibility.md).

## Client compatibility

The PicoForge single-reader caveat above is one of a set of client-side gaps
that no firmware change can fix. The rest — PicoForge's OpenPGP factory-reset
retry loop surviving this card's `63Cx`-not-`6983` exhaustion behaviour, the
OpenPGP serial change and the host key-stub cleanup it needs, and the
hardware-verified algorithm list — lives in
[`docs/client-compatibility.md`](docs/client-compatibility.md).

## Size budget

C baseline: **530,980 B text**, 86,804 B bss. Two ceilings, both enforced:
`text` ≤ 3,670,016 B (3.5 MiB) and `bss` ≤ **SRAM − the 98,304 B stack
ceiling** — the number that decides whether the board boots, not the link.
Per-story deltas and every measured figure:
[`docs/size-report.md`](docs/size-report.md).

## Capacity

Hardware-verified ceilings: **12** FIDO2 resident credentials, **30** OATH
credentials, **24** secure-store entries. Constants that look like capacity
claims but are not (`MAX_CREDS = 68` is a table bound) are called out in
[`docs/capacity.md`](docs/capacity.md).

## Testing

Three layers: **host unit tests** (`cargo test` per crate); **black-box
protocol suites** (the *same* pytest suites that gate the C build —
`tests/pico-fido/`, `tests/openpgp/`, `tests/harness/` — over CCID/HID TCP
sockets via the emulation feature, harness shims only, no suite edits); and the
**hardware matrix** (UF2 via BOOTSEL, CCID over `pcscd`, FIDO over HID —
`docs/hardware-matrix.md`).

> GreenBoost telemetry (`[gb_*]`) pollutes Python stdout; filter it
> (`tests/harness/_filter.py`).

## License

GNU AGPLv3 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

## Security

**Not independently audited; no warranty is offered.** Read
[`SECURITY.md`](SECURITY.md) before trusting this with anything you cannot
afford to lose, and report vulnerabilities there rather than in a public issue.
