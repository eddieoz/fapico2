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

```bash
./build.sh                     # release UF2 for RP2350 -> firmware/fapico2.uf2
cargo test -p fapico2-fido --target x86_64-unknown-linux-gnu
./run_tests.sh                 # clippy + gates + pytest (needs the ../pico-fido2/.test-venv
                                 # interpreter; override with PICO_FIDO2_VENV=/path/to/python)
```

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