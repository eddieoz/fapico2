//! RS-Key / pico-fido **Rescue applet** — AID `A0 58 3F C1 9B 7E 4F 21`
//! (US-161a / US-161b / US-162 / US-163, PICOForge-COMPAT Phase H).
//!
//! One AID-dispatched CCID applet over **CLA `0x80`** with four commands. It
//! is the only applet in this firmware reachable with **no PIN, no
//! `pinUvAuthToken`, no OATH access code, no OpenPGP PW3 and no touch**, and
//! the security justification for shipping that is
//! `docs/tasks/rescue-threat-model.md` (US-165). This module doc does not
//! restate that document; it records what the *code* had to decide, and every
//! decision here cites the client line it was read from.
//!
//! | Command | APDU | Response |
//! |---|---|---|
//! | SELECT | `00 A4 04 04 08 <AID>` | 12 identity bytes + `9000` |
//! | READ FlashInfo | `80 1E 02 00 00` | 5 × u32 BE (20 B) |
//! | READ SecureBootStatus | `80 1E 03 00 00` | `[enabled, locked]` |
//! | READ PhyConfig | `80 1E 01 01 00` | the PHY TLV blob |
//! | WRITE PhyConfig | `80 1C 01 00 <Lc> <TLV>` | `9000` |
//! | REBOOT | `80 1F <mode> 00 00` | `9000`, **mode in P1** |
//! | SECURE | `80 1D 00 <lock> 00` | `9000`, **lock in P2** |
//!
//! # The three wire facts that are easy to get backwards
//!
//! **1. REBOOT's mode is in P1, not P2.** The client's own enum doc comment
//! says P2 — *"P2 parameter determines reboot mode (0x00=Normal,
//! 0x01=Bootsel)"* (`picoforge/src/hal/rescue/constants.rs:143-145`) — and the
//! code sends P1 (`ops.rs:646-652`, and again at `:651` where the byte after
//! the INS is `param as u8`). Three other call sites in the client agree with
//! the code, not the comment. A device that follows the comment always
//! normal-reboots, silently, and no test anywhere notices — the client's own
//! `reboot_device` is `#[allow(dead_code)]` and never called. **This applet
//! implements P1**; see [`RescueApp::cmd_reboot`].
//!
//! **2. PhyConfig READ and WRITE disagree about P2.** The client reads
//! PhyConfig with **P2 = `0x01`** (`ops.rs:295`) while FlashInfo and
//! SecureBootStatus use `P2_UNUSED` = `0x00` (`ops.rs:254`, `:278`), and the
//! WRITE uses `0x00` again (`ops.rs:606`) — so the *same record* is written
//! with `0x00` and read with `0x01`. The `RescueInstruction::Read` doc comment
//! says P2 is "typically 0x00" (`constants.rs:135`), which is true of two of
//! the three reads. This applet therefore **accepts both `0x00` and `0x01` on
//! the PhyConfig read** and nothing else: the two values are indistinguishable
//! on the client side, a device that accepted only one would be unreachable
//! from whichever build chose the other, and the read has no operands for a
//! third value to select. The WRITE accepts only `0x00`, because there the
//! client is unambiguous.
//!
//! **3. Every non-SELECT command is CLA `0x80`.** `APDU_CLA_PROPRIETARY`
//! (`constants.rs:68`) on all six (`ops.rs:251`, `:275`, `:292`, `:603`,
//! `:647`, `:692`). Anything else is `6E00`. The CLA gate is load-bearing in
//! both directions and is not a formality — see
//! *The INS collision* below.
//!
//! ## The INS collision with the Management applet
//!
//! Three of the four Rescue INS values are also Management INS values
//! (`apps/mgmt/src/lib.rs:150-152`: `0x1D` `READ_CONFIG`, `0x1C`
//! `WRITE_CONFIG`, `0x1E` `RESET`). The two applets are separated by **AID and
//! CLA together**, never by INS.
//!
//! The dangerous direction is a `CLA 0x00` APDU arriving at this applet,
//! because the Rescue *SELECT* is itself `CLA 0x00` and the dispatcher's
//! non-AID-SELECT fallthrough is a well-trodden path
//! (`platform/src/dispatch.rs:150-198`). [`RescueApp::process`] therefore gates
//! `cla == 0x80` exactly as Management gates `cla == 0x00`
//! (`apps/mgmt/src/lib.rs:429-431`). The other direction is already closed by
//! Management's own gate: a `0x80` APDU selected on the Management AID is
//! refused `6E00`, never mis-executed — so the worst outcome of a dispatch
//! mistake cannot be an unauthenticated `RESET`. Both directions are pinned by
//! `tests/protocol.rs`.
//!
//! # SELECT: the identity block, and the version byte that is not the version
//!
//! The response is a **raw block, not BER-TLV** — 12 data bytes:
//!
//! ```text
//! [0]        MCU type       1 = RP2350
//! [1]        product type   2 = FIDO
//! [2]        SDK major      8      <-- see below
//! [3]        SDK minor      0
//! [4..12]    chip id        8 bytes, big-endian
//! ```
//!
//! The client keeps the trailing `9000` in the same buffer
//! (`picoforge/src/hal/transport/pcsc.rs:73`, `:89`), so its
//! `select_resp.len() >= 14` test (`ops.rs:234`) is 12 data + 2 status — the
//! EPIC's test name `rescue_select_returns_14_byte_block` and the brief's
//! "12-byte identity block" are the same number seen from two ends.
//!
//! ## [`RSKEY_SDK_MAJOR`] is 8 and must never be "fixed" to 1
//!
//! The classifier is `data.len() >= 4 && data[2] >= 8` → `FirmwareType::RSKey`,
//! else `FirmwareType::PicoFido` (`picoforge/src/hal/transport/pcsc.rs:75-81`),
//! and the same byte is read back as `version_major` (`ops.rs:221`). The
//! reader-name path that runs *first* (`pcsc.rs:45-50`) looks for `"RS-Key"` or
//! `"RSK"` in the PC/SC reader name; this firmware's USB product string is
//! `"fapico2"` (`platform/src/usb.rs:206-211`), which contains neither, so the
//! name path cannot fire and **byte 2 alone decides**.
//!
//! The EPIC's US-161a also says to *"align it with US-102's version constant"*,
//! and US-102's target is `1.1.0` — so `fapico2_mgmt::VERSION_MAJOR` is `5`
//! (`apps/mgmt/src/lib.rs:42`). **Those two instructions contradict each
//! other and cannot both be satisfied.** A byte 2 of `1` classifies this device
//! as `PicoFido` and gates off every RS-Key-only client path, which is the
//! entire point of the phase.
//!
//! So byte 2 is a **separate constant answering a different question**:
//!
//! * `fapico2_mgmt::VERSION_MAJOR` answers *"what firmware am I"* and is `1`.
//! * [`RSKEY_SDK_MAJOR`] answers *"I speak the RS-Key SDK protocol from major
//!   version 8 onward"* and is `8`.
//!
//! The client treats the byte as a protocol-compatibility marker — it
//! classifies on `>= 8` rather than on equality, which is a capability
//! statement, not an identity statement. This is a wart in the client protocol
//! (one byte is both a version field and a product-class discriminator), not
//! something the firmware can satisfy both ways. `tests/protocol.rs` pins the
//! value at 8 *and* asserts it is not `fapico2_mgmt::VERSION_MAJOR`, so a
//! future "consistency" edit that sets it to 1 fails here rather than silently
//! disabling every RS-Key path in the field.
//!
//! # What the WRITE can and cannot actually do
//!
//! The threat model's §0 found that this firmware's USB identity is
//! compile-time: `UsbConfig::new(ident.vid, ident.pid)` then
//! `manufacturer = Some(ident.manufacturer); product = Some(ident.product)`,
//! all resolved from the build-time identity block
//! (`fapico2_platform::identity`), and `Usb::new` is the sole constructor and
//! takes no `PhyConfig` (`firmware/src/main.rs:585-593`). So a `0x00` write
//! records operator intent in the FIDO keystore's auth-map key 6 and changes
//! nothing observable on the bus.
//!
//! Worse, the client **can** write tags this firmware has nowhere to put. Of
//! the twelve PHY tags, five have a field in the persisted record
//! (`vendorff::PhyConfig`: `vid_pid`, `led_gpio`, `led_brightness`, `options`,
//! `enabled_usb_itf`) and **seven do not**: `Curves` (`0x0A`),
//! `PresenceTimeout` (`0x08`), `UsbProduct` (`0x09`), `LedDriver` (`0x0C`),
//! `LedOrder` (`0x0D`), `LedNum` (`0x0E`), `UsbManufacturer` (`0x0F`). The
//! `0x41` path already refuses exactly that group with
//! `CTAP2_ERR_UNSUPPORTED_OPTION` (`0x2A`,
//! `apps/fido/src/vendor41.rs:1680-1687`), and the threat model §10.3 records
//! that **accepted-and-ignored is not available**: the client's reader skips a
//! tag it does not know with a `_ => {}` arm
//! (`picoforge/src/hal/fido/mod.rs:1001-1003`), so a silently-dropped record
//! would be reported to the operator as a successful configuration change.
//!
//! **Decision: this applet takes §0.2 Option A — the undestined seven are
//! refused, whole, with `6A86`, and nothing in the blob is applied.** That is
//! the same rule `0x41` applies and the only answer that does not lie to the
//! client. The consequence is recorded here because it is a real functional
//! limit, not an implementation detail: **a Rescue WRITE that carries any of
//! those seven tags fails, including the tags next to it in the same blob.** The
//! normal client path stays inside the writable set, because the client only
//! round-trips tags the device *reported* on READ — and this applet reports
//! exactly the five that have a destination (see below). A user who types a new
//! product name into the client's Config screen gets an honest `6A86` rather
//! than a success that changed nothing.
//!
//! The alternative, Option B (add the seven fields to the persisted record),
//! stays refused. It is a change to the secure-snapshot codec with its own size
//! budget, and it would *create* two new unauthenticated-writable identity
//! strings on a surface that is already unauthenticated — US-115's
//! *"identity-spoofing surface"* made worse, not better.
//!
//! # The CCID-mask guard: a **safety** property, not a security one
//!
//! Tag `0x0B` (`EnabledUsbItf`) must never lose bit `0x01` (`USB_ITF_CCID`).
//! The client volunteers this on our behalf — *"SAFETY: Never write a mask
//! without CCID, otherwise Rescue applet is unreachable"*,
//! `picoforge/src/hal/rescue/ops.rs:580-582` — but a client-side courtesy is
//! not a control: an attacker writing raw APDUs is under no obligation to
//! reproduce it, and the whole point of this surface is that the client is not
//! in the trust boundary. Without the device-side rule, the six-byte APDU
//! `80 1C 01 00 06 0B 01 00` writes a zero mask, the device re-enumerates with
//! no CCID interface, and the applet that performed the write can no longer be
//! reached to undo it.
//!
//! **It is a safety property because it protects the operator, not the
//! operator's secrets.** Nothing about a cleared mask discloses a credential,
//! lifts a PIN or reaches key material; what it does is brick the recovery
//! path. A control that the thing it protects can remove is not a security
//! control, and this one is the reason the lock decision in the threat model's
//! §6 is survivable: a device whose PHY writes are locked is still
//! re-configurable *within* the applet, because any write it accepts is a
//! write that kept CCID on.
//!
//! ## It is deliberately *not* the `0x41` rule
//!
//! `vendor41` has an unconditional refusal of a **zero** mask
//! (`zero_mask_refusal_value`, `apps/fido/src/vendor41.rs:1409-1415`), which
//! refuses exactly one value: `0`. It would happily accept `0x02` (WCID only,
//! no CCID) — equally a brick on this surface, because CCID *is* this applet's
//! own transport. **The Rescue guard is strictly stronger: it requires bit
//! `0x01` to be retained, not merely the mask to be non-zero.** The two rules
//! must both exist and must not converge; a reviewer who sees them converge
//! should assume one was copied without reading (threat model §9 tripwire 4).
//!
//! ## Merge semantics, and which "merge" is meant
//!
//! Two different merges are in play and the threat model's §7 uses the word for
//! both, so this applet separates them:
//!
//! * **Blob-level merge** — *"The rescue WRITE 0x1C merges (RS-Key bcd
//!   0x083A+), so an omitted tag is preserved"* (`ops.rs:584-585`). This is what
//!   [`RescueApp::cmd_write`] implements: a tag absent from the blob keeps its
//!   stored value. A single WRITE therefore changes exactly one field, and the
//!   CCID guard is a **whole-blob pre-check** rather than a post-write rollback
//!   — the applet has no transaction to roll back with.
//! * **Field-level replace** — when the blob *does* carry `0x0B`, it replaces
//!   the stored mask outright; the incoming byte is the whole value. So the
//!   "proposed mask after merging over the stored one" the guard evaluates is
//!   simply the incoming byte, and the guard is `incoming & 0x01 != 0`.
//!   Recording this because the two merges are easy to conflate and a reader
//!   who assumes a bitwise-OR merge would write the wrong guard.
//!
//! Because the blob-level merge is a merge, an attacker **cannot** clear the
//! mask by omission — they must write `0x0B` with the bit cleared explicitly,
//! which is precisely the request the guard refuses. That is why the guard
//! tests the *value* and not the *presence* of the tag.
//!
//! ## The width guard, and why it is separate
//!
//! `0x0B`'s value is one byte. A wrong-width record is refused **on width,
//! before the value is read**, exactly as `zero_mask_refusal` does
//! (`apps/fido/src/vendor41.rs:1424-1437`): a three-byte record that merely
//! starts with `0x00` is not a one-byte zero mask, and refusing it with the
//! same status would make one status word mean two things. `platform::phy_tlv`
//! already types the widths (`PhyTag::declared_width`, `:306`), so the check
//! reads a table instead of re-spelling a per-tag width list.
//!
//! ## SECURE: implemented per the EPIC, with the caveat the EPIC omits
//!
//! `80 1D 00 <lock> 00` — lock byte in **P2**, boot-key index in **P1**.
//! Implemented because US-163 asks for it, with three facts stated plainly
//! because a reader will otherwise assume the mitigation exists:
//!
//! * **Nothing in this firmware implements secure boot.** `grep -rn
//!   "secure_boot\|SECURE_BOOT" firmware/src/ platform/src/` has no hits: no
//!   secure-boot state, no bootrom key, no verification step. The command is a
//!   seam for the decision, not the mechanism (threat model §0.3).
//! * **The client never calls it.** `enable_secure_boot` is
//!   `#[allow(dead_code)]` and carries `UNSTABLE — work in progress`
//!   (`ops.rs:665`).
//! * **The client documents it as pico-fido-only**: *"This instruction is only
//!   available on pico-fido firmware (RP2350/ESP32). RS-Key uses `OtpLock =
//!   0x1B` instead"* (`constants.rs:130-134`). fapico2 is neither pico-fido nor
//!   RS-Key, so the statement does not bind — but it is why a reader should not
//!   expect a client caller.
//!
//! **The P1 boot-key index has no named constant and no documented meaning
//! anywhere in the client.** The code sends `0x00` with the comment `// Boot Key
//! Index (0 = Default)` (`ops.rs:694`). This applet treats P1 as the key index
//! and passes it through to the owner unchanged, because a byte the protocol
//! defines and the code fills in is not this firmware's to reinterpret — but
//! only `0x00` is ever observed, and no index other than 0 has a known
//! destination. The applet does not validate it.
//!
//! # Ownership: why the PHY record is a hook and not a field
//!
//! The record this applet serves is **not its own**. `PhyConfig` lives in
//! `apps/fido` (`vendorff.rs:253-283`), the merge helper
//! (`vendor41::apply_phy_record`) is private, and the record persists into the
//! **FIDO keystore's auth map, key 6** (`apps/fido/src/device_keystore.rs`),
//! not into the Management applet's `EF_DEV_CONF`.
//!
//! So this crate depends on **`fapico2-platform` only** and commits through
//! [`RescueConfigHandler`], the same injection shape as
//! `fapico2_mgmt::FactoryResetHandler` (`apps/mgmt/src/lib.rs:172-183`): the
//! applet stays device-agnostic, the firmware injects the real owner, host
//! tests inject a fixture. That is also the dependency answer to the threat
//! model's §0.4, and it is the answer that keeps an **unauthenticated** applet
//! from holding a `&mut` that can reach a key (threat model §2): what crosses
//! the boundary is a [`PhySnapshot`] out and a [`PhyUpdate`] in — two `Copy`
//! structs of small integers, no store handle, no keystore, no keystore
//! capability.
//!
//! ## What a `None` handler means
//!
//! `ManagementApp` answers a `None` [`fapico2_mgmt::FactoryResetHandler`] by
//! proceeding with the part it *does* own — clearing its own config blob
//! (`apps/mgmt/src/lib.rs:576-586`). That answer is available there because the
//! management applet owns a durable record. **This applet owns none**: it holds
//! no store slot, no RAM copy of the record and no dirty flag, so there is no
//! "own part" to proceed with. Accepting a write that goes nowhere is exactly
//! the lie the threat model §10.3 rules out, so a `None` handler makes the WRITE
//! fail `6A86` — the same status as an undestined tag, and deliberately so,
//! because both mean the same thing: *there is no destination for this record
//! in this build*.
//!
//! A `None` [`RescueDeviceHandler`] is fail-closed in the same way: `REBOOT`
//! and `SECURE` are privileged actions with no local fallback, so both answer
//! `6A86` rather than pretending to have rebooted.
//!
//! The reads are the exception, because a read cannot lie by omission: with no
//! config handler, `READ PhyConfig` returns an **empty** TLV blob and with no
//! state supplied, `READ FlashInfo` / `SecureBootStatus` return the applet's
//! boot-time values. Neither build shape is a shipped configuration — the
//! device and the emulation both attach every handler — so this is the
//! behaviour of a deliberately bare applet, and it is what the host tests
//! exercise to reach the no-handler arms.
//!
//! # Placement, and why it is registered on the device
//!
//! One applet per crate, matching the workspace convention (the vendor LED
//! applet took the same decision in US-160 and says why in
//! `apps/vendor_led/src/lib.rs:14-21`). The EPIC's commit titles all say
//! `feat(mgmt): rescue applet …`, which would put this surface *inside* the
//! management applet — an unauthenticated command set sharing a crate, a file
//! and a review with the applet that holds the presence gate. The crate split
//! keeps them apart, and keeps the unauthenticated applet from holding a
//! `fapico2-fido` dependency at all.
//!
//! **It is registered on the device, not only in the emulator.** The client
//! reaches it over CCID, which is a device transport; a Rescue applet that only
//! existed under the emulator would not be reachable by the thing that
//! motivates it, and US-163's BOOTSEL reboot means nothing on a host process.
//!
//! **The risk of registering it**, recorded because it is real and it is the
//! price of the surface: the device gains a permanent, unauthenticated,
//! no-rate-limit, no-presence write path to a stored record (threat model R1),
//! a permanent unauthenticated reboot primitive (R5), and a disclosure of the
//! full 8-byte OTP chip id where every other surface leaks only
//! `SHA-256(chipid)[..4]` (R2/R3). All four are **accepted, not fixed** in the
//! threat model §8, and all four are inert-or-availability today only because
//! nothing reads the record (threat model §0.1) — a tripwire that fires the day
//! the USB descriptors become runtime-configurable.

#![cfg_attr(not(feature = "host"), no_std)]

use fapico2_platform::dispatch::{
    App, MAX_RESPONSE, Sw, SW_CLA_NOT_SUPPORTED, SW_INS_NOT_SUPPORTED, SW_OK, SW_WRONG_LENGTH,
};
use fapico2_platform::phy_tlv::{self, PhyTag, USB_ITF_CCID};
use heapless::Vec as HeaplessVec;

/// Rescue applet AID (`picoforge/src/hal/rescue/constants.rs:106`).
///
/// Shared by pico-fido's C `rescue.c` and the RS-Key Rust applet, so it is
/// not a vendor AID and not one this firmware may choose.
pub const RESCUE_AID: &[u8] = &[0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21];

/// The only class byte this applet accepts. `APDU_CLA_PROPRIETARY`
/// (`constants.rs:68`); the vendor applets on this firmware use `0x00` instead
/// (see `apps/vendor_led::CLA_ISO`), which is the other half of why this
/// surface is a separate crate.
pub const CLA_PROPRIETARY: u8 = 0x80;

/// `READ` (`RescueInstruction::Read`, `constants.rs:139`).
pub const INS_READ: u8 = 0x1E;
/// `WRITE` (`RescueInstruction::Write`, `constants.rs:120`).
pub const INS_WRITE: u8 = 0x1C;
/// `SECURE` (`RescueInstruction::Secure`, `constants.rs:127`).
pub const INS_SECURE: u8 = 0x1D;
/// `REBOOT` (`RescueInstruction::Reboot`, `constants.rs:146`).
pub const INS_REBOOT: u8 = 0x1F;

/// READ P1 = full PHY configuration (`ReadParam::PhyConfig`, `constants.rs:156`).
pub const READ_P1_PHY_CONFIG: u8 = 0x01;
/// READ P1 = flash statistics (`ReadParam::FlashInfo`, `constants.rs:159`).
pub const READ_P1_FLASH_INFO: u8 = 0x02;
/// READ P1 = secure-boot status (`ReadParam::SecureBootStatus`,
/// `constants.rs:162`).
pub const READ_P1_SECURE_BOOT_STATUS: u8 = 0x03;

/// WRITE P1 = full PHY configuration (`WriteParam::PhyConfig`,
/// `constants.rs:171`).
pub const WRITE_P1_PHY_CONFIG: u8 = 0x01;

/// **READ PhyConfig carries P2 = `0x01`**, unlike the other two reads
/// (`ops.rs:295`). See the module docs: this applet accepts `0x00` *and*
/// `0x01` there, and this is the value the client actually sends.
pub const READ_P2_PHY_CONFIG: u8 = 0x01;
/// The P2 the WRITE and the other two READs use (`P2_UNUSED`,
/// `constants.rs:234`).
pub const P2_UNUSED: u8 = 0x00;

/// `[0]` of the SELECT block: the MCU. `1` = RP2350.
pub const MCU_TYPE_RP2350: u8 = 1;
/// `[1]` of the SELECT block: the product. `2` = FIDO.
///
/// This device is a Yubikey-compatible *FIDO* authenticator carrying OATH,
/// OTP, OpenPGP and PIV beside it; `2` is the code the client's classifier
/// uses to keep the FIDO-shaped screens, and it is what the FIDO2 applet this
/// firmware is first and foremost is.
pub const PRODUCT_TYPE_FIDO: u8 = 2;

/// `[2]` of the SELECT block — the **RS-Key SDK major version**, and the byte
/// the client classifies the device on.
///
/// **This is 8 and it is deliberately *not* the firmware version.** Read the
/// module docs' "`RSKEY_SDK_MAJOR` is 8 and must never be "fixed" to 1" before
/// changing it: the client requires `data[2] >= 8`
/// (`picoforge/src/hal/transport/pcsc.rs:75-81`), and
/// `fapico2_mgmt::VERSION_MAJOR` is `5`.
pub const RSKEY_SDK_MAJOR: u8 = 8;
/// `[3]` of the SELECT block — the RS-Key SDK minor version. The client reads
/// it (`ops.rs:222`) and uses it only for a log line
/// (`"Device Version: {major}.{minor}"`); nothing gates on it.
pub const RSKEY_SDK_MINOR: u8 = 0;

/// The SELECT response data length: 4 identity bytes plus the 8-byte chip id.
///
/// The client's `select_resp.len() >= 14` test (`ops.rs:234`) counts those 12
/// plus the 2 status bytes. Emitting fewer than 6 total fails
/// `read_device_details` with *"Invalid select response"* (`ops.rs:221-224`),
/// and the EPIC's `rescue_select_returns_14_byte_block` name is a wire count,
/// not a data count.
pub const SELECT_BLOCK_LEN: usize = 12;

/// `REBOOT` mode: restart into the firmware (`RebootParam::Normal`,
/// `constants.rs:205`) — **in P1**.
pub const REBOOT_MODE_NORMAL: u8 = 0x00;
/// `REBOOT` mode: restart into BOOTSEL / USB mass storage
/// (`RebootParam::Bootsel`, `constants.rs:210`) — **in P1**.
pub const REBOOT_MODE_BOOTSEL: u8 = 0x01;

/// `SECURE` P2: unlock (`0x00`).
pub const SECURE_UNLOCK: u8 = 0x00;
/// `SECURE` P2: lock (`0x01`).
pub const SECURE_LOCK: u8 = 0x01;

/// ISO 7816-4 status words, spelled out here so this crate's refusals are
/// readable in one place (the `apps/vendor_led` convention). Each means
/// exactly one thing on this surface:
///
/// * [`SW_WRONG_LENGTH`] (`0x6700`) — a **length**: an APDU shorter than the
///   4-byte header, a case-3 body that is not `Lc` bytes, a TLV record whose
///   declared length runs past the blob, or a record whose width disagrees
///   with its tag's [`PhyTag::declared_width`].
/// * [`SW_WRONG_PARAMETERS`] (`0x6A86`) — a **named target that this build
///   does not serve**: an unknown PHY tag, one of the seven tags with no
///   field in the persisted record, a P1/P2 that names no command variant
///   here, or a `None` handler (no destination for the record at all).
/// * [`SW_INVALID_DATA`] (`0x6A80`) — well-formed data that **conflicts with a
///   device requirement**. Exactly one thing on this applet: the `0x0B` write
///   that would clear [`USB_ITF_CCID`]. Kept separate from `0x6A86` so a
///   "this firmware cannot store that" is never confused with "that value
///   would brick this applet".
const SW_WRONG_PARAMETERS: Sw = 0x6A86;
const SW_INVALID_DATA: Sw = 0x6A80;

/// The two `REBOOT` modes, as a type.
///
/// Exists so a mode byte that is neither `0x00` nor `0x01` cannot reach the
/// owner's `reboot()` as a `u8` — the enum's absence *is* the validation, so
/// there is no second list of legal modes to fall out of step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebootMode {
    /// `80 1F 00 00 00` — restart the firmware.
    Normal,
    /// `80 1F 01 00 00` — restart into the BOOTSEL USB bootloader.
    ///
    /// Destructive from the client's point of view: the device leaves the CCID
    /// bus and re-enumerates as mass storage, and a reflash on top of a stale
    /// secure partition leaves the token a brick needing
    /// `nuke_universal.uf2`. The EPIC's answer is client-side — *"gate it
    /// behind an explicit confirm in any UI-driving script"* — and a host-side
    /// control is not a mitigation against a hand-built APDU, so the device
    /// ships it anyway and the abuse case is threat model §5 / R5.
    Bootsel,
}

impl RebootMode {
    /// Map the P1 byte, or `None` for a mode the protocol does not define.
    ///
    /// A third value is refused rather than clamped: `0x02` is not "normal" and
    /// it is not "BOOTSEL", and answering `9000` to a mode we did not perform
    /// is the same class of lie the undestined-tag refusal exists to prevent.
    pub const fn from_p1(p1: u8) -> Option<Self> {
        Some(match p1 {
            REBOOT_MODE_NORMAL => RebootMode::Normal,
            REBOOT_MODE_BOOTSEL => RebootMode::Bootsel,
            _ => return None,
        })
    }

    /// The P1 byte this mode is sent as.
    pub const fn p1(self) -> u8 {
        match self {
            RebootMode::Normal => REBOOT_MODE_NORMAL,
            RebootMode::Bootsel => REBOOT_MODE_BOOTSEL,
        }
    }
}

/// The five `READ FlashInfo` words, in the client's order
/// (`ops.rs:264-270`): free, used, total, nfiles, chip size — all big-endian
/// `u32`.
///
/// The client reads all five and keeps `nfiles` and `chip_size`
/// (`ops.rs:423`, `:425`); `free`, `used` and `total` are read into locals and
/// dropped. The shape is still load-bearing: the reader is a `Cursor` with
/// `read_u32` per field, so a short reply leaves the trailing fields at their
/// `unwrap_or(0)` default **and reports no error**.
///
/// The applet does not measure its own flash; [`RescueApp::with_flash_stats`]
/// takes the numbers the firmware computed at boot, because the flash layout
/// is the firmware's knowledge and not the applet's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlashStats {
    /// Free bytes in the device's durable store.
    pub free: u32,
    /// Bytes of that store in use.
    pub used: u32,
    /// The store's total capacity. The client calls this the "KV partition"
    /// (`ops.rs:264`), which is what it is here: the sealed secure-partition
    /// image, not the whole flash.
    pub total: u32,
    /// Count of live records in the store.
    ///
    /// **Always 0 in the shipped builds, and that is not a measurement.**
    /// `SecureStore` exposes `contains` but no enumeration
    /// (`platform/src/secure_store.rs:344-390`), so counting live records would
    /// mean changing the platform trait for a number the client only displays.
    /// Reported as 0 with this note rather than fabricated; the client's Config
    /// screen shows "0 files" for a token that has records, which is a cosmetic
    /// inaccuracy in exchange for never publishing a number that is not true.
    pub nfiles: u32,
    /// The chip's flash size in bytes — a compile-time constant
    /// (`firmware/src/boot.rs:185`).
    pub chip_size: u32,
}

impl FlashStats {
    /// The 20 wire bytes: five big-endian `u32` words in the client's field
    /// order — free, used, total, nfiles, chip size (`ops.rs:264-270`).
    ///
    /// `const` and hand-rolled rather than a `[u32; 5].concat()` or a `to_be_bytes`
    /// loop, so the field order is stated once and the array is a fixed size
    /// the caller can push straight into a reply.
    pub const fn to_bytes(self) -> [u8; 5 * 4] {
        let words = [
            self.free,
            self.used,
            self.total,
            self.nfiles,
            self.chip_size,
        ];
        let mut out = [0u8; 20];
        let mut i = 0;
        while i < 5 {
            let w = words[i].to_be_bytes();
            let base = i * 4;
            out[base] = w[0];
            out[base + 1] = w[1];
            out[base + 2] = w[2];
            out[base + 3] = w[3];
            i += 1;
        }
        out
    }
}

/// The two `READ SecureBootStatus` bytes, in the client's order: enabled,
/// then locked (`ops.rs:284-288`).
///
/// Both are the applet's boot-time state. On the shipped builds both are
/// `false`: **nothing in this firmware implements secure boot** (threat model
/// §0.3 — no secure-boot state, no bootrom key, no verification step anywhere
/// in the tree). The command is implemented because US-163 asks for it, and
/// what it reports is a seam, not a measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecureBootStatus {
    /// Whether secure boot is enabled.
    pub enabled: bool,
    /// Whether secure boot is locked.
    pub locked: bool,
}

impl SecureBootStatus {
    /// The two wire bytes, `0x01` / `0x00` each.
    ///
    /// The client reads them as `rx[0] != 0` / `rx[1] != 0`
    /// (`ops.rs:285-286`), so any non-zero byte means set; emitting canonical
    /// `0x01` keeps the read-back stable whatever a future owner stores.
    pub const fn to_bytes(self) -> [u8; 2] {
        // `u8::from(bool)` is not a `const fn` on this toolchain, and the
        // two-byte encoding is worth being able to state in a `const`.
        [
            if self.enabled { 1 } else { 0 },
            if self.locked { 1 } else { 0 },
        ]
    }
}

/// A copy of the device's persisted PHY record, as this applet serves it.
///
/// Field-for-field the `Option`-carrying part of
/// `fapico2_fido::vendorff::PhyConfig` (`vendorff.rs:253-283`), with the same
/// names, the same widths and the same big-endian wire order — so the owner's
/// [`RescueConfigHandler::commit`] is a field copy with no conversion and no
/// place for a width bug. It is a distinct type rather than *being*
/// `PhyConfig` because this crate must not depend on `fapico2-fido`
/// (Decision B / threat model §0.4): an unauthenticated applet holding a
/// dependency on the app that owns the FIDO keystore is a dependency worth not
/// having.
///
/// `led_conf` is absent because it has no PHY tag — the 17-byte LED block is a
/// `CONFIG_READ` target `0x02` record, not a `0xNN` record
/// (`apps/fido/src/vendor41.rs:2302-2321`), so it is not reachable over
/// Rescue's `READ PhyConfig` on any device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PhySnapshot {
    /// Tag `0x00` — `(vid << 16) | pid`, as `vendorff::pack_vidpid` produces
    /// it.
    pub vid_pid: Option<u32>,
    /// Tag `0x04` — activity-LED GPIO index.
    pub led_gpio: Option<u8>,
    /// Tag `0x05` — LED brightness, `0..=100`.
    pub led_brightness: Option<u8>,
    /// Tag `0x06` — the `PHYSICAL_OPTIONS` word.
    pub options: Option<u16>,
    /// Tag `0x0B` — the enabled USB-interface mask.
    ///
    /// `u16` because the field in the persisted record is `u16` and the FIDO
    /// `DEV_CONF` carrier writes it as a 2-byte big-endian word. **Only the low
    /// byte is defined**: the mask is one byte on this wire and
    /// `phy_tlv::USB_ITF_MASK` is five bits
    /// (`platform/src/phy_tlv.rs:105-112`). A Rescue write replaces the whole
    /// field with the byte it carried, so a stored high byte does not survive
    /// one — recording that, because "what does a Rescue write do to the bits
    /// above 0x07" has no answer other than "clears them, and they are
    /// undefined".
    pub enabled_usb_itf: Option<u16>,
    /// Tag `0x09` — the USB product name, stored **without** its NUL.
    ///
    /// The client's reader trims NULs off both ends
    /// (`picoforge/src/hal/rescue/ops.rs:348-350`) and its writer appends one
    /// (`ops.rs:543`), so the terminator belongs to the wire and not to what
    /// is persisted — the same split `fapico2_fido::vendorff::IdentityName`
    /// makes, and the reason this is a plain bounded byte buffer rather than a
    /// `String`.
    pub product: Option<[u8; fapico2_platform::phy_tlv::MAX_NUL_STRING_LEN]>,
    /// Tag `0x0F` — the USB manufacturer name, framed exactly as
    /// [`PhySnapshot::product`].
    ///
    /// Length-carrying by construction: a fixed buffer with a `len` in the
    /// codec's hands would make a short name a NUL run, and the client trims
    /// NULs, so the two agree — but only because both sides are written that
    /// way. Bounding the field at the type level removes the question.
    pub manufacturer: Option<[u8; phy_tlv::MAX_NUL_STRING_LEN]>,
}

/// Whether a wire name value is a NUL-terminated string within the codec's
/// bound.
///
/// Requires the terminator to be **present** and **last**, and caps the total at
/// the codec's own limit. An unterminated value is refused rather than
/// terminated here: the client's writer always appends the NUL, so a value
/// without one did not come from the client, and guessing where the name ends
/// is how a name silently becomes a name-plus-garbage.
fn nul_terminated_within(value: &[u8]) -> bool {
    value.len() <= phy_tlv::MAX_NUL_STRING_LEN
        && value.last() == Some(&0)
        && !value[..value.len().saturating_sub(1)].contains(&0)
}

/// Copy a wire name into the fixed buffer [`PhySnapshot`] carries, without its
/// terminator and zero-padded after it.
///
/// The padding is why the buffer is a fixed array and not a `String`: the
/// snapshot has to stay `Copy` (the threat model's §2 boundary argument), and
/// the reader on the other side finds the end by looking for the NUL.
fn pad_name(value: &[u8]) -> [u8; phy_tlv::MAX_NUL_STRING_LEN] {
    let mut buf = [0u8; phy_tlv::MAX_NUL_STRING_LEN];
    let body = &value[..value.len() - 1];
    buf[..body.len()].copy_from_slice(body);
    buf
}

/// The change a Rescue `WRITE` proposes, handed to the owner to commit.
///
/// `None` in a field means **"leave it alone"**, which is what makes the WRITE
/// a merge rather than a replace (`ops.rs:584-585`) and is the mechanism by
/// which a one-record write cannot silently clear the others. A field can only
/// be set to `Some` by a record that was actually in the blob, so "absent" and
/// "explicitly null" are not two spellings of one thing — the format has no
/// null, only omission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PhyUpdate {
    /// Tag `0x00`.
    pub vid_pid: Option<u32>,
    /// Tag `0x04`.
    pub led_gpio: Option<u8>,
    /// Tag `0x05`.
    pub led_brightness: Option<u8>,
    /// Tag `0x06`.
    pub options: Option<u16>,
    /// Tag `0x0B` — always `Some(0x01)`-or-more by the time it is built, or
    /// the applet has already refused the write.
    pub enabled_usb_itf: Option<u16>,
    /// Tag `0x09` — the USB product name, NUL-terminated on the wire and
    /// stored in whatever form the owner keeps it.
    ///
    /// An `Option` because absent means *preserve*, which is the merge the
    /// Rescue WRITE is defined to be (`ops.rs:584-585`); the owner-side merge
    /// is `firmware/src/boot.rs`.
    pub product: Option<[u8; phy_tlv::MAX_NUL_STRING_LEN]>,
    /// Tag `0x0F` — the USB manufacturer name, framed as
    /// [`PhyUpdate::product`].
    pub manufacturer: Option<[u8; fapico2_platform::phy_tlv::MAX_NUL_STRING_LEN]>,
}

/// The owner of the persisted PHY record — the **firmware**, which holds the
/// FIDO keystore this record lives in.
///
/// The applet does its own parsing, its own width checks and its own CCID-mask
/// guard, then hands a validated [`PhyUpdate`] to this trait and does the
/// mutation itself. That split is the point: the safety property belongs to
/// the surface (only the applet can be reached by an unauthenticated APDU, so
/// only the applet can enforce the guard), while the durable commit belongs to
/// whoever owns the keystore.
///
/// A `commit` that answers anything but [`SW_OK`] has changed nothing the
/// applet can observe, and the applet propagates the status verbatim — the
/// same contract as [`fapico2_mgmt::FactoryResetHandler`], where a non-`9000`
/// return aborts the applet's own follow-on work.
pub trait RescueConfigHandler {
    /// The current record, for `READ PhyConfig` and for the owner-side half of
    /// any merge it performs itself.
    ///
    /// Takes `&self` and returns a `Copy` struct of small integers: no store
    /// handle, no keystore and no capability crosses this boundary in the read
    /// direction either, which is what keeps the threat model's §2 rule — *the
    /// applet must never be able to reach key material* — true by construction
    /// rather than by inspection.
    fn snapshot(&self) -> PhySnapshot;

    /// Durably commit `update`, merging it over the stored record.
    ///
    /// Returns the status the `WRITE` APDU answers. Implementations should be
    /// transactional with respect to the record: either every `Some` field of
    /// `update` reaches the store, or the reply says so.
    fn commit(&mut self, update: &PhyUpdate) -> Sw;
}

/// The privileged device actions `REBOOT` and `SECURE` need.
///
/// Separate from [`RescueConfigHandler`] because they share nothing with it:
/// a config record is *data*, and these two *act* — one of them irreversibly.
/// An owner that has a keystore and declines to have a reboot path should be
/// able to say so per method, which a single combined trait could not express.
pub trait RescueDeviceHandler {
    /// Restart the device, in `mode`.
    ///
    /// The owner must **not** reset before the `9000` has left: the client
    /// checks the status word (`ops.rs:653-656`) and a reset that outruns the
    /// reply surfaces to the operator as a transport error on a command that
    /// in fact succeeded. The device wiring therefore records the mode and the
    /// owning task performs the reset after the reply is written.
    fn reboot(&mut self, mode: RebootMode) -> Sw;

    /// Set the secure-boot lock state for the boot key `key_index`.
    ///
    /// `key_index` is the `SECURE` P1, which the protocol defines as a boot-key
    /// index and the client always fills with `0`
    /// (`picoforge/src/hal/rescue/ops.rs:694`, `// Boot Key Index (0 = Default)`).
    /// The applet passes it through unchanged and does **not** validate it: a
    /// byte the protocol defines and the code sets is not this firmware's to
    /// reinterpret, and refusing `0x00`-only would make the command
    /// unreachable for a future client that names a second key. What a non-zero
    /// index *means* is documented nowhere in the client, so an owner that
    /// cannot honour it should answer a failure status rather than guess.
    ///
    /// `lock = true` is the mitigation the threat model's §6 nominates for
    /// firmware replacement, with the §6.1 caveat attached: on a tree with no
    /// secure-boot mechanism (§0.3) a lock that only refuses future PHY writes
    /// costs the owner a permanent reconfiguration lockout and prevents no
    /// reflash (R9). An owner should refuse a lock it cannot back with a
    /// mechanism.
    fn set_secure_boot(&mut self, key_index: u8, lock: bool) -> Sw;
}

/// The `0x0B` enabled-interface mask, or the value the applet reports for a
/// record that has none.
///
/// A device that has never been written has no mask, and the honest report for
/// "no mask configured" is **not** `0x00` — a zero mask is the value
/// `vendor41` refuses unconditionally (`apps/fido/src/vendor41.rs:1409-1415`)
/// and the one §7 of the threat model is about. Reporting `USB_ITF_CCID` for an
/// unconfigured record says "CCID is on", which is both true on this firmware
/// (the CCID interface is compiled in and enumerated today) and the only value
/// that keeps the client's read-modify-write writing a mask the device will
/// then accept.
pub const UNCONFIGURED_USB_ITF: u8 = USB_ITF_CCID;

/// The tags this firmware has a field for, ascending — the only records a
/// Rescue `WRITE` can apply and the only records `READ PhyConfig` emits.
///
/// Five of the twelve. The seven that are **not** here are refused whole by
/// [`RescueApp::cmd_write`] with [`SW_WRONG_PARAMETERS`]; see the module docs'
/// "What the WRITE can and cannot actually do" and threat model §0.2 / §10.3.
pub const SUPPORTED_PHY_TAGS: [PhyTag; 5] = [
    PhyTag::VidPid,
    PhyTag::LedGpio,
    PhyTag::LedBrightness,
    PhyTag::Options,
    PhyTag::EnabledUsbItf,
];

/// The RS-Key Rescue applet.
///
/// Holds no durable state of its own: the PHY record is the owner's
/// ([`RescueConfigHandler`]), the flash figures and the secure-boot status are
/// supplied at boot, and the privileged actions are the owner's
/// ([`RescueDeviceHandler`]). What it owns is the *protocol* — the four INS
/// values, the P1/P2 placements, the TLV parse, the width rules, the
/// undestined-tag refusal and the CCID-mask guard — and those are the parts
/// that have to be right for the client to work and the brick to not happen.
pub struct RescueApp {
    /// The device chip id, emitted as SELECT bytes `[4..12]`.
    ///
    /// The full 8 raw OTP bytes, which is **a widening of what this firmware
    /// discloses elsewhere**: every other surface leaks only
    /// `SHA-256(chipid)[..4]` (`apps/mgmt/src/lib.rs:75-77`,
    /// `platform/src/usb.rs:103-120`). Accepted at Low–Medium as R2/R3 in the
    /// threat model — the chip id is a manufacturing identifier rather than a
    /// secret, and a holder in physical possession can read the OTP row by
    /// other means — but it is a real change in disclosure and is recorded as
    /// one rather than left as a by-product of copying the client's layout.
    chipid: u64,
    /// The `READ FlashInfo` figures, supplied by the firmware at boot.
    flash: FlashStats,
    /// The `READ SecureBootStatus` figures, supplied by the firmware at boot.
    secure_boot: SecureBootStatus,
    /// The record owner. `None` ⇒ `READ PhyConfig` answers an empty blob and
    /// `WRITE` is refused `6A86` (see the module docs' "What a `None` handler
    /// means").
    config: Option<&'static mut dyn RescueConfigHandler>,
    /// The privileged actions. `None` ⇒ `REBOOT` and `SECURE` are refused
    /// `6A86`.
    device: Option<&'static mut dyn RescueDeviceHandler>,
}

impl Default for RescueApp {
    fn default() -> Self {
        Self::new()
    }
}

impl RescueApp {
    /// A factory-fresh applet.
    ///
    /// The chip id defaults to [`fapico2_platform::usb_ident::EMULATION_CHIPID`]
    /// — the same fixed stand-in `apps/mgmt` uses (`ManagementApp::new`), so a
    /// host test and a host build report the same identity rather than a zero
    /// one. The device overrides it through [`RescueApp::with_chipid`].
    pub fn new() -> Self {
        Self {
            chipid: fapico2_platform::usb_ident::EMULATION_CHIPID,
            flash: FlashStats::default(),
            secure_boot: SecureBootStatus::default(),
            config: None,
            device: None,
        }
    }

    /// Device wiring: report the real OTP chip id
    /// (`embassy_rp::otp::get_chipid()`) instead of the emulation stand-in.
    pub fn with_chipid(mut self, chipid: u64) -> Self {
        self.chipid = chipid;
        self
    }

    /// The flash figures `READ FlashInfo` reports. The applet cannot measure
    /// its own storage; the firmware knows its layout and says so here.
    pub fn with_flash_stats(mut self, flash: FlashStats) -> Self {
        self.flash = flash;
        self
    }

    /// The secure-boot state `READ SecureBootStatus` reports. Both fields are
    /// `false` on every shipped build — see [`SecureBootStatus`].
    pub fn with_secure_boot_status(mut self, status: SecureBootStatus) -> Self {
        self.secure_boot = status;
        self
    }

    /// Attach the PHY-record owner (device wiring, and the host test fixture).
    pub fn with_config_handler(mut self, h: &'static mut dyn RescueConfigHandler) -> Self {
        self.config = Some(h);
        self
    }

    /// Attach the privileged device actions.
    pub fn with_device_handler(mut self, h: &'static mut dyn RescueDeviceHandler) -> Self {
        self.device = Some(h);
        self
    }

    /// The 12 SELECT identity bytes — see the module docs for the layout and
    /// for why `[2]` is [`RSKEY_SDK_MAJOR`] and not the firmware version.
    pub fn select_block(&self) -> [u8; SELECT_BLOCK_LEN] {
        let mut out = [0u8; SELECT_BLOCK_LEN];
        out[0] = MCU_TYPE_RP2350;
        out[1] = PRODUCT_TYPE_FIDO;
        out[2] = RSKEY_SDK_MAJOR;
        out[3] = RSKEY_SDK_MINOR;
        out[4..SELECT_BLOCK_LEN].copy_from_slice(&self.chipid.to_be_bytes());
        out
    }

    /// Encode the five supported records of `snap` into a PHY TLV blob, in
    /// ascending tag order.
    ///
    /// Ascending is [`PhyTag::ALL`]'s order, and the client's reader is a flat
    /// `while offset < data.len()` walk with no ordering rule
    /// (`ops.rs:307-315`), so any order reads back the same. A field left
    /// `None` is **omitted**, not emitted as a zero record: the client tracks
    /// each field as an `Option` and would render a zeroed brightness or a
    /// `0x0000` mask as a real configured value.
    ///
    /// A record is emitted only if it has a destination, so the blob the client
    /// reads back contains **only tags a Rescue `WRITE` will accept**. That is
    /// deliberate and it is what keeps the normal client round-trip inside the
    /// writable set: the client builds its write blob from the fields it
    /// parsed from this read (`ops.rs:470-620`), so a tag this function does not
    /// emit is a tag the client has no reason to send back
    /// (`product_name` and `manufacturer_name` are filtered on empty, and
    /// `led_order` / `led_num` / `raw_curves_mask` stay `None`).
    fn encode_phy(&self, snap: &PhySnapshot, out: &mut HeaplessVec<u8, MAX_RESPONSE>) {
        if let Some(v) = snap.vid_pid {
            // `(vid << 16) | pid` is the packed form; the wire is
            // `vid:u16 BE, pid:u16 BE`, which is the same four bytes.
            let _ = phy_tlv::encode_record(PhyTag::VidPid, &v.to_be_bytes(), out);
        }
        if let Some(v) = snap.led_gpio {
            let _ = phy_tlv::encode_record(PhyTag::LedGpio, &[v], out);
        }
        if let Some(v) = snap.led_brightness {
            let _ = phy_tlv::encode_record(PhyTag::LedBrightness, &[v], out);
        }
        if let Some(v) = snap.options {
            let _ = phy_tlv::encode_record(PhyTag::Options, &v.to_be_bytes(), out);
        }
        if let Some(v) = snap.enabled_usb_itf {
            let _ = phy_tlv::encode_record(PhyTag::EnabledUsbItf, &[v as u8], out);
        }
        // The two identity names, NUL-terminated on the wire. This is the
        // record the client's `read_phy_config` walks
        // (`picoforge/src/hal/rescue/ops.rs:346-357`), so emitting them is
        // what makes PicoForge's device-details screen show a product name
        // and a manufacturer instead of two empty fields.
        for (tag, name) in
            [(PhyTag::UsbProduct, snap.product), (PhyTag::UsbManufacturer, snap.manufacturer)]
        {
            if let Some(name) = name {
                let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                let mut buf = [0u8; phy_tlv::MAX_NUL_STRING_LEN + 1];
                buf[..len].copy_from_slice(&name[..len]);
                buf[len] = 0;
                let _ = phy_tlv::encode_record(tag, &buf[..=len], out);
            }
        }
    }

    /// `READ` (INS `0x1E`) — dispatch the three P1 targets.
    fn cmd_read(&mut self, p1: u8, p2: u8, resp: &mut HeaplessVec<u8, MAX_RESPONSE>) -> Sw {
        match p1 {
            READ_P1_PHY_CONFIG => {
                // P2 is `0x01` on the wire (`ops.rs:295`) and `0x00` on the
                // WRITE (`ops.rs:606`); both are accepted here, and nothing
                // else is. See the module docs' "PhyConfig READ and WRITE
                // disagree about P2".
                if p2 != READ_P2_PHY_CONFIG && p2 != P2_UNUSED {
                    return SW_WRONG_PARAMETERS;
                }
                // No owner ⇒ no record ⇒ an empty blob, which the client
                // reads as "nothing configured". A read cannot lie by
                // omission the way a write can, so that is the honest answer
                // rather than a refusal.
                if let Some(h) = &self.config {
                    let snap = h.snapshot();
                    self.encode_phy(&snap, resp);
                }
                SW_OK
            }
            READ_P1_FLASH_INFO => {
                if p2 != P2_UNUSED {
                    return SW_WRONG_PARAMETERS;
                }
                resp.extend_from_slice(&self.flash.to_bytes()).ok();
                SW_OK
            }
            READ_P1_SECURE_BOOT_STATUS => {
                if p2 != P2_UNUSED {
                    return SW_WRONG_PARAMETERS;
                }
                resp.extend_from_slice(&self.secure_boot.to_bytes()).ok();
                SW_OK
            }
            _ => SW_WRONG_PARAMETERS,
        }
    }

    /// `WRITE` (INS `0x1C`) — merge a PHY TLV blob into the record.
    ///
    /// The parse is a **single collecting pass**: nothing is applied while
    /// records are examined, and the only mutation in the whole command is the
    /// owner's [`RescueConfigHandler::commit`] at the end, reached only once
    /// every record has passed every check. That is what makes the
    /// whole-blob refusals whole: there is no partial application to roll back
    /// and no transaction needed to avoid one.
    fn cmd_write(&mut self, p1: u8, p2: u8, data: &[u8]) -> Sw {
        if p1 != WRITE_P1_PHY_CONFIG || p2 != P2_UNUSED {
            return SW_WRONG_PARAMETERS;
        }
        let mut update = PhyUpdate::default();
        for record in phy_tlv::Decoder::new(data) {
            let (tag_byte, value) = match record {
                Ok(r) => r,
                // A declared length that runs past the end of the blob, or a
                // tag with no length byte: a length problem, so `6700` and
                // nothing else.
                Err(_) => return SW_WRONG_LENGTH,
            };
            // A tag byte the protocol does not define. `PhyTag::from_byte` has
            // no `_` arm, so a thirteenth tag cannot even be spelled; the
            // refusal is here for a raw-APDU writer, and it is the same
            // `6A86` as an undestined tag because both say "there is nowhere
            // for this record to go in this build".
            let tag = match PhyTag::from_byte(tag_byte) {
                Some(t) => t,
                None => return SW_WRONG_PARAMETERS,
            };
            // The width check, from the codec's own table rather than a second
            // list spelled out here. Before the value is read, so a
            // three-byte `0x0B` that merely starts with `0x00` is a *width*
            // refusal and not a *mask* refusal.
            if let Some(w) = tag.declared_width() {
                if value.len() != w {
                    return SW_WRONG_LENGTH;
                }
            }
            match tag {
                PhyTag::VidPid => update.vid_pid = Some(u32::from_be_bytes([
                    value[0], value[1], value[2], value[3],
                ])),
                PhyTag::LedGpio => update.led_gpio = Some(value[0]),
                PhyTag::LedBrightness => update.led_brightness = Some(value[0]),
                PhyTag::Options => {
                    update.options = Some(u16::from_be_bytes([value[0], value[1]]));
                }
                PhyTag::EnabledUsbItf => {
                    let mask = value[0];
                    // **The CCID-mask guard.** A `0x0B` record replaces the
                    // stored mask outright, so the value proposed *after*
                    // merging over the stored one is this byte — see the module
                    // docs' "Merge semantics, and which 'merge' is meant".
                    // Refusing here, before any field of the blob is applied,
                    // is what stops a six-byte APDU from bricking the transport
                    // this applet is reached over. A safety property, not a
                    // security one: nothing about a cleared mask discloses
                    // anything, it just removes the recovery path.
                    if mask & USB_ITF_CCID == 0 {
                        return SW_INVALID_DATA;
                    }
                    update.enabled_usb_itf = Some(u16::from(mask));
                }
                // The two USB identity names. Unlike the FIDO `0x41` carrier,
                // the value arriving here has already been length-checked
                // against `tag.declared_width()` — which is `None` for the
                // string tags, so the width check above is a no-op for them and
                // this arm owns the length. The client's writer emits the name
                // plus a NUL (`ops.rs:543-560`) and refuses a name over 32
                // bytes itself (`:456`), so the bound here is the second of the
                // two, not a second opinion on the first.
                PhyTag::UsbProduct => {
                    if !nul_terminated_within(value) {
                        return SW_INVALID_DATA;
                    }
                    update.product = Some(pad_name(value));
                }
                PhyTag::UsbManufacturer => {
                    if !nul_terminated_within(value) {
                        return SW_INVALID_DATA;
                    }
                    update.manufacturer = Some(pad_name(value));
                }
                // The five tags with no field in the persisted record. Refused
                // as a group and whole, with the status that says "this
                // firmware does not support this record". See the module docs
                // for why accepted-and-ignored is not available.
                PhyTag::Curves
                | PhyTag::PresenceTimeout
                | PhyTag::LedDriver
                | PhyTag::LedOrder
                | PhyTag::LedNum => return SW_WRONG_PARAMETERS,
            }
        }
        let Some(h) = &mut self.config else {
            // No record owner in this build: nowhere for the write to go, and
            // the same `6A86` the undestined tags get because it is the same
            // fact. See the module docs' "What a `None` handler means".
            return SW_WRONG_PARAMETERS;
        };
        h.commit(&update)
    }

    /// `REBOOT` (INS `0x1F`) — **the mode is P1, not P2.**
    ///
    /// `ops.rs:646-652` puts the mode in P1 and the client's
    /// `RescueInstruction::Reboot` doc comment says P2
    /// (`constants.rs:143-145`). The code wins; the comment is wrong, and a
    /// device that implemented the comment would silently always
    /// normal-reboot. Documented at both sites.
    fn cmd_reboot(&mut self, p1: u8, p2: u8) -> Sw {
        if p2 != P2_UNUSED {
            return SW_WRONG_PARAMETERS;
        }
        let Some(mode) = RebootMode::from_p1(p1) else {
            return SW_WRONG_PARAMETERS;
        };
        match &mut self.device {
            Some(h) => h.reboot(mode),
            None => SW_WRONG_PARAMETERS,
        }
    }

    /// `SECURE` (INS `0x1D`) — **the lock byte is P2**, and P1 is a boot-key
    /// index the applet passes through unvalidated.
    ///
    /// The inversion against `REBOOT` — mode in P1 there, lock in P2 here — is
    /// in the client at `ops.rs:691-696` and is the reason both arms read P1
    /// and P2 separately rather than sharing a helper.
    fn cmd_secure(&mut self, p1: u8, p2: u8) -> Sw {
        let lock = match p2 {
            SECURE_UNLOCK => false,
            SECURE_LOCK => true,
            _ => return SW_WRONG_PARAMETERS,
        };
        match &mut self.device {
            Some(h) => h.set_secure_boot(p1, lock),
            None => SW_WRONG_PARAMETERS,
        }
    }
}

impl App for RescueApp {
    fn aid(&self) -> &[u8] {
        RESCUE_AID
    }

    fn select(&mut self, _internal: bool) -> Sw {
        SW_OK
    }

    fn deselect(&mut self) {}

    /// The SELECT response is the **raw identity block**, not an FCI.
    ///
    /// The client sends P1 `0x04` / P2 `0x04` because its SELECT is a generic
    /// builder (`pcsc.rs:53-61`), then reads the reply's bytes `[2]`, `[3]` and
    /// `[4..12]` as the identity fields regardless of what P2 asked for
    /// (`ops.rs:221-236`). So P2 is ignored here — unlike
    /// `fapico2_vendor_led::VendorLedApp::select_apdu`, which honours it,
    /// because that applet's client throws the reply away and this one's does
    /// not.
    ///
    /// Note this is *why* the client's reader-name path matters and is not
    /// usable here: the same sniff reads `data[2] >= 8` as "this is an RS-Key
    /// device", so a *BER* FCI would land its `0x4F` DF-name tag on that byte
    /// and misclassify. The Rescue protocol is a raw block and this applet
    /// emits one.
    fn select_apdu(
        &mut self,
        _internal: bool,
        _apdu: &[u8],
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) -> Sw {
        resp.extend_from_slice(&self.select_block()).ok();
        SW_OK
    }

    fn process(&mut self, apdu: &[u8], resp: &mut HeaplessVec<u8, MAX_RESPONSE>) {
        // Header guard first: a sub-4-byte APDU passes the CLA comparison
        // below and would then be indexed out of bounds (the US-701 panic
        // class, `apps/mgmt` `process`).
        if apdu.len() < 4 {
            write_sw(resp, SW_WRONG_LENGTH);
            return;
        }
        // The CLA gate, and the reason it cannot be relaxed: three of this
        // applet's four INS values are also Management INS values, and the
        // Rescue *SELECT* is `CLA 0x00`, so a `0x00` APDU reaching this applet
        // through the dispatcher's non-AID-SELECT fallthrough is a real path.
        // See the module docs' "The INS collision with the Management applet".
        if apdu[0] != CLA_PROPRIETARY {
            write_sw(resp, SW_CLA_NOT_SUPPORTED);
            return;
        }
        let ins = apdu[1];
        let p1 = apdu[2];
        let p2 = apdu[3];
        match ins {
            INS_READ => {
                // The three reads are case-4 on this wire: the client appends
                // `Le = 0x00` (`ops.rs:249-255`, `:275-279`, `:292-296`), so
                // each APDU is exactly 5 bytes and nothing after the header is
                // load-bearing. A longer wire is unambiguous and is accepted
                // rather than refused, matching `apps/vendor_led`'s GET.
                let sw = self.cmd_read(p1, p2, resp);
                write_sw(resp, sw);
            }
            // The WRITE is case-3 short form: 4 header + `Lc` + data, and the
            // client appends **no `Le`** (`ops.rs:601-609`). `Lc` bounds the
            // data, so a trailing byte beyond it is ignored the way
            // `apps/mgmt`'s `parse_data` ignores one — this is a data-bearing
            // command, and refusing a well-formed body over a trailing byte
            // would break a future client revision for no safety gain.
            INS_WRITE => {
                let sw = match apdu.get(4) {
                    Some(&lc) => {
                        let end = 5 + lc as usize;
                        match apdu.get(5..end) {
                            Some(data) => self.cmd_write(p1, p2, data),
                            // `Lc` longer than what arrived: a length problem.
                            None => SW_WRONG_LENGTH,
                        }
                    }
                    None => SW_WRONG_LENGTH,
                };
                write_sw(resp, sw);
            }
            // REBOOT and SECURE are case-3 with **no data field**: the client
            // sends `80 1F <mode> 00 00` and `80 1D 00 <lock> 00`, five bytes
            // with no `Lc` and no `Le` (`ops.rs:646-652`, `:691-696`). An
            // off-length wire is refused rather than absorbed — for REBOOT a
            // frame with a body nobody looked at is a reboot the caller did
            // not intend, which is the same class of surprise the byte-exactness
            // rules above exist to prevent.
            INS_REBOOT | INS_SECURE => {
                let sw = if apdu.len() == 5 {
                    if ins == INS_REBOOT {
                        self.cmd_reboot(p1, p2)
                    } else {
                        self.cmd_secure(p1, p2)
                    }
                } else {
                    SW_WRONG_LENGTH
                };
                write_sw(resp, sw);
            }
            _ => write_sw(resp, SW_INS_NOT_SUPPORTED),
        }
    }

    // The remaining `App` methods are left at their defaults, and that is a
    // deliberate non-action rather than an omission, so it is spelled out here
    // because the three are easy to read as "not implemented":
    //
    // * `persist_state` / `mark_dirty` / `is_dirty` — this applet has **no
    //   durable state of its own**. The record belongs to the owner, which
    //   commits it inside `RescueConfigHandler::commit` — deliberately
    //   durable-before-ack, so the `9000` is only written after the store
    //   write, exactly as the `0x41` path's commit is. Because the applet can
    //   never be dirty, the persist gate's two `false` outcomes (nothing was
    //   dirty / a persist failed) never have to be told apart for it.
    // * `factory_wipe` — a management factory reset must reach the PHY record,
    //   and it reaches it through **the owner's** wipe, not through a
    //   per-applet call this applet would have no way to honour.
    //   `Dispatcher::factory_wipe_apps` calls every applet; this one correctly
    //   does nothing, because it stores nothing.
}

fn write_sw(resp: &mut HeaplessVec<u8, MAX_RESPONSE>, sw: Sw) {
    resp.extend_from_slice(&sw.to_be_bytes()).ok();
}
