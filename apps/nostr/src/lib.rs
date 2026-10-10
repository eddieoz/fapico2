//! The Nostr applet — AID `F0 00 00 00 02` (US-1642, EPIC design §2.1).
//!
//! One AID-dispatched CCID applet serving a small identity set (8 identities
//! in the keyregion's Nostr reservation, US-1639/US-1641) with BIP-340 signing
//! and — later, Phase 2 — NIP-44 v2 encryption. The client is OpenXrypt
//! (`/home/eddieoz/Projects/git/openxrypt`), which reaches the applet by
//! SELECT over CCID in Phase 1 and over a dedicated HID interface (usage page
//! `0xFF00`, US-1657+) in Phase 3.
//!
//! # Why this is its own crate
//!
//! The workspace convention is one applet per crate, and this applet shares
//! nothing with the management applet beyond the dispatcher: its storage is
//! the keyregion's Nostr reservation (a *flash* store with its own payload
//! key, `platform/src/keyregion/nostr_store.rs`), not the shared secure
//! partition, and its trust level is not that of Rescue (unauthenticated) or
//! the vendor LED applet (benign state). Signing with a Nostr identity is an
//! outward-facing act, which is why the design §2.3 consent model is part of
//! this applet from the start.
//!
//! # The command surface so far (US-1645)
//!
//! The three **touch-free** reads (§2.3) are implemented over the store:
//! [`INS_GET_INFO`], [`INS_LIST_KEYS`] and [`INS_GET_PUBKEY`] — and the key
//! management trio [`INS_GENERATE_KEY`] / [`INS_IMPORT_KEY`] /
//! [`INS_SIGN`] (US-1644/US-1645), which are touch-gated (§2.2) and served
//! from the RNG and presence seams below. Every other command arm is still
//! the US-1642 skeleton refusal (`6D00`) and is replaced by its own story:
//! US-1649 label/delete/export, US-1653 the NIP-44 pair.
//!
//! # The seams
//!
//! Two injectable `fn`-pointer providers shape the device/host split — the
//! same pattern as the region provider (`install_region_provider`'s OATH
//! precedent):
//!
//! * **randomness** (`with_rng_provider`) — the device boot fills a pool
//!   from the DRBG (before `take_drbg` hands the generator to trussed) and
//!   wires a draining provider; a host build with no provider falls back to
//!   the platform's OS entropy. A draw with *neither* is a wiring bug and
//!   refuses `6F00` — a fabricated key is the one thing this applet must
//!   never produce.
//! * **presence** (`with_presence_grant`) — US-1646's wiring. Absent, the
//!   applet falls back to a device-denies / host-acks default, the rescue
//!   applet's fail-closed shape.
//!
//! SELECT answers `9000` with no FCI template: the client reads the applet's
//! identity through [`INS_GET_INFO`], not through the SELECT response, so
//! there is no template and none is invented.

#![cfg_attr(not(feature = "host"), no_std)]

pub mod crypto;

use fapico2_platform::dispatch::{
    App, MAX_RESPONSE, Sw, SW_CLA_NOT_SUPPORTED, SW_FILE_NOT_FOUND, SW_INS_NOT_SUPPORTED,
    SW_OK, SW_WRONG_LENGTH,
};
use heapless::Vec as HeaplessVec;

/// Nostr applet AID (EPIC design §2.1).
///
/// `F0 00 00 00 02` — the second vendor-range AID, one past the vendor LED
/// applet's `F0 00 00 00 01`. Registered in `apps/src/registry.rs` as
/// `AID_NOSTR`; the two
/// share their first four bytes and diverge at the fifth, so
/// `no_device_aid_is_a_prefix_of_another` stays green.
pub const NOSTR_AID: &[u8] = &[0xF0, 0x00, 0x00, 0x00, 0x02];

/// The ISO 7816-4 CLA the applet's commands arrive with.
///
/// US-1643 enforces it (`6E00` on any other CLA); US-1648's status-word
/// rebuild owns the final vocabulary.
pub const CLA_ISO: u8 = 0x00;

// ---------------------------------------------------------------------------
// Commands (§2.2 wire table)
// ---------------------------------------------------------------------------

/// `GET_INFO` — `applet_ver(2) ‖ caps(2) ‖ max_plaintext(2) ‖ n_identities(1)
/// ‖ flags(1)`. Touch-free.
pub const INS_GET_INFO: u8 = 0x10;
/// `LIST_KEYS` — `n(1)` then per key `idx ‖ flags ‖ npub(32) ‖ label_len(1)
/// ‖ label`. Touch-free.
pub const INS_LIST_KEYS: u8 = 0x11;
/// `GET_PUBKEY` — P1 = idx, `npub(32) ‖ bech32_npub(63)`. Touch-free.
pub const INS_GET_PUBKEY: u8 = 0x12;
/// `GENERATE_KEY` — P1 = idx, `npub(32)`. Touch-gated. US-1644.
pub const INS_GENERATE_KEY: u8 = 0x13;
/// `IMPORT_KEY` — `scalar(32)`, `npub(32)`. Touch-gated. US-1644.
pub const INS_IMPORT_KEY: u8 = 0x14;
/// `SIGN` — `sighash(32)`, `npub(32) ‖ sig(64)`. Touch-gated. US-1645.
pub const INS_SIGN: u8 = 0x15;
/// `NIP44_ENCRYPT` — `peer_x(32) ‖ plaintext(n)`, `0x02 ‖ nonce(32) ‖ ct(m)
/// ‖ mac(32)`. Touch-gated. US-1653.
pub const INS_NIP44_ENCRYPT: u8 = 0x16;
/// `NIP44_DECRYPT` — `sender_x(32) ‖ payload(65+m)`, `plaintext(n)`.
/// Touch-gated. US-1653.
pub const INS_NIP44_DECRYPT: u8 = 0x17;
/// `SET_LABEL` — `utf8(≤32 bytes)`. Touch-gated. US-1649.
pub const INS_SET_LABEL: u8 = 0x18;
/// `DELETE_KEY` — `npub(32)` naming what was destroyed. Touch-gated. US-1649.
pub const INS_DELETE_KEY: u8 = 0x19;
/// `EXPORT_KEY` — `scalar(32)`, touch-gated and permanent (§2.2.0a).
/// US-1649.
pub const INS_EXPORT_KEY: u8 = 0x1A;

// ---------------------------------------------------------------------------
// Status words (§2.2.0 — US-1648 owns the full rebuild)
// ---------------------------------------------------------------------------

/// Wrong data / bad index — an index outside the 8-slot range, or a payload
/// on a command that takes none.
pub const SW_WRONG_DATA: Sw = 0x6A80;
/// No such identity at `idx` — the slot holds no live identity. Same value
/// as the dispatcher's `SW_FILE_NOT_FOUND`; named here for the design's
/// vocabulary.
pub const SW_NO_SUCH_IDENTITY: Sw = SW_FILE_NOT_FOUND;
/// Incorrect P1/P2 — the command's shape names a P1/P2 this command does not
/// implement.
pub const SW_WRONG_P1_P2: Sw = 0x6A86;
/// Touch required / not granted. Named now so every story reads the same
/// constant; the touch gate itself arrives with US-1646.
pub const SW_TOUCH_REQUIRED: Sw = 0x6985;
/// Identity index already occupied — [`GENERATE_KEY`](INS_GENERATE_KEY) and
/// [`IMPORT_KEY`](INS_IMPORT_KEY) never overwrite. The occupant need not be
/// a Nostr identity: a foreign or unopenable record in the slot is the same
/// actionable fact (pick another index, or delete what owns it).
pub const SW_INDEX_OCCUPIED: Sw = 0x6A84;
/// Key set full — all eight slots are committed, so no index choice helps;
/// something must be deleted first. Takes precedence over
/// [`SW_INDEX_OCCUPIED`]: it names the remedy, not just the symptom.
pub const SW_KEY_SET_FULL: Sw = 0x6A88;
/// The applet cannot answer honestly — no store handle (boot degraded: the
/// OTP row or the recovery failed) or a slot that would not open. Refusing
/// with a fault beats reporting `n = 0` about a device that may hold all
/// eight identities.
pub const SW_STORE_FAULT: Sw = 0x6F00;

// ---------------------------------------------------------------------------
// GET_INFO fields
// ---------------------------------------------------------------------------

/// The applet protocol version, `(0, 1)` — bumped when the wire layout
/// changes, not when commands are added (clients branch on caps for that).
pub const APPLET_VERSION: [u8; 2] = [0x00, 0x01];

/// The largest NIP-44 plaintext the applet will accept or return (§2.2.1).
///
/// **Derived, not chosen**: `MAX_WIRE = 2074` (`firmware/src/ccid_reasm.rs`)
/// caps both directions of the CCID transport, and the two heavy rows leave
/// ≈1995 (encrypt response) and ≈1962 (decrypt request) — 1900 sits under
/// both with headroom. Advertising the host's 4096 dispatch-buffer scale
/// would be a wire claim the device does not honour: an over-long response
/// is dropped by `handle_ccid_message` with *no frame and no status word*.
/// `tests/wire.rs::wire_fits_max_wire` asserts the arithmetic against the
/// device constant.
pub const MAX_PLAINTEXT: u16 = 1900;

/// caps bit 0: key management and `SIGN` (`0x13`–`0x15`) are served. Set in
/// the same edit as US-1644/1645 — an advertised command that refuses is
/// the §4 failure mode (`apps/fido` getInfo history).
pub const CAP_KEY_MGMT: u16 = 0x0001;
/// caps bit 1: the NIP-44 pair (`0x16`/`0x17`) is served. Set with US-1653.
pub const CAP_NIP44: u16 = 0x0002;

/// What `GET_INFO` advertises: [`CAP_KEY_MGMT`] — the key-management trio
/// (`0x13`–`0x15`) is served, set in the same edit as the commands
/// themselves (US-1644/US-1645; `tests/wire.rs` re-derives the cap rows when
/// the NIP-44 story adds the next bit). An advertised command that refuses
/// is the §4 failure mode (`apps/fido` getInfo history).
pub const CAPS: u16 = CAP_KEY_MGMT;

/// Reserved `flags` byte of `GET_INFO` — zero until a story defines a bit.
pub const INFO_FLAGS: u8 = 0x00;

// ---------------------------------------------------------------------------
// bech32 npub (NIP-19)
// ---------------------------------------------------------------------------

/// The npub bech32 string length: `"npub"` + `1` + 52 data chars + 6
/// checksum chars.
pub const BECH32_NPUB_LEN: usize = 63;

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33f3, 0x2a14_62b3];

/// BIP-173 polymod over `values`.
fn bech32_polymod(values: &[u32]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = (chk & 0x01ff_ffff) << 5 ^ v;
        for (i, &g) in BECH32_GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// 8-bit → 5-bit conversion with zero padding of the final partial group
/// (BIP-173 `convertbits`, `pad=true`). 32 bytes is 256 bits, which pads to
/// 260 — exactly the 52 data characters [`BECH32_NPUB_LEN`] carries.
fn to_5bits<const N: usize>(data: &[u8], out: &mut [u32; N]) -> usize {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut n = 0;
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out[n] = (acc >> bits) & 31;
            n += 1;
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out[n] = (acc << (5 - bits)) & 31;
        n += 1;
    }
    n
}

/// The NIP-19 `npub` bech32 encoding of an x-only public key — 63 ASCII
/// bytes, `npub1…`, standard bech32 checksum (not bech32m).
///
/// Implemented here rather than pulled as a crate: the encoder is the whole
/// dependency (an npub is only ever *encoded* on device — clients decode),
/// and every byte is pinned against independently derived vectors in
/// `tests/wire.rs::bech32_npub_matches_the_reference_vectors`.
pub fn bech32_npub(x_only: &[u8; 32]) -> [u8; BECH32_NPUB_LEN] {
    const HRP: &[u8; 4] = b"npub";
    let mut data5 = [0u32; 52];
    let n = to_5bits(x_only, &mut data5);
    debug_assert_eq!(n, 52);

    // hrp_expand: high 5 bits of each char, a zero, the low 5 bits.
    const DATA_START: usize = 4 + 1 + 4; // hrp high + zero + hrp low
    let mut values = [0u32; DATA_START + 52 + 6];
    let mut i = 0;
    for &c in HRP {
        values[i] = (c >> 5) as u32;
        i += 1;
    }
    values[i] = 0;
    i += 1;
    for &c in HRP {
        values[i] = (c & 31) as u32;
        i += 1;
    }
    values[i..i + 52].copy_from_slice(&data5);
    debug_assert_eq!(i + 52, DATA_START + 52);
    let polym = bech32_polymod(&values[..DATA_START + 52 + 6]) ^ 1;
    for k in 0..6 {
        values[DATA_START + 52 + k] = (polym >> (5 * (5 - k))) & 31;
    }

    let mut out = [0u8; BECH32_NPUB_LEN];
    out[..4].copy_from_slice(HRP);
    out[4] = b'1';
    for (k, &v) in values[DATA_START..DATA_START + 52 + 6].iter().enumerate() {
        out[5 + k] = BECH32_CHARSET[v as usize];
    }
    out
}

// ---------------------------------------------------------------------------
// The applet
// ---------------------------------------------------------------------------

/// The Nostr applet.
///
/// Holds the Nostr key-region handle for its whole session (the same
/// take-once discipline OATH's applet applies — `boot::take_nostr_key_region`
/// moves the handle out of its boot slot exactly once). `None` means the
/// region is not attached *yet*: either the boot degraded (the OTP row or the
/// interrupted-commit recovery failed) or the device boot has not reached the
/// release gate yet, and the applet refuses reads with [`SW_STORE_FAULT`]
/// rather than reporting a fiction.
#[derive(Debug, Default)]
pub struct NostrApp {
    region: Option<fapico2_platform::keyregion::nostr_store::NostrRegion>,
    /// The device path's lazy region source — `install_region_provider`'s
    /// OATH precedent: the handle cannot be *taken* before
    /// `release_key_region()` (`boot.rs` gates it behind `KEY_REGION_READY`),
    /// and the applet is constructed before that line, so the attach happens
    /// on the first read instead. `None` on the test/emulator path, which
    /// boots the region eagerly through [`NostrApp::boot`].
    provider: Option<fn() -> Option<fapico2_platform::keyregion::nostr_store::NostrRegion>>,
    /// The randomness source (US-1644). See the module docs: device = the
    /// boot pool drained through `with_rng_provider`; host default = the
    /// platform's OS entropy; *neither* = refuse rather than fabricate.
    rng: Option<fn(&mut [u8])>,
    /// The user-presence grant path (US-1646 wires it; US-1644 consults
    /// it). `None` ⇒ [`default_user_present`] — deny on device, auto-ack on
    /// host — the rescue applet's shape.
    presence_grant: Option<fn(u32) -> bool>,
}

impl NostrApp {
    /// A bare applet: no store handle, no randomness, no presence grant.
    ///
    /// The registration test (`apps/tests/registry.rs`) registers this
    /// shape; the firmware and the emulator boot a region instead.
    pub fn new() -> Self {
        NostrApp { region: None, provider: None, rng: None, presence_grant: None }
    }

    /// Boot the applet over `region`, finishing any commit a power cut
    /// interrupted first.
    ///
    /// `NostrStore::recover` **must** run before the region is read — a live
    /// sector caught between its erase and its copy-back reads as empty —
    /// so the one-shot mount happens here, at construction, not lazily on
    /// the first read. A failed recovery leaves `region` unset: the applet
    /// keeps answering APDUs and refuses every read with [`SW_STORE_FAULT`]
    /// (S10: degrade, never halt — the same shape `boot.rs` uses for a
    /// missing OATH payload key).
    pub fn boot(mut region: fapico2_platform::keyregion::nostr_store::NostrRegion) -> Self {
        match region.store().recover() {
            Ok(_) => NostrApp { region: Some(region), provider: None, rng: None, presence_grant: None },
            Err(_) => NostrApp { region: None, provider: None, rng: None, presence_grant: None },
        }
    }

    /// Register the device path's lazy region source.
    ///
    /// A `fn` pointer, not a closure: the provider outlives this call by
    /// living in the applet, and the device boot hands it
    /// `|| boot::nostr_region()` — a capture-free closure, which is a plain
    /// `fn` pointer. Asked at most until it succeeds: the first successful
    /// attach runs the interrupted-commit recovery (the same discipline
    /// [`NostrApp::boot`] states) and clears the provider.
    pub fn with_region_provider(
        mut self,
        provider: fn() -> Option<fapico2_platform::keyregion::nostr_store::NostrRegion>,
    ) -> Self {
        self.provider = Some(provider);
        self
    }

    /// Register the randomness source (US-1644). The device boot wires a
    /// provider that drains the boot pool filled from the DRBG; a host
    /// build may leave it unset and draw OS entropy. The tests pin draws
    /// through it (the BIP-340 vectors' `aux_rand`).
    pub fn with_rng_provider(mut self, rng: fn(&mut [u8])) -> Self {
        self.rng = Some(rng);
        self
    }

    /// Register the user-presence grant path — the rescue applet's
    /// `with_presence_grant` shape (US-1536). Wired by US-1646 on the
    /// device; the tests deny through it to pin the `6985` rows.
    pub fn with_presence_grant(mut self, grant: fn(u32) -> bool) -> Self {
        self.presence_grant = Some(grant);
        self
    }

    /// The applet's region view — attaching the deferred region first when
    /// the provider can — or refusing with [`SW_STORE_FAULT`] when the boot
    /// degraded (see [`NostrApp::boot`]).
    fn store(
        &mut self,
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) -> Option<fapico2_platform::keyregion::nostr_store::NostrStore<'_>> {
        attach_store(&mut self.region, &mut self.provider, resp)
    }

    /// `GET_INFO` — `applet_ver(2) ‖ caps(2) ‖ max_plaintext(2) ‖
    /// n_identities(1) ‖ flags(1)`, P1 = P2 = 0, no payload, touch-free.
    fn get_info(&mut self, p1: u8, p2: u8, data: &[u8], resp: &mut HeaplessVec<u8, MAX_RESPONSE>) {
        use fapico2_platform::keyregion::nostr_store::NOSTR_SLOTS;
        if p1 != 0 || p2 != 0 {
            write_sw(resp, SW_WRONG_P1_P2);
            return;
        }
        if !refuse_payload(data, resp) {
            return;
        }
        let Some(mut store) = self.store(resp) else { return };
        let mut n: u8 = 0;
        for index in 0..NOSTR_SLOTS as u16 {
            match read_identity(&mut store, index) {
                Ok(_) => n += 1,
                Err(SW_NO_SUCH_IDENTITY) => {}
                Err(sw) => {
                    write_sw(resp, sw);
                    return;
                }
            }
        }
        resp.extend_from_slice(&APPLET_VERSION).ok();
        resp.extend_from_slice(&CAPS.to_be_bytes()).ok();
        resp.extend_from_slice(&MAX_PLAINTEXT.to_be_bytes()).ok();
        resp.push(n).ok();
        resp.push(INFO_FLAGS).ok();
        write_sw(resp, SW_OK);
    }

    /// `LIST_KEYS` — `n(1)` then, in index order, `idx ‖ flags ‖ npub(32) ‖
    /// label_len(1) ‖ label` per live identity. P1 = P2 = 0, no payload,
    /// touch-free.
    fn list_keys(&mut self, p1: u8, p2: u8, data: &[u8], resp: &mut HeaplessVec<u8, MAX_RESPONSE>) {
        use fapico2_platform::keyregion::nostr_store::NOSTR_SLOTS;
        if p1 != 0 || p2 != 0 {
            write_sw(resp, SW_WRONG_P1_P2);
            return;
        }
        if !refuse_payload(data, resp) {
            return;
        }
        let Some(mut store) = self.store(resp) else { return };
        // Count first: `n` leads the response, and the entries follow it.
        let mut live: heapless::Vec<
            (u16, fapico2_platform::keyregion::nostr_store::NostrIdentity),
            8,
        > = heapless::Vec::new();
        for index in 0..NOSTR_SLOTS as u16 {
            match read_identity(&mut store, index) {
                Ok(id) => {
                    let _ = live.push((index, id));
                }
                Err(SW_NO_SUCH_IDENTITY) => {}
                Err(sw) => {
                    write_sw(resp, sw);
                    return;
                }
            }
        }
        resp.push(live.len() as u8).ok();
        for (index, id) in live {
            resp.push(index as u8).ok();
            resp.push(id.flags).ok();
            resp.extend_from_slice(&id.npub).ok();
            let label = id.label();
            resp.push(label.len() as u8).ok();
            resp.extend_from_slice(label).ok();
        }
        write_sw(resp, SW_OK);
    }

    /// `GET_PUBKEY` — P1 = idx, P2 = 0, no payload; `npub(32) ‖
    /// bech32_npub(63)`. Touch-free (§2.3): a public key is public.
    fn get_pubkey(&mut self, p1: u8, p2: u8, data: &[u8], resp: &mut HeaplessVec<u8, MAX_RESPONSE>) {
        if p2 != 0 {
            write_sw(resp, SW_WRONG_P1_P2);
            return;
        }
        if !refuse_payload(data, resp) {
            return;
        }
        let Some(mut store) = self.store(resp) else { return };
        let id = match read_identity(&mut store, p1 as u16) {
            Ok(id) => id,
            Err(sw) => {
                write_sw(resp, sw);
                return;
            }
        };
        resp.extend_from_slice(&id.npub).ok();
        resp.extend_from_slice(&bech32_npub(&id.npub)).ok();
        write_sw(resp, SW_OK);
    }

    /// `GENERATE_KEY` — P1 = idx, no payload; `npub(32)`. Touch-gated (§2.2).
    ///
    /// The refusal order is the one the user can act on: a full set is
    /// [`SW_KEY_SET_FULL`] (no index choice helps), an occupied index is
    /// [`SW_INDEX_OCCUPIED`] (pick another), and the touch is **last** — a
    /// press the host could have avoided by consulting the touch-free reads
    /// is a press wasted.
    fn generate_key(
        &mut self,
        p1: u8,
        p2: u8,
        data: &[u8],
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) {
        use fapico2_platform::keyregion::nostr_store::NOSTR_SLOTS;
        if p2 != 0 {
            write_sw(resp, SW_WRONG_P1_P2);
            return;
        }
        if !refuse_payload(data, resp) {
            return;
        }
        // Destructure once: the store borrow must coexist with the RNG pool
        // draw, and disjoint field borrows compose where a `&mut self`
        // method call would not.
        let Self { region, provider, rng, presence_grant } = self;
        let Some(mut store) = attach_store(region, provider, resp) else { return };

        // State before the touch (see the doc comment).
        let mut any_writable = false;
        let mut idx_writable = false;
        for i in 0..NOSTR_SLOTS as u16 {
            match writability(&mut store, i) {
                Ok(true) => {
                    any_writable = true;
                    idx_writable |= i == p1 as u16;
                }
                Ok(false) => {}
                Err(sw) => {
                    write_sw(resp, sw);
                    return;
                }
            }
        }
        if !any_writable {
            write_sw(resp, SW_KEY_SET_FULL);
            return;
        }
        if !idx_writable {
            write_sw(resp, SW_INDEX_OCCUPIED);
            return;
        }
        if !user_present(*presence_grant, p1 as u32) {
            write_sw(resp, SW_TOUCH_REQUIRED);
            return;
        }

        // A uniform draw is a valid secret scalar unless it is zero or ≥ the
        // curve order (~2⁻²⁵⁶); retry rather than map an astronomically
        // unlikely draw onto a fault.
        let mut scalar = None;
        for _ in 0..4 {
            let mut buf = [0u8; 32];
            match draw_random(*rng, &mut buf) {
                Some(()) if crypto::scalar_valid(&buf) => {
                    scalar = Some(buf);
                    break;
                }
                None => break, // the source refused — fault below
                Some(()) => {}
            }
        }
        let Some(scalar) = scalar else {
            write_sw(resp, SW_STORE_FAULT);
            return;
        };
        let Some(npub) = crypto::xonly_pubkey(&scalar) else {
            // Unreachable for a validated scalar; refuse rather than answer
            // with a key that was never derived.
            write_sw(resp, SW_STORE_FAULT);
            return;
        };
        if !write_identity(&mut store, p1 as u16, &scalar, &npub, resp) {
            return;
        }
        resp.extend_from_slice(&npub).ok();
        write_sw(resp, SW_OK);
    }

    /// `IMPORT_KEY` — P1 = idx, `scalar(32)`; `npub(32)`. Touch-gated.
    ///
    /// The scalar is validated **before** anything else (`6A80`): garbage is
    /// refused without a press, and the same word covers a wrong length, so
    /// no state leaks through the ordering.
    fn import_key(
        &mut self,
        p1: u8,
        p2: u8,
        data: &[u8],
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) {
        use fapico2_platform::keyregion::nostr_store::NOSTR_SLOTS;
        if p2 != 0 {
            write_sw(resp, SW_WRONG_P1_P2);
            return;
        }
        let Ok(scalar) = <[u8; 32]>::try_from(data) else {
            write_sw(resp, SW_WRONG_DATA);
            return;
        };
        if p1 as u16 >= NOSTR_SLOTS as u16 {
            write_sw(resp, SW_WRONG_DATA);
            return;
        }
        if !crypto::scalar_valid(&scalar) {
            write_sw(resp, SW_WRONG_DATA);
            return;
        }
        // IMPORT_KEY draws nothing: the scalar is the host's, and its
        // validity is checked above.
        let Self { region, provider, rng: _, presence_grant } = self;
        let Some(mut store) = attach_store(region, provider, resp) else { return };
        match writability(&mut store, p1 as u16) {
            Ok(true) => {}
            Ok(false) => {
                write_sw(resp, SW_INDEX_OCCUPIED);
                return;
            }
            Err(sw) => {
                write_sw(resp, sw);
                return;
            }
        }
        if !user_present(*presence_grant, p1 as u32) {
            write_sw(resp, SW_TOUCH_REQUIRED);
            return;
        }
        let Some(npub) = crypto::xonly_pubkey(&scalar) else {
            // Unreachable for a validated scalar.
            write_sw(resp, SW_STORE_FAULT);
            return;
        };
        if !write_identity(&mut store, p1 as u16, &scalar, &npub, resp) {
            return;
        }
        resp.extend_from_slice(&npub).ok();
        write_sw(resp, SW_OK);
    }

    /// `SIGN` — P1 = idx, `sighash(32)`; `npub(32) ‖ sig(64)`. Touch-gated.
    ///
    /// The npub rides **alongside** the signature (§2.2.0a): a host that
    /// signs against the wrong identity cannot paper over it, because the
    /// answer names the key that produced the signature.
    fn sign(&mut self, p1: u8, p2: u8, data: &[u8], resp: &mut HeaplessVec<u8, MAX_RESPONSE>) {
        if p2 != 0 {
            write_sw(resp, SW_WRONG_P1_P2);
            return;
        }
        let Ok(sighash) = <[u8; 32]>::try_from(data) else {
            write_sw(resp, SW_WRONG_DATA);
            return;
        };
        let Self { region, provider, rng, presence_grant } = self;
        let Some(mut store) = attach_store(region, provider, resp) else { return };
        let id = match read_identity(&mut store, p1 as u16) {
            Ok(id) => id,
            Err(sw) => {
                write_sw(resp, sw);
                return;
            }
        };
        if !user_present(*presence_grant, p1 as u32) {
            write_sw(resp, SW_TOUCH_REQUIRED);
            return;
        }
        let mut aux = [0u8; 32];
        if draw_random(*rng, &mut aux).is_none() {
            write_sw(resp, SW_STORE_FAULT);
            return;
        }
        match crypto::bip340_sign(&id.scalar, &sighash, &aux) {
            Some(sig) => {
                resp.extend_from_slice(&id.npub).ok();
                resp.extend_from_slice(&sig).ok();
                write_sw(resp, SW_OK);
            }
            // A stored scalar that would not sign is a record this device
            // cannot honour; refusing beats answering with fiction.
            None => write_sw(resp, SW_STORE_FAULT),
        }
    }
}

impl App for NostrApp {
    fn aid(&self) -> &[u8] {
        NOSTR_AID
    }

    /// SELECT answers `9000` with no response data — see the module docs.
    fn select(&mut self, _internal: bool) -> Sw {
        SW_OK
    }

    fn deselect(&mut self) {}

    /// Dispatch the §2.2 wire table. Unimplemented arms are the US-1642
    /// skeleton refusal until their stories replace them.
    fn process(&mut self, apdu: &[u8], resp: &mut HeaplessVec<u8, MAX_RESPONSE>) {
        // Header guard first: a sub-4-byte APDU would index `apdu[2]`/
        // `apdu[3]` out of bounds (the US-701 panic class, `apps/mgmt`).
        if apdu.len() < 4 {
            write_sw(resp, SW_WRONG_LENGTH);
            return;
        }
        if apdu[0] != CLA_ISO {
            write_sw(resp, SW_CLA_NOT_SUPPORTED);
            return;
        }
        let ins = apdu[1];
        let p1 = apdu[2];
        let p2 = apdu[3];
        let data = parse_data(apdu);
        match ins {
            INS_GET_INFO => self.get_info(p1, p2, data, resp),
            INS_LIST_KEYS => self.list_keys(p1, p2, data, resp),
            INS_GET_PUBKEY => self.get_pubkey(p1, p2, data, resp),
            INS_GENERATE_KEY => self.generate_key(p1, p2, data, resp),
            INS_IMPORT_KEY => self.import_key(p1, p2, data, resp),
            INS_SIGN => self.sign(p1, p2, data, resp),
            // US-1649 label/delete/export, US-1653 the NIP-44 pair — each
            // replaces its arm here.
            _ => write_sw(resp, SW_INS_NOT_SUPPORTED),
        }
    }
}

/// The APDU data field: short (`Lc` in `apdu[4]`) or extended (`00 Hi Lo`)
/// form — the `apps/mgmt` convention the C-harness encodings share.
fn parse_data(apdu: &[u8]) -> &[u8] {    if apdu.len() >= 7 && apdu[4] == 0x00 {
        let lc = u16::from_be_bytes([apdu[5], apdu[6]]) as usize;
        return apdu.get(7..7 + lc).unwrap_or(&[]);
    }
    if apdu.len() < 5 {
        return &[];
    }
    let lc = apdu[4] as usize;
    apdu.get(5..5 + lc).unwrap_or(&[])
}

fn write_sw(resp: &mut HeaplessVec<u8, MAX_RESPONSE>, sw: Sw) {
    resp.extend_from_slice(&sw.to_be_bytes()).ok();
}

/// The commands take no payload in this story; a payload is wrong data.
fn refuse_payload(data: &[u8], resp: &mut HeaplessVec<u8, MAX_RESPONSE>) -> bool {
    if !data.is_empty() {
        write_sw(resp, SW_WRONG_DATA);
        false
    } else {
        true
    }
}

/// Read one identity, mapping the store's outcomes onto the §2.2.0 words.
///
/// An index outside the range is [`SW_WRONG_DATA`]; an in-range slot with no
/// live identity is [`SW_NO_SUCH_IDENTITY`] (a tombstone, an erased slot and
/// a foreign record all mean "there is no Nostr identity at idx" — the last
/// is exactly the stale-FIDO-record case US-1641's guard protects). A slot
/// that carries our tag but would not open, or a region fault, is
/// [`SW_STORE_FAULT`]: the applet cannot say what is in that slot, and
/// inventing "no such identity" would hide a corrupt record from its owner.
fn read_identity(
    store: &mut fapico2_platform::keyregion::nostr_store::NostrStore<'_>,
    index: u16,
) -> Result<fapico2_platform::keyregion::nostr_store::NostrIdentity, Sw> {
    use fapico2_platform::keyregion::nostr_store::{Entry, NostrStoreError};
    match store.read(index) {
        Ok(Entry::Live(id)) => Ok(id),
        Ok(Entry::Empty | Entry::Tombstone | Entry::Foreign) => Err(SW_NO_SUCH_IDENTITY),
        Ok(Entry::Undecodable) => Err(SW_STORE_FAULT),
        Err(NostrStoreError::IndexOutOfRange { .. }) => Err(SW_WRONG_DATA),
        Err(_) => Err(SW_STORE_FAULT),
    }
}

/// The applet's region view — the store-attach half of the old `store`
/// method, split out so the mutating commands can hold it beside the
/// destructured RNG/presence fields (disjoint field borrows compose; a
/// `&mut self` method call would not). A recovery failure keeps the
/// provider: the next read retries the mount rather than pinning a
/// transient fault onto the applet for good.
fn attach_store<'region>(
    region: &'region mut Option<fapico2_platform::keyregion::nostr_store::NostrRegion>,
    provider: &mut Option<fn() -> Option<fapico2_platform::keyregion::nostr_store::NostrRegion>>,
    resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
) -> Option<fapico2_platform::keyregion::nostr_store::NostrStore<'region>> {
    if region.is_none() {
        if let Some(attach) = provider {
            if let Some(mut candidate) = attach() {
                if candidate.store().recover().is_ok() {
                    *provider = None;
                    *region = Some(candidate);
                }
            }
        }
    }
    match region.as_mut() {
        Some(region) => Some(region.store()),
        None => {
            write_sw(resp, SW_STORE_FAULT);
            None
        }
    }
}

/// Draw from the applet's randomness source. `None` when there is none —
/// the fail-closed answer: the device wiring always provides one, so this
/// is a wiring bug refusing loudly, never a fabricated key.
fn draw_random(rng: Option<fn(&mut [u8])>, out: &mut [u8]) -> Option<()> {
    match rng {
        Some(f) => {
            f(out);
            Some(())
        }
        None => platform_random(out),
    }
}

/// The host/emulation default — OS entropy (`platform::trng`'s free entry
/// point). Not compiled on the device: the device path always wires a
/// provider, so the arm fallback there is the refuse path above.
#[cfg(not(target_arch = "arm"))]
fn platform_random(out: &mut [u8]) -> Option<()> {
    fapico2_platform::trng::random_bytes_into(out);
    Some(())
}

#[cfg(target_arch = "arm")]
fn platform_random(_out: &mut [u8]) -> Option<()> {
    None
}

/// The device user-presence source for the applet's own fallback path —
/// the rescue applet's shape verbatim (`apps/rescue/src/lib.rs`): a
/// **device** build denies, so the fail-closed case is the one that ships,
/// while a **host/emulation** build auto-acks so the emulator suites —
/// which have no button to press — keep exercising the command paths.
/// US-1646 wires the real grant on the device path.
fn default_user_present() -> bool {
    #[cfg(feature = "device")]
    {
        false
    }
    #[cfg(not(feature = "device"))]
    {
        true
    }
}

fn user_present(grant: Option<fn(u32) -> bool>, idx: u32) -> bool {
    match grant {
        Some(g) => g(idx),
        None => default_user_present(),
    }
}

/// The writers' view of one slot: `true` when a write may commit (erased,
/// or our own committed tombstone), `false` when the slot is occupied — a
/// live identity, a record ours would not open, or another domain's record
/// (the US-1641 occupancy guard refuses all three alike). Occupied is
/// [`SW_INDEX_OCCUPIED`] for the writers even when the occupant is not a
/// Nostr identity: the actionable fact is the same.
fn writability(
    store: &mut fapico2_platform::keyregion::nostr_store::NostrStore<'_>,
    index: u16,
) -> Result<bool, Sw> {
    use fapico2_platform::keyregion::nostr_store::{Entry, NostrStoreError};
    match store.read(index) {
        Ok(Entry::Empty | Entry::Tombstone) => Ok(true),
        Ok(_) => Ok(false),
        Err(NostrStoreError::IndexOutOfRange { .. }) => Err(SW_WRONG_DATA),
        Err(_) => Err(SW_STORE_FAULT),
    }
}

/// Commit one identity to `index`, mapping the store's refusals onto the
/// §2.2.0 words. `true` when committed; the status word is written either
/// way.
fn write_identity(
    store: &mut fapico2_platform::keyregion::nostr_store::NostrStore<'_>,
    index: u16,
    scalar: &[u8; 32],
    npub: &[u8; 32],
    resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
) -> bool {
    use fapico2_platform::keyregion::nostr_store::{NostrIdentity, NostrStoreError};
    let Some(id) = NostrIdentity::new(*scalar, *npub, &[], 0) else {
        // Unreachable: an empty label is always valid.
        write_sw(resp, SW_STORE_FAULT);
        return false;
    };
    match store.write(index, &id) {
        Ok(_) => true,
        // The guard refused after our own writability check passed — the
        // same fact twice; the word is the one the host can act on.
        Err(NostrStoreError::OccupiedForeign { .. }) => {
            write_sw(resp, SW_INDEX_OCCUPIED);
            false
        }
        Err(_) => {
            write_sw(resp, SW_STORE_FAULT);
            false
        }
    }
}
