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
//! # The skeleton (US-1642)
//!
//! This revision wires the applet into the registry at
//! [`NOSTR_AID`] and answers nothing: every command reaches `process`
//! and every command is refused with `SW_INS_NOT_SUPPORTED` (`6D00`). The
//! command set arrives with the Phase 1 stories (US-1643 reads, US-1644
//! generate/import, US-1645 sign), each of which replaces an arm of the
//! dispatch below rather than widening this skeleton.
//!
//! The SELECT answers `9000` with no FCI template: the client reads the
//! applet's identity through `GET_INFO` (US-1643), not through the SELECT
//! response, so there is no template yet and none is invented.

#![cfg_attr(not(feature = "host"), no_std)]

use fapico2_platform::dispatch::{App, MAX_RESPONSE, Sw, SW_INS_NOT_SUPPORTED, SW_OK};
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
/// Recorded now so the applet's own tests can name it; the skeleton does not
/// branch on CLA (every command is `6D00` regardless), and US-1648's
/// status-word vocabulary decides whether the CLA guard is enforced here or
/// left to the dispatcher.
pub const CLA_ISO: u8 = 0x00;

/// The Nostr applet.
///
/// Stateless in this revision: no identity is reachable yet (the store exists
/// at `platform/src/keyregion/nostr_store.rs` but no command reads it), so
/// there is nothing to persist and [`App::persist_state`] keeps its default.
#[derive(Debug, Default)]
pub struct NostrApp {}

impl NostrApp {
    /// A bare applet: no store handle, no presence source.
    ///
    /// Registration is a wiring assertion and a bare applet is the honest
    /// thing to register until Phase 1 stories add the state and the
    /// injections (`apps/tests/registry.rs` registers it the same way).
    pub fn new() -> Self {
        NostrApp {}
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

    /// Every command is refused: the skeleton implements no commands.
    ///
    /// The response is the bare status word, `6D00` — the same shape
    /// `vendor_led`'s `_` arm produces, and the one thing a client can rely
    /// on from an applet it has selected but whose protocol it cannot
    /// negotiate (US-1643 advertises the real surface).
    fn process(&mut self, _apdu: &[u8], resp: &mut HeaplessVec<u8, MAX_RESPONSE>) {
        write_sw(resp, SW_INS_NOT_SUPPORTED);
    }
}

fn write_sw(resp: &mut HeaplessVec<u8, MAX_RESPONSE>, sw: Sw) {
    resp.extend_from_slice(&sw.to_be_bytes()).ok();
}
