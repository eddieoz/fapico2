//! AID-based application dispatcher (US-305).
//!
//! Mirrors the C `pico-keys-sdk/src/main.c` `select_app()` /
//! `select_app_internal()` behavior in Rust:
//! * A registry of `App` trait objects keyed by AID.
//! * Unknown AID → ISO 7816-4 SW `6A82` (file not found), current selection untouched.
//! * Host-issued SELECT resets the app's security state (internal=0).
//! * Internal re-select (multiplexing) preserves the cached security session (internal=1).
//!
//! `heapless::Vec` bounds the response buffer; no heap.

use heapless::Vec;

use crate::secure_store::SecureStore;

/// Max response bytes an app can return in one PDU (bounded by heapless).
pub const MAX_RESPONSE: usize = 4096;

/// ISO 7816-4 status words.
pub type Sw = u16;

pub const SW_OK: Sw = 0x9000;
pub const SW_FILE_NOT_FOUND: Sw = 0x6A82;
pub const SW_INS_NOT_SUPPORTED: Sw = 0x6D00;
pub const SW_CLA_NOT_SUPPORTED: Sw = 0x6E00;
pub const SW_WRONG_LENGTH: Sw = 0x6700;
/// Conditions not met — a protected command issued before the required PIN
/// verification (ISO 7816-4). Used by the US-211 app-switching parity test.
pub const SW_CONDITIONS_NOT_SATISFIED: Sw = 0x6982;

/// An app that can be selected, processed, and deselected.
pub trait App {
    /// Return the full AID bytes this app responds to.
    fn aid(&self) -> &[u8];

    /// Called on SELECT AID.
    ///
    /// `internal` = false: host-issued SELECT (security state reset per ISO 7816-4).
    /// `internal` = true: internal multiplexed switch (preserve security state).
    ///
    /// Return `SW_OK` on success, an error SW on failure.
    fn select(&mut self, internal: bool) -> Sw;

    /// Called when another app is selected or the connection tears down.
    fn deselect(&mut self);

    /// Process an APDU. The response bytes (data + SW) are written into `resp`.
    /// `resp` arrives empty (the dispatcher clears it before every dispatch)
    /// and the app must write the complete response — data and trailing status
    /// word — into it.
    fn process(&mut self, apdu: &[u8], resp: &mut Vec<u8, MAX_RESPONSE>);

    /// SELECT AID handler that may append response data to `resp` before the
    /// status word (OATH SELECT returns version/name/challenge). Defaults to
    /// `select()` with no data.
    fn select_apdu(
        &mut self,
        internal: bool,
        _apdu: &[u8],
        _resp: &mut Vec<u8, MAX_RESPONSE>,
    ) -> Sw {
        self.select(internal)
    }

    /// Persist the app's durable state through the platform secure store
    /// (US-388): FIDO credential store + auth state, OpenPGP card state + PIN,
    /// OATH credential list, OTP slot contents, Management `EF_DEV_CONF`.
    /// Default: the app holds no durable state. Apps with a dirty durable
    /// state write it through the store and return `true`; volatile session
    /// state is never persisted. Called after every dispatched APDU by the
    /// platform persist gate (see [`crate::persist`]).
    ///
    /// Failure contract (US-421): when the store write fails, the app keeps
    /// its dirty flag set so the next persist run retries the write.
    fn persist_state(&mut self, _store: &mut dyn SecureStore) -> bool {
        false
    }

    /// Re-mark the app's durable state dirty (the persist gate's failure
    /// path, US-421: the store write succeeded but the partition image could
    /// not be programmed — the change must be retried on the next command).
    /// Default: the app does not track dirtiness, so there is nothing to
    /// re-mark.
    fn mark_dirty(&mut self) {}

    /// Is the app left with dirty durable state that has not reached the
    /// store (US-427)? Transports call this **after** the persist gate to
    /// tell the two `false` outcomes apart: the gate returns `false` both
    /// when nothing was dirty (a clean no-op — the success reply may go
    /// out) and when a persist failed (the writing apps are re-marked
    /// dirty — durable-before-ack, the transport answers the error reply
    /// instead). Default: the app does not track dirtiness (mirrors the
    /// [`App::persist_state`] default — it can never be left dirty).
    fn is_dirty(&self) -> bool {
        false
    }

    /// US-711: clear the app's durable state to factory-fresh and mark it
    /// dirty (the transport's persist gate flushes the emptied state right
    /// after). Default: the app holds no durable state. Called by the
    /// **owning transport** — through its dispatcher, which holds the sole
    /// `&mut` to each app — never from inside another app's `process` (the
    /// management RESET hook cannot reach the other apps without aliasing).
    fn factory_wipe(&mut self) {}
}

/// AID dispatcher: routes SELECT-by-AID to registered apps.
pub struct Dispatcher<'a, const N: usize> {
    apps: Vec<&'a mut dyn App, N>,
    current_idx: Option<usize>,
}

impl<'a, const N: usize> Default for Dispatcher<'a, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, const N: usize> Dispatcher<'a, N> {
    pub fn new() -> Self {
        Self {
            apps: Vec::new(),
            current_idx: None,
        }
    }

    /// Register an app. The app's AID must be unique.
    pub fn register(&mut self, app: &'a mut dyn App) -> bool {
        for existing in &self.apps {
            if existing.aid() == app.aid() {
                return false;
            }
        }
        self.apps.push(app).is_ok()
    }

    /// Check if `aid` is a registered AID.
    fn find_app(&self, aid: &[u8]) -> Option<usize> {
        self.apps.iter().position(|app: &&mut dyn App| app.aid() == aid)
    }

    /// Process a raw APDU.
    ///
    /// If the APDU is a SELECT (CLA=0x00, INS=0xA4, P1=0x04, P2=0x00),
    /// dispatch by AID to the registered app. Otherwise, forward to the
    /// currently selected app.
    pub fn dispatch(&mut self, apdu: &[u8], resp: &mut Vec<u8, MAX_RESPONSE>) {
        resp.clear();

        if self.is_select_apdu(apdu) {
            let aid = self.extract_aid(apdu);
            let internal = false; // host-issued SELECT
            if aid.is_empty() {
                // SELECT with no AID — this is a "select MF" or similar;
                // we don't support it yet.
                resp.extend_from_slice(&SW_FILE_NOT_FOUND.to_be_bytes())
                    .unwrap();
                return;
            }

            if let Some(idx) = self.find_app(aid) {
                // Same app already selected: re-select with security reset.
                if self.current_idx == Some(idx) {
                    let sw = self.apps[idx].select_apdu(internal, apdu, resp);
                    resp.extend_from_slice(&sw.to_be_bytes()).unwrap();
                } else {
                    // Deselect previous, select new.
                    if let Some(prev) = self.current_idx {
                        self.apps[prev].deselect();
                    }
                    let sw = self.apps[idx].select_apdu(internal, apdu, resp);
                    if sw == SW_OK {
                        self.current_idx = Some(idx);
                    }
                    resp.extend_from_slice(&sw.to_be_bytes()).unwrap();
                }
            } else {
                // Unknown AID: 6A82, current selection unchanged (US-211).
                resp.extend_from_slice(&SW_FILE_NOT_FOUND.to_be_bytes())
                    .unwrap();
            }
        } else if let Some(idx) = self.current_idx {
            self.apps[idx].process(apdu, resp);
        } else {
            // No app selected: ISO 7816-4 "file not found" — parity with the
            // C SDK (`apdu.c`: non-AID-SELECT with no current app returns
            // `SW_FILE_NOT_FOUND()`). 6E00 here is not just a cosmetic
            // difference: gpg's scd maps 6E00 (SW_CLA_NOT_SUP) to
            // GPG_ERR_CARD, which triggers its Yubikey-manager probe
            // (SELECT `A0 00 00 05 27 47 11 17` + GET DATA 0x001D). The
            // management app answers both, so a fresh-boot card — the one
            // state in which no app is selected — gets classified as a
            // Yubikey and `gpg --card-status` prints a synthetic Yubikey
            // AID instead of the OpenPGP AID. 6A82 (GPG_ERR_ENOENT) takes
            // scd down the normal ATR/OpenPGP path, as on the C board.
            resp.extend_from_slice(&SW_FILE_NOT_FOUND.to_be_bytes()).unwrap();
        }
    }

    /// Deselect the current app (if any).
    pub fn deselect_current(&mut self) {
        if let Some(idx) = self.current_idx {
            self.apps[idx].deselect();
            self.current_idx = None;
        }
    }

    /// Mutable access to the registered apps (US-421): the call site of the
    /// platform persist gate (`crate::persist::persist_apps`), which runs the
    /// store write **and** the snapshot→program sequence in one place.
    pub fn apps_mut(&mut self) -> &mut [&'a mut dyn App] {
        &mut self.apps[..]
    }

    /// US-711: run [`App::factory_wipe`] on every registered app. The owning
    /// transport calls this after a management factory reset (its RESET hook
    /// wiped the durable slots and signalled the generation) and before the
    /// persist gate, so the emptied app tables reach the store in the same
    /// gate run. The dispatcher holds the sole `&mut` to each app — no
    /// aliasing.
    pub fn factory_wipe_apps(&mut self) {
        for app in self.apps.iter_mut() {
            app.factory_wipe();
        }
    }

    /// Is this APDU a SELECT AID?
    fn is_select_apdu(&self, apdu: &[u8]) -> bool {
        apdu.len() >= 4 && apdu[0] == 0x00 && apdu[1] == 0xA4 && apdu[2] == 0x04
    }

    /// Extract the AID from a SELECT AID APDU.
    ///
    /// Both Lc encodings are accepted: short form (`Lc` at [4]) and the
    /// C-harness extended form (`0x00 ‖ LcHi ‖ LcLo` at [4..7]).
    fn extract_aid<'b>(&self, apdu: &'b [u8]) -> &'b [u8] {
        if apdu.len() >= 5 && apdu[4] == 0x00 && apdu.len() >= 7 {
            let lc = u16::from_be_bytes([apdu[5], apdu[6]]) as usize;
            if apdu.len() >= 7 + lc {
                return &apdu[7..7 + lc];
            }
        }
        if apdu.len() >= 5 {
            let lc = apdu[4] as usize;
            if apdu.len() >= 5 + lc {
                return &apdu[5..5 + lc];
            }
        }
        &[]
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    /// Stub app for testing.
    struct StubApp {
        aid: Vec<u8, 16>,
        selected: bool,
        select_count: u32,
        deselect_count: u32,
    }

    impl StubApp {
        fn new(aid: &[u8]) -> Self {
            let mut v = Vec::new();
            v.extend_from_slice(aid).unwrap();
            Self {
                aid: v,
                selected: false,
                select_count: 0,
                deselect_count: 0,
            }
        }
    }

    impl App for StubApp {
        fn aid(&self) -> &[u8] {
            &self.aid
        }

        fn select(&mut self, _internal: bool) -> Sw {
            self.selected = true;
            self.select_count += 1;
            // Internal re-select preserves state (but we still count it).
            SW_OK
        }

        fn deselect(&mut self) {
            self.selected = false;
            self.deselect_count += 1;
        }

        fn process(&mut self, apdu: &[u8], resp: &mut Vec<u8, MAX_RESPONSE>) {
            // Echo the INS byte + 9000.
            resp.push(apdu[1]).unwrap();
            resp.extend_from_slice(&SW_OK.to_be_bytes()).unwrap();
        }
    }

    #[test]
    fn unknown_aid_returns_6a82() {
        let mut app = StubApp::new(&[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]);
        let mut d: Dispatcher<4> = Dispatcher::new();
        d.register(&mut app);

        let select_unknown = [0x00u8, 0xA4, 0x04, 0x00, 0x03, 0x01, 0x02, 0x03];
        let mut resp = Vec::new();
        d.dispatch(&select_unknown, &mut resp);
        assert_eq!(resp.as_slice(), &SW_FILE_NOT_FOUND.to_be_bytes());
        // Current selection must remain untouched (None).
        assert_eq!(d.current_idx, None);
    }

    /// gpg's card-open probe: scd's `iso7816_select_file(0x3F00)` sends
    /// `00 A4 00 0C 02 3F 00` (P1=0x00 file-ID form — not a SELECT-by-AID,
    /// so the AID path above is never taken). With no app selected the C
    /// SDK answers 6A82. A 6E00 here maps to GPG_ERR_CARD in scd, fires its
    /// Yubikey-manager probe, and the management app's success turns the
    /// card into CARDTYPE_YUBIKEY (the 2026-09-16 AID anomaly).
    #[test]
    fn select_mf_with_no_app_selected_answers_6a82() {
        let mut app = StubApp::new(&[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]);
        let mut d: Dispatcher<4> = Dispatcher::new();
        d.register(&mut app);

        let mut resp = Vec::new();
        d.dispatch(&[0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00], &mut resp);
        assert_eq!(resp.as_slice(), &SW_FILE_NOT_FOUND.to_be_bytes());
        // Current selection must remain untouched (None).
        assert_eq!(d.current_idx, None);
    }

    #[test]
    fn known_aid_selects_app() {
        let mut app = StubApp::new(&[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]);
        let mut d: Dispatcher<4> = Dispatcher::new();
        d.register(&mut app);

        let select = [0x00u8, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
        let mut resp = Vec::new();
        d.dispatch(&select, &mut resp);
        assert_eq!(resp.as_slice(), &SW_OK.to_be_bytes());
        assert_eq!(d.current_idx, Some(0));
    }

    #[test]
    fn interleaved_apps_state_isolation() {
        let mut app1 = StubApp::new(&[0xD2, 0x76]);
        let mut app2 = StubApp::new(&[0xA0, 0x00]);
        let mut d: Dispatcher<4> = Dispatcher::new();
        d.register(&mut app1);
        d.register(&mut app2);

        // Select app1
        let sel1 = [0x00u8, 0xA4, 0x04, 0x00, 0x02, 0xD2, 0x76];
        let mut resp = Vec::new();
        d.dispatch(&sel1, &mut resp);
        assert_eq!(d.current_idx, Some(0));

        // Select app2: should deselect app1, select app2.
        let sel2 = [0x00u8, 0xA4, 0x04, 0x00, 0x02, 0xA0, 0x00];
        let mut resp = Vec::new();
        d.dispatch(&sel2, &mut resp);
        assert_eq!(d.current_idx, Some(1));

        // Unknown AID doesn't change selection.
        let unknown = [0x00u8, 0xA4, 0x04, 0x00, 0x02, 0xFF, 0xFF];
        let mut resp = Vec::new();
        d.dispatch(&unknown, &mut resp);
        assert_eq!(d.current_idx, Some(1)); // unchanged
        assert_eq!(resp.as_slice(), &SW_FILE_NOT_FOUND.to_be_bytes());
    }

    #[test]
    fn process_forwards_to_selected_app() {
        let mut app = StubApp::new(&[0xD2, 0x76]);
        let mut d: Dispatcher<4> = Dispatcher::new();
        d.register(&mut app);

        // SELECT first
        let sel = [0x00u8, 0xA4, 0x04, 0x00, 0x02, 0xD2, 0x76];
        let mut resp = Vec::new();
        d.dispatch(&sel, &mut resp);

        // Process: INS=0xA4 → should echo 0xA4 + 9000
        let process = [0x00u8, 0xA4, 0x00, 0x00, 0x00];
        let mut resp = Vec::new();
        d.dispatch(&process, &mut resp);
        assert_eq!(resp.as_slice(), &[0xA4, 0x90, 0x00]);
    }

    /// AIDs shared with `pico-fido2/tests/merged/test_app_switching.py` so the
    /// assertions below exercise the same real AIDs the merged suite drives.
    const AID_OPENPGP: &[u8] = &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
    const AID_FIDO2: &[u8] = &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];

    /// Select `aid` through the dispatcher, asserting a clean SW_OK result.
    fn select(d: &mut Dispatcher<4>, aid: &[u8]) {
        let mut apdu: Vec<u8, 32> = Vec::new();
        apdu.push(0x00).unwrap();
        apdu.push(0xA4).unwrap();
        apdu.push(0x04).unwrap();
        apdu.push(0x00).unwrap();
        apdu.push(aid.len() as u8).unwrap();
        apdu.extend_from_slice(aid).unwrap();
        let mut resp = Vec::new();
        d.dispatch(&apdu, &mut resp);
        assert_eq!(resp.as_slice(), &SW_OK.to_be_bytes(), "SELECT {aid:?}");
    }

    /// App whose protected command (INS 0x27) requires a verified PIN. Models
    /// ISO 7816-4 security state: host SELECT and dispatcher deselect both reset
    /// the session, so a stale PIN must not survive an app switch (US-211).
    struct SecureApp {
        aid: Vec<u8, 16>,
        pin_verified: bool,
    }

    impl SecureApp {
        fn new(aid: &[u8]) -> Self {
            let mut v = Vec::new();
            v.extend_from_slice(aid).unwrap();
            Self { aid: v, pin_verified: false }
        }
    }

    impl App for SecureApp {
        fn aid(&self) -> &[u8] {
            &self.aid
        }

        // Host SELECT resets security state (ISO 7816-4).
        fn select(&mut self, _internal: bool) -> Sw {
            self.pin_verified = false;
            SW_OK
        }

        fn deselect(&mut self) {
            self.pin_verified = false;
        }

        fn process(&mut self, apdu: &[u8], resp: &mut Vec<u8, MAX_RESPONSE>) {
            // INS 0x20 VERIFY PIN — a single successful verify (UP granted).
            if apdu.get(1) == Some(&0x20) {
                self.pin_verified = true;
            }
            // INS 0x27 PSO SIGN — protected: requires a verified PIN.
            if apdu.get(1) == Some(&0x27) {
                let sw = if self.pin_verified { SW_OK } else { SW_CONDITIONS_NOT_SATISFIED };
                resp.extend_from_slice(&sw.to_be_bytes()).unwrap();
            }
        }
    }

    // US-211 scenario 1 (test_app_switching.py): interleaved OpenPGP -> FIDO2 ->
    // re-open OpenPGP leaves no residue; a non-SELECT APDU after re-select still
    // reaches OpenPGP, never the previously-deselected FIDO2 app.
    #[test]
    fn interleaved_openpgp_then_fido_then_reselect_no_residue() {
        let mut openpgp = SecureApp::new(AID_OPENPGP);
        let mut fido = StubApp::new(AID_FIDO2);
        let mut d: Dispatcher<4> = Dispatcher::new();
        d.register(&mut openpgp);
        d.register(&mut fido);

        select(&mut d, AID_OPENPGP); // OpenPGP selects cleanly.
        select(&mut d, AID_FIDO2); // FIDO2 alive on its transport.
        select(&mut d, AID_OPENPGP); // Re-select OpenPGP.

        // After re-selecting OpenPGP, a protected command reaches it (not the
        // previously-deselected FIDO2 app): SecureApp returns bare 9000 while a
        // generic stub would echo the INS byte — so 9000 alone proves routing.
        let mut resp = Vec::new();
        d.dispatch(&[0x00, 0x20, 0x00, 0x00, 0x00], &mut resp); // VERIFY PIN
        d.dispatch(&[0x00, 0x27, 0x00, 0x86, 0x00], &mut resp); // PSO SIGN
        assert_eq!(resp.as_slice(), &SW_OK.to_be_bytes());
    }

    // US-211 scenario 2 (test_app_switching.py): an unregistered AID returns
    // 6A82 and leaves the previously selected app intact and re-selectable.
    #[test]
    fn unknown_aid_returns_6a82_and_keeps_current_app() {
        let mut openpgp = SecureApp::new(AID_OPENPGP);
        let mut d: Dispatcher<4> = Dispatcher::new();
        d.register(&mut openpgp);

        select(&mut d, AID_OPENPGP);
        // Unregistered AID -> 6A82.
        let mut resp = Vec::new();
        d.dispatch(
            &[0x00, 0xA4, 0x04, 0x00, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            &mut resp,
        );
        assert_eq!(resp.as_slice(), &SW_FILE_NOT_FOUND.to_be_bytes());
        // Current app preserved: re-select and a following protected command
        // still work (proves OpenPGP was never deselected by the unknown AID).
        select(&mut d, AID_OPENPGP);
        let mut resp = Vec::new();
        d.dispatch(&[0x00, 0x20, 0x00, 0x00, 0x00], &mut resp); // VERIFY PIN
        d.dispatch(&[0x00, 0x27, 0x00, 0x86, 0x00], &mut resp); // PSO SIGN
        assert_eq!(resp.as_slice(), &SW_OK.to_be_bytes());
    }

    // US-211 scenario 3 (test_app_switching.py) + PW re-verify semantics: after a
    // foreign transport switches the shared current app away, re-selecting the
    // original app must present a fresh security session — a stale PIN must not
    // survive, so the protected command fails until it is re-verified.
    #[test]
    fn foreign_session_resets_secure_state() {
        let mut openpgp = SecureApp::new(AID_OPENPGP);
        let mut fido = StubApp::new(AID_FIDO2);
        let mut d: Dispatcher<4> = Dispatcher::new();
        d.register(&mut openpgp);
        d.register(&mut fido);

        // CCID selects OpenPGP, verifies the PIN, signs successfully.
        select(&mut d, AID_OPENPGP);
        let mut resp = Vec::new();
        d.dispatch(&[0x00, 0x20, 0x00, 0x00, 0x00], &mut resp); // VERIFY PIN
        d.dispatch(&[0x00, 0x27, 0x00, 0x86, 0x00], &mut resp); // PSO SIGN
        assert_eq!(resp.as_slice(), &SW_OK.to_be_bytes());

        // FIDO2 runs on the other transport: current app switches to FIDO2,
        // deselecting OpenPGP and resetting its security session.
        select(&mut d, AID_FIDO2);

        // CCID re-selects OpenPGP (as gpg does on its next session) — PIN must
        // be re-verified; the protected command is refused without it.
        select(&mut d, AID_OPENPGP);
        let mut resp = Vec::new();
        d.dispatch(&[0x00, 0x27, 0x00, 0x86, 0x00], &mut resp);
        assert_eq!(resp.as_slice(), &SW_CONDITIONS_NOT_SATISFIED.to_be_bytes());

        // After re-verify, the protected command succeeds again.
        let mut resp = Vec::new();
        d.dispatch(&[0x00, 0x20, 0x00, 0x00, 0x00], &mut resp);
        d.dispatch(&[0x00, 0x27, 0x00, 0x86, 0x00], &mut resp);
        assert_eq!(resp.as_slice(), &SW_OK.to_be_bytes());
    }
}
