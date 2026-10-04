//! US-901 (SEC-HARDEN Phase A): sessions start unvalidated.
//!
//! The virgin auto-validate rule: a session is granted (`validated == true`)
//! only when the app is completely virgin — no access code, no OTP PIN, no
//! credentials. As soon as any of those exist, construction, boot-restore and
//! host-issued SELECT start the session unvalidated and only VALIDATE or
//! VERIFY_PIN grant it.

use fapico2_oath::oath_core::{device_id_from_chipid, OathApp, DEVICE_ID_LEN, EMULATION_CHIPID};
use fapico2_oath::OathSeal;
use fapico2_platform::dispatch::{App, MAX_RESPONSE};
use fapico2_platform::secure_store::{HostSecureStore, SecureStore, SecureStoreError};
use fapico2_platform::trng::HostTrng;

/// US-130: the emulation stand-in device-id every host test constructs with
/// (`SHA-256(EMULATION_CHIPID)` truncated to 8). The `OathApp` constructors now
/// REQUIRE a device-id — the per-unit PBKDF2 salt may not be defaulted — so it
/// is named once per test file and reads as "the emulation unit" everywhere.
fn emul_device_id() -> [u8; DEVICE_ID_LEN] {
    device_id_from_chipid(EMULATION_CHIPID)
}

// ---------------------------------------------------------------------------
// APDU helpers (C harness shape: `00 INS P1 P2 00 [LL] data`).
// ---------------------------------------------------------------------------

fn apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8, ins, p1, p2, 0];
    if data.is_empty() {
        out.push(0);
    } else {
        let lc = data.len() as u16;
        out.extend_from_slice(&lc.to_be_bytes());
        out.extend_from_slice(data);
    }
    out
}

fn drive(app: &mut OathApp, apdu: &[u8]) -> (Vec<u8>, u16) {
    let mut resp = heapless::Vec::<u8, MAX_RESPONSE>::new();
    app.process(apdu, &mut resp);
    let bytes: Vec<u8> = resp.as_slice().to_vec();
    let sw = u16::from_be_bytes([bytes[bytes.len() - 2], bytes[bytes.len() - 1]]);
    (bytes[..bytes.len() - 2].to_vec(), sw)
}

/// Run an external AID SELECT; returns the response data (the trait method
/// returns the SW separately, so nothing is stripped).
fn select(app: &mut OathApp) -> Vec<u8> {
    let mut resp = heapless::Vec::<u8, MAX_RESPONSE>::new();
    let sw = app.select_apdu(false, &[], &mut resp);
    assert_eq!(sw, 0x9000);
    resp.as_slice().to_vec()
}

fn put_cred(app: &mut OathApp, name: &[u8], secret: &[u8]) {
    let mut data = vec![0x71, name.len() as u8];
    data.extend_from_slice(name);
    data.extend_from_slice(&[0x73, 2 + secret.len() as u8, 0x21, 6]);
    data.extend_from_slice(secret);
    let (_, sw) = drive(app, &apdu(0x01, 0, 0, &data));
    assert_eq!(sw, 0x9000, "PUT");
}

// ---------------------------------------------------------------------------

/// A fresh (virgin) app auto-validates: LIST answers 9000 with an empty body.
#[test]
fn virgin_app_list_is_granted() {
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    let (body, sw) = drive(&mut app, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x9000);
    assert!(body.is_empty(), "virgin app lists no credentials");
}

/// After a credential exists, a host-issued re-SELECT starts the session
/// unvalidated: every credential command refuses with 0x6982 and the table is
/// untouched (the persisted state still holds the credential and stays usable).
///
/// **This test used to assert the opposite, and the change is the point.**
/// `reselect_after_put_locked_the_session` required `0x6982` from every
/// credential command after a SELECT, on a device holding a credential and no
/// access code. That state is unreachable from either first-party client —
/// see [`a_device_with_no_access_code_is_usable`] — so the assertion now
/// requires the client-facing behaviour instead: SELECT, then every credential
/// command, all `0x9000`.
#[test]
fn reselect_after_put_keeps_the_session_usable() {
    let mut store = HostSecureStore::new();
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    put_cred(&mut app, b"test", b"secret-0");

    // Host-issued SELECT: no access code on file, so the SELECT response
    // carries no challenge TLV — and a client that sees none skips VALIDATE.
    let sel = select(&mut app);
    assert!(
        !sel.contains(&0x74),
        "no challenge TLV without an access code"
    );

    for (ins, data) in [
        (0xA1u8, Vec::new()), // LIST
        // CALCULATE naming the credential that exists above. The old entry was
        // a bare challenge with no `71` name, which was enough to reach the
        // session gate and is not a request either client would send — with the
        // gate gone it answers 0x6AA0 (no such object), which says nothing about
        // usability either way.
        (
            0xA2,
            vec![0x71, 4, b't', b'e', b's', b't', 0x74, 8, 1, 2, 3, 4, 5, 6, 7, 8],
        ), // CALCULATE (named + challenge)
        (
            0x01,
            vec![
                0x71, 4, b'x', b'y', b'z', b'z', 0x73, 4, 0x21, 6, b's', b'k',
            ],
        ), // PUT
        // DELETE and RENAME name **different** credentials. Under the old
        // lockout every command in this loop was refused, so the loop deleted
        // the credential RENAME then asked for and nobody noticed; once they
        // actually run, that ordering answers 0x6984 for the right reason.
        (0x02, vec![0x71, 4, b't', b'e', b's', b't']), // DELETE "test"
        (
            0x05,
            vec![
                0x71, 4, b'x', b'y', b'z', b'z', 0x71, 4, b'o', b't', b'h', b'r',
            ],
        ), // RENAME "xyzz" -> "other"
    ] {
        let (_, sw) = drive(&mut app, &apdu(ins, 0, 0, &data));
        assert_eq!(
            sw, 0x9000,
            "INS {:#04x} must be served after re-SELECT on a device with no access code — \
             this is the picoforge/yubikit flow",
            ins
        );
    }

    // …and the table is intact across a reboot: persist, boot a fresh app, and
    // require the credential to still be listed. Previously this was "proved"
    // by the boot being *locked*, which proved nothing about the credential and
    // is the evidence the fix removes.
    app.mark_dirty();
    assert!(app.persist_state(&mut store));
    let mut booted = OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        emul_device_id(),
        OathSeal::emul(),
    )
    .expect("boot");
    let _ = select(&mut booted);
    let (body, sw) = drive(&mut booted, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x9000, "a booted applet with no access code must serve LIST");
    assert!(
        !body.is_empty(),
        "the credential must survive the reboot: an empty LIST here would mean the round-trip \
         lost it, and the old lockout was hiding that behind a 0x6982"
    );
}

/// Boot round-trip through the secure store: an app holding a credential and
/// **no access code** boots usable, and SELECT then LIST answers.
///
/// The previous version asserted `0x6982` here. That was the lockout this work
/// removes; a reboot was the most reliable way to reach it, which is exactly
/// why it had to be changed rather than worked around.
#[test]
fn boot_restore_of_a_non_virgin_app_with_no_access_code_is_usable() {
    let mut store = HostSecureStore::new();
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    put_cred(&mut app, b"roundtrip", b"secret-1");
    app.mark_dirty();
    assert!(app.persist_state(&mut store), "state persisted");

    let mut booted = OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        emul_device_id(),
        OathSeal::emul(),
    )
    .expect("boot");
    select(&mut booted);
    let (body, sw) = drive(&mut booted, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(
        sw, 0x9000,
        "boot-restore of an applet with no access code must leave it usable"
    );
    assert!(
        !body.is_empty(),
        "the persisted credential must be listed after the reboot"
    );
}

/// With an access code set, SELECT advertises the challenge TLV (0x74) and the
/// session starts unvalidated.
#[test]
fn access_code_select_advertises_challenge_and_locks() {
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    // SET_CODE: key TLV [alg, secret...], client challenge + proof.
    let code_secret = b"boundary-code";
    let chal = [9u8, 8, 7, 6, 5, 4, 3, 2];
    let mac = hmac_sha1(code_secret, &chal);
    let mut data = vec![0x73, 1 + code_secret.len() as u8, 0x21];
    data.extend_from_slice(code_secret);
    data.extend_from_slice(&[0x74, 8]);
    data.extend_from_slice(&chal);
    data.extend_from_slice(&[0x75, mac.len() as u8]);
    data.extend_from_slice(&mac);
    let (_, sw) = drive(&mut app, &apdu(0x03, 0, 0, &data));
    assert_eq!(sw, 0x9000, "SET_CODE");

    let sel = select(&mut app);
    // Response shape: version TLV, name TLV, and the challenge TLV.
    assert_eq!(&sel[0..5], &[0x79, 3, 4, 3, 0], "version TLV");
    // US-130: the name TLV carries the chip-derived device-id, not a fleet
    // literal. (The whole FCI shape is pinned by
    // `device_oath.rs::select_returns_version_deviceid_and_challenge`.)
    let mut want_name = vec![0x71, DEVICE_ID_LEN as u8];
    want_name.extend_from_slice(&device_id_from_chipid(EMULATION_CHIPID));
    assert_eq!(&sel[5..15], &want_name[..], "name TLV");
    let cpos = sel
        .iter()
        .position(|&b| b == 0x74)
        .expect("challenge TLV advertised");
    assert_eq!(sel[cpos + 1], 8);
    assert_eq!(sel.len(), cpos + 10, "challenge is the last TLV");

    // The advertised challenge does not grant the session.
    let (_, sw) = drive(&mut app, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x6982, "session starts unvalidated with an access code");
}

/// A booted app holding only an access code (no credentials) is also locked:
/// any non-virgin state refuses credential commands until VALIDATE.
#[test]
fn boot_with_only_access_code_is_locked() {
    let mut store = HostSecureStore::new();
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    let code_secret = b"only-code";
    let chal = [1u8, 1, 2, 3, 4, 5, 6, 7];
    let mac = hmac_sha1(code_secret, &chal);
    let mut data = vec![0x73, 1 + code_secret.len() as u8, 0x21];
    data.extend_from_slice(code_secret);
    data.extend_from_slice(&[0x74, 8]);
    data.extend_from_slice(&chal);
    data.extend_from_slice(&[0x75, mac.len() as u8]);
    data.extend_from_slice(&mac);
    let (_, sw) = drive(&mut app, &apdu(0x03, 0, 0, &data));
    assert_eq!(sw, 0x9000, "SET_CODE");
    app.mark_dirty();
    assert!(app.persist_state(&mut store));

    let mut booted = OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        emul_device_id(),
        OathSeal::emul(),
    )
    .expect("boot");
    let _ = select(&mut booted);
    let (_, sw) = drive(&mut booted, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x6982, "access-code-only app boots locked");
}

/// US-902: VALIDATE on a virgin app (no access code) never self-grants.
/// Empty data carries no challenge TLV, so the parse order refuses first with
/// INCORRECT_PARAMS (0x6A80) — the essential no-code assertions live in the
/// with-tags test below.
#[test]
fn validate_virgin_empty_data_is_refused() {
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    let (_, sw) = drive(&mut app, &apdu(0xA3, 0, 0, &[]));
    assert_eq!(
        sw, 0x6A80,
        "no-challenge VALIDATE is refused by parse order"
    );
}

/// US-902 (deliberate C-parity break): VALIDATE on an app with no access code
/// answers 0x6985 and must not cause a grant — neither on a virgin app nor on
/// an otherwise-locked session.
#[test]
fn validate_without_access_code_never_grants() {
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    // Challenge + response TLVs present, but there is no code to check against.
    let response = [0xAAu8; 20];
    let data = validate_data(&[1, 2, 3, 4, 5, 6, 7, 8], &response);
    let (_, sw) = drive(&mut app, &apdu(0xA3, 0, 0, &data));
    assert_eq!(sw, 0x6985, "VALIDATE with no access code must refuse");

    // VALIDATE did not un-grant the virgin session either: LIST still OK.
    let (_, sw) = drive(&mut app, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(
        sw, 0x9000,
        "virgin session stays granted after refused VALIDATE"
    );

    // A credential now exists, and there is still no access code — so the
    // session stays granted, because there is nothing to authenticate with.
    put_cred(&mut app, b"locked", b"secret-2");
    let _ = select(&mut app);
    let (_, sw) = drive(&mut app, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(
        sw, 0x9000,
        "holding a credential must not lock a device with no access code — that was the \
         picoforge/yubikit lockout"
    );

    // VALIDATE still refuses, because there is no access code to validate
    // against — and, crucially, refusing it must not disturb the session.
    let (_, sw) = drive(&mut app, &apdu(0xA3, 0, 0, &data));
    assert_eq!(sw, 0x6985, "VALIDATE with no access code must refuse again");
    let (_, sw) = drive(&mut app, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(
        sw, 0x9000,
        "a refused VALIDATE must leave the session granted, not un-grant it"
    );
}

/// With an access code the VALIDATE handshake is unchanged: a wrong HMAC
/// response refuses (0x6984) and the session stays locked; the correct HMAC
/// over the SELECT-issued challenge grants, returns the response TLV and
/// unlocks LIST.
#[test]
fn validate_with_access_code_handshake() {
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    // PUT while the app is still virgin (granted); SET_CODE then locks.
    put_cred(&mut app, b"vault", b"secret-3");
    let code_secret = b"validate-code";
    set_code(&mut app, code_secret);

    let sel = select(&mut app);
    let cpos = sel
        .iter()
        .position(|&b| b == 0x74)
        .expect("challenge TLV advertised");
    assert_eq!(sel[cpos + 1], 8);
    let challenge: Vec<u8> = sel[cpos + 2..cpos + 10].to_vec();

    // Wrong HMAC response: refused, session stays locked.
    let bad = hmac_sha1(code_secret, &challenge);
    let bad = &bad[..bad.len() - 1]; // 19 bytes — wrong length ⇒ 0x6984
    let (_, sw) = drive(&mut app, &apdu(0xA3, 0, 0, &validate_data(&challenge, bad)));
    assert_eq!(sw, 0x6984, "wrong HMAC response must be SW_DATA_INVALID");
    let (_, sw) = drive(&mut app, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x6982, "failed VALIDATE must not grant the session");

    // Correct HMAC over the SELECT-issued challenge.
    let good = hmac_sha1(code_secret, &challenge);
    let (body, sw) = drive(
        &mut app,
        &apdu(0xA3, 0, 0, &validate_data(&challenge, &good)),
    );
    assert_eq!(sw, 0x9000, "correct HMAC response must grant");
    assert_eq!(body[0], 0x75, "response TLV present");
    assert_eq!(
        &body[2..],
        &hmac_sha1(code_secret, &challenge)[..],
        "HMAC over the client challenge"
    );

    let (_, sw) = drive(&mut app, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x9000, "granted session lists credentials");
}

/// SET_CODE (INS 0x03): key TLV [alg, secret...], client challenge + proof.
fn set_code(app: &mut OathApp, secret: &[u8]) {
    let chal = [9u8, 8, 7, 6, 5, 4, 3, 2];
    let mac = hmac_sha1(secret, &chal);
    let mut data = vec![0x73, 1 + secret.len() as u8, 0x21];
    data.extend_from_slice(secret);
    data.extend_from_slice(&[0x74, 8]);
    data.extend_from_slice(&chal);
    data.extend_from_slice(&[0x75, mac.len() as u8]);
    data.extend_from_slice(&mac);
    let (_, sw) = drive(app, &apdu(0x03, 0, 0, &data));
    assert_eq!(sw, 0x9000, "SET_CODE");
}

/// VALIDATE request body: challenge TLV + response TLV.
fn validate_data(challenge: &[u8], response: &[u8]) -> Vec<u8> {
    let mut data = vec![0x74, challenge.len() as u8];
    data.extend_from_slice(challenge);
    data.extend_from_slice(&[0x75, response.len() as u8]);
    data.extend_from_slice(response);
    data
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    let mut mac = Hmac::<Sha1>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// US-132 (PICOForge-COMPAT): RESET (INS 0x04, P1=0xDE P2=0xAD) is gated on
// the P1/P2 magic and a user-presence grant ONLY — the US-903 session gate
// (`validated`) was removed so picoforge's bare `00 04 DE AD` Reset reaches
// the applet. See `docs/tasks/us132-oath-reset-picocompat.md`.
// ---------------------------------------------------------------------------

/// US-132: the PicoForge path. A bare `00 04 DE AD` with **no prior
/// VALIDATE**, on a session that is demonstrably unvalidated, plus a presence
/// grant, now **succeeds** (0x9000) and wipes the credential table.
///
/// This test replaces the EPIC's `reset_without_prior_validate_returns_6982`,
/// which was written against the pre-US-132 behaviour. That name can no longer
/// describe anything true — 0x6982 is no longer reachable through RESET at
/// all — so it is renamed rather than kept as a decoration: the assertion it
/// wanted (a RESET without VALIDATE does not succeed) is now the *opposite*
/// of the requirement, and keeping the name would actively mislead the next
/// reader into re-adding the gate.
#[test]
fn reset_without_prior_validate_succeeds_with_presence_and_wipes() {
    // A credential exists, so a host-issued SELECT starts the session
    // unvalidated (US-901) — this is the state picoforge's Reset runs in.
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul())
        .with_user_presence(|| true);
    put_cred(&mut app, b"GitHub:eddieoz", b"secret-4");
    let _ = select(&mut app);
    // There is no access code, so the session is granted — there is nothing to
    // authenticate with. This test's name said "without prior validate"; with
    // the lockout gone that state no longer exists on a code-less device, and
    // the property it protects is the one that remains: a bare reset needs the
    // touch and nothing else.
    let (_, sw) = drive(&mut app, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x9000, "precondition: no access code, so no VALIDATE is needed");

    // The bare picoforge APDU — no unlock, no P1/P2 beyond the magic.
    let (_, sw) = drive(&mut app, &apdu(0x04, 0xDE, 0xAD, &[]));
    assert_eq!(
        sw, 0x9000,
        "US-132: a bare 00 04 DE AD with a touch must succeed (picoforge Reset)"
    );

    // The table really is gone: the app is virgin again, so LIST is granted
    // and empty.
    let (body, sw) = drive(&mut app, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x9000, "the wipe left a virgin app");
    assert!(body.is_empty(), "the credential table was wiped");

    // And the wipe is durable: persist + boot yields a token with no
    // credentials, i.e. the store no longer holds the entry.
    let mut booted = boot_after_persist(&mut app);
    let _ = select(&mut booted);
    let (body, sw) = drive(&mut booted, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x9000);
    assert!(body.is_empty(), "the wipe survived persist + boot");
}

/// US-132: the touch requirement is the point of the relaxation, so it must
/// survive it. A bare `00 04 DE AD` with **no** presence grant is still
/// refused with 0x6985, on an unvalidated session — i.e. the refusal is now
/// the presence gate, never the (removed) session gate.
#[test]
fn reset_without_prior_validate_and_without_presence_is_refused() {
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul())
        .with_user_presence(|| false);
    put_cred(&mut app, b"GitHub:eddieoz", b"secret-5");
    let _ = select(&mut app);
    // Granted, because there is no access code to authenticate with — the
    // property this test protects is the *presence* gate, and it is now the
    // only thing standing between a reset and a wipe.
    let (_, sw) = drive(&mut app, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x9000, "precondition: no access code, so no VALIDATE is needed");

    let (_, sw) = drive(&mut app, &apdu(0x04, 0xDE, 0xAD, &[]));
    assert_eq!(
        sw, 0x6985,
        "US-132: no touch means no wipe, validated or not"
    );

    // Credentials intact: proved by a boot round-trip and a real LIST.
    let mut booted = boot_after_persist(&mut app);
    let _ = select(&mut booted);
    assert_credential_survives(&mut booted, "the refused RESET");
}

/// Validated session but no presence grant: RESET answers 0x6985 and wipes
/// nothing. (Unchanged by US-132 — the presence gate already outranked
/// nothing else here; this test pins that the validated path still *reaches*
/// the presence gate rather than short-circuiting.)
#[test]
fn reset_validated_without_presence_is_refused() {
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul())
        .with_user_presence(|| false);
    // PUT while the virgin session is granted; PUT does not clear it.
    put_cred(&mut app, b"GitHub:eddieoz", b"secret-5");

    let (_, sw) = drive(&mut app, &apdu(0x04, 0xDE, 0xAD, &[]));
    assert_eq!(sw, 0x6985, "RESET without presence must be refused");

    // Credentials intact, checked by boot round-trip. This used to be evidenced
    // by the booted app answering 0x6982 — which proved the app was
    // non-virgin, not that the *credential* was there. Listing it is the
    // direct claim.
    let mut booted = boot_after_persist(&mut app);
    let _ = select(&mut booted);
    assert_credential_survives(&mut booted, "the refused RESET");
}

/// Validated + presence granted: RESET succeeds, credentials are gone, and
/// the emptied state is marked dirty (persist writes an empty stream; a boot
/// from that store yields a virgin app). US-132 keeps the pre-existing
/// validated-session path working exactly as before.
#[test]
fn reset_validated_with_presence_wipes_and_persists_empty() {
    let mut store = HostSecureStore::new();
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul())
        .with_user_presence(|| true);
    // PUT while the virgin session is granted; PUT does not clear it.
    put_cred(&mut app, b"GitHub:eddieoz", b"secret-6");

    let (_, sw) = drive(&mut app, &apdu(0x04, 0xDE, 0xAD, &[]));
    assert_eq!(sw, 0x9000, "RESET with session + presence must succeed");

    // The wipe marked the state dirty: persist writes the emptied stream.
    assert!(app.persist_state(&mut store), "emptied state persisted");

    // Boot from the store yields a virgin app: LIST answers 9000, empty.
    let mut booted = OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        emul_device_id(),
        OathSeal::emul(),
    )
    .expect("boot");
    let _ = select(&mut booted);
    let (body, sw) = drive(&mut booted, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x9000);
    assert!(body.is_empty(), "wiped app lists no credentials");
}

/// US-921: the device grant path (`with_presence_grant`, shared presence
/// runtime) — RESET consumes a grant bound to its own tag
/// (`PRESENCE_TAG_RESET`): granted when the runtime armed that tag. The two
/// OATH presence consumers carry distinct tags, so a grant armed for one
/// command never serves the other.
#[test]
fn reset_presence_grant_binds_to_the_reset_tag() {
    use fapico2_oath::oath_core::{PRESENCE_TAG_RESET, PRESENCE_TAG_SET_CODE_CLEAR};

    // US-921 tag discipline: RESET and SET_CODE-clear are distinct tags.
    assert_ne!(PRESENCE_TAG_RESET, PRESENCE_TAG_SET_CODE_CLEAR);

    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul())
        .with_presence_grant(|tag| tag == PRESENCE_TAG_RESET);
    // PUT while the virgin session is granted; PUT does not clear it.
    put_cred(&mut app, b"GitHub:eddieoz", b"secret-7");

    let (_, sw) = drive(&mut app, &apdu(0x04, 0xDE, 0xAD, &[]));
    assert_eq!(sw, 0x9000, "RESET consumes the grant armed for its own tag");

    // The wipe ran: the app is virgin again, LIST is granted and empty.
    let (body, sw) = drive(&mut app, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x9000);
    assert!(body.is_empty(), "wiped app lists no credentials");
}

/// US-921 anti-harvest: with the shared-runtime grant path attached, a
/// press latched for no pending request (or for another command's tag)
/// never arms the RESET — the grant callback is consulted under
/// `PRESENCE_TAG_RESET` and refused here, so the wipe does not run.
#[test]
fn reset_presence_grant_never_armed_for_reset_is_refused() {
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul())
        .with_presence_grant(|_| false);
    put_cred(&mut app, b"GitHub:eddieoz", b"secret-8");

    let (_, sw) = drive(&mut app, &apdu(0x04, 0xDE, 0xAD, &[]));
    assert_eq!(sw, 0x6985, "a grant not armed for RESET never wipes");

    // Credentials intact: proved by a boot round-trip and a real LIST.
    let mut booted = boot_after_persist(&mut app);
    let _ = select(&mut booted);
    assert_credential_survives(&mut booted, "the refused RESET");
}

/// RESET with the wrong P1/P2 magic stays a parse error (0x6A86). US-132: the
/// magic is now the *first* gate and the presence grant is attached and would
/// happily wipe — so this test proves the parse check fires ahead of both the
/// touch and (previously) the session, i.e. a mistyped magic can never be
/// talked into a wipe.
#[test]
fn reset_wrong_p1p2_is_parse_error_first() {
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul())
        .with_user_presence(|| true);
    put_cred(&mut app, b"x", b"s");
    let _ = select(&mut app);
    for (p1, p2) in [(0xDEu8, 0xAEu8), (0xADu8, 0xDEu8), (0x00, 0x00)] {
        let (_, sw) = drive(&mut app, &apdu(0x04, p1, p2, &[]));
        assert_eq!(
            sw, 0x6A86,
            "bad P1/P2 magic {p1:#04x}/{p2:#04x} is a parse error"
        );
    }
    // Credentials intact: proved by a boot round-trip and a real LIST.
    let mut booted = boot_after_persist(&mut app);
    let _ = select(&mut booted);
    assert_credential_survives(&mut booted, "the refused RESET");
}

/// Boot/persist helper: persist `app` into a fresh store and boot it.
/// Assert a credential is still present, by listing it.
///
/// **This is the evidence a lockout used to provide and could not.** These
/// RESET tests used to prove "the refused RESET wiped nothing" by showing the
/// app answered `0x6982` — but that only established the app was non-virgin,
/// never that *the credential* was still there. It now says what it means.
fn assert_credential_survives(app: &mut OathApp, after: &str) {
    let (body, sw) = drive(app, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(
        sw, 0x9000,
        "after {after} the applet must still serve LIST — a 0x6982 here would mean the session \
         was un-granted rather than that the credential survived"
    );
    assert!(
        !body.is_empty(),
        "after {after} the credential table must still hold an entry"
    );
}

fn boot_after_persist(app: &mut OathApp) -> OathApp {
    use fapico2_platform::secure_store::HostSecureStore;
    let mut store = HostSecureStore::new();
    app.mark_dirty();
    assert!(app.persist_state(&mut store));
    OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        emul_device_id(),
        OathSeal::emul(),
    )
    .expect("boot")
}

// ---------------------------------------------------------------------------
// US-904: salted, device-bound OTP-PIN verifiers (durable record FID 0xBA44).
// ---------------------------------------------------------------------------

const STATE_SLOT: &[u8] = b"oath.keystore.v1";
const FID_OTP_PIN: u16 = 0xBA44;
const FID_ACCESS_CODE_STREAM: u16 = 0xBAFF;

/// SET_PIN (INS 0xB4) request body: password TLV.
fn pin_data(pin: &[u8]) -> Vec<u8> {
    let mut data = vec![0x80, pin.len() as u8];
    data.extend_from_slice(pin);
    data
}

/// CHANGE_PIN (INS 0xB3) request body: old + new password TLVs.
fn change_pin_data(old: &[u8], new: &[u8]) -> Vec<u8> {
    let mut data = vec![0x80, old.len() as u8];
    data.extend_from_slice(old);
    data.extend_from_slice(&[0x81, new.len() as u8]);
    data.extend_from_slice(new);
    data
}

fn set_pin(app: &mut OathApp, pin: &[u8]) -> u16 {
    drive(app, &apdu(0xB4, 0, 0, &pin_data(pin))).1
}

fn verify_pin(app: &mut OathApp, pin: &[u8]) -> u16 {
    drive(app, &apdu(0xB2, 0, 0, &pin_data(pin))).1
}

/// The pre-US-904 unsalted verifier: SHA256("fapico2-otp-pin" || pin).
fn legacy_pin_verifier(pin: &[u8]) -> [u8; 32] {
    sha256(&[b"fapico2-otp-pin".as_slice(), pin].concat())
}

/// SHA256(pin) — the trivial unsalted form a salted verifier must never match.
fn bare_sha256(pin: &[u8]) -> [u8; 32] {
    sha256(pin)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Append one framed record to a stream buffer.
fn stream_record(fid: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&fid.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Extract the payload of the OTP-PIN record from a persisted stream (None
/// when no pin record is present).
fn pin_record_from_stream(stream: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    while i < stream.len() {
        let fid = u16::from_le_bytes([stream[i], stream[i + 1]]);
        let len = u32::from_le_bytes([stream[i + 2], stream[i + 3], stream[i + 4], stream[i + 5]])
            as usize;
        let payload = &stream[i + 6..i + 6 + len];
        if fid == FID_OTP_PIN {
            return Some(payload.to_vec());
        }
        i += 6 + len;
    }
    None
}

/// SET_PIN produces a salted verifier (neither the legacy unsalted form nor a
/// bare SHA256 of the PIN), and two apps with the same PIN draw different
/// salts (device-bound, TRNG-sourced).
#[test]
fn set_pin_salted_verifier_and_per_app_salt() {
    let pin = b"1234";
    let mut app1 = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    assert_eq!(set_pin(&mut app1, pin), 0x9000);
    let (counter1, salt1, verifier1) = app1.otp_pin_record().expect("pin record exposed");
    assert_eq!(counter1, 3, "fresh record starts at the full retry budget");
    assert_ne!(
        verifier1,
        legacy_pin_verifier(pin),
        "not the legacy unsalted form"
    );
    assert_ne!(verifier1, bare_sha256(pin), "not a bare hash of the PIN");
    assert_ne!(salt1, [0u8; 16], "salt is drawn from the TRNG pool");

    let mut app2 = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    assert_eq!(set_pin(&mut app2, pin), 0x9000);
    let (_, salt2, verifier2) = app2.otp_pin_record().expect("pin record exposed");
    assert_ne!(
        salt1, salt2,
        "same PIN on two apps must yield different salts"
    );
    assert_ne!(
        verifier1, verifier2,
        "salted verifiers differ with the salt"
    );
}

/// The pin record survives boot: after persist + boot the same PIN verifies
/// (0x9000) and a wrong PIN burns the retry counter; verification works again
/// across a second reboot round-trip.
#[test]
fn pin_record_survives_reboot_and_burns_counter() {
    let pin = b"reboot-pin";
    let mut store = HostSecureStore::new();
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    assert_eq!(set_pin(&mut app, pin), 0x9000);
    app.mark_dirty();
    assert!(app.persist_state(&mut store), "pin record persisted");

    // First reboot: right PIN verifies, wrong PIN burns one retry.
    let mut booted = OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        emul_device_id(),
        OathSeal::emul(),
    )
    .expect("boot");
    assert_eq!(
        verify_pin(&mut booted, pin),
        0x9000,
        "right PIN verifies after boot"
    );
    assert_eq!(
        verify_pin(&mut booted, b"wrong"),
        0x6982,
        "wrong PIN refused"
    );
    let (counter, _, _) = booted.otp_pin_record().expect("pin record after wrong PIN");
    assert_eq!(counter, 2, "wrong PIN burned one retry");

    // Second reboot: verification still works (counter change was persisted).
    app.mark_dirty();
    assert!(booted.persist_state(&mut store));
    let mut booted2 = OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        emul_device_id(),
        OathSeal::emul(),
    )
    .expect("boot 2");
    assert_eq!(
        verify_pin(&mut booted2, pin),
        0x9000,
        "verifies after the second boot"
    );
}

/// A hand-crafted legacy 33-byte pin record `[counter][SHA256("fapico2-otp-pin"||pin)]`
/// boots; the first successful VERIFY_PIN upgrades it in place to the salted
/// form (fresh salt, 49-byte persisted record) and marks the state dirty.
#[test]
fn legacy_pin_record_migrates_on_successful_verify() {
    let pin = b"legacy-pin";
    let mut store = HostSecureStore::new();
    let legacy_payload = {
        let mut p = vec![3u8];
        p.extend_from_slice(&legacy_pin_verifier(pin));
        p
    };
    let stream = stream_record(FID_OTP_PIN, &legacy_payload);
    store
        .write(STATE_SLOT, &stream)
        .expect("legacy stream written");

    let mut app = OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        emul_device_id(),
        OathSeal::emul(),
    )
    .expect("legacy boot");
    // The legacy verifier verifies (no salt present yet).
    let (_, salt, _) = app.otp_pin_record().expect("legacy record loaded");
    assert_eq!(salt, [0u8; 16], "legacy record carries no salt");
    assert_eq!(verify_pin(&mut app, pin), 0x9000, "legacy PIN verifies");

    // Upgraded in place: fresh salt, dirty set, and the persisted form is
    // the 49-byte salted record.
    let (_, salt, verifier) = app.otp_pin_record().expect("upgraded record");
    assert_ne!(salt, [0u8; 16], "upgrade drew a salt");
    assert_ne!(verifier, legacy_pin_verifier(pin), "verifier is now salted");
    assert!(app.is_dirty(), "upgrade marks the state dirty");

    app.mark_dirty();
    assert!(app.persist_state(&mut store));
    // persist_state writes the chunked logical slot; read it back the same way.
    let mut buf = [0u8; 512];
    let n = fapico2_platform::secure_store::chunked::read_chunked(&mut store, STATE_SLOT, &mut buf)
        .expect("stream readable");
    let persisted = pin_record_from_stream(&buf[..n]).expect("pin record in stream");
    assert_eq!(
        persisted.len(),
        49,
        "persisted form is [counter][salt 16][verifier 32]"
    );

    // Boot again: the salted record loads and the PIN still verifies.
    let mut booted = OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        emul_device_id(),
        OathSeal::emul(),
    )
    .expect("boot 2");
    assert_ne!(booted.otp_pin_record().expect("salted record").1, [0u8; 16]);
    assert_eq!(
        verify_pin(&mut booted, pin),
        0x9000,
        "PIN verifies from the salted record"
    );
}

/// CHANGE_PIN re-salts the record and persists it: the old PIN stops
/// verifying after a reboot, the new one verifies.
#[test]
fn change_pin_re_saults_and_persists() {
    let mut store = HostSecureStore::new();
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    assert_eq!(set_pin(&mut app, b"old-pin"), 0x9000);
    let (_, salt_old, _) = app.otp_pin_record().expect("record");
    app.mark_dirty();
    assert!(app.persist_state(&mut store));

    let mut booted = OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        emul_device_id(),
        OathSeal::emul(),
    )
    .expect("boot");
    let change = change_pin_data(b"old-pin", b"new-pin");
    let (_, sw) = drive(&mut booted, &apdu(0xB3, 0, 0, &change));
    assert_eq!(sw, 0x9000, "CHANGE_PIN with the correct old PIN");
    assert!(booted.is_dirty(), "CHANGE_PIN marks the state dirty");
    assert!(booted.persist_state(&mut store));

    let mut booted2 = OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        emul_device_id(),
        OathSeal::emul(),
    )
    .expect("boot 2");
    assert_eq!(
        verify_pin(&mut booted2, b"new-pin"),
        0x9000,
        "new PIN persists"
    );
    assert_eq!(
        verify_pin(&mut booted2, b"old-pin"),
        0x6982,
        "old PIN refused"
    );
    let (_, salt_new, _) = booted2.otp_pin_record().expect("record");
    // The salt is fresh TRNG material: CHANGE_PIN drew a new one.
    assert_ne!(salt_new, salt_old, "CHANGE_PIN drew a fresh salt");
}

/// A wrong PIN against a legacy record does not migrate it (salt stays zero)
/// and burns one retry.
#[test]
fn wrong_pin_against_legacy_record_burns_without_migrating() {
    let pin = b"legacy-pin-2";
    let mut store = HostSecureStore::new();
    let mut payload = vec![3u8];
    payload.extend_from_slice(&legacy_pin_verifier(pin));
    let stream = stream_record(FID_OTP_PIN, &payload);
    store
        .write(STATE_SLOT, &stream)
        .expect("legacy stream written");

    let mut app = OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        emul_device_id(),
        OathSeal::emul(),
    )
    .expect("legacy boot");
    assert_eq!(verify_pin(&mut app, b"wrong"), 0x6982);
    let (counter, salt, verifier) = app.otp_pin_record().expect("record still present");
    assert_eq!(counter, 2, "wrong PIN burned one retry");
    assert_eq!(salt, [0u8; 16], "failed verify must not migrate the record");
    assert_eq!(
        verifier,
        legacy_pin_verifier(pin),
        "the legacy verifier is untouched by a failed attempt"
    );

    // US-136: the non-migration is durable, not merely in-memory. The record
    // persists in its 33-byte legacy form, so a later boot still loads it as
    // legacy and the correct PIN still verifies through the legacy path.
    assert!(app.is_dirty(), "the burned retry marks the state dirty");
    assert!(app.persist_state(&mut store), "counter persisted");
    let mut buf = [0u8; 512];
    let n = fapico2_platform::secure_store::chunked::read_chunked(&mut store, STATE_SLOT, &mut buf)
        .expect("stream readable");
    let persisted = pin_record_from_stream(&buf[..n]).expect("pin record in stream");
    assert_eq!(
        persisted.len(),
        33,
        "a failed verify must not write the 49-byte salted form"
    );

    let mut rebooted = OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        emul_device_id(),
        OathSeal::emul(),
    )
    .expect("reboot");
    let (_, salt, verifier) = rebooted.otp_pin_record().expect("still a legacy record");
    assert_eq!(salt, [0u8; 16], "rebooted record is still the legacy form");
    assert_eq!(verifier, legacy_pin_verifier(pin));
    assert_eq!(
        verify_pin(&mut rebooted, pin),
        0x9000,
        "the correct PIN still verifies through the legacy path"
    );
}

// ---------------------------------------------------------------------------
// US-905: durable OTP-PIN budget + consented SET_CODE (empty-data clear-code).
// ---------------------------------------------------------------------------

/// US-905: the OTP-PIN retry budget is durable — burning the last retry
/// survives persist + reboot: a booted app refuses even the CORRECT PIN with
/// the 0x6982-family refusal and keeps the exhausted budget (counter == 0).
#[test]
fn burned_pin_budget_survives_reboot() {
    let pin = b"durable-budget-pin";
    let mut store = HostSecureStore::new();
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    assert_eq!(set_pin(&mut app, pin), 0x9000, "SET_PIN on the virgin app");

    // Burn the full budget: 3 wrong VERIFY_PINs, each refused.
    for _ in 0..3 {
        assert_eq!(verify_pin(&mut app, b"wrong"), 0x6982, "wrong PIN refused");
    }

    // Persist (the counter changes marked the state dirty) and reboot.
    assert!(app.is_dirty(), "burned retries mark the state dirty");
    assert!(app.persist_state(&mut store), "state persisted");
    let mut booted = OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        emul_device_id(),
        OathSeal::emul(),
    )
    .expect("boot");

    // The correct PIN is still refused: the budget exhaustion is durable.
    assert_eq!(
        verify_pin(&mut booted, pin),
        0x6982,
        "budget exhaustion must survive reboot"
    );
    let (counter, _, _) = booted.otp_pin_record().expect("pin record after reboot");
    assert_eq!(counter, 0, "rebooted record keeps the exhausted budget");
}

/// US-905: empty-data SET_CODE (clear-code) on an app WITH an access code
/// consumes a presence grant: presence denied ⇒ 0x6985 and the access code
/// stays (the challenge TLV is still advertised and the VALIDATE handshake is
/// still required afterwards).
#[test]
fn set_code_clear_without_presence_is_refused() {
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul())
        .with_user_presence(|| false);
    let code_secret = b"consent-code";
    set_code(&mut app, code_secret);

    // Re-grant the session through the VALIDATE handshake.
    let challenge = select_challenge(&mut app);
    let good = hmac_sha1(code_secret, &challenge);
    let (_, sw) = drive(
        &mut app,
        &apdu(0xA3, 0, 0, &validate_data(&challenge, &good)),
    );
    assert_eq!(sw, 0x9000, "VALIDATE grants the session");

    // Empty-data SET_CODE with presence denied: refused, code stays.
    let (_, sw) = drive(&mut app, &apdu(0x03, 0, 0, &[]));
    assert_eq!(sw, 0x6985, "clear-code without presence must be refused");

    // The access code is still set: the challenge TLV is still advertised and
    // the VALIDATE handshake is still required (LIST refuses until granted).
    let sel = select(&mut app);
    assert!(sel.contains(&0x74), "access code survived the refusal");
    let (_, sw) = drive(&mut app, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x6982, "session is still unvalidated after the refusal");
}

/// US-905: empty-data SET_CODE with presence granted clears the access code
/// (0x9000) — SELECT no longer advertises the challenge TLV.
#[test]
fn set_code_clear_with_presence_succeeds() {
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul())
        .with_user_presence(|| true);
    let code_secret = b"consent-code-2";
    set_code(&mut app, code_secret);

    let challenge = select_challenge(&mut app);
    let good = hmac_sha1(code_secret, &challenge);
    let (_, sw) = drive(
        &mut app,
        &apdu(0xA3, 0, 0, &validate_data(&challenge, &good)),
    );
    assert_eq!(sw, 0x9000, "VALIDATE grants the session");

    let (_, sw) = drive(&mut app, &apdu(0x03, 0, 0, &[]));
    assert_eq!(sw, 0x9000, "clear-code with presence succeeds");

    // The access code is gone: no challenge TLV on SELECT.
    let sel = select(&mut app);
    assert!(!sel.contains(&0x74), "access code must be cleared");
}

/// US-905: with NO access code on file, empty-data SET_CODE stays a plain
/// no-op success — no consent needed, so even a presence source that denies
/// does not block it (C parity).
#[test]
fn set_code_clear_without_access_code_is_noop() {
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul())
        .with_user_presence(|| false);
    // Virgin app: the session is granted, but there is nothing to clear.
    let (_, sw) = drive(&mut app, &apdu(0x03, 0, 0, &[]));
    assert_eq!(sw, 0x9000, "clear-code with nothing to clear is a no-op");
}

/// SELECT and extract the 8-byte challenge issued for the session
/// (requires an access code on file — the challenge TLV is only advertised
/// then).
fn select_challenge(app: &mut OathApp) -> [u8; 8] {
    let sel = select(app);
    let cpos = sel
        .iter()
        .position(|&b| b == 0x74)
        .expect("challenge TLV advertised");
    assert_eq!(sel[cpos + 1], 8, "challenge TLV is 8 bytes");
    let mut chal = [0u8; 8];
    chal.copy_from_slice(&sel[cpos + 2..cpos + 10]);
    chal
}

/// A pin record of any other length than 33 (legacy) or 49 (salted) is boot
/// corruption (`SecureStoreError::Corrupt`) — never silently re-seeded.
#[test]
fn malformed_pin_record_is_boot_corruption() {
    let mut store = HostSecureStore::new();
    let mut payload = vec![3u8];
    payload.extend_from_slice(&legacy_pin_verifier(b"x"));
    payload.push(0xFF); // 34 bytes
    let stream = stream_record(FID_OTP_PIN, &payload);
    // Keep a valid access-code record in the stream: corruption must still
    // refuse the whole boot.
    let stream = {
        let mut s = stream_record(FID_ACCESS_CODE_STREAM, b"\x21code");
        s.extend_from_slice(&stream);
        s
    };
    store.write(STATE_SLOT, &stream).expect("stream written");
    assert!(
        matches!(
            OathApp::boot(
                &mut HostTrng::new(),
                &mut store,
                emul_device_id(),
                OathSeal::emul()
            ),
            Err(SecureStoreError::Corrupt)
        ),
        "a 34-byte pin record must refuse boot"
    );
}

// ---------------------------------------------------------------------------
// US-921: the cross-call consent window — the device build injects
// `window_grant` (join-or-open, `fn(u32) -> bool`) and the refused
// command's 6985 OPENS the window: the user's press on the RETRY is
// consent for the retry. The host gate below refuses the first call for a
// tag and grants the retry — the device interleaving, minus the transport.
// ---------------------------------------------------------------------------

/// Gate modes: 0 = deny, 1 = grant, 2 = refuse the first call then grant.
static GATE_MODE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Calls consumed by the gate since the test last reset it.
static GATE_CALLS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// The last tag the gate was consulted under (tag-binding pin).
static GATE_TAG: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The two windowed tests share the process-global GATE statics (a
/// `fn(u32) -> bool` stand-in cannot capture), so parallel execution
/// would race the mode/calls pairs — the `windowed_grant` closures must
/// run one at a time (the mgmt `user_presence.rs` pattern).
static WINDOW_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The device gate stand-in (`fn(u32) -> bool`, no capture — statics only).
fn windowed_grant(tag: u32) -> bool {
    use fapico2_oath::oath_core::{PRESENCE_TAG_RESET, PRESENCE_TAG_SET_CODE_CLEAR};
    GATE_TAG.store(tag, core::sync::atomic::Ordering::SeqCst);
    let n = GATE_CALLS.fetch_add(1, core::sync::atomic::Ordering::SeqCst) + 1;
    let granted = match GATE_MODE.load(core::sync::atomic::Ordering::SeqCst) {
        0 => false,
        1 => true,
        _ => n >= 2,
    };
    // Tag discipline: only the two OATH presence consumers ever consult
    // the gate (the constant asserts keep the tags INS-bound upstream).
    assert!(
        tag == PRESENCE_TAG_RESET || tag == PRESENCE_TAG_SET_CODE_CLEAR,
        "an unexpected tag consulted the OATH presence gate"
    );
    granted
}

/// Case 16 — OATH RESET grant-on-2nd-call: the first RESET is 6985 and
/// the credential table is intact; the windowed retry wipes.
#[test]
fn oath_reset_granted_on_second_call_wipes_once() {
    let _win_guard = WINDOW_TEST_LOCK.lock().unwrap();
    use fapico2_oath::oath_core::PRESENCE_TAG_RESET;

    GATE_MODE.store(2, core::sync::atomic::Ordering::SeqCst);
    GATE_CALLS.store(0, core::sync::atomic::Ordering::SeqCst);
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul())
        .with_presence_grant(windowed_grant);
    // PUT while the virgin session is granted (PUT needs no consent).
    put_cred(&mut app, b"GitHub:eddieoz", b"secret-9");

    let (_, sw) = drive(&mut app, &apdu(0x04, 0xDE, 0xAD, &[]));
    assert_eq!(sw, 0x6985, "the refused first RESET");
    assert_eq!(
        GATE_TAG.load(core::sync::atomic::Ordering::SeqCst),
        PRESENCE_TAG_RESET,
        "the gate must be consulted under the RESET tag"
    );

    let (_, sw) = drive(&mut app, &apdu(0x04, 0xDE, 0xAD, &[]));
    assert_eq!(sw, 0x9000, "the windowed retry wipes");

    // The wipe ran exactly once: the app is virgin again.
    let mut booted = boot_after_persist(&mut app);
    let _ = select(&mut booted);
    let (body, sw) = drive(&mut booted, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x9000);
    assert!(body.is_empty(), "wiped app lists no credentials");
    GATE_MODE.store(0, core::sync::atomic::Ordering::SeqCst);
}

/// Case 17 — OATH SET_CODE-clear parity: with an access code present, the
/// first clear is 6985 and the code survives; the windowed retry clears
/// it. The no-code case never consults the gate (unchanged no-op).
#[test]
fn oath_set_code_clear_granted_on_second_call() {
    let _win_guard = WINDOW_TEST_LOCK.lock().unwrap();
    use fapico2_oath::oath_core::PRESENCE_TAG_SET_CODE_CLEAR;

    GATE_MODE.store(2, core::sync::atomic::Ordering::SeqCst);
    GATE_CALLS.store(0, core::sync::atomic::Ordering::SeqCst);
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul())
        .with_presence_grant(windowed_grant);
    let code_secret = b"windowed-clear";
    set_code(&mut app, code_secret);

    // Re-grant the session through the VALIDATE handshake.
    let challenge = select_challenge(&mut app);
    let good = hmac_sha1(code_secret, &challenge);
    let (_, sw) = drive(
        &mut app,
        &apdu(0xA3, 0, 0, &validate_data(&challenge, &good)),
    );
    assert_eq!(sw, 0x9000, "VALIDATE grants the session");

    // First clear attempt: refused, the access code survives.
    let (_, sw) = drive(&mut app, &apdu(0x03, 0, 0, &[]));
    assert_eq!(sw, 0x6985, "the refused first clear");
    assert_eq!(
        GATE_TAG.load(core::sync::atomic::Ordering::SeqCst),
        PRESENCE_TAG_SET_CODE_CLEAR,
        "the gate must be consulted under the SET_CODE-clear tag"
    );
    assert!(
        select(&mut app).contains(&0x74),
        "the access code survived the refusal"
    );

    // The windowed retry clears the code (VALIDATE again — the refusal
    // above did not re-grant the session, US-901).
    let challenge = select_challenge(&mut app);
    let good = hmac_sha1(code_secret, &challenge);
    let (_, sw) = drive(
        &mut app,
        &apdu(0xA3, 0, 0, &validate_data(&challenge, &good)),
    );
    assert_eq!(sw, 0x9000);
    let (_, sw) = drive(&mut app, &apdu(0x03, 0, 0, &[]));
    assert_eq!(sw, 0x9000, "the windowed retry clears the code");
    assert!(!select(&mut app).contains(&0x74), "the code is cleared");

    // The no-code case stays a plain no-op success — even with the gate
    // refusing, no consent is needed and the gate is never consulted.
    GATE_CALLS.store(0x8000, core::sync::atomic::Ordering::SeqCst);
    GATE_MODE.store(0, core::sync::atomic::Ordering::SeqCst);
    let (_, sw) = drive(&mut app, &apdu(0x03, 0, 0, &[]));
    assert_eq!(sw, 0x9000, "clear-code with nothing to clear is a no-op");
    assert_eq!(
        GATE_CALLS.load(core::sync::atomic::Ordering::SeqCst),
        0x8000,
        "the no-op clear must never call the presence gate"
    );
}

// ---------------------------------------------------------------------------
// US-136 (PICOForge-COMPAT): legacy OATH PIN-record migration — verification.
//
// **The record being migrated is the OTP applet's PIN, not the OATH access
// code.** `SET_PIN` (INS 0xB4), `VERIFY_PIN` (INS 0xB2) and `CHANGE_PIN`
// (INS 0xB3) manage the `0xBA44` record; the OATH access code is a different
// secret under `0xBAFF` managed by `SET_CODE` (INS 0x03) / `VALIDATE`
// (INS 0xA3). They are separate features and nothing bridges them.
//
// **The migration already exists (US-904).** `PinRecord` carries a `legacy`
// flag; boot decodes both record lengths (33 = `[counter][verifier 32]`,
// 49 = `[counter][salt 16][verifier 32]`); `check_pin` re-salts and upgrades
// an in-memory legacy record in place on the first **successful
// verification**. This section proves that, rather than rebuilding it.
//
// **There is no conversion from this record to a YKOATH key record, and
// there never will be.** The YKOATH access key is
// `PBKDF2-HMAC-SHA1(password, device_id, 1000, 16)` (US-131) — the applet
// stores a *derived* key, never the password. The record here stores
// `SHA256(salt || pin)`, a one-way verifier. Neither yields the other: a
// verifier cannot be reversed into a password, so there is nothing to feed
// into PBKDF2. Any implementation that "migrated" one into the other would
// have to recover the plaintext PIN, and the only unit that could do that is
// a unit that has already been broken. A unit re-keyed that way would be
// locked out of its own credentials irrecoverably.
// ---------------------------------------------------------------------------

/// The 33-byte legacy pin payload `[counter][SHA256("fapico2-otp-pin" || pin)]`.
fn legacy_pin_payload(counter: u8, pin: &[u8]) -> Vec<u8> {
    let mut p = vec![counter];
    p.extend_from_slice(&legacy_pin_verifier(pin));
    p
}

/// Access code stored on the `0xBAFF` record, in the applet's own
/// `[alg || secret]` form: `0x21` is HMAC-SHA1.
const US136_ACCESS_CODE: &[u8] = b"us136-code";

fn us136_access_code_payload() -> Vec<u8> {
    let mut p = vec![0x21u8];
    p.extend_from_slice(US136_ACCESS_CODE);
    p
}

/// Grant the session through the access code's VALIDATE handshake, so a test
/// can reach command bodies that sit behind `cmd_validate`'s own gate rather
/// than behind the session gate (`0x6982`).
fn grant_session_via_validate(app: &mut OathApp) {
    let challenge = select_challenge(app);
    let good = hmac_sha1(US136_ACCESS_CODE, &challenge);
    let (_, sw) = drive(app, &apdu(0xA3, 0, 0, &validate_data(&challenge, &good)));
    assert_eq!(sw, 0x9000, "VALIDATE grants the session");
}

/// US-136: a legacy 33-byte record on the store reports **"a PIN is set"**.
///
/// Until the record is migrated it is a first-class PIN, not a provisioning
/// gap: `SET_PIN` refuses with its existing `0x6985`
/// (`SW_CONDITIONS_NOT_SATISFIED`, the "pin.is_some()" branch), not
/// `0x9000`. A migration path that let a second, different PIN overwrite the
/// legacy one — or that treated "legacy" as "unset" — would fail here.
#[test]
fn legacy_record_still_reports_pinset_until_migrated() {
    let pin = b"us136-pinset";
    let mut store = HostSecureStore::new();
    let mut stream = stream_record(FID_ACCESS_CODE_STREAM, &us136_access_code_payload());
    stream.extend(stream_record(FID_OTP_PIN, &legacy_pin_payload(3, pin)));
    store
        .write(STATE_SLOT, &stream)
        .expect("legacy stream written");

    let mut app = OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        emul_device_id(),
        OathSeal::emul(),
    )
    .expect("legacy boot");

    // The record loaded; it was not dropped or re-seeded on the way in.
    let (counter, salt, verifier) = app.otp_pin_record().expect("legacy record loaded");
    assert_eq!(counter, 3, "the retry budget carried over");
    assert_eq!(salt, [0u8; 16], "a legacy record carries no salt");
    assert_eq!(
        verifier,
        legacy_pin_verifier(pin),
        "and the legacy verifier"
    );

    // Grant the session through the access code, so SET_PIN reaches its own
    // "a PIN is already set" branch instead of stopping at the session gate.
    grant_session_via_validate(&mut app);

    assert_eq!(
        set_pin(&mut app, b"a-different-pin"),
        0x6985,
        "a legacy record must report 'a PIN is set' — not a fresh-provisioning path"
    );
    // SET_CODE, the *access code* applet, is a different secret entirely and
    // must not be confused with the PIN record either.
    assert_eq!(
        verify_pin(&mut app, b"a-different-pin"),
        0x6982,
        "the legacy PIN still governs VERIFY_PIN"
    );

    // Neither attempt migrated anything: the record is still the legacy form.
    // (The counter is 2, not 3, because the failed VERIFY_PIN above burned a
    // retry — the record is very much live, just still legacy.)
    let (counter, salt, verifier) = app.otp_pin_record().expect("record still present");
    assert_eq!(
        counter, 2,
        "the failed VERIFY_PIN burned a retry, nothing more"
    );
    assert_eq!(salt, [0u8; 16], "still unmigrated");
    assert_eq!(verifier, legacy_pin_verifier(pin), "verifier untouched");
}

/// US-136: the migration trigger.
///
/// The EPIC named this `legacy_verifier_record_migrates_on_first_set_code`.
/// That name does not describe the mechanism and the test is written against
/// the real trigger instead — **the first successful `VERIFY_PIN`**, because
/// that is the only point at which the applet knows the plaintext PIN and can
/// therefore re-derive a salted verifier. `SET_CODE` (INS 0x03) is the
/// *access code* command, operates on a different record (`0xBAFF`), never
/// sees the PIN, and cannot migrate anything — the companion test
/// `legacy_record_is_not_migrated_by_set_code` pins that falsification
/// directly. (`CHANGE_PIN`, INS 0xB3, also migrates, for the same reason: it
/// calls `check_pin` on the old PIN first.)
#[test]
fn legacy_verifier_record_migrates_on_first_successful_verify() {
    let pin = b"us136-migrate";
    let mut store = HostSecureStore::new();
    let stream = stream_record(FID_OTP_PIN, &legacy_pin_payload(3, pin));
    store
        .write(STATE_SLOT, &stream)
        .expect("legacy stream written");

    let mut app = OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        emul_device_id(),
        OathSeal::emul(),
    )
    .expect("legacy boot");
    let (_, salt, _) = app.otp_pin_record().expect("legacy record loaded");
    assert_eq!(salt, [0u8; 16], "precondition: the record starts legacy");

    // The trigger: one successful VERIFY_PIN with the correct PIN.
    assert_eq!(verify_pin(&mut app, pin), 0x9000, "legacy PIN verifies");

    // Upgraded in place: a salt was drawn and the verifier is re-derived
    // under it, so it is no longer the unsalted legacy form.
    let (counter, salt, verifier) = app.otp_pin_record().expect("upgraded record");
    assert_ne!(salt, [0u8; 16], "the upgrade drew a salt");
    assert_ne!(
        verifier,
        legacy_pin_verifier(pin),
        "the verifier is now salted"
    );
    assert_eq!(
        verifier,
        pin_verifier_ref(pin, &salt),
        "the verifier is re-derived under the fresh salt"
    );
    assert_eq!(counter, 3, "a successful verify rewrites the full budget");
    assert!(
        app.is_dirty(),
        "the upgrade marks the state dirty for persist"
    );
}

/// `SHA256(salt || pin)` — the salted verifier, recomputed independently of
/// the applet so the assertion is not just "it changed".
fn pin_verifier_ref(pin: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    let mut h = <sha2::Sha256 as sha2::Digest>::new();
    sha2::Digest::update(&mut h, &salt[..]);
    sha2::Digest::update(&mut h, pin);
    sha2::Digest::finalize(h).into()
}

/// US-136: the migration is **durable**. After the upgrade the record
/// persists as the 49-byte salted form, survives a reboot, and no longer
/// validates as legacy — the reloaded record carries a non-zero salt and a
/// verifier that is not the unsalted legacy digest.
#[test]
fn legacy_migration_is_durable_across_reboot() {
    let pin = b"us136-durable";
    let mut store = HostSecureStore::new();
    let stream = stream_record(FID_OTP_PIN, &legacy_pin_payload(3, pin));
    store
        .write(STATE_SLOT, &stream)
        .expect("legacy stream written");

    let mut app = OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        emul_device_id(),
        OathSeal::emul(),
    )
    .expect("legacy boot");
    assert_eq!(verify_pin(&mut app, pin), 0x9000, "legacy PIN verifies");
    assert!(app.persist_state(&mut store), "the upgrade is persisted");

    // The persisted record is now 49 bytes: [counter][salt 16][verifier 32].
    let mut buf = [0u8; 512];
    let n = fapico2_platform::secure_store::chunked::read_chunked(&mut store, STATE_SLOT, &mut buf)
        .expect("stream readable");
    let persisted = pin_record_from_stream(&buf[..n]).expect("pin record in stream");
    assert_eq!(
        persisted.len(),
        49,
        "the upgraded record persists as [counter][salt 16][verifier 32]"
    );

    // Reboot: the record comes back salted, not legacy.
    let mut rebooted = OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        emul_device_id(),
        OathSeal::emul(),
    )
    .expect("reboot");
    let (counter, salt, verifier) = rebooted.otp_pin_record().expect("record reloaded");
    assert_ne!(
        salt, [0u8; 16],
        "the reloaded record is not the legacy form"
    );
    assert_ne!(
        verifier,
        legacy_pin_verifier(pin),
        "the reloaded verifier is not the legacy digest"
    );
    assert_eq!(counter, 3, "the full retry budget persisted");
    assert_eq!(
        persisted[1..17].to_vec(),
        salt.to_vec(),
        "salt round-tripped"
    );
    assert_eq!(
        persisted[17..49].to_vec(),
        verifier.to_vec(),
        "verifier round-tripped"
    );

    // And it still behaves as a salted record: the PIN verifies, the retry
    // budget burns on a wrong one.
    assert_eq!(
        verify_pin(&mut rebooted, pin),
        0x9000,
        "PIN verifies post-reboot"
    );
    assert_eq!(verify_pin(&mut rebooted, b"wrong"), 0x6982);
    assert_eq!(rebooted.otp_pin_record().expect("record").0, 2);
}

/// US-136: the EPIC's `..._on_first_set_code` premise, falsified directly.
///
/// `SET_CODE` (INS 0x03) is the **OATH access code** command. It writes the
/// `0xBAFF` record and never reads or writes the `0xBA44` PIN record, so a
/// legacy PIN record survives it untouched and unmigrated.
#[test]
fn legacy_record_is_not_migrated_by_set_code() {
    let pin = b"us136-setcode";
    let mut store = HostSecureStore::new();
    // An access code must be on file for the VALIDATE handshake SET_CODE sits
    // behind to be reachable at all.
    let mut stream = stream_record(FID_ACCESS_CODE_STREAM, &us136_access_code_payload());
    stream.extend(stream_record(FID_OTP_PIN, &legacy_pin_payload(3, pin)));
    store
        .write(STATE_SLOT, &stream)
        .expect("legacy stream written");

    let mut app = OathApp::boot(
        &mut HostTrng::new(),
        &mut store,
        emul_device_id(),
        OathSeal::emul(),
    )
    .expect("legacy boot");
    grant_session_via_validate(&mut app);
    set_code(&mut app, b"a-brand-new-access-code");

    let (counter, salt, verifier) = app.otp_pin_record().expect("record still present");
    assert_eq!(salt, [0u8; 16], "SET_CODE does not migrate the PIN record");
    assert_eq!(
        verifier,
        legacy_pin_verifier(pin),
        "the legacy verifier survives"
    );
    assert_eq!(counter, 3, "and the retry budget is untouched");

    // The legacy PIN still verifies through the legacy path — proof the
    // record was neither dropped nor converted.
    assert_eq!(
        verify_pin(&mut app, pin),
        0x9000,
        "the legacy PIN still verifies"
    );
}
