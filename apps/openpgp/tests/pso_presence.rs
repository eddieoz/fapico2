//! US-914 TDD: touch-to-sign presence gating on the OpenPGP device path.
//!
//! The device build consumes a presence grant bound to the operation at
//! the opcard seam (`command::pso::confirm_user_presence`) — only after
//! authorization (factory gate, PW1 session, key resolution) succeeded
//! and immediately before key material is used, so consent still precedes
//! the side effect but the touch prompt is never offered for commands
//! that cannot succeed (US-914 review: a hostile host must not hold the
//! shared transport's serve task with the 10 s touch window). Host and
//! emulation auto-ack by default so the existing suites stay green.
//! These tests pin the app-layer gate over the real opcard stack (host
//! backend):
//!
//! * a fail-closed source refuses every gated op with `6982` and an
//!   **empty** body — the signature was never framed and nothing is
//!   staged (durable rule: consent precedes side effect);
//! * the grant is bound to the pending operation's tag — a PSO:SIGN-only
//!   grant serves PSO:SIGN but not INT-AUTH / PSO:DECIPHER;
//! * non-gated commands (GET DATA) are served regardless;
//! * a command that cannot succeed (factory gate, missing PW1 session)
//!   is refused WITHOUT consulting the presence source;
//! * the `None` default (no injected source) auto-acks — the pre-gate
//!   host behavior the existing suites rely on (`device_pso.rs` proves
//!   the full matrix end-to-end on the same seam).
//!
//! US-912 interplay: the tests personalize PW1/PW3 first so the
//! factory-default gate (6985) cannot mask the presence refusal (6982).

use ed25519_dalek::Verifier;
use fapico2_openpgp::{
    OpenPgpApp, OPENPGP_AID, PRESENCE_TAG_PSO_DECIPHER, PRESENCE_TAG_PSO_SIGN,
    PRESENCE_TAG_INT_AUTH,
};
use fapico2_platform::dispatch::{Dispatcher, MAX_RESPONSE};
use fapico2_platform::trusted_backend::host::with_host_backend;
use hex_literal::hex;
use sha2::{Digest, Sha256};

fn command(
    dispatcher: &mut Dispatcher<'_, 1>,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
    sw: u16,
) -> Vec<u8> {
    let mut apdu = vec![0, ins, p1, p2];
    if !data.is_empty() {
        apdu.push(u8::try_from(data.len()).unwrap());
        apdu.extend_from_slice(data);
    }
    apdu.push(0);
    let mut response = heapless::Vec::<u8, MAX_RESPONSE>::new();
    dispatcher.dispatch(&apdu, &mut response);
    assert!(response.len() >= 2);
    let body_len = response.len() - 2;
    assert_eq!(
        u16::from_be_bytes(response[body_len..].try_into().unwrap()),
        sw,
        "INS={ins:02x} P1={p1:02x} P2={p2:02x}"
    );
    response[..body_len].to_vec()
}

const ED: &[u8] = &hex!("162b06010401da470f01");
const CV: &[u8] = &hex!("122b060104019755010501");

const ED_SEED: &[u8; 32] = &hex!("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
const CV_SEED: &[u8; 32] = &hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");

fn import(dispatcher: &mut Dispatcher<'_, 1>, slot: u8, secret: &[u8; 32]) {
    let mut template = vec![
        0x4d, 0x2a, slot, 0, 0x7f, 0x48, 2, 0x92, 0x20, 0x5f, 0x48, 0x20,
    ];
    template.extend_from_slice(secret);
    command(dispatcher, 0xdb, 0x3f, 0xff, &template, 0x9000);
}

/// Personalize both PINs away from the factory defaults (US-912), then
/// install the ED/CV/ED key set through the PW3-authenticated template
/// path (the `device_pso.rs` fixtures).
fn personalize_and_import(dispatcher: &mut Dispatcher<'_, 1>) -> ([u8; 32], [u8; 32]) {
    command(dispatcher, 0x24, 0, 0x81, b"123456654321", 0x9000);
    command(dispatcher, 0x24, 0, 0x83, b"1234567887654321", 0x9000);
    command(dispatcher, 0x20, 0, 0x83, b"87654321", 0x9000);
    let mut cv_import = *CV_SEED;
    cv_import[0] &= 248;
    cv_import[31] = (cv_import[31] & 127) | 64;
    cv_import.reverse();
    let attrs = [ED, CV, ED];
    for (i, slot) in [0xb6, 0xb8, 0xa4].into_iter().enumerate() {
        command(dispatcher, 0xda, 0, 0xc1 + i as u8, attrs[i], 0x9000);
        let secret: &[u8; 32] = if slot == 0xb8 { &cv_import } else { ED_SEED };
        import(dispatcher, slot, secret);
    }
    (*ED_SEED, cv_import)
}

/// The x25519 PSO:DECIPHER input for the imported CV decryption key
/// (same shape as `device_pso.rs`).
fn decipher_data() -> Vec<u8> {
    let eph = x25519_dalek::StaticSecret::from(<[u8; 32]>::from(Sha256::digest(
        b"fapico2-us914-eph",
    )));
    let mut data = hex!("a6257f49228620").to_vec();
    data.extend_from_slice(x25519_dalek::PublicKey::from(&eph).as_bytes());
    data
}

#[test]
fn presence_refusal_blocks_all_key_ops_and_stages_nothing() {
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client).with_presence_grant(|_| false);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        let (_ed, _cv) = personalize_and_import(&mut dispatcher);
        // The touch gate is UIF-gated (spec §7.2.13): enable it for all
        // three keys — PUT DATA DO 0xD6/0xD7/0xD8, [uif, GFM=0x20].
        for p2 in [0xd6, 0xd7, 0xd8] {
            command(&mut dispatcher, 0xda, 0, p2, &[0x01, 0x20], 0x9000);
        }
        let digest = Sha256::digest(b"US-914 presence gate");

        // PW1 sessions verified (sign + other): with the session gates
        // satisfied, only the presence gate can refuse — and the refusal
        // carries an EMPTY body: no signature was ever framed.
        command(&mut dispatcher, 0x20, 0, 0x81, b"654321", 0x9000);
        assert_eq!(
            command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest, 0x6982),
            Vec::<u8>::new(),
            "PSO:SIGN must be refused with no reply data"
        );
        command(&mut dispatcher, 0x20, 0, 0x82, b"654321", 0x9000);
        assert_eq!(
            command(&mut dispatcher, 0x88, 0, 0, &digest, 0x6982),
            Vec::<u8>::new(),
            "INT-AUTH must be refused with no reply data"
        );
        let data = decipher_data();
        assert_eq!(
            command(&mut dispatcher, 0x2a, 0x80, 0x86, &data, 0x6982),
            Vec::<u8>::new(),
            "PSO:DECIPHER must be refused with no reply data"
        );

        // Non-gated commands are served — the gate is selective, not a
        // transport wedge (GET DATA 0xC4: PW-status bytes).
        assert!(
            !command(&mut dispatcher, 0xca, 0, 0xc4, &[], 0x9000).is_empty(),
            "GET DATA must stay served under a refused presence source"
        );
    });
}

#[test]
fn presence_grant_binds_to_the_pending_operation() {
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client)
            // Grants ONLY the PSO:SIGN operation tag — the US-906
            // tag-binding discipline as seen from this app.
            .with_presence_grant(|tag| tag == PRESENCE_TAG_PSO_SIGN);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        let (ed, _cv) = personalize_and_import(&mut dispatcher);
        // UIF-gated seam: enable all three UIFs so the tag-binding
        // discipline can be exercised (PUT DATA DO 0xD6/0xD7/0xD8).
        for p2 in [0xd6, 0xd7, 0xd8] {
            command(&mut dispatcher, 0xda, 0, p2, &[0x01, 0x20], 0x9000);
        }
        let digest = Sha256::digest(b"US-914 presence gate");

        command(&mut dispatcher, 0x20, 0, 0x81, b"654321", 0x9000);
        let signature = command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest, 0x9000);
        assert_eq!(signature.len(), 64, "the granted PSO:SIGN must complete");
        let key = ed25519_dalek::SigningKey::from_bytes(&ed).verifying_key();
        key.verify(
            &digest,
            &ed25519_dalek::Signature::from_slice(&signature).unwrap(),
        )
        .unwrap();

        // The other operations' tags hold no grant: refused, nothing staged.
        command(&mut dispatcher, 0x20, 0, 0x82, b"654321", 0x9000);
        assert_eq!(
            command(&mut dispatcher, 0x88, 0, 0, &digest, 0x6982),
            Vec::<u8>::new(),
            "INT-AUTH must not consume a PSO:SIGN grant"
        );
        assert_eq!(
            command(&mut dispatcher, 0x2a, 0x80, 0x86, &decipher_data(), 0x6982),
            Vec::<u8>::new(),
            "PSO:DECIPHER must not consume a PSO:SIGN grant"
        );
        // The unused tags are exactly the other two operation constants.
        assert_ne!(PRESENCE_TAG_PSO_SIGN, PRESENCE_TAG_PSO_DECIPHER);
        assert_ne!(PRESENCE_TAG_PSO_SIGN, PRESENCE_TAG_INT_AUTH);
        assert_ne!(PRESENCE_TAG_PSO_DECIPHER, PRESENCE_TAG_INT_AUTH);
    });
}

/// One raw APDU through the dispatcher; returns (body, SW) — for the
/// `61XX` staging-dialogue asserts below.
fn apdu_raw(dispatcher: &mut Dispatcher<'_, 1>, ins: u8, p1: u8, p2: u8) -> (Vec<u8>, u16) {
    let mut response = heapless::Vec::<u8, MAX_RESPONSE>::new();
    let apdu = [0, ins, p1, p2, 0];
    dispatcher.dispatch(&apdu, &mut response);
    assert!(response.len() >= 2);
    let sw = u16::from_be_bytes([response[response.len() - 2], response[response.len() - 1]]);
    (response[..response.len() - 2].to_vec(), sw)
}

/// US-914: "no signature response is framed before the grant check" — and
/// a refusal must not leave a previous command's staged `61XX` remainder
/// servable through GET RESPONSE (stale reply data must not survive the
/// refusal).
#[test]
fn presence_refusal_drops_staged_reply_data() {
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client).with_presence_grant(|_| false);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        // Stage an oversized reply: GET DATA 0x6E with Le 0 (→ 256)
        // leaves the remainder pending as `61XX` — the S-723-A2 dialogue
        // shape (the default card's 0x6E exceeds 256 bytes, pinned in
        // `dispatch.rs::oversized_6e_chunks_per_le`).
        let (body, sw) = apdu_raw(&mut dispatcher, 0xca, 0, 0x6e);
        assert_eq!(body.len(), 256, "the first exchange serves exactly Le");
        assert_eq!(sw & 0xFF00, 0x6100, "the remainder must pend as 61XX");
        // The refused PSO must drop the staged remainder — the digest
        // never reaches the key. On this factory-default card the refusal
        // is the US-912 factory gate (6985), which now fires inside opcard
        // BEFORE the touch seam (US-914: the prompt is not offered for
        // commands that cannot succeed); an authorized-but-untouched
        // refusal answers 6982 instead.
        let digest = Sha256::digest(b"US-914 presence gate");
        assert_eq!(
            command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest, 0x6985),
            Vec::<u8>::new()
        );
        // GET RESPONSE now serves NOTHING stale — the pre-refusal
        // remainder is gone (upstream answers an empty 9000 when nothing
        // is staged).
        let (stale, sw) = apdu_raw(&mut dispatcher, 0xc0, 0, 0);
        assert_eq!(
            stale,
            Vec::<u8>::new(),
            "no stale reply data may survive the refusal"
        );
        assert_eq!(sw, 0x9000);
    });
}

/// US-914 review finding: the touch prompt is a POST-AUTHORIZATION seam.
/// A command that cannot succeed — the factory-default gate (6985) or a
/// missing PW1 session (6982) — must be refused WITHOUT consulting the
/// presence source, so a hostile host cannot hold the shared transport's
/// serve task in the 10 s touch window with APDUs that will never be
/// signed. The injected source GRANTS everything: any consultation would
/// show up as a call, so a zero count proves no prompt was ever offered.
#[test]
fn unauthorized_pso_never_consults_the_presence_source() {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    fn counting_grant(_tag: u32) -> bool {
        CALLS.fetch_add(1, Ordering::SeqCst);
        true
    }
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client).with_presence_grant(counting_grant);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        let digest = Sha256::digest(b"US-914 unauthorized");

        // Fresh card: the factory-default gate refuses every gated op
        // before the touch seam — empty bodies, and the source is never
        // asked (the refusals answer 6985, not a presence 6982).
        assert_eq!(
            command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest, 0x6985),
            Vec::<u8>::new()
        );
        assert_eq!(
            command(&mut dispatcher, 0x88, 0, 0, &digest, 0x6985),
            Vec::<u8>::new()
        );
        assert_eq!(
            command(&mut dispatcher, 0x2a, 0x80, 0x86, &decipher_data(), 0x6985),
            Vec::<u8>::new()
        );

        // Personalize (US-912 gate lifted) but do NOT verify PW1: the
        // session-gated ops are refused before the touch seam, still
        // without a prompt.
        personalize_and_import(&mut dispatcher);
        assert_eq!(
            command(&mut dispatcher, 0x88, 0, 0, &digest, 0x6982),
            Vec::<u8>::new(),
            "INT-AUTH without a PW1-other session must be refused before the prompt"
        );
        assert_eq!(
            command(&mut dispatcher, 0x2a, 0x80, 0x86, &decipher_data(), 0x6982),
            Vec::<u8>::new(),
            "PSO:DECIPHER without a PW1-other session must be refused before the prompt"
        );

        assert_eq!(
            CALLS.load(Ordering::SeqCst),
            0,
            "the presence source must not be consulted for unauthorized commands"
        );
    });
}

#[test]
fn default_presence_auto_ack_keeps_key_ops_working() {
    // The `None` default (host/emulation): no injected source ⇒ auto-ack,
    // the pre-US-914 behavior the existing suites and host builds rely on.
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        let (ed, _cv) = personalize_and_import(&mut dispatcher);
        let digest = Sha256::digest(b"US-914 presence gate");

        command(&mut dispatcher, 0x20, 0, 0x81, b"654321", 0x9000);
        let signature = command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest, 0x9000);
        assert_eq!(signature.len(), 64);
        let key = ed25519_dalek::SigningKey::from_bytes(&ed).verifying_key();
        key.verify(
            &digest,
            &ed25519_dalek::Signature::from_slice(&signature).unwrap(),
        )
        .unwrap();
    });
}

/// The device always installs the US-914 presence grant — but the grant
/// must only be consulted when the card's UIF flag for the operation is
/// ENABLED (upstream opcard semantics, OpenPGP spec §7.2.13, vendor-card
/// default UIF=Disabled). The 2026-09-25 hardware session proved the
/// always-on consultation breaks stock gpg: `generate` fails at
/// make_keysig_packet ("Bad PIN") because each of the 3 on-card PSO:SIGN
/// self/binding signatures consumes one press (1 press failed, 4 presses
/// succeeded). UIF-disabled ⇒ no prompt at all: a never-granting source
/// must not even be consulted, and the signature must complete.
#[test]
fn uif_disabled_never_consults_the_presence_source() {
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client).with_presence_grant(|_| false);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        let (ed, _cv) = personalize_and_import(&mut dispatcher);
        let digest = Sha256::digest(b"US-914 presence gate");

        command(&mut dispatcher, 0x20, 0, 0x81, b"654321", 0x9000);
        let signature = command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest, 0x9000);
        assert_eq!(signature.len(), 64, "UIF-disabled PSO:SIGN must complete without a touch");
        let key = ed25519_dalek::SigningKey::from_bytes(&ed).verifying_key();
        key.verify(
            &digest,
            &ed25519_dalek::Signature::from_slice(&signature).unwrap(),
        )
        .unwrap();
    });
}

/// The opt-in path stays: once the user enables the UIF (gpg
/// `--edit-card > uif`, PUT DATA DO 0xD6 — admin-authorized), the touch
/// prompt is back and the never-granting source refuses with 6982.
#[test]
fn uif_enabled_restores_the_touch_gate() {
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client).with_presence_grant(|_| false);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        personalize_and_import(&mut dispatcher);
        let digest = Sha256::digest(b"US-914 presence gate");

        command(&mut dispatcher, 0x20, 0, 0x81, b"654321", 0x9000);
        // PUT DATA DO 0xD6 (UIF signing): [uif, GFM] — 1 = Enabled, GFM 0x20.
        command(&mut dispatcher, 0xda, 0, 0xd6, &[0x01, 0x20], 0x9000);
        assert_eq!(
            command(&mut dispatcher, 0x2a, 0x9e, 0x9a, &digest, 0x6982),
            Vec::<u8>::new(),
            "UIF-enabled PSO:SIGN must still demand the touch"
        );
    });
}
