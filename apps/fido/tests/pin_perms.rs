//! Tests for pinUvAuthToken permission enforcement (FX-405).

mod common;

use common::*;

#[test]
fn test_acfg_token_rejected_for_make_credential() {
    let (mut app, client) = setup();
    let token = client.get_token(&mut app, 0x09, Some(0x20), None).unwrap();
    let hash = [0x5Au8; 32];
    let resp = app.process_ctap2(0x01, &make_mc_request(&hash, "example.com", &token), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x33, "acfg token must be rejected by makeCredential");
}

#[test]
fn test_acfg_token_rejected_for_get_assertion() {
    let (mut app, client) = setup();
    let token = client.get_token(&mut app, 0x09, Some(0x20), None).unwrap();
    let hash = [0x5Bu8; 32];
    let resp = app.process_ctap2(0x02, &make_ga_request(&hash, "example.com", &token), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x33, "acfg token must be rejected by getAssertion");
}

#[test]
fn test_ga_token_rejected_for_make_credential() {
    let (mut app, client) = setup();
    let token = client.get_token(&mut app, 0x09, Some(0x02), None).unwrap();
    let hash = [0x5Cu8; 32];
    let resp = app.process_ctap2(0x01, &make_mc_request(&hash, "example.com", &token), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x33, "getAssertion-only token must be rejected by makeCredential");
}

#[test]
fn test_mc_token_rejected_for_cred_mgmt() {
    let (mut app, client) = setup();
    let token = client.get_token(&mut app, 0x09, Some(0x01), None).unwrap();
    let resp = app
        .process_ctap2(0x0A, &make_cm_request(0x01, &token), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x33, "mc-only token must be rejected by credMgmt");
}

#[test]
fn test_cm_token_accepted_for_cred_mgmt() {
    let (mut app, client) = setup();
    let token = client.get_token(&mut app, 0x09, Some(0x04), None).unwrap();
    let resp = app
        .process_ctap2(0x0A, &make_cm_request(0x01, &token), [1, 2, 3, 4]);
    // enumerateRpsBegin with an empty store must NOT be a PIN auth error;
    // CTAP2_OK (0x00) with empty metadata is the expected outcome.
    assert_eq!(resp[0], 0x00, "cm token must be accepted by credMgmt");
}

#[test]
fn test_legacy_token_allows_mc_and_ga() {
    let (mut app, client) = setup();
    let token = client.get_token(&mut app, 0x05, None, None).unwrap();
    let hash = [0x5Du8; 32];
    let resp = app.process_ctap2(0x01, &make_mc_request(&hash, "example.com", &token), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00, "legacy 0x05 token must allow makeCredential");
    let resp = app.process_ctap2(0x02, &make_ga_request(&hash, "example.com", &token), [1, 2, 3, 4]);
    assert_ne!(resp[0], 0x33, "legacy 0x05 token must allow getAssertion");
}

#[test]
fn test_get_pin_token_using_pin_requires_permissions() {
    let (mut app, client) = setup();
    let err = client
        .get_token(&mut app, 0x09, None, None)
        .expect_err("0x09 without permissions must fail");
    assert_eq!(err, 0x14, "expected CTAP2_ERR_MISSING_PARAMETER");
}

#[test]
fn test_token_rp_id_binding_enforced() {
    let (mut app, client) = setup();
    let token = client
        .get_token(&mut app, 0x09, Some(0x01), Some("example.com"))
        .unwrap();
    let hash = [0x5Eu8; 32];
    let resp = app.process_ctap2(0x01, &make_mc_request(&hash, "other.com", &token), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x33, "rpId-bound token must be rejected for another RP");
    let hash2 = [0x5Fu8; 32];
    let resp = app
        .process_ctap2(0x01, &make_mc_request(&hash2, "example.com", &token), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00, "rpId-bound token must be accepted for the bound RP");
}

// ---------------------------------------------------------------------------
// US-112: AUTHENTICATOR_CONFIG (0x20) authorises the RS-Key `0x41` channel.
//
// # Why these live next to the FX-405 tests
//
// `0x20` was already the right bit for CTAP2 `authenticatorConfig` and this
// story gives it a second job: the RS-Key `0x41` vendor channel. The two
// facts are the same fact about the bit and a different fact about the
// client, and the client is what has to be right — PicoForge mints `0x20` for
// every authenticated `0x41` call (`picoforge/src/hal/fido/ops.rs:1576-1580`
// and the `mod.rs` call sites), so a firmware that demanded anything else
// would lock PicoForge out of all five screens.
//
// The bits are written as literals, matching
// `picoforge/src/hal/fido/constants.rs:302-320` (`PinUvAuthTokenPermissions`),
// not read from the firmware. Reading `vendor41::required_permission`'s own
// constant here would make the test assert that a table agrees with itself.
// ---------------------------------------------------------------------------

use fapico2_fido::cbor;
use fapico2_fido::crypto;
use fapico2_fido::vendor41::{self, required_permission, Requirement, Subcommand};

/// `AUTHENTICATOR_CONFIG` — `picoforge/.../constants.rs:309`.
const ACFG: u8 = 0x20;
/// `CREDENTIAL_MANAGEMENT` — `picoforge/.../constants.rs:310`.
const CRED_MGMT: u8 = 0x04;
/// `MAKE_CREDENTIAL` — `picoforge/.../constants.rs:306`.
const MC: u8 = 0x01;

/// The RS-Key `0x41` command opcode (`vendor41::CMD`).
const VENDOR_41: u8 = 0x41;
/// `RSKEY_CONFIG_WRITE` — `picoforge/.../constants.rs` RSKEY block.
const CONFIG_WRITE: u8 = 0x0C;
/// RS-Key pinUvAuth MAC length: protocol 1 truncates HMAC-SHA256 to 16.
const MAC_LEN: usize = 16;

/// `CONFIG_WRITE` params in the shape PicoForge builds
/// (`picoforge/src/hal/fido/ops.rs:1520-1523`): `{1: target, 2: blob}` with a
/// 32-byte blob.
///
/// A `Value` rather than bytes, because the params are the request's CBOR key
/// 2 — the MAC covers the *encoding* of this value as it goes on the wire,
/// and re-encoding it from the parsed form is what makes the client's bytes
/// and the device's bytes the same bytes.
fn config_write_params() -> cbor::Value {
    cbor::Value::M(vec![
        (cbor::Value::U(1), cbor::Value::U(1)),
        (
            cbor::Value::U(2),
            cbor::Value::B((0u8..32).collect()),
        ),
    ])
}

/// The MAC PicoForge signs for a `0x41` request
/// (`picoforge/src/hal/fido/ops.rs:1581-1586`):
/// `HMAC-SHA256(token, 0xFF*32 || 0x41 || subCommand || cbor(params))[..16]`.
fn rskey_mac(token: &[u8], sub: u8, params: &cbor::Value) -> Vec<u8> {
    let mut msg: Vec<u8> = vec![0xFFu8; 32];
    msg.push(VENDOR_41);
    msg.push(sub);
    msg.extend_from_slice(&cbor::encode(params));
    crypto::hmac_sha256(token, &msg)[..MAC_LEN].to_vec()
}

/// The `0x41` request body `{1: sub, 2: params, 3: protocol, 4: mac}` — the
/// key order PicoForge's canonical CBOR produces.
fn rskey_request(sub: u8, params: &cbor::Value, mac: &[u8]) -> Vec<u8> {
    cbor::encode(&cbor::Value::M(vec![
        (cbor::Value::U(1), cbor::Value::U(sub as u64)),
        (cbor::Value::U(2), params.clone()),
        (cbor::Value::U(3), cbor::Value::U(1)),
        (cbor::Value::U(4), cbor::Value::B(mac.to_vec())),
    ]))
}

/// The status byte [`vendor41::authorize`] refuses with, or `None` when it
/// admits the call.
///
/// The tests below assert on bytes rather than on `Ctap2Response` variants so
/// that "refused" is checked against the CTAP2.1 wire value (`0x40`) and not
/// against whatever the enum happens to be called this week — the same reason
/// `tests/vendor41.rs` spells `0x30` and `0x3E` out.
fn refusal(sub: Subcommand, permissions: Option<u8>) -> Option<u8> {
    vendor41::authorize(sub, permissions)
        .err()
        .map(|code| code.code())
}

/// A token the way the two `FidoApp` types narrow it for the `0x41` channel.
fn as_token32(token: &[u8]) -> [u8; 32] {
    token
        .get(..32)
        .and_then(|t| t.try_into().ok())
        .expect("clientPin returns a 32-byte token")
}

// ---------------------------------------------------------------------------
// The named EPIC test.
// ---------------------------------------------------------------------------

/// # `acfg_permission_grants_vendor41_config_write`
///
/// `getPinUvAuthTokenUsingPinWithPermissions` (`0x09`) with permission `0x20`
/// must succeed, and the token it returns must be one the `0x41` channel
/// accepts: it must satisfy US-111's MAC check, and the US-112 gate must
/// admit it for `CONFIG_WRITE`.
///
/// The three assertions are one claim seen from three places, and dropping any
/// of them leaves the story unproven:
///
/// * the mint itself — a firmware that rejected `0x20` would fail here before
///   either of the others ran;
/// * the MAC — a `0x20` token that verifies nothing is a token the vendor
///   channel cannot use, which is the failure this story exists to prevent;
/// * the gate — the permission table is the new code, and it is the only part
///   that could refuse a token the protocol says to accept.
///
/// The MAC is built by a **third** implementation of the message
/// ([`rskey_mac`] here, the out-of-band constants in `tests/vendor41.rs`, and
/// `vendor41::verify_mac` in the firmware), so agreement between them is
/// evidence rather than a tautology.
#[test]
fn acfg_permission_grants_vendor41_config_write() {
    let (mut app, client) = setup();
    let token = client
        .get_token(&mut app, 0x09, Some(ACFG), None)
        .expect("0x09 with AUTHENTICATOR_CONFIG must mint a token");
    let key = as_token32(&token);

    let params = config_write_params();
    let req = rskey_request(CONFIG_WRITE, &params, &rskey_mac(&key, CONFIG_WRITE, &params));
    vendor41::verify_mac(&req, Some(&key))
        .expect("an AUTHENTICATOR_CONFIG token must satisfy the 0x41 MAC check");

    assert_eq!(
        refusal(Subcommand::ConfigWrite, Some(ACFG)),
        None,
        "0x20 is the only bit PicoForge ever mints for CONFIG_WRITE, so a \
         correct table must admit it",
    );
}

/// The negative half: a token **without** the required bit is refused, and the
/// refusal is `0x40` (`CTAP2_ERR_UNAUTHORIZED_PERMISSION`) rather than
/// `0x33`.
///
/// `0x40` is the CTAP2.1 status for "your token does not carry the permission
/// this command needs" and it is distinct from `0x33` on purpose: `0x33` says
/// your MAC was wrong, which would send a desktop app back to the PIN prompt
/// for a PIN that was accepted. Asserting the exact status is what keeps a
/// later story from collapsing the two.
#[test]
fn token_without_acfg_is_refused_vendor41_config_write() {
    assert_eq!(
        refusal(Subcommand::ConfigWrite, Some(MC)),
        Some(0x40),
        "a MAKE_CREDENTIAL-only token must be refused 0x40 — answering 0x33 \
         would blame the MAC for a permission problem",
    );
    assert_eq!(
        refusal(Subcommand::ConfigWrite, Some(MC | CRED_MGMT)),
        Some(0x40),
        "holding other permissions is not holding the required one",
    );
}

/// No token at all is refused the same way. This is the case that separates
/// "the permission is missing" from "there is nothing to check", and it is
/// why `authorize` takes `Option<u8>` rather than a bare byte.
#[test]
fn no_token_is_refused_vendor41_config_write() {
    assert_eq!(
        refusal(Subcommand::ConfigWrite, None),
        Some(0x40),
        "an app holding no token must authorise nothing on this channel",
    );
}

/// A legacy `getPinToken` (`0x05`) token carries permission byte `0`, which
/// both `FidoApp` twins already read as "makeCredential or getAssertion
/// only". It must not acquire a config authority here by being zero.
#[test]
fn legacy_token_is_refused_vendor41_config_write() {
    let (mut app, client) = setup();
    client
        .get_token(&mut app, 0x05, None, None)
        .expect("legacy getPinToken must still mint a token");
    assert_eq!(
        refusal(Subcommand::ConfigWrite, Some(0)),
        Some(0x40),
        "a zero permission byte is the legacy MC/GA token, not a wildcard; \
         treating it as 'unrestricted' would hand every PIN-less app config \
         authority",
    );
}

/// # The discrimination test
///
/// A `CREDENTIAL_MANAGEMENT`-only token must **not** authorise a device
/// configuration write.
///
/// This is the test the per-sub-command table exists for. PicoForge requests
/// `0x04` for CTAP2 `credentialManagement` — enumerate and delete credentials
/// (`picoforge/src/hal/fido/ops.rs:1082`, `:1230`, `:1407`) — and that is a
/// genuinely different authority from writing the token's own configuration.
/// A single channel-wide rule of "accept `0x20` or `0x04`" would be
/// observationally identical on the wire (those are the only two bits the
/// client ever mints) and would let a credential-management session rewrite
/// device configuration. An implementation that collapsed the table to a
/// single-bit gate passes
/// `acfg_permission_grants_vendor41_config_write` and fails here.
#[test]
fn cm_only_token_cannot_authorize_vendor41_config_write() {
    let (mut app, client) = setup();
    client
        .get_token(&mut app, 0x09, Some(CRED_MGMT), None)
        .expect("0x04 is a permission the clientPin path does mint");
    assert_eq!(
        refusal(Subcommand::ConfigWrite, Some(CRED_MGMT)),
        Some(0x40),
        "CREDENTIAL_MANAGEMENT authorises CTAP2 credentialManagement, not \
         device configuration — collapsing the table to a channel-wide \
         0x20||0x04 gate would let this escalate",
    );
    assert_eq!(
        refusal(Subcommand::ConfigWrite, Some(CRED_MGMT | ACFG)),
        None,
        "the two bits are alternatives, not a bundle: a token holding both \
         must still be admitted, which a 'CM implies ACFG' shortcut would break",
    );
}

/// `CONFIG_READ` is ungated, so the *absence* of a token is not a refusal.
///
/// The real client sends it with no token and no MAC and uses it as the probe
/// for whether this firmware supports `0x41` at all
/// (`picoforge/src/hal/fido/ops.rs:1461-1479`,
/// `picoforge/src/hal/fido/mod.rs:1163-1166`). Gating it would answer `0x40`
/// to a request the protocol deliberately sends bare, and PicoForge would
/// report "this firmware does not support FIDO configuration" for a device
/// that does.
#[test]
fn config_read_is_ungated() {
    for permissions in [None, Some(0), Some(MC), Some(CRED_MGMT), Some(ACFG)] {
        assert_eq!(
            refusal(Subcommand::ConfigRead, permissions),
            None,
            "CONFIG_READ is the client's ungated 0x41 feature probe; every \
             token state must admit it, including none at all",
        );
    }
    assert_eq!(
        vendor41::required_permission(Subcommand::ConfigRead),
        Requirement::Ungated,
        "and it must be declared ungated in the table, not merely happen to \
         pass — a future arm reading this row has to see it",
    );
}

/// # The token-optional rows — and the presence gate they still owe
///
/// Twelve of the fourteen sub-commands are sent by the real client with **no
/// token at all**. `HidTransport::rs_key_vendor` attaches a `0x20` token only
/// when its `pin` argument is `Some`
/// (`picoforge/src/hal/fido/ops.rs:1556-1586`), and of the twelve, six pass
/// `None` outright — `MSE` (`mod.rs:1709`), `FINALIZE` (`:1757`), `STATE`
/// (`:1741`), `UNLOCK` (`:1826`/`:1867`), `AUDIT_CONFIG` (`:1653`) and
/// `ATT_STATE` (`:1895`) — while the other six pass `pin.as_deref()` and so
/// send a token only if the caller happens to have one: `EXPORT` (`:1771`),
/// `LOAD` (`:1797`), `AUDIT_READ` (`:1573`), `AUDIT_CHECKPOINT` (`:1611`),
/// `ATT_IMPORT` (`:1987`) and `ATT_CLEAR` (`:1916`).
///
/// Those are the sub-commands the client documents as *"ungated"*
/// (`backup_status`, `lock_unlock`, `att_status`, `audit_status`) or
/// *"touch-gated"* (`backup_finalize`). A gate that demanded `0x20` of them
/// would answer `0x40` to the ordinary call, breaking four of the five screens
/// US-106 made reachable — and only once a Phase I story wires the gate, so
/// nothing would have failed before then.
///
/// The companion assertion is that "optional" is about the *absence* of a
/// token, not about any token sufficing: a `CREDENTIAL_MANAGEMENT`-only token
/// is still refused on these rows.
///
/// # Read the last assertion in this test as a warning, not a specification
///
/// This test asserts, as a **passing** test, that a request with no token and
/// no MAC clears `authorize` for all twelve rows — two of which are `Export`
/// ("read the encrypted master seed") and `State` (`has_seed` / `locked`).
/// That is correct about the *authorisation layer and nothing else*. The
/// client's reason for sending them bare is that the firmware is supposed to
/// gate them on a physical touch instead
/// (`picoforge/src/hal/fido/ops.rs:1573-1575`).
///
/// **That other half now exists** (US-170 … US-175; US-1516 recorded it): eight
/// of the twelve rows take a presence grant on the tokenless path, each proved
/// behaviourally by its own module's tests. The four that do not — `Mse`,
/// `State`, `Unlock`, `AttState` — each answer with something the touch was
/// standing in for; that is recorded per sub-command in `vendor41::decision`
/// and pinned by name in
/// `vendor41::the_token_optional_rows_without_a_touch_are_the_four_named_ones`.
///
/// This paragraph used to say "no such gate exists — every row is a `0x30`
/// stub", and kept saying it long after the stubs drained. That is the failure
/// US-1516 was raised about: a green test is not a specification, and prose
/// about the state of the world decays silently while the test beside it goes
/// on passing.
#[test]
fn token_optional_rows_admit_a_tokenless_request() {
    use fapico2_fido::vendor41::requires_presence_when_tokenless;
    for sub in [
        Subcommand::Mse,
        Subcommand::Export,
        Subcommand::Load,
        Subcommand::Finalize,
        Subcommand::State,
        Subcommand::Unlock,
        Subcommand::AuditRead,
        Subcommand::AuditCheckpoint,
        Subcommand::AuditConfig,
        Subcommand::AttImport,
        Subcommand::AttClear,
        Subcommand::AttState,
    ] {
        assert_eq!(
            required_permission(sub),
            Requirement::TokenOptional(ACFG),
            "{:?} is sent bare or PIN-or-touch by the client and must be \
             declared token-optional, not token-required",
            sub.byte(),
        );
        assert_eq!(
            refusal(sub, None),
            None,
            "{:?}: a tokenless request is the client's normal call for this \
             sub-command and must clear the *authorisation* layer. Read \
             todo_us1xx_presence_gate_covers_every_tokenless_row before \
             treating that as sufficient — the presence gate it defers to \
             does not exist yet",
            sub.byte(),
        );
        assert_eq!(
            refusal(sub, Some(CRED_MGMT)),
            Some(0x40),
            "{:?}: optional means the token may be absent — a token that is \
             present must still carry AUTHENTICATOR_CONFIG, or the optional \
             rows become a hole in the permission model",
            sub.byte(),
        );
        assert_eq!(
            refusal(sub, Some(ACFG)),
            None,
            "{:?}: the 0x20 token the client does mint must be admitted",
            sub.byte(),
        );
        // The debt, named. See the test's module comment for why this is
        // asserted next to the admission rather than left to a doc line.
        assert!(
            requires_presence_when_tokenless(sub),
            "{:?} admits a tokenless request, so it owes a presence check. \
             The predicate is what makes that obligation greppable; it is \
             not yet discharged by anything",
            sub.byte(),
        );
    }
}

/// The other half of [`token_optional_rows_admit_a_tokenless_request`]: what
/// each of the twelve token-optional rows actually does when the token is
/// absent.
///
/// **This test used to be `todo_us1xx_presence_gate_covers_every_tokenless_row`,
/// `#[ignore]`d, ending in an unconditional `panic!`.** It claimed that "no
/// presence gate exists on the 0x41 channel" — which was true when it was
/// written and stayed in the file long after it stopped being true. Eight of
/// the twelve rows take a presence grant today, and the other four are not
/// debt: each answers with something the touch was standing in for, recorded
/// in `vendor41::decision`.
///
/// Deleting it is not what closes that: an obligation that lives only in prose
/// is what let the stale sentence survive in the first place. So the check is
/// back, as a test that passes and says what it says — one row per
/// sub-command, the mechanism each actually uses, and a pointer to the
/// behavioural test that proves it. A sixth row without a touch, or a
/// mechanism that stops existing, fails here rather than in a review nobody
/// performs.
///
/// The per-row *behaviour* is proved elsewhere, not restated here:
/// `tests/vendor_backup.rs::export_falls_back_to_a_touch_when_there_is_no_pin`,
/// `tests/vendor_audit.rs::all_three_audit_subcommands_use_the_same_union_gate`,
/// and the `presence(false)` legs of `tests/vendor_att.rs`.
#[test]
fn every_token_optional_row_is_either_touch_gated_or_named_as_an_exception() {
    use fapico2_fido::vendor41::{decision, Tokenless};

    // The twelve, each with the mechanism the device uses on the tokenless
    // path. A row appearing here for the first time is the moment to say
    // *why* a tokenless request is safe, in this table, where the next reader
    // is already looking.
    let rows: [(Subcommand, Tokenless); 12] = [
        // vendor_backup's backup_auth falls through to the presence window.
        (Subcommand::Mse, Tokenless::Ungated),
        (Subcommand::Export, Tokenless::Touch),
        (Subcommand::Load, Tokenless::Touch),
        (Subcommand::Finalize, Tokenless::Touch),
        (Subcommand::State, Tokenless::StatusOnly),
        (Subcommand::Unlock, Tokenless::Possession),
        (Subcommand::AuditRead, Tokenless::Touch),
        (Subcommand::AuditCheckpoint, Tokenless::Touch),
        (Subcommand::AuditConfig, Tokenless::Touch),
        (Subcommand::AttImport, Tokenless::Touch),
        (Subcommand::AttClear, Tokenless::Touch),
        (Subcommand::AttState, Tokenless::StatusOnly),
    ];

    for (sub, tokenless) in rows {
        let d = decision(sub);
        assert_eq!(
            d.tokenless, tokenless,
            "{:?}: this file says the tokenless path is {tokenless:?}, \
             vendor41::decision says {:?}. One of the two is out of date — \
             find out which before changing either.",
            sub.byte(),
            d.tokenless
        );
    }

    // And the count, so a fourteenth token-optional row cannot appear without
    // this array growing: the array is the enumeration, and a sub-command
    // missing from it would otherwise be silently unaccounted for.
    let declared = rows.len();
    let token_optional = Subcommand::ALL
        .iter()
        .filter(|s| required_permission(**s) == Requirement::TokenOptional(ACFG))
        .count();
    assert_eq!(
        declared, token_optional,
        "this list must cover every TokenOptional row ({token_optional} of them)"
    );
}
