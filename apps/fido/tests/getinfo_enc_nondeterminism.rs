//! US-1600 / US-1608 / US-1609 — the `encCredStoreState` equality oracle.
//!
//! ```gherkin
//! Scenario: getInfo currently publishes a constant ciphertext
//!   Given the device in any state
//!   When authenticatorGetInfo is called twice with no intervening command
//!   Then the ciphertext half of key 0x1E is byte-identical across both responses
//!
//! Scenario: the encrypted-state ciphertext must not repeat across calls
//!   Given the device in any state
//!   When getInfo is called twice with no state-changing command between
//!   Then the 16-byte ciphertext halves differ
//!   And the 16-byte IV halves differ
//! ```
//!
//! # The oracle, precisely
//!
//! CTAP 2.2 getInfo key `0x1E` (`encCredStoreState`) is 32 bytes: a 16-byte
//! **IV** followed by a 16-byte AES-256-CBC **ciphertext** of an HMAC over
//! `device_random ‖ cred_counter`. Key `0x19` (`encIdentifier`) has the same
//! layout.
//!
//! Measured on the live board over six consecutive unauthenticated getInfo
//! calls (red-team assessment, 2026-10-05):
//!
//! ```text
//! IV half         f317bb1c… — differs every call
//! ciphertext half           — byte-identical every call
//! ```
//!
//! That identity **is** the vulnerability. The plaintext is an HMAC over the
//! credential counter, so a ciphertext that repeats across two unauthenticated
//! getInfo calls is a machine-checkable assertion that *nothing happened to the
//! counter between them* — and a caller who polls until the ciphertext stops
//! changing has learned, without a PIN and without a touch, that an assertion
//! occurred and when it stopped occurring. `alwaysUv` and `makeCredUvNotRqd`
//! make this a claim about a **PIN-set** device, so the oracle is available
//! against exactly the deployment where losing the counter matters.
//!
//! # Why the IV half is a *pinned contract* and not the bug
//!
//! `tests/pico-fido/test_000_getinfo.py:45` already asserts
//! `refreshed.enc_cred_store_state != info.enc_cred_store_state`. That test
//! passes today because the **IV** differs, which says nothing about the
//! ciphertext. So the existing suite *looks* like it covers this and does not,
//! and a fix that made the IV constant would turn that suite green while
//! destroying the property it was written to protect. US-1608 therefore
//! asserts the two halves **separately**, and the IV half is asserted to keep
//! differing — a regression guard in the opposite direction from the fix.
//!
//! # What the fix is, and why it breaks no client (US-1609)
//!
//! `device_core.rs` draws a fresh random `iv`, advertises it, and then
//! **discards it**: the ciphertext is produced by `pin_cbc_encrypt_zero_iv`,
//! i.e. CBC under an all-zero IV. The client decodes with the *advertised* IV
//! (`fido2/ctap2/base.py:125,135` — `iv = encrypted[:16]`, then
//! `Cipher(AES(HKDF(pin_token)), modes.CBC(iv))`). The two halves therefore
//! disagree and **no conforming client has ever recovered this plaintext**.
//!
//! The fix is to encrypt with the IV that is already being advertised. All
//! three consequences are desirable:
//!
//! * the equality oracle dies — different IV, different ciphertext;
//! * the field becomes internally coherent (fact 7's incoherence repaired);
//! * no client can regress, because no client could decrypt the field before
//!   and still cannot after — the key-derivation mismatch is untouched.
//!
//! # The twins
//!
//! **The host twin already encrypts with the advertised IV** — `app.rs`'s
//! `get_info` calls `aes_cbc_encrypt(&key, &iv, state_pt)`. So this defect is
//! a **device-only** one, which is the mirror image of the `AGENTS.md` §1 trap
//! rather than an instance of it: here the twin is right and the shipped path
//! is wrong. The baseline below is asserted on both, and the asymmetry is
//! itself an assertion — it is what proves the fix is a change to
//! `device_core.rs` rather than a change to a shared helper.

mod region_boot;

use fapico2_fido::app::FidoApp as HostApp;
use fapico2_fido::keystore::MemoryKeystore;
use fapico2_fido::FidoApp as DeviceApp;
use fapico2_platform::secure_store::HostSecureStore;
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HV;

use region_boot::lock;

// ---------------------------------------------------------------------------
// Constants, transcribed not derived
// ---------------------------------------------------------------------------

/// `CTAP2_OK`.
const OK: u8 = 0x00;
/// getInfo key `0x1E` — `encCredStoreState`.
const ENC_CRED_STORE_STATE: u64 = 0x1E;
/// getInfo key `0x19` — `encIdentifier`.
const ENC_IDENTIFIER: u64 = 0x19;
/// One AES block: the IV half and the ciphertext half are each 16 bytes, and
/// the field is 32. From CTAP 2.2 §5.1.2 and from `getinfo.rs`'s
/// `test_get_info_enc_cred_store_state_is_32_bytes`.
const HALF: usize = 16;
/// The whole field. Asserted separately from [`HALF`] because "the field is 32
/// bytes" and "the field is two 16-byte halves" are different claims, and a
/// change that lengthened one half silently would pass a length-only check.
const FIELD_LEN: usize = 2 * HALF;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// The device twin, booted and otherwise idle.
///
/// No region and no PIN: the point of the oracle is that it is available to an
/// **unauthenticated** reader, so a fixture that needed a token to reach getInfo
/// would be asserting about a device the attacker cannot address. The caller
/// must already hold [`lock`] because [`install`] publishes a process-global
/// provider — this fixture does not install one, but the tests share the file's
/// lock discipline so a future credential-bearing case can be added without
/// re-deriving it.
fn device() -> DeviceApp {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    DeviceApp::boot(&mut trng, &mut store).expect("host TRNG + store boot the device app")
}

/// The host twin, likewise idle and unauthenticated.
fn host() -> HostApp {
    HostApp::with_keystore(MemoryKeystore::new())
}

/// The 32 bytes of `key` out of a getInfo response, read off the **wire**.
///
/// `region_boot::bstr_at` walks the CBOR head-by-head rather than decoding into
/// a map, for the reason its own doc gives: a second CBOR grammar inside a test
/// file fails in ways that look like applet bugs. The response's one-byte
/// status prefix is stripped here so callers pass the body.
fn enc_field(body: &[u8], key: u64) -> Vec<u8> {
    region_boot::bstr_at(body, key).unwrap_or_else(|| {
        panic!("getInfo must carry key {key:#04x}; a missing key is a different defect from a \
                 repeating one and must not be read as this test passing")
    })
}

/// `(iv, ciphertext)` halves of an `enc*` field.
///
/// The split is the whole subject of this file, so it is a function rather
/// than two arithmetic expressions repeated at each call site.
fn halves(field: &[u8], key: u64) -> (Vec<u8>, Vec<u8>) {
    assert_eq!(
        field.len(),
        FIELD_LEN,
        "getInfo key {key:#04x} must be {FIELD_LEN} bytes (IV ‖ one CBC block); it is {}",
        field.len(),
    );
    (field[..HALF].to_vec(), field[HALF..].to_vec())
}

/// One getInfo call, returning the response body.
fn get_info_device(app: &mut DeviceApp) -> Vec<u8> {
    let mut out = HV::<u8, { fapico2_fido::CTAP2_MAX_MSG }>::new();
    let n = app.process_ctap2(0x04, &[], [1, 2, 3, 4], &mut out);
    assert_eq!(out[..n][0], OK, "getInfo must succeed");
    out[..n][1..].to_vec()
}

fn get_info_host(app: &mut HostApp) -> Vec<u8> {
    let resp = app.process_ctap2(0x04, &[], [1, 2, 3, 4]);
    assert_eq!(resp[0], OK, "getInfo must succeed");
    resp[1..].to_vec()
}

// ---------------------------------------------------------------------------
// US-1600 — the baseline, as it stood before US-1609. These passed against
// the defective tree, which was US-1600's acceptance criterion.
//
// **They are `#[ignore]`d now, and that is the record of the flip.** US-1609
// changed exactly the behaviour they characterise, so they would now fail —
// and a test that fails after its own fix is a test that gets deleted, which
// is the one way a measurement can be lost. Kept and ignored, they say what
// the board did on 2026-10-05; `cargo test -- --ignored` reproduces it.
// ---------------------------------------------------------------------------

/// **Before US-1609: the device's `encCredStoreState` ciphertext was
/// byte-identical across calls.**
///
/// Red-team F3. Two consecutive getInfo calls with nothing in between: the IV
/// half differs (so the existing pytest assertion passes) and the ciphertext
/// half does not (so an unauthenticated poller can watch the counter).
///
/// **On the device twin only.** Asserting this on the host twin would fail,
/// because `app.rs` encrypts with the advertised IV — and that asymmetry is
/// the point, not an accident of the fixture. It is what identifies
/// `device_core.rs`'s `pin_cbc_encrypt_zero_iv` as the single line to change.
#[test]
#[ignore = "US-1600 baseline. Characterises the device twin's zero-IV defect; US-1609 binds the \
             ciphertext to the advertised IV and this now fails by design. Kept as the \
             measured before-state."]
fn getinfo_currently_publishes_a_constant_ciphertext_on_the_device() {
    let _lock = lock();
    let mut app = device();

    let first = enc_field(&get_info_device(&mut app), ENC_CRED_STORE_STATE);
    let second = enc_field(&get_info_device(&mut app), ENC_CRED_STORE_STATE);

    let (iv_a, ct_a) = halves(&first, ENC_CRED_STORE_STATE);
    let (iv_b, ct_b) = halves(&second, ENC_CRED_STORE_STATE);

    assert_ne!(
        iv_a, iv_b,
        "the IV is drawn fresh per call and must be — `tests/pico-fido/test_000_getinfo.py:45` \
         already depends on it"
    );
    assert_eq!(
        ct_a, ct_b,
        "THE FINDING: the ciphertext half is byte-identical across two unauthenticated getInfo \
         calls, because `device_core.rs` advertises a random IV and then encrypts under an \
         all-zero one. The plaintext is an HMAC over the credential counter, so a poller watching \
         this field learns when an assertion happened without a PIN and without a touch. \
         When US-1609 lands this assertion inverts and moves to the anti-oracle section below.",
    );
}

/// **The same oracle exists on `encIdentifier`, and it does not need the counter.**
///
/// Worth its own assertion because it is the **stronger** half of the finding:
/// `encIdentifier`'s plaintext is an HMAC over `device_random` alone, with no
/// counter in it, so its ciphertext is not merely *usually* constant — it is
/// constant for the entire life of a boot, on a device that has never
/// enrolled anything. An attacker can therefore learn "this key has not been
/// factory-reset" from a field that does not depend on any activity at all.
#[test]
#[ignore = "US-1600 baseline. `encIdentifier` had no counter in its plaintext at all, so its \
             ciphertext was constant for a whole boot; US-1609 binds it to its IV too. Kept as \
             the measured before-state."]
fn getinfo_currently_publishes_a_constant_identifier_ciphertext() {
    let _lock = lock();
    let mut app = device();

    let first = enc_field(&get_info_device(&mut app), ENC_IDENTIFIER);
    let second = enc_field(&get_info_device(&mut app), ENC_IDENTIFIER);

    let (_, ct_a) = halves(&first, ENC_IDENTIFIER);
    let (_, ct_b) = halves(&second, ENC_IDENTIFIER);
    assert_eq!(
        ct_a, ct_b,
        "encIdentifier's plaintext has no counter in it, so its ciphertext is constant for the \
         whole life of a boot — the oracle needs no assertion activity to work, only patience"
    );
}

/// **The host twin did not have the defect, and that named the fix.**
///
/// `app.rs`'s `get_info` encrypts with the advertised IV, so its ciphertext
/// already varies per call. The defect is therefore **device-only**, and the
/// asymmetry is the evidence that the fix belongs in `device_core.rs` — a
/// change to a shared helper would have been unnecessary, and a change to
/// `app.rs` would have been harmful.
#[test]
fn the_host_twin_already_encrypts_with_the_advertised_iv() {
    let _lock = lock();
    let mut app = host();

    let first = enc_field(&get_info_host(&mut app), ENC_CRED_STORE_STATE);
    let second = enc_field(&get_info_host(&mut app), ENC_CRED_STORE_STATE);
    let (_, ct_a) = halves(&first, ENC_CRED_STORE_STATE);
    let (_, ct_b) = halves(&second, ENC_CRED_STORE_STATE);

    assert_ne!(
        ct_a, ct_b,
        "app.rs's get_info encrypts with the IV it advertises, so the oracle does not exist here. \
         If this ever fails, the host twin has been changed to match the device twin's defect and \
         both need US-1609's fix."
    );
}

// ---------------------------------------------------------------------------
// US-1608 — red. The anti-oracle property, asserted half by half.
// ---------------------------------------------------------------------------

/// **The ciphertext must not repeat across calls. (RED today, on the device.)**
///
/// The inverse of the baseline above, and the assertion US-1609 has to flip.
/// Fails today on the ciphertext half **only** — which is the split that
/// matters: the IV half of the very next test passes now and must keep
/// passing, so this pair cannot both be satisfied by "make the field
/// constant".
#[test]
fn the_encrypted_state_ciphertext_must_not_repeat_across_calls() {
    let _lock = lock();
    let mut app = device();

    let first = enc_field(&get_info_device(&mut app), ENC_CRED_STORE_STATE);
    let second = enc_field(&get_info_device(&mut app), ENC_CRED_STORE_STATE);
    let (_, ct_a) = halves(&first, ENC_CRED_STORE_STATE);
    let (_, ct_b) = halves(&second, ENC_CRED_STORE_STATE);

    assert_ne!(
        ct_a, ct_b,
        "an unauthenticated reader must not be able to tell 'no assertion happened' from 'an \
         assertion happened' by comparing two getInfo replies. The ciphertext is an HMAC over the \
         signature counter; if it repeats, equality is a free oracle for assertion activity."
    );
}

/// **The IV must keep differing. (Green today, and must stay green.)**
///
/// Not the anti-oracle assertion — the **opposite** one, and it is here for a
/// specific reason. `test_000_getinfo.py:45` is satisfied by the IV alone, so a
/// fix that made the field deterministic end-to-end would pass US-1608's first
/// half and quietly retire a contract the pytest suite has depended on since
/// it was written. Pinning the IV's behaviour separately means the two
/// assertions cannot be satisfied by the same move.
#[test]
fn the_encrypted_state_iv_must_keep_differing_across_calls() {
    let _lock = lock();
    let mut app = device();

    let first = enc_field(&get_info_device(&mut app), ENC_CRED_STORE_STATE);
    let second = enc_field(&get_info_device(&mut app), ENC_CRED_STORE_STATE);
    let (iv_a, _) = halves(&first, ENC_CRED_STORE_STATE);
    let (iv_b, _) = halves(&second, ENC_CRED_STORE_STATE);

    assert_ne!(
        iv_a, iv_b,
        "`tests/pico-fido/test_000_getinfo.py:45` asserts the whole field differs between calls, \
         which today it satisfies through the IV alone. Fixing the oracle must not be done by \
         making the field constant."
    );
}

/// **The field's shape is unchanged: 32 bytes, on both twins, both fields.**
///
/// The fix moves bytes *inside* an already-present byte string, so the CBOR
/// shape a client decodes must be bit-for-bit what it was. This is the cheap
/// half of US-1611's "CBOR-shape-preserving" reasoning stated as a test rather
/// than argued in prose — a fix that lengthened a half, or dropped a key, would
/// pass every ciphertext assertion above and break every client.
#[test]
fn the_encrypted_fields_keep_their_shape_on_both_twins() {
    let _lock = lock();

    let mut d = device();
    for key in [ENC_IDENTIFIER, ENC_CRED_STORE_STATE] {
        assert_eq!(
            enc_field(&get_info_device(&mut d), key).len(),
            FIELD_LEN,
            "device twin getInfo key {key:#04x} must stay {FIELD_LEN} bytes"
        );
    }

    let mut h = host();
    for key in [ENC_IDENTIFIER, ENC_CRED_STORE_STATE] {
        assert_eq!(
            enc_field(&get_info_host(&mut h), key).len(),
            FIELD_LEN,
            "host twin getInfo key {key:#04x} must stay {FIELD_LEN} bytes"
        );
    }
}

/// **Both twins carry both keys — the fix must not turn into a removal.**
///
/// The alternative fix (US-1610: omit `0x19`/`0x1E` entirely) is recorded in
/// the epic as *rejected in favour of* binding the ciphertext to the IV, and
/// this is the test that says the rejection still holds. Removing a key is a
/// wire-shape change that breaks `test_get_info_ctap_23_fields_are_well_formed`
/// (`test_000_getinfo.py:40-45`); if a future change removes them deliberately,
/// this fails and the reasoning has to be re-argued rather than inherited.
#[test]
fn both_encrypted_state_keys_are_still_present_on_both_twins() {
    let _lock = lock();

    let mut d = device();
    let keys = region_boot::top_level_keys(&get_info_device(&mut d));
    for key in [ENC_IDENTIFIER, ENC_CRED_STORE_STATE] {
        assert!(
            keys.contains(&key),
            "device twin getInfo must still carry key {key:#04x}"
        );
    }

    let mut h = host();
    let keys = region_boot::top_level_keys(&get_info_host(&mut h));
    for key in [ENC_IDENTIFIER, ENC_CRED_STORE_STATE] {
        assert!(
            keys.contains(&key),
            "host twin getInfo must still carry key {key:#04x}"
        );
    }
}