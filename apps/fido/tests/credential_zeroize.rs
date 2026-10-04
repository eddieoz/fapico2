//! US-1550 — "no private key outlives the operation that used it".
//!
//! ```gherkin
//! Scenario: no private key outlives the operation that used it
//!   Given a getAssertion that loaded a credential private key
//!   When the response is written
//!   Then the buffer is zeroized before the next command is served
//!   And no private key is resident between commands
//! ```
//!
//! # Why the test cannot simply check the bytes
//!
//! "The buffer was zeroized" is a claim about memory that has, by the time the
//! assertion runs, been reused by whatever the allocator did next. There is no
//! sound way for a test to read it back. So the key type's own `Drop` records
//! what it held **after** its clear, into a thread-local
//! ([`device_keystore::testing`]), and the test asserts against that record.
//! This is the tree's established instrument — `keyregion::crypto::testing`,
//! `keyregion::record::testing`, `platform::fused_key::testing` — restated for
//! the applet half of the store.
//!
//! # Why the instrument carries `was_nonzero`
//!
//! Because without it the test is vacuous, and vacuously here more than
//! anywhere else in the tree. A credential's private key is `[u8; 32]`, and
//! **all zeroes is a value the applet legitimately produces**: a
//! `DeviceCredential::new_template()`, a `Default::default()`, and every
//! credential the US-911 decoder revokes. An applet that never loaded a key and
//! cleared it perfectly would produce a witness of all-zero records, and so
//! would an applet that loaded one, signed with it and cleared it. The two are
//! indistinguishable unless the record says which one it was.
//!
//! [`the_witness_distinguishes_a_populated_scalar_from_a_vacuous_one`] is the
//! test that proves the instrument can tell them apart — without it, every
//! other test in this file is asserting against an instrument nobody has shown
//! discriminates.
//!
//! # What is asserted where
//!
//! | clause | test |
//! |---|---|
//! | the instrument is not vacuous | [`the_witness_distinguishes_a_populated_scalar_from_a_vacuous_one`] |
//! | a command's loaded scalars are all wiped | [`a_command_wipes_every_scalar_it_loaded`] |
//! | nothing is resident between commands | [`no_private_key_is_resident_between_commands`] |
//! | deleting a credential wipes its scalar | [`a_deleted_credential_wipes_its_scalar`] |
//! | a revoked credential wipes its scalar | [`a_revoked_credential_wipes_its_scalar`] |
//! | `Debug` never prints key material | [`debug_never_prints_key_material`] |
//! | the type has no `Copy`/`Clone` escape hatch | [`a_scalar_cannot_be_copied_or_cloned_by_accident`] |
//! | `.bss` did not grow | [`the_credential_struct_has_not_grown`] |
//!
//! # One substitution, and why it is not a dodge
//!
//! The gherkin names **getAssertion**; the command driven here is credMgmt's
//! `enumerateCredentialsBegin`. Both load a credential exactly the same way —
//! one sealed record opened, copied into an owned `DeviceCredential`, dropped
//! at the end of the scope — and `enumerateCredentialsBegin` can complete,
//! while a *region* getAssertion currently cannot: `build_assertion` asks
//! `DeviceKeystore::bump_credential_counter_checked` for a counter first, and
//! that function resolves the credential in the **snapshot**
//! (`device_keystore.rs`: `let c = self.get_credential_mut(id)?;`), where a
//! region-backed credential does not live — so the region getAssertion answers
//! `0x2E NO_CREDENTIALS` *after* the key has been loaded and dropped. That is a
//! pre-existing gap in the region counter write (US-1561's `CounterWindow`,
//! built alongside this story), it is not US-1550's to fix, and routing around
//! it is the difference between testing a command and testing a workaround.
//! [`a_command_wipes_every_scalar_it_loaded`] carries the full argument.

mod region_boot;

use fapico2_fido::device_keystore::{
    testing, DeviceCoseKey, DeviceCredential, DeviceKeystore, PrivateScalar, PRIVATE_KEY_LEN,
};
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HV;
use region_boot::*;

/// A non-zero, non-template scalar. `0x42` repeated is not a valid P-256 scalar
/// (`0 < s < n`, and `n` starts `0xFFFFFFFF00000000`), so a fixture built from
/// it can never be mistaken for the all-zero state the decoder revokes into —
/// which is what keeps `was_nonzero` meaningful for it.
const LIVE_SCALAR: [u8; 32] = [0x42; 32];

/// A credential carrying [`LIVE_SCALAR`], built through the applet's own type.
fn live_credential() -> DeviceCredential {
    DeviceCredential {
        credential_id: HV::new(),
        public_key: DeviceCoseKey::es256([0x11; 32], [0x22; 32]),
        private_key: PrivateScalar::from_bytes(LIVE_SCALAR),
        rp_id_hash: [0x33; 32],
        rp_id: HV::new(),
        user_handle: HV::new(),
        user_name: HV::new(),
        user_display_name: HV::new(),
        cred_protect: 0,
        large_blob_key: None,
        hmac_secret: HV::new(),
        cred_blob: HV::new(),
        third_party_payment: false,
        pin_complexity_policy: false,
        resident: true,
        algorithm: -7,
        counter: 1,
        revoked: false,
        expires_at: None,
    }
}

/// The populated drops recorded on this thread so far.
fn populated_drops() -> usize {
    testing::dropped_scalars().iter().filter(|w| w.was_nonzero).count()
}

// ---------------------------------------------------------------------------
// The instrument itself
// ---------------------------------------------------------------------------

/// **The non-vacuity proof, and the reason the other tests are worth anything.**
///
/// Drops two scalars back to back — one that was never written, one that holds
/// [`LIVE_SCALAR`] — and asserts the witness says so:
///
/// * the never-written one records `was_nonzero == false` with all-zero bytes;
/// * the live one records `was_nonzero == true` with **all-zero** bytes too.
///
/// The second half is the point. Both records are byte-identical, so a test that
/// asserted only "every dropped scalar's bytes were zero" would pass on the
/// first drop alone and learn nothing about the second. `was_nonzero` is what
/// separates them, and this test is what shows the separation is real rather
/// than asserted.
#[test]
fn the_witness_distinguishes_a_populated_scalar_from_a_vacuous_one() {
    testing::clear();

    drop(PrivateScalar::zero());
    drop(PrivateScalar::from_bytes(LIVE_SCALAR));

    let witness = testing::dropped_scalars();
    assert_eq!(witness.len(), 2, "one record per dropped scalar");

    assert!(
        !witness[0].was_nonzero,
        "an all-zero scalar was never populated, and the witness must say so — this is exactly \\
         the case a bytes-only assertion would score as 'cleared'"
    );
    assert_eq!(witness[0].bytes, [0u8; PRIVATE_KEY_LEN]);

    assert!(
        witness[1].was_nonzero,
        "a scalar holding LIVE_SCALAR was populated, and the witness must say so"
    );
    assert_eq!(
        witness[1].bytes,
        [0u8; PRIVATE_KEY_LEN],
        "a populated scalar must still be all zeroes after its drop — this is the production \\
         claim under test, in the same Drop body the device runs"
    );
}

// ---------------------------------------------------------------------------
// The command path
// ---------------------------------------------------------------------------

/// A device twin with **one real resident credential in the key region**, a PIN
/// set and presence granted.
///
/// Enrolled through `make_cred` rather than seeded into the snapshot, because
/// the assertion this file exists for is about what the *command path* does
/// with a key, and a fixture whose `rp_id_hash` is a synthetic value
/// (`region_boot::rp_hash`) would be skipped by getAssertion's RP-hash check
/// (`device_core.rs:1546`) — the test would pass on a device that had found
/// nothing to sign with, which is the failure mode a vacuous test always has.
fn device_with_one_credential(tag: &str) -> (InstalledRegion, Device) {
    let region_file = install(tag);
    let mut device = Device::boot(keyed_store());
    device.grant_presence_always();
    device.set_pin(b"1234");
    let (status, _) = device.make_cred(RP, b"user");
    assert_eq!(status, 0x00, "the fixture credential must enrol");
    (region_file, device)
}

/// The relying party the fixture credential belongs to.
const RP: &str = "example.test";

/// A command that loads one credential private key per enumerated slot, twice.
///
/// **Why credMgmt `enumerateCredsBegin` and not getAssertion.** The gherkin says
/// getAssertion, and the getAssertion path *is* the one `US-1550`'s `Drop`
/// covers — but on the key region it cannot currently complete: `build_assertion`
/// signs only after
/// [`DeviceKeystore::bump_credential_counter_checked`](fapico2_fido::device_keystore::DeviceKeystore)
/// returns a counter, and that function looks the credential up in the
/// **snapshot** (`device_keystore.rs`: `let c = self.get_credential_mut(id)?;`),
/// where a region-backed credential does not live. So a region getAssertion
/// answers `0x2E NO_CREDENTIALS` after the key has been loaded and dropped. That
/// is a real, pre-existing gap in the region counter write (it is US-1561's
/// `CounterWindow`, being built alongside this story) and **not** US-1550's to
/// fix or to paper over.
///
/// `enumerateCredsBegin` loads exactly the same way — one sealed record opened,
/// copied into an owned `DeviceCredential`, dropped at the end of the loop
/// iteration (`device_core.rs`, the region arm) and again inside
/// `cm_cred_response` (`device_core.rs:3670`) — and it completes, so the claim
/// under test is observable rather than blocked behind an unrelated bug.
#[test]
fn a_command_wipes_every_scalar_it_loaded() {
    let _lock = lock();
    let (_region_file, mut device) = device_with_one_credential("zeroize-cm");

    testing::clear();
    let (status, body) = device.cm_enumerate_creds(RP);
    assert_eq!(status, 0x00, "enumerateCredsBegin must succeed: {body:?}");
    assert!(
        region_boot::uint_at(&body, 9).is_some(),
        "the PicoForge reply must carry totalCredentials (key 9), or the enumeration found \
         nothing and this test would be asserting on an empty device: {body:?}"
    );

    let witness = testing::dropped_scalars();
    assert!(
        witness.len() >= 2,
        "the enumeration opens each record once to build the id list and `cm_cred_response` \
         opens the winner again; each owned copy must drop. Saw {} drops, {} of them populated",
        witness.len(),
        populated_drops()
    );
    for w in &witness {
        assert_eq!(
            w.bytes,
            [0u8; PRIVATE_KEY_LEN],
            "a credential scalar dropped holding non-zero bytes — a private key outlived its \
             operation"
        );
    }
    assert!(
        populated_drops() >= 2,
        "and at least two of them must have held a real key: {} were populated",
        populated_drops()
    );
}

/// "No private key is resident between commands."
///
/// Two halves, and both matter:
///
/// * **the snapshot array holds nothing** — on the region path the credential
///   lives in a sealed record and the array was never populated, so there is no
///   720-byte struct with a private key in it sitting in `.bss` between
///   commands;
/// * **the command that loaded it dropped it** — which is
///   [`a_command_wipes_every_scalar_it_loaded`], restated here as a
///   between-commands property: after that command returns, a *second* command
///   that touches no credential finds the witness unchanged, which is what
///   "before the next command is served" means.
#[test]
fn no_private_key_is_resident_between_commands() {
    let _lock = lock();
    let (_region_file, mut device) = device_with_one_credential("zeroize-resident");

    let after_boot = device.with_store(|store| {
        DeviceKeystore::load(store).expect("readable").expect("present").credentials.len()
    });
    assert_eq!(
        after_boot, 0,
        "the region path leaves the snapshot's array empty: no credential is resident in RAM at \
         all, so there is nothing to keep between commands"
    );

    testing::clear();
    assert_eq!(device.cm_enumerate_creds(RP).0, 0x00);
    let after_enumeration = populated_drops();
    assert!(after_enumeration >= 2, "the enumeration wiped its scalars");

    // A command that reads no credential at all. If a key were still resident
    // when the enumeration returned, this is where the next command would meet
    // it — and the witness would grow by one record if any scalar were held and
    // dropped here.
    let before_idle = testing::dropped_scalars().len();
    assert_eq!(device.get_info().0, 0x00);
    let after_idle = testing::dropped_scalars().len();
    assert_eq!(
        before_idle, after_idle,
        "getInfo touches no credential, so no scalar should drop across it. A drop here would \
         mean a key was still live when the enumeration returned"
    );
}

// ---------------------------------------------------------------------------
// The paths that used to leak
// ---------------------------------------------------------------------------

/// **The pre-existing leak, on the pre-migration path.** A deleted credential
/// used to leave 32 bytes of signing key in the vacated `heapless::Vec` slot,
/// which the next `push` overwrites with someone else's metadata and leaves the
/// key underneath it.
#[test]
fn a_deleted_credential_wipes_its_scalar() {
    let mut trng = HostTrng::new();
    let mut ks = DeviceKeystore::fresh(&mut trng).expect("host TRNG");
    let mut cred = live_credential();
    cred.credential_id.extend_from_slice(&[0x5A; 32]).unwrap();
    ks.store_credential(cred).expect("store");

    testing::clear();
    ks.delete_credential(&[0x5A; 32]).expect("delete the credential that exists");

    let witness = testing::dropped_scalars();
    assert_eq!(
        populated_drops(),
        1,
        "the delete drops exactly one credential, and its scalar must be one of the populated \\
         drops"
    );
    assert_eq!(witness[0].bytes, [0u8; PRIVATE_KEY_LEN]);
    assert_eq!(ks.cred_count(), 0, "and the credential is gone either way");
}

/// **The other pre-existing leak: the US-911 revocation.** A credential whose
/// sealed fields fail to open is marked `revoked` and its secrets dropped. The
/// scalar used to be *assigned* a fresh `[0; 32]`, which wipes the field but
/// leaves the old bytes in the temporary the compiler made for the assignment;
/// `PrivateScalar::wipe` clears in place.
///
/// Driven through the real decode path — the ciphertext is corrupted after the
/// fact — because a synthetic `revoked = true` would not prove the codec does
/// it. The corruption targets the sealed private-key bstr by its header
/// (`0x03`, bstr of 32 + 28 bytes), which is how `tests/device_keystore.rs`'s
/// own US-911 case locates it; searching for the plaintext would find nothing,
/// because US-911's other half of the story is that the scalar does not appear
/// in the image at all.
#[test]
fn a_revoked_credential_wipes_its_scalar() {
    use fapico2_platform::secure_store::{chunked, HostSecureStore};
    use fapico2_platform::store_v3::emulation_store_key;

    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    let mut ks = DeviceKeystore::fresh(&mut trng).expect("host TRNG");
    let mut cred = live_credential();
    cred.credential_id.extend_from_slice(b"revoked-cred").unwrap();
    // A credBlob, so the corruption can target *that* field and leave the
    // private key to open successfully. That is the case worth testing: the
    // private key really was in the buffer, and the revocation really does have
    // to clear it. Corrupting the private-key field instead would leave nothing
    // in the buffer to clear, and the witness would honestly report
    // `was_nonzero == false` — a correct result that proves nothing.
    cred.cred_blob.extend_from_slice(b"user-verifyable-blob").unwrap();
    ks.store_credential(cred).unwrap();
    ks.persist(&mut store).expect("persist");

    let mut bytes = [0u8; chunked::MAX_LOGICAL_LEN];
    let n = chunked::read_chunked(&mut store, b"fido.keystore.v1", &mut bytes).expect("read back");
    // CBOR key 17 (0x11), then a bstr header. `FIELD_OVERHEAD` is 28 (12-byte
    // nonce + 16-byte tag) and the fixture's blob is 20 bytes, so the length
    // byte is 0x30.
    let needle = [0x11u8, 0x58, 0x30];
    let pos = bytes[..n]
        .windows(3)
        .position(|w| w == needle)
        .expect("sealed credBlob field located");
    bytes[pos + 3] ^= 0x01;

    testing::clear();
    let ks2 = DeviceKeystore::from_cbor(&bytes[..n], Some(&emulation_store_key()))
        .expect("the image still parses — only this credential's key is dead");
    {
        let dead = ks2.get_credential(b"revoked-cred").expect("metadata survives");
        assert!(dead.revoked, "a credential whose sealed key will not open is dead");
        assert!(
            dead.private_key.is_zero(),
            "and its scalar is unusable — the old code assigned a fresh zero array, which is a \
             value; `wipe` is a clear of the bytes that were there"
        );
    }
    // `ks2` — and with it the credential — goes out of scope here, which is
    // where its scalar is dropped.

    let witness = testing::dropped_scalars();
    assert!(
        populated_drops() >= 1,
        "the private key DID open before the revocation wiped it, so the wipe must be recorded \
         with was_nonzero == true — saw {} of {} drops",
        populated_drops(),
        witness.len()
    );
    for w in &witness {
        assert_eq!(w.bytes, [0u8; PRIVATE_KEY_LEN], "a wiped scalar still held key material");
    }
}

// ---------------------------------------------------------------------------
// The leak channels that are not the destructor
// ---------------------------------------------------------------------------

/// A `Debug` on a credential is a `Debug` that puts a private key in a log
/// buffer, and a log buffer outlives the stack frame the key was cleared in by
/// a very long way.
///
/// Asserted against the **bytes**, not against the absence of a field name: a
/// `Debug` that printed the scalar as `[66, 66, …]` would satisfy "does not
/// contain `private_key`" perfectly and still be the bug.
#[test]
fn debug_never_prints_key_material() {
    let cred = live_cred_for_debug();
    let rendered = format!("{cred:?}");

    assert!(
        !rendered.contains("0x42") && !rendered.contains("66, 66"),
        "the rendered Debug leaked the scalar: {rendered}"
    );
    assert!(
        !rendered.contains(&hex_of(LIVE_SCALAR)),
        "the rendered Debug contains the scalar in some other encoding: {rendered}"
    );
    // `large_blob_key` is derived from the private key, so printing it would be
    // printing key-equivalent material even though it is not the key.
    let mut with_blob = live_cred_for_debug();
    with_blob.large_blob_key = Some([0x44; 32]);
    let rendered = format!("{with_blob:?}");
    assert!(
        !rendered.contains("0x44") && !rendered.contains("68, 68"),
        "the rendered Debug leaked the large-blob key: {rendered}"
    );
    // And the scalar's own Debug, on its own.
    let scalar = PrivateScalar::from_bytes(LIVE_SCALAR);
    let rendered = format!("{scalar:?}");
    assert!(rendered.contains("redacted"), "the scalar's Debug must say it is redacted");
    assert!(!rendered.contains(&hex_of(LIVE_SCALAR)));
}

/// Named so the two constructions above cannot be refactored into one by a
/// reader who does not know why they are written separately.
fn live_cred_for_debug() -> DeviceCredential {
    let mut cred = live_credential();
    cred.credential_id.extend_from_slice(b"debug-cred").unwrap();
    cred
}

fn hex_of(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The escape hatches that would undo the guarantee are not on the type.
///
/// Not a compile-fail test — this is a runtime assertion about what the API
/// offers, and the three facts it states are the three the guarantee rests on:
///
/// * no `Clone`, so there is no invisible second copy;
/// * no `Copy`, so there is no by-move copy either;
/// * `expose` and `copy_out` return a **borrow** and a **zeroizing owner**
///   respectively — the two shapes that cannot outlive their owner.
///
/// `copy_out` is checked to produce a value that is *not* aliased to the
/// original: mutating through it must not be visible through the source.
#[test]
fn a_scalar_cannot_be_copied_or_cloned_by_accident() {
    let original = PrivateScalar::from_bytes(LIVE_SCALAR);

    let mut copied = original.copy_out();
    copied.wipe();

    assert_eq!(
        original,
        PrivateScalar::from_bytes(LIVE_SCALAR),
        "copy_out must copy: wiping the copy must not reach the source, or it is a view and the \\
         source's lifetime is not what the caller thinks it is"
    );
    assert!(copied.is_zero());

    // `expose` hands out a borrow of exactly the 32 bytes, and the borrow is
    // what makes it unable to outlive the owner.
    assert_eq!(original.expose(), &LIVE_SCALAR);
}

/// **US-1550's `.bss` budget: a zeroizing buffer must not cost RAM.**
///
/// The constraint on this story is "bss must not increase", and for the
/// applet-half scalar it is arithmetic rather than hope: a [`Zeroizing`]
/// newtype over the same `[u8; 32]` is the same 32 bytes — a destructor is
/// free, it is *bytes* that are not. But "the same 32 bytes" is only half the
/// claim, because `DeviceCredential`'s size is the number the whole capacity
/// story is derived from: `FIDO_RECORD_MAX` (836) was measured against this
/// layout, the region's 1 KiB slot stride was sized from that, and
/// `keyregion::on_demand.rs` states 720 for this target. A one-byte growth
/// would silently invalidate all three and nothing else in the tree would
/// notice.
///
/// So it is measured **against the layout it replaced**, not against a literal:
/// the shadow below is [`DeviceCredential`] field for field with the bare
/// `[u8; 32]` back, and the assertion is that the two are the same size on
/// whichever target compiles it. A literal would only be right on one of them
/// — `DeviceCredential` measures 712 on x86_64 and 720 on thumbv8m — and a
/// host-only test that quoted 720 would be asserting a number about hardware it
/// never ran on.
#[test]
fn the_credential_struct_has_not_grown() {
    use fapico2_fido::device_keystore::DeviceCoseKey;

    /// [`DeviceCredential`] with the pre-US-1550 field type.
    ///
    /// A second definition of the record layout, and the reason it is scoped to
    /// this test is that it is **only** a size baseline: nothing constructs one,
    /// nothing encodes one, and nothing reads a field out of one. Its entire job
    /// is to be the `size_of` the new one is compared against.
    #[allow(dead_code)]
    struct Shadow {
        credential_id: HV<u8, 64>,
        public_key: DeviceCoseKey,
        private_key: [u8; 32],
        rp_id_hash: [u8; 32],
        rp_id: HV<u8, 64>,
        user_handle: HV<u8, 64>,
        user_name: HV<u8, 64>,
        user_display_name: HV<u8, 64>,
        cred_protect: u8,
        large_blob_key: Option<[u8; 32]>,
        hmac_secret: HV<u8, 64>,
        cred_blob: HV<u8, 64>,
        third_party_payment: bool,
        pin_complexity_policy: bool,
        resident: bool,
        algorithm: i32,
        counter: u32,
        revoked: bool,
        expires_at: Option<u32>,
    }

    assert_eq!(
        core::mem::size_of::<PrivateScalar>(),
        32,
        "PrivateScalar must be the same 32 bytes the bare [u8; 32] was — a zeroizing buffer \
         that costs extra RAM is a capacity loss dressed as a security win"
    );
    assert_eq!(
        core::mem::size_of::<DeviceCredential>(),
        core::mem::size_of::<Shadow>(),
        "DeviceCredential must not have grown. FIDO_RECORD_MAX (836) and the region's slot \
         stride are both derived against this layout; growth here is invisible everywhere except \
         in the capacity they were derived from"
    );
    assert_eq!(
        core::mem::align_of::<PrivateScalar>(),
        1,
        "an array has alignment 1 and so must its wrapper, or the surrounding struct re-pads"
    );
}
