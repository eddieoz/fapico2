//! US-1560 — "a key-region failure degrades to an empty key set".
//!
//! ```gherkin
//! Scenario: an unreadable key region does not stop the device
//!   Given the key region erased, corrupt or backed by a failing store
//!   When the device boots and enumerates
//!   Then getInfo succeeds and reports zero remaining credentials
//!   And getAssertion answers a clean CTAP error
//!   And MakeCredential answers KeyStoreFull
//!   And the device stays responsive
//!
//! Scenario: the degradation is at the applet layer, not the boot layer
//!   Given the failure is confined to the key region
//!   Then no fatal_boot call is reachable from the key-region read path
//!   And the OATH applet reports an empty credential set rather than refusing
//! ```
//!
//! # Where this firmware reports "zero remaining credentials"
//!
//! **A note on the gherkin's wording, because it changes what these tests
//! assert.** `authenticatorGetInfo` in this build has no
//! `remainingDiscoverableCredentialsCount` member — `ctap2::Ctap2Info` has never
//! carried one, and adding a getInfo field is a wire change on every device,
//! outside two stories about what happens to a store. The credential count this
//! firmware puts on the wire is credMgmt `getCredsMetadata`'s (keys 1/2, plus
//! key 3 as the PicoForge extension), and that is what these tests read.
//! `getInfo` is pinned separately, as **succeeding and answering the full map**,
//! which is the other half of the same clause and the half a brick would fail.
//!
//! # What is *not* relaxed here, and why
//!
//! The EPIC records a correction: the failure is injected **at the key region**,
//! not at `read_otp_key_1`. A cold OTP array halts the board today for four
//! pre-existing reasons — `derive_boot_store_key` (`firmware/src/boot.rs:1326`),
//! `init_drbg` (`boot.rs:716`), `derive_oath_seal` (`boot.rs:1346`) and the
//! migration authority (`boot.rs:285`) — all of them before `RUNG_USB`, and none
//! of them this epic's to change. What US-1560 owns is narrower and is the
//! second scenario's own words: **the degradation is at the applet layer**. So
//! [`no_new_halt_site_is_reachable_from_the_key_region`] counts the sites, and
//! [`an_unreadable_region_degrades_to_an_empty_key_set`] shows the applet layer
//! answering rather than refusing.
//!
//! # The `KeyStoreFull` answer is deliberate, not a limitation
//!
//! `device_core.rs`'s store arm reverts the counter bump and answers
//! `KeyStoreFull` for **any** failure to make the credential durable — a flash
//! that is merely sick included. Its comment names the reason: a distinct error
//! for "the flash is failing" would tell a user their authenticator is full,
//! which is a claim about capacity the device never established. `AGENTS.md` §4
//! is about a wire claim the device does not honour, and refusing to make one is
//! what this is.

mod region_boot;

use fapico2_platform::keyregion::host::{Faults, FileKeyRegion};
use fapico2_platform::keyregion::{SlotRead, FIDO_SLOT_BYTES};
use region_boot::*;

/// `CTAP2_ERR_NO_CREDENTIALS` (`ctap2.rs`) — the clean error a sick region must
/// answer a getAssertion with.
const NO_CREDENTIALS: u8 = 0x2E;
/// `CTAP2_ERR_KEY_STORE_FULL` — `Ctap2Response::KeyStoreFull`.
const KEY_STORE_FULL: u8 = 0x28;

/// One resident credential, enrolled **into the region**, plus the region file.
///
/// Booted with an empty snapshot, so the enrolment takes the region path and
/// the snapshot's array stays empty. That is what makes every later assertion
/// about the region rather than about the snapshot.
///
/// The caller must already hold [`region_boot::lock`] — this returns while still
/// holding it, so the region stays single-threaded for the rest of the test.
fn provisioned(tag: &str) -> (InstalledRegion, Device) {
    let region_file = install(tag);
    let mut device = Device::boot(keyed_store());
    device.set_pin(b"123456");
    let (status, cbor) = device.make_cred("example.test", b"user-1");
    assert_eq!(status, 0x00, "makeCredential into the region: {cbor:02x?}");
    (region_file, device)
}

// ---------------------------------------------------------------------------
// Scenario: an unreadable key region does not stop the device
// ---------------------------------------------------------------------------

#[test]
fn an_unreadable_region_degrades_to_an_empty_key_set() {
    let _lock = lock();
    let (region_file, mut device) = provisioned("degrade-read");

    // **The failure.** Every `read_slot` on the region now fails at the
    // transport — `FileKeyRegion`'s own fault injector, the same one
    // `key_region_one_record.rs` uses, so nothing here damages the file.
    region_file.with(|r| r.inject_faults(Faults { reads: true, ..Faults::default() }));

    // 1. getInfo succeeds, and answers the full map rather than a stub.
    let (status, info) = device.get_info();
    assert_eq!(status, 0x00, "getInfo must succeed against a sick region");
    assert!(!info.is_empty(), "and must answer a real info map: {info:02x?}");

    // 2. …and reports zero remaining credentials. `remaining_capacity` is `None`
    //    on a fault — "the index could not be read" is not "the device is full" —
    //    so the credMgmt arm falls to its conservative answer.
    let (status, cbor) = device.cm_get_metadata();
    assert_eq!(status, 0x00, "getCredsMetadata must succeed: {cbor:02x?}");
    assert_eq!(
        uint_at(&cbor, 2),
        Some(0),
        "a region we could not measure must be reported as taking no further \
         credential — the conservative direction (AGENTS.md §4: never promise \
         capacity that was not established)",
    );

    // 3. getAssertion answers a clean CTAP error, not a transport failure and
    //    not a panic.
    let (status, body) = device.get_assertion("example.test", None);
    assert_eq!(
        status, NO_CREDENTIALS,
        "a sick region must answer a clean CTAP error, got {status:#04x} / {body:02x?}",
    );

    // 4. MakeCredential answers KeyStoreFull — a capacity statement the device
    //    *can* stand behind: it has nowhere to put the credential.
    let (status, body) = device.make_cred("example.test", b"user-2");
    assert_eq!(
        status, KEY_STORE_FULL,
        "makeCredential against a sick region must be refused cleanly, got \
         {status:#04x} / {body:02x?}",
    );

    // 5. The device stays responsive…
    let (status, _) = device.get_info();
    assert_eq!(status, 0x00, "getInfo after the failures");
    let (status, _) = device.cm_get_metadata();
    assert_eq!(status, 0x00, "credMgmt after the failures");

    // …and recovers the moment the medium does.
    region_file.with(|r| r.inject_faults(Faults::default()));
    let (status, body) = device.make_cred("example.test", b"user-3");
    assert_eq!(status, 0x00, "and the same device enrols once the region works: {body:02x?}");
}

#[test]
fn a_region_that_refuses_writes_degrades_the_same_way() {
    let _lock = lock();
    let (region_file, mut device) = provisioned("degrade-write");

    // Reads work; erases and programs do not. This is the write-only failure,
    // and it has to reach the **same** answers: a device that can read its
    // index and cannot write a record is a device that must not pretend either
    // happened.
    region_file
        .with(|r| r.inject_faults(Faults { erases: true, programs: true, ..Faults::default() }));

    let (status, info) = device.get_info();
    assert_eq!(status, 0x00, "getInfo");
    assert!(!info.is_empty());

    // The index still reads, so this is the case where the count comes from a
    // *measurement* rather than from a fault.
    let (status, cbor) = device.cm_get_metadata();
    assert_eq!(status, 0x00, "getCredsMetadata: {cbor:02x?}");
    assert_eq!(uint_at(&cbor, 1), Some(1), "the existing credential is still counted");

    let (status, _) = device.make_cred("example.test", b"user-9");
    assert_eq!(status, KEY_STORE_FULL, "an unwritable region refuses the enrolment");

    let (status, _) = device.get_info();
    assert_eq!(status, 0x00, "still responsive");
}

#[test]
fn a_corrupt_record_costs_itself_alone_and_the_device_still_answers() {
    let _lock = lock();
    let region_file = install("degrade-corrupt");
    let mut device = Device::boot(keyed_store());
    device.set_pin(b"123456");
    assert_eq!(device.make_cred("example.test", b"user-1").0, 0x00);

    let keys = device.with_store(|s| {
        let ks = fapico2_fido::device_keystore::DeviceKeystore::load(s)
            .expect("readable")
            .expect("present");
        region_keys(s, &ks)
    });

    // **Corrupt**, not erased: the index still points at the slot and the slot
    // no longer opens. This is the distinction US-1573 draws — a transport
    // failure and an absent record both answer "nothing here" if the API returns
    // `None` for both, and only one of them may be memoized as absence.
    let slot = {
        let mut region = FileKeyRegion::open(region_file.path()).expect("the region");
        let mut creds =
            fapico2_fido::device_keystore::RegionCredentials::new(&mut region, &keys);
        creds.nth_entry_slot(0).expect("the enrolled credential has an index entry")
    };

    // Scramble the slot's header bytes directly. `FileKeyRegion::program` would
    // refuse this — NOR cannot set a bit from 0 back to 1 — which is exactly why
    // corruption is modelled as damage from outside rather than as a write.
    {
        let path = region_file.path();
        let mut bytes = std::fs::read(path).expect("read the region file");
        let at = slot.index() as usize * FIDO_SLOT_BYTES as usize;
        for b in bytes[at..at + 64].iter_mut() {
            *b ^= 0xA5;
        }
        std::fs::write(path, bytes).expect("write the scrambled region");
    }

    // The header CRC now fails, so `KeyRegion::read_slot` reports the slot erased
    // (`keyregion/mod.rs`: "a slot whose header CRC fails is reported as
    // all-0xFF (erased), because a record that cannot be authenticated is not a
    // record") and nothing opens.
    let (status, _) = device.get_info();
    assert_eq!(status, 0x00, "getInfo survives a corrupt record");
    let (status, body) = device.get_assertion("example.test", None);
    assert_eq!(
        status, NO_CREDENTIALS,
        "the corrupt credential is unreachable, and only it: {body:02x?}",
    );
    let (status, body) = device.make_cred("example.test", b"user-2");
    assert_eq!(
        status, 0x00,
        "and the device still enrols a new credential — one bad record must not \
         take the store with it (US-1549): {body:02x?}",
    );

    // The entry is still counted, because the index still holds it. That is the
    // honest direction: the device reports what it can *see*, and re-enrolling
    // the credential is what repairs it.
    let (status, cbor) = device.cm_get_metadata();
    assert_eq!(status, 0x00, "getCredsMetadata: {cbor:02x?}");
    assert_eq!(uint_at(&cbor, 1), Some(2), "the index is what a credential count counts");
}

// ---------------------------------------------------------------------------
// Scenario: the degradation is at the applet layer, not the boot layer
// ---------------------------------------------------------------------------

/// The repository root, from this test's own manifest directory.
///
/// `CARGO_MANIFEST_DIR` is `apps/fido`, so two levels up is the workspace —
/// which matters, because the assertion is about files in **three** crates
/// (`firmware/`, `apps/`, `platform/`). A relative guess would pass in one
/// checkout and quietly scan nothing in another.
fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("apps/fido has a workspace two levels up")
        .to_path_buf()
}

/// Every `.rs` file under `rel`, recursively.
fn rust_files(rel: &str) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![repo_root().join(rel)];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Real `fatal_boot` call sites under `rel` — `rel`, the line, and the line.
///
/// # Why this counts what it counts
///
/// A naive `grep -rn "fatal_boot"` over the tree returns 51 lines, of which
/// **28 are prose**: doc comments, module docs and test commentary explaining
/// *why* a path does not halt. Counting those would make the number a measure of
/// how well this epic is documented, and a story that documents itself well
/// would look like a story that added a halt site. So the filter drops three
/// shapes and nothing else:
///
/// * a line whose first non-space character is `/` — a `//` or `///` comment;
/// * `pub fn fatal_boot` — the definition, not a call to it;
/// * a line naming `fatal_boot::` — a path reference, which this tree does not
///   use today but which is not an invocation.
///
/// What survives is a line that *calls* `fatal_boot(`. 23 of them: 18 in
/// `boot.rs`, 5 in `main.rs`, and none anywhere else.
fn fatal_boot_call_sites(rel: &str) -> Vec<String> {
    let mut out = Vec::new();
    for path in rust_files(rel) {
        // **This file, skipped.** The scanner has to spell `fatal_boot(` in its
        // own source — that is what it is scanning for — so including it makes
        // the count one higher than the truth and the test unrunnable, which is
        // a worse failure than the one it exists to catch. Everything else under
        // `apps/` is counted, tests included.
        if path.ends_with("tests/region_degradation.rs") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        for (n, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if !trimmed.contains("fatal_boot(") {
                continue;
            }
            if trimmed.starts_with("//") || trimmed.starts_with("pub fn fatal_boot") {
                continue;
            }
            out.push(format!("{}:{}: {}", path.display(), n + 1, trimmed.trim()));
        }
    }
    out
}

/// Every `fatal_boot` call site in the three trees the brief names.
fn all_halt_sites() -> Vec<String> {
    fatal_boot_call_sites("firmware/src")
        .into_iter()
        .chain(fatal_boot_call_sites("apps"))
        .chain(fatal_boot_call_sites("platform/src"))
        .collect()
}

#[test]
fn no_new_halt_site_is_reachable_from_the_key_region() {
    // **The epic's own number.** Measured before US-1558/US-1560 and required to
    // be unchanged by them: this epic adds no halt site.
    //
    // All 23 are in `firmware/src` — `boot.rs` and `main.rs` — which is the other
    // reason the count is a meaningful assertion: nothing this epic touched
    // could have added one, so the test says so about the tree rather than about
    // one directory.
    let sites = all_halt_sites();
    assert_eq!(sites.len(), 23, "the fatal_boot call-site count must not change:\n{}", sites.join("\n"));

    // **The second scenario's first clause, checked where it can actually
    // fail.** Not "the total is 23" — "there is no `fatal_boot` anywhere under
    // `platform/src/keyregion/`", which is the claim: a key-region read that
    // halts is exactly the failure S10 exists to prevent, and it would be
    // invisible in the total if someone removed a site somewhere else.
    let region = fatal_boot_call_sites("platform/src/keyregion");
    assert!(region.is_empty(), "the key region must not be able to halt the board:\n{}", region.join("\n"));

    // And the same for the three applet files this epic changed, which are on
    // the read path the degradation runs through.
    for file in [
        "apps/fido/src/device_app.rs",
        "apps/fido/src/device_keystore.rs",
        "apps/fido/src/device_core.rs",
    ] {
        let sites = fatal_boot_call_sites(file);
        assert!(sites.is_empty(), "{file} is on the key-region read path and must not halt:\n{}", sites.join("\n"));
    }
}

#[test]
fn the_oath_applet_reports_an_empty_credential_set_rather_than_refusing() {
    // `apps/oath` and `platform/src/keyregion/oath_store.rs` are **not this
    // story's files** — the brief assigns them to another agent — so what is
    // pinned here is the *invariant* the second scenario names, at the level
    // this test can reach without duplicating behaviour that already has a
    // test: no halt site in the OATH applet, and none in the OATH half of the
    // region.
    //
    // The behavioural half is `oath_core.rs`'s `RegionStatus::Degraded` path and
    // `oath_store.rs`'s "Degrade, never halt" section, exercised by `apps/oath`'s
    // own suite. Re-asserting them from here would be a second definition of a
    // behaviour that has a test — `AGENTS.md` §5's "two files describing one
    // layout".
    let oath = fatal_boot_call_sites("apps/oath/src");
    assert!(oath.is_empty(), "the OATH applet must not halt on a key-region failure:\n{}", oath.join("\n"));

    let store = fatal_boot_call_sites("platform/src/keyregion/oath_store.rs");
    assert!(store.is_empty(), "and neither must the OATH half of the region:\n{}", store.join("\n"));
}

#[test]
fn an_absent_region_is_a_degradation_and_not_a_halt() {
    // The provider is uninstalled — which is every host build, and a device
    // before `boot::release_key_region()`. `region_keys_for` answers `None`, the
    // snapshot is the store, and the device serves.
    let _lock = lock();
    let mut device = Device::boot(keyed_store());
    device.set_pin(b"123456");

    let (status, _) = device.get_info();
    assert_eq!(status, 0x00, "getInfo with no region at all");
    let (status, _) = device.make_cred("example.test", b"user-1");
    assert_eq!(status, 0x00, "enrolment falls back to the snapshot");
    // **After** the enrolment, so the enumeration has something to enumerate.
    // Called before, it would answer `NO_CREDENTIALS` — a correct answer to a
    // different question, and one that would make this test pass for the wrong
    // reason.
    let (status, cbor) = device.cm_enumerate_rps();
    assert_eq!(status, 0x00, "enumerateRpsBegin with no region must answer, not refuse: {cbor:02x?}");
    assert_eq!(
        enumerate_rps_id(&cbor).as_deref(),
        Some(&b"example.test"[..]),
        "and it must actually name the RP — an empty reply would be a device \
         reporting credentials it never looked for (US-1573)",
    );
    let (status, _) = device.get_assertion("example.test", None);
    assert_eq!(status, 0x00, "and the assertion is served from the snapshot");
}

// ---------------------------------------------------------------------------
// The three-state read the whole degradation rests on
// ---------------------------------------------------------------------------

#[test]
fn a_region_fault_is_not_reported_as_an_empty_region() {
    // The property US-1573 exists for, pinned at the seam the degradation
    // depends on. `used()` and `remaining()` must answer `None` — "we could not
    // find out" — and never `Some(0)`, which is "we found out and there is
    // nothing there". A caller that collapsed the two would tell a user their
    // passkeys are gone when the device simply cannot read them, and would
    // report the same thing again on the next command.
    let _lock = lock();
    let region_file = install("degrade-three-state");
    let mut device = Device::boot(keyed_store());
    device.set_pin(b"123456");
    assert_eq!(device.make_cred("example.test", b"user-1").0, 0x00);

    let keys = device.with_store(|s| {
        let ks = fapico2_fido::device_keystore::DeviceKeystore::load(s)
            .expect("readable")
            .expect("present");
        region_keys(s, &ks)
    });

    let read_with = |faults: Faults| {
        let mut region = FileKeyRegion::open(region_file.path()).expect("the region");
        region.inject_faults(faults);
        let mut creds = fapico2_fido::device_keystore::RegionCredentials::new(&mut region, &keys);
        (creds.used(), creds.remaining())
    };

    let (used_ok, remaining_ok) = read_with(Faults::default());
    assert_eq!(used_ok, Some(1), "a healthy region counts its credential");
    assert!(remaining_ok.is_some());

    let (used_bad, remaining_bad) = read_with(Faults { reads: true, ..Faults::default() });
    assert_eq!(used_bad, None, "a faulted region must not read as 'zero credentials'");
    assert_eq!(remaining_bad, None, "nor as 'a full device'");
}

#[test]
fn a_faulted_read_is_distinguishable_from_an_absent_one() {
    // `Fault` and `Absent` must stay two answers. The device turns both into
    // `NO_CREDENTIALS` for a getAssertion — deliberately, `device_core.rs`:
    // "inventing a distinct error for a sick flash would tell a user their
    // passkey is gone" — but the *internal* distinction is what stops the same
    // translation being applied to the credential count, where it would be a lie
    // about capacity.
    let absent: SlotRead<u8> = SlotRead::Absent;
    let fault: SlotRead<u8> = SlotRead::Fault("a transport failure");
    assert!(!absent.is_fault());
    assert!(fault.is_fault());
    assert_eq!(absent.present(), None);
    assert_eq!(fault.present(), None);
}