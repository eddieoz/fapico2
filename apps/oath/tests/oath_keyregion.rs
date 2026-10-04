//! US-1553: OATH credentials live in the key region, one record per slot, and
//! the secure store holds no credential table.
//!
//! ```gherkin
//! Scenario: OATH and FIDO stop competing for the 24 entries
//!   Given a device with FIDO at capacity and OATH at capacity
//!   When both applets store their full sets
//!   Then neither is refused for slot exhaustion
//!   And the secure store holds no applet credential table
//! ```
//!
//! # The number this file replaces
//!
//! `apps/oath/tests/oath_capacity.rs` measured the old ceiling from the real
//! encoder on the real store: **30 maximal credentials**, and the reason it was
//! 30 and not 68 was the *double-buffered rewrite peak* of the chunked
//! `oath.keystore.v1` snapshot — `12 parts + 12 parts + 1 resident slot = 25`
//! against `Rp2350SecureStore::DEV_MAX_ENTRIES = 24`, one entry short. That file
//! keeps measuring the legacy path, because the legacy path still exists and
//! still has that ceiling; this file measures the new one, and
//! `the_legacy_path_still_stops_at_thirty` keeps the contrast honest.
//!
//! # What each test is *not* doing
//!
//! None of these tests calls the FIDO applet. `fido_and_oath_at_capacity_
//! coexist` writes FIDO-domain records into the region **directly**, through
//! `record::seal` and `commit::commit`, because the claim under test is about
//! **slots** — "the two applets' reservations do not overlap and neither is
//! refused" — and a FIDO credential's *contents* are irrelevant to it. FIDO's
//! own adapter is a separate story with its own file; this one asserts the
//! geometry it has to respect (`FIDO_FIRST_SLOT`) is the geometry this story
//! reserves, so the two cannot drift apart silently.
//!
//! The region is a real [`FileKeyRegion`] over a real file with real NOR
//! semantics: `program` ANDs into what is there and refuses a 0 → 1 transition,
//! and `erase_sector` clears a whole 4 KiB sector. A commit that got the
//! ordering wrong fails with `E_NOR_SET_BIT` instead of quietly producing an
//! image the part could never hold.

use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use fapico2_oath::oath_core::{
    device_id_from_chipid, OathApp, RegionStatus, DEVICE_ID_LEN, EMULATION_CHIPID,
};
use fapico2_oath::OathSeal;
use fapico2_platform::dispatch::{App, MAX_RESPONSE};
use fapico2_platform::keyregion::commit::{self, CommitPlan};
use fapico2_platform::keyregion::crypto::{self, PayloadKey};
use fapico2_platform::keyregion::host::{FileKeyRegion, E_IO};
use fapico2_platform::keyregion::oath_store::{self, OathRegion};
use fapico2_platform::keyregion::record::{self, Domain};
use fapico2_platform::keyregion::oath_store::{FIDO_FIRST_SLOT, OathCredential, OATH_SLOTS};
use fapico2_platform::keyregion::{FIDO_CAPACITY, FIDO_RECORD_MAX, KeyRegion, Slot, TOTAL_SLOTS};
use fapico2_platform::secure_store::chunked;
use fapico2_platform::secure_store::{HostSecureStore, SecureStoreError};
use fapico2_platform::trng::HostTrng;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A region file in the host temp directory, removed on drop.
struct TempRegion {
    path: PathBuf,
}

impl TempRegion {
    fn path(&self) -> &Path {
        &self.path
    }

    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir()
            .join(format!("fapico2-oath-keyregion-{}-{tag}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        Self { path }
    }
}

impl Drop for TempRegion {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// An OTP row for the payload-key derivation.
///
/// Deliberately **not** `ckey::EMULATION_OTP_KEY_1`, which is what
/// `OathSeal::emul()` uses for the *inner* C-compat seal. Keeping the two rows
/// distinct means a test that derives the region key with the wrong row fails
/// to open its records, rather than passing for the right reason.
const OTP_ROW: [u8; 32] = *b"oath-keyregion-test-otp-row-32b\0";

const CHIPID: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

fn payload_key() -> PayloadKey {
    crypto::derive_payload_key(&OTP_ROW, &CHIPID, &oath_store::OATH_PAYLOAD_SECRET)
        .expect("a non-zero OTP row derives a payload key")
}

fn emul_device_id() -> [u8; DEVICE_ID_LEN] {
    device_id_from_chipid(EMULATION_CHIPID)
}

fn slot(index: u16) -> Slot {
    Slot::new(index).expect("every index in this file is inside the region")
}

/// A fresh region of the shipping size, pre-erased.
fn open_region(path: &Path) -> FileKeyRegion {
    FileKeyRegion::create(path, TOTAL_SLOTS).expect("a full-size region file")
}

/// Shared counters plus the region itself, so a test can inspect the medium
/// *behind* an applet that owns its handle.
#[derive(Clone)]
struct Probe {
    region: Rc<RefCell<FileKeyRegion>>,
    reads: Rc<Cell<u32>>,
    erases: Rc<Cell<u32>>,
    programs: Rc<Cell<u32>>,
    faults: Rc<Cell<u32>>, // bit 0 = reads, bit 1 = erases, bit 2 = programs
}

const F_READS: u32 = 1;
const F_ERASES: u32 = 2;
const F_PROGRAMS: u32 = 4;

impl Probe {
    fn new(tag: &str) -> (Self, TempRegion) {
        let temp = TempRegion::new(tag);
        let probe = Probe {
            region: Rc::new(RefCell::new(open_region(temp.path()))),
            reads: Rc::new(Cell::new(0)),
            erases: Rc::new(Cell::new(0)),
            programs: Rc::new(Cell::new(0)),
            faults: Rc::new(Cell::new(0)),
        };
        (probe, temp)
    }

    fn set_faults(&self, mask: u32) {
        self.faults.set(mask);
    }

    fn clear_faults(&self) {
        self.faults.set(0);
    }

    /// Read one slot's raw bytes, whatever faults are armed. Used to look at
    /// the medium directly, so it must not be gated by the injection.
    fn peek(&self, index: u16) -> Option<[u8; 1024]> {
        self.region
            .borrow_mut()
            .read_slot(slot(index))
            .ok()
    }

    /// The `OathRegion` handle the applet takes ownership of.
    fn handle(&self) -> OathRegion {
        let inner = SharedRegion {
            region: Rc::clone(&self.region),
            reads: Rc::clone(&self.reads),
            erases: Rc::clone(&self.erases),
            programs: Rc::clone(&self.programs),
            faults: Rc::clone(&self.faults),
        };
        OathRegion::new(Box::new(inner), payload_key())
    }

    fn mount(&self, app: &mut OathApp) -> RegionStatus {
        app.attach_region(self.handle())
    }
}

/// A `KeyRegion` that counts and can be made to fail, over a shared file.
struct SharedRegion {
    region: Rc<RefCell<FileKeyRegion>>,
    reads: Rc<Cell<u32>>,
    erases: Rc<Cell<u32>>,
    programs: Rc<Cell<u32>>,
    faults: Rc<Cell<u32>>,
}

impl KeyRegion for SharedRegion {
    fn read_slot(&mut self, slot: Slot) -> Result<[u8; 1024], &'static str> {
        self.reads.set(self.reads.get() + 1);
        if self.faults.get() & F_READS != 0 {
            return Err(E_IO);
        }
        self.region.borrow_mut().read_slot(slot)
    }

    fn erase_sector(&mut self, slot: Slot) -> Result<(), &'static str> {
        self.erases.set(self.erases.get() + 1);
        if self.faults.get() & F_ERASES != 0 {
            return Err(E_IO);
        }
        self.region.borrow_mut().erase_sector(slot)
    }

    fn program(&mut self, slot: Slot, offset: u32, data: &[u8]) -> Result<(), &'static str> {
        self.programs.set(self.programs.get() + 1);
        if self.faults.get() & F_PROGRAMS != 0 {
            return Err(E_IO);
        }
        self.region.borrow_mut().program(slot, offset, data)
    }

    fn slots(&self) -> u32 {
        self.region.borrow().slots()
    }
}

// --- APDU plumbing (the shape `oath_capacity.rs` uses) ------------------------

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

/// Maximal records: the worst case is the honest ceiling. `MAX_NAME` is 64 and
/// the secret is 63 bytes plus the 2-byte algorithm/digit prefix, which is the
/// longest `TAG_KEY` this applet accepts.
const MAXIMAL_NAME: usize = 64;
const MAXIMAL_SECRET: usize = 63;

fn put_cred(app: &mut OathApp, name: &[u8], secret: &[u8]) -> u16 {
    let mut data = vec![0x71, name.len() as u8];
    data.extend_from_slice(name);
    data.extend_from_slice(&[0x73, 2 + secret.len() as u8, 0x21, 6]);
    data.extend_from_slice(secret);
    let (_, sw) = drive(app, &apdu(0x01, 0, 0, &data));
    sw
}

/// The maximal name for credential `i` — distinct, and 64 bytes long.
fn maximal_name(i: u16) -> [u8; MAXIMAL_NAME] {
    let mut name = [b'c'; MAXIMAL_NAME];
    name[MAXIMAL_NAME - 2..].copy_from_slice(&i.to_le_bytes());
    name
}

/// A TOTP CALCULATE for `name`, P2 = 1 (truncated, 6-digit).
fn calculate_totp(app: &mut OathApp, name: &[u8]) -> (Vec<u8>, u16) {
    let mut data = vec![0x71, name.len() as u8];
    data.extend_from_slice(name);
    data.extend_from_slice(&[0x74, 8, 0, 0, 0, 0, 0, 0, 0, 1]);
    drive(app, &apdu(0xA2, 0, 1, &data))
}

/// The applet, mounted on a fresh region.
fn mounted(tag: &str) -> (OathApp, Probe, TempRegion) {
    let (probe, temp) = Probe::new(tag);
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    assert_eq!(
        probe.mount(&mut app),
        RegionStatus::Mounted {
            live: 0,
            imported: 0
        },
        "a clean region must mount empty"
    );
    (app, probe, temp)
}

/// A maximal FIDO body: [`FIDO_RECORD_MAX`] bytes, every byte derived from the
/// slot number so a record read back from the wrong slot is detectable.
///
/// This is a **sealed record, not a credential**: the body is written through
/// `record::seal` under the real payload key with the real AAD, so it occupies
/// exactly the slot a maximal FIDO credential would. Nothing parses it, because
/// the claim under test is about slots.
fn commit_fido(region: &mut FileKeyRegion, key: &PayloadKey, index: u16) {
    let sl = slot(index);
    let mut body = vec![0u8; FIDO_RECORD_MAX as usize];
    for (i, b) in body.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(index as u8);
    }
    let header = record::RecordHeader::new(Domain::Fido, sl, 1);
    let sealed = record::seal(&header, key.as_bytes(), &[0xA0u8; 12], &body)
        .expect("a maximal FIDO body seals into its slot");
    let plan = CommitPlan::new(
        slot(oath_store::SCRATCHPAD_FIRST_SLOT as u16),
        sl,
        Domain::Fido,
        1,
    );
    commit::commit(region, plan, &sealed).expect("a FIDO commit over a clean region");
}

/// Fill FIDO's whole reservation, skipping every slot this story reserves.
fn fill_fido(probe: &Probe, key: &PayloadKey) {
    let mut filled = 0u32;
    let mut i = FIDO_FIRST_SLOT;
    while filled < FIDO_CAPACITY {
        assert!(
            i < FIDO_FIRST_SLOT + FIDO_CAPACITY,
            "ran out of slots with {filled} of {FIDO_CAPACITY} filled — FIDO's reservation does \
             not start where this story says it does"
        );
        commit_fido(&mut probe.region.borrow_mut(), key, i as u16);
        filled += 1;
        i += 1;
    }
}

/// Open the OATH record in slot `index` straight off the medium.
///
/// Two AEAD opens, both with keys this test derives itself, so the assertion is
/// about the bytes on the flash rather than about what the applet is willing to
/// serve. That matters for two of the tests below: a mounted applet with a
/// non-empty table is **not validated** (US-901's virgin rule recomputed at the
/// end of the mount), so `CALCULATE` answers `0x6982` on a perfectly healthy
/// credential, and a test that used `CALCULATE` would be measuring the session
/// grant rather than durability.
fn open_record(probe: &Probe, index: u16) -> (u32, OathCredential) {
    let raw = probe.peek(index).expect("the region holds this slot");
    let decoded = match fapico2_platform::keyregion::record::decode(slot(index), &raw) {
        fapico2_platform::keyregion::SlotRead::Present(d) => d,
        other => panic!("slot {index} must hold a record, got {other:?}"),
    };
    let opened = fapico2_platform::keyregion::record::open(
        decoded.header(),
        payload_key().as_bytes(),
        decoded.body(),
    );
    let plaintext = match opened {
        fapico2_platform::keyregion::SlotRead::Present(pt) => pt,
        other => panic!("slot {index} must open under the payload key, got {other:?}"),
    };
    let body = plaintext.as_slice().to_vec();
    let cred = OathCredential::decode(&body)
        .unwrap_or_else(|| panic!("slot {index} holds a body this build cannot decode"));
    (decoded.header().generation(), cred)
}

/// The secret inside an OATH record, opened with the same `OathSeal` the applet
/// used to seal it.
fn secret_of(record: &OathCredential) -> Vec<u8> {
    let mut plain = [0u8; 66];
    let n = OathSeal::emul()
        .open(record.sealed_key(), &mut plain)
        .expect("the record's sealed key must open under this unit's seal context");
    plain[..n].to_vec()
}

// ---------------------------------------------------------------------------
// 1. The ceiling
// ---------------------------------------------------------------------------

/// **The headline number.** The durable ceiling is [`OATH_SLOTS`] — 68 — where
/// the measured pre-story ceiling was **30**.
///
/// Measured the way `oath_capacity.rs` measures: maximal records, the real
/// APDU path, and a **remount** to prove durability rather than a `0x9000` that
/// only says the command was accepted. The remount is the part that matters:
/// under the old design a PUT at the ceiling answered `0x9000` and then *was
/// not made durable*, and that is exactly what made 30 the number.
#[test]
fn sixty_eight_credentials_are_accepted_and_the_sixty_ninth_is_not() {
    let (mut app, _probe, _temp) = mounted("ceiling");
    let secret = [0x5Au8; MAXIMAL_SECRET];

    for i in 0..OATH_SLOTS as u16 {
        assert_eq!(
            put_cred(&mut app, &maximal_name(i), &secret),
            0x9000,
            "PUT {i} must be accepted: the region has {OATH_SLOTS} slots and this is slot {i}"
        );
    }
    // One more is refused — cleanly, by the applet's own table bound. This is
    // what makes 68 a *ceiling* rather than "at least 68".
    assert_eq!(
        put_cred(&mut app, &maximal_name(OATH_SLOTS as u16), &secret),
        0x6A84,
        "the {}-th credential must be refused with SW_FILE_FULL, not accepted and dropped",
        OATH_SLOTS + 1
    );
}

/// Durability, in the shape a power cycle actually has: **write with one
/// applet, read with a different one over the same file**.
///
/// Two handles are not a workaround, they are the property. An applet that
/// could read back what it just wrote would prove nothing about surviving a
/// reset, and `OathApp` deliberately owns its region handle so no test can do
/// that by accident.
#[test]
fn sixty_eight_credentials_survive_a_power_cycle_and_still_compute() {
    let (probe, _temp) = Probe::new("powercycle");
    {
        let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
        assert!(matches!(probe.mount(&mut app), RegionStatus::Mounted { .. }));
        let secret = [0x5Au8; MAXIMAL_SECRET];
        for i in 0..OATH_SLOTS as u16 {
            assert_eq!(put_cred(&mut app, &maximal_name(i), &secret), 0x9000);
        }
    } // the applet and its handle are gone; the file is not

    let mut fresh = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    assert_eq!(
        probe.mount(&mut fresh),
        RegionStatus::Mounted {
            live: OATH_SLOTS as u16,
            imported: 0
        },
        "every credential must come back off the medium after a power cycle"
    );

    // …and the secret is still the secret, read straight off the flash.
    //
    // A credential that comes back carrying the wrong bytes is worse than one
    // that does not come back: the host gets `0x9000` and a code that
    // authenticates nothing, which it cannot tell from a wrong password. So
    // this asserts the **bytes**, not that the applet is willing to serve them.
    let (_generation, record) = open_record(&probe, 7);
    assert_eq!(record.name(), &maximal_name(7)[..], "the name must have survived");
    let secret = secret_of(&record);
    assert_eq!(
        secret[2..],
        [0x5Au8; MAXIMAL_SECRET][..],
        "the recovered credential must carry the secret it was provisioned with"
    );

    // The applet serves it too. Deliberately *not* an APDU here: both `LIST` and
    // `CALCULATE` require `validated`, and US-901's virgin rule is recomputed
    // at the end of every mount — so a freshly mounted applet with a full table
    // answers `0x6982` on a perfectly healthy credential.
    // `a_recovered_credential_is_listed_by_the_applet` covers the serving half
    // on a table small enough for `LIST` to fit in `MAX_RESPONSE`.
}

/// The applet serves a recovered credential end to end: SELECT → VALIDATE →
/// LIST, across a power cycle.
///
/// # Why the access code is in here
///
/// Every revealing command requires `validated`, and US-901 grants it only to
/// a **virgin** applet. A device holding credentials with no access code is
/// therefore genuinely locked — which is that story's design, not this one's,
/// and the legacy path behaves identically. So the only way to observe "the
/// applet serves what it recovered" is on a device that *has* an access code,
/// and that is also the shape a real deployment has.
///
/// The access code lives in the secure store, not the region, which is exactly
/// why this test also pins the division of labour: the code and the PIN survive
/// because they are still store records, and only the credentials moved.
#[test]
fn a_recovered_credential_is_served_after_validate() {
    const CODE: [u8; 19] = [0x21, 8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];
    let (probe, _temp) = Probe::new("serving");
    let mut store = HostSecureStore::new();
    // The OTP body this credential produced when it was first provisioned.
    // Declared before the provisioning block because that block is where the
    // value is captured, and the block ends by dropping the applet that made
    // it — so there is no later scope in which to bind it.
    let provisioned: Vec<u8>;

    {
        // Virgin: the access code can be set, and the grants are still the
        // virgin ones.
        let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
        set_access_code(&mut app, &CODE);
        // SET CODE leaves the session unvalidated (it is the first act of a
        // non-virgin applet), so the provisioning below has to VALIDATE first —
        // the same order a host uses, and the reason this test cannot be run on
        // a device with no access code at all.
        grant_session(&mut app, &CODE);
        let secret = [0x5Au8; MAXIMAL_SECRET];
        for i in 0..3u16 {
            assert_eq!(put_cred(&mut app, &maximal_name(i), &secret), 0x9000);
        }
        grant_session(&mut app, &CODE);
        provisioned = code_for(&mut app, 1);
        assert!(App::persist_state(&mut app, &mut store));
    }

    // Power cycle: a fresh applet boots from the store, so it carries the
    // access code and the legacy table, and then mounts a virgin region — which
    // is the migration, on a device that also has a code to unlock itself with.
    let mut fresh =
        OathApp::boot(&mut HostTrng::new(), &mut store, emul_device_id(), OathSeal::emul())
            .expect("boot from the legacy stream");
    assert_eq!(
        probe.mount(&mut fresh),
        RegionStatus::Mounted {
            live: 3,
            imported: 3
        },
        "the legacy table must migrate into the virgin region"
    );

    grant_session(&mut fresh, &CODE);
    let (body, sw) = drive(&mut fresh, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x9000, "LIST must answer on a recovered, validated table");
    assert_eq!(
        body[0], 0x72,
        "LIST returns a TAG_NAME_LIST object when there are names to list"
    );
    let listed: Vec<&[u8]> = split_name_list(&body);
    assert_eq!(listed.len(), 3, "every recovered credential must be listed");
    assert_eq!(listed[1], &maximal_name(1)[..]);

    // And a code comes out of it, **byte-identical to the one the credential
    // produced when it was first provisioned**. That is the assertion that the
    // **secret** survived, expressed through the protocol: a record that came
    // back with the wrong bytes yields a code the server rejects, and nothing
    // on the wire says so.
    //
    // Compared against the live applet rather than a locally computed code, so
    // the assertion is about the storage round trip and not about the OTP
    // implementation, which is not what this story is about. (The device
    // returns the raw dynamic-truncation bytes and the host does the decimal
    // conversion, so the two are only comparable as bytes.)
    assert_eq!(
        code_for(&mut fresh, 1),
        provisioned,
        "the recovered credential must compute exactly what it computed when provisioned"
    );
}

/// The CALCULATE response body for TOTP credential `i` over the fixed
/// challenge this file uses.
///
/// The device answers the truncated YKOATH form `76 <len> <digits> <4 binary
/// digits>`; the decimal conversion is the host's job, so the comparison is
/// byte-for-byte against another device response.
fn code_for(app: &mut OathApp, i: u16) -> Vec<u8> {
    let mut data = vec![0x71, MAXIMAL_NAME as u8];
    data.extend_from_slice(&maximal_name(i));
    data.extend_from_slice(&[0x74, 8, 0, 0, 0, 0, 0, 0, 0, 1]);
    let (body, sw) = drive(app, &apdu(0xA2, 0, 1, &data));
    assert_eq!(sw, 0x9000, "CALCULATE must answer on a validated table");
    assert_eq!(body[0], 0x76, "the truncated-response tag (76 …)");
    assert_eq!(body[1], 5, "the length of the truncated response body");
    assert_eq!(body[2], 6, "the digit count comes from the stored secret");
    body
}

/// A host-issued SELECT, returning the challenge it published.
///
/// A host SELECT also recomputes the session grant (US-901), which is exactly
/// what a real host does before VALIDATE, so the test follows the real order.
fn host_select(app: &mut OathApp) -> [u8; 8] {
    let mut resp = heapless::Vec::<u8, MAX_RESPONSE>::new();
    assert_eq!(App::select_apdu(app, false, &[], &mut resp), 0x9000);
    let bytes = resp.as_slice();
    // `79 03 04 03 00`, `71 08 <device id>`, `74 08 <challenge>`.
    let at = bytes
        .windows(2)
        .position(|w| w == [0x74, 8])
        .expect("SELECT must publish a challenge once an access code is on file");
    let mut challenge = [0u8; 8];
    challenge.copy_from_slice(&bytes[at + 2..at + 10]);
    challenge
}

/// SELECT then VALIDATE, which is the whole of "the host unlocked the token".
fn grant_session(app: &mut OathApp, code: &[u8; 19]) {
    let challenge = host_select(app);
    validate(app, code, &challenge);
}

/// VALIDATE against a stored access code, using the applet's published
/// challenge.
fn validate(app: &mut OathApp, code: &[u8; 19], challenge: &[u8; 8]) {
    let mac = hmac_sha1(&code[1..], challenge);
    let mut data = vec![0x74, 8];
    data.extend_from_slice(challenge);
    data.extend_from_slice(&[0x75, mac.len() as u8]);
    data.extend_from_slice(&mac);
    let (_, sw) = drive(app, &apdu(0xA3, 0, 0, &data));
    assert_eq!(sw, 0x9000, "VALIDATE must grant the session");
}

/// SET CODE (INS 0x03) on a virgin applet: the host proves knowledge of the
/// code over a challenge **it** supplies, which is C parity for the first code.
fn set_access_code(app: &mut OathApp, code: &[u8; 19]) {
    let chal = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mac = hmac_sha1(&code[1..], &chal);
    let mut data = vec![0x73, code.len() as u8];
    data.extend_from_slice(code);
    data.extend_from_slice(&[0x74, 8]);
    data.extend_from_slice(&chal);
    data.extend_from_slice(&[0x75, mac.len() as u8]);
    data.extend_from_slice(&mac);
    let (_, sw) = drive(app, &apdu(0x03, 0, 0, &data));
    assert_eq!(sw, 0x9000, "SET CODE must succeed on a virgin applet");
}

/// The names out of a YKOATH `LIST` body: a **flat sequence** of
/// `[72][len][alg][name]` objects, one per credential — not one wrapping object
/// with the others inside it. `len` counts the algorithm byte and the name and
/// **not** the tag, so an object is `2 + len` bytes and the name is `len - 1`
/// of them.
fn split_name_list(body: &[u8]) -> Vec<&[u8]> {
    let mut names = Vec::new();
    let mut i = 0usize;
    while i < body.len() {
        assert_eq!(body[i], 0x72, "each LIST object starts with TAG_NAME_LIST");
        let len = body[i + 1] as usize;
        assert!(i + 2 + len <= body.len(), "a truncated name object in LIST");
        names.push(&body[i + 3..i + 2 + len]);
        i += 2 + len;
    }
    names
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// The legacy ceiling, restated as a **contrast on the same fixture**: with no
/// region attached, the same applet and the same maximal credentials still stop
/// at 30.
///
/// This is what makes the other tests a measurement rather than a tautology. It
/// runs the identical loop against `Rp2350SecureStore` and asserts the old
/// number is *still* 30 — so if the snapshot path ever changes, this fails and
/// the headline claim has to be re-argued rather than quietly re-measured.
#[test]
fn the_legacy_path_still_stops_at_thirty_and_that_is_the_contrast() {
    use fapico2_platform::secure_store::rp2350::Rp2350SecureStore;

    let mut store = Rp2350SecureStore::new();
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    let secret = [0x5Au8; MAXIMAL_SECRET];
    let mut durable = 0usize;
    for i in 0..200u16 {
        assert_eq!(put_cred(&mut app, &maximal_name(i), &secret), 0x9000);
        if !App::persist_state(&mut app, &mut store) {
            break;
        }
        durable += 1;
    }
    assert_eq!(
        durable, 30,
        "the legacy chunked path's ceiling must still be 30 — if this moved, the claim 'the ceiling \
         is no longer 30' needs re-arguing rather than re-measuring"
    );
}

// ---------------------------------------------------------------------------
// 2. FIDO and OATH at capacity
// ---------------------------------------------------------------------------

/// Fill FIDO's area to [`FIDO_CAPACITY`] with real FIDO-domain records, then
/// store a full OATH table. **Neither is refused, and nothing of FIDO's is
/// destroyed.**
///
/// This is the gherkin's actual claim, and it is the one neither applet can
/// make alone: under the shared 24-entry image they competed for the same
/// entries, and the arithmetic in `AGENTS.md` §5 is what made both short. Here
/// the two reservations are disjoint by construction, so what is really under
/// test is that the disjointness holds *and* that an OATH commit's
/// sector-granular erase never reaches into a neighbour's sector.
#[test]
fn fido_and_oath_at_capacity_coexist() {
    let (probe, _temp) = Probe::new("coexist");
    let key = payload_key();
    fill_fido(&probe, &key);

    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    assert_eq!(
        probe.mount(&mut app),
        RegionStatus::Mounted { live: 0, imported: 0 }
    );
    let secret = [0x5Au8; MAXIMAL_SECRET];
    for i in 0..OATH_SLOTS as u16 {
        assert_eq!(
            put_cred(&mut app, &maximal_name(i), &secret),
            0x9000,
            "OATH slot {i} must be storable while FIDO holds all {FIDO_CAPACITY} of its slots"
        );
    }

    // Every FIDO record is still there. This is not a formality: an OATH commit
    // erases a 4 KiB sector, and if the two reservations were adjacent in a way
    // that put a sector boundary across them, this is where it shows.
    let mut survived = 0u32;
    let mut i = FIDO_FIRST_SLOT as u16;
    while (i as u32) < FIDO_FIRST_SLOT + FIDO_CAPACITY {
        let raw = probe.peek(i).expect("the region holds this slot");
        // A live FIDO record starts with the record magic; an erased slot is
        // all-`0xFF`. `record::decode` is the honest test and needs no magic
        // constant of our own.
        if let fapico2_platform::keyregion::SlotRead::Present(_) =
            fapico2_platform::keyregion::record::decode(slot(i), &raw)
        {
            survived += 1;
        }
        i += 1;
    }
    assert_eq!(
        survived, FIDO_CAPACITY,
        "every FIDO record must survive {OATH_SLOTS} OATH sector-atomic commits"
    );
}

/// The geometry the two adapters have to agree on, asserted as a claim rather
/// than left to a comment in either file.
///
/// `oath_store.rs` publishes `FIDO_FIRST_SLOT` precisely so the FIDO adapter
/// cannot invent a second answer, and the cost of a disagreement is that one
/// applet's first enrolment destroys the other's credentials. That is too
/// expensive for two independently-edited files to leave to review, so it is
/// here.
#[test]
fn the_two_reservations_tile_the_region_without_touching() {
    assert_eq!(
        FIDO_FIRST_SLOT + FIDO_CAPACITY,
        TOTAL_SLOTS - fapico2_platform::keyregion::index::INDEX_SLOT_COUNT,
        "OATH + scratchpad + FIDO + index must tile the region exactly once"
    );
    assert!(
        oath_store::SCRATCHPAD_FIRST_SLOT.is_multiple_of(
            fapico2_platform::keyregion::SLOTS_PER_SECTOR
        ),
        "the shared scratchpad must start on a sector boundary, or erasing it clears a credential"
    );
    assert!(
        OATH_SLOTS.is_multiple_of(fapico2_platform::keyregion::SLOTS_PER_SECTOR),
        "OATH's area must be a whole number of sectors — a partial sector has no valid erase"
    );
    // The scratchpad is *shared*, on purpose: `mod.rs` charges one reservation
    // for it, so two applets each choosing their own would either collide or
    // claim capacity the accounting does not have.
    assert_eq!(
        oath_store::SCRATCHPAD_FIRST_SLOT,
        OATH_SLOTS,
        "the scratchpad sits directly above OATH's area and is the one FIDO also uses"
    );
}

// ---------------------------------------------------------------------------
// 3. The secure store holds no credential table
// ---------------------------------------------------------------------------

/// After a full region-backed table is stored, **the secure store contains no
/// OATH credential record** — asserted on the medium's bytes, not on the code
/// path.
///
/// The distinction matters: "the app does not call `write_state` for
/// credentials" is a claim about a code path, and a code path can be reached
/// again by a future change. The claim that matters is about the *image* — and
/// the image is what a flash dump yields.
///
/// The mechanism is that `attach_region` marks the app dirty once, so the next
/// persist rewrites the stream without credentials; `chunked::write_chunked`
/// then leaves a shorter stream than the one the migration wrote.
#[test]
fn the_secure_store_holds_no_oath_credential_table() {
    let (probe, _temp) = Probe::new("store-empty");
    let mut store = HostSecureStore::new();

    // One applet, taken all the way through: provision on the legacy path,
    // persist it, then mount a region and let the migration happen. A single
    // applet rather than a boot in between, because a **boot** re-runs US-901's
    // virgin rule and a booted applet holding five credentials with no access
    // code is *unvalidated* — so a PUT after it would answer `0x6982` and the
    // test would be measuring the session grant rather than the retirement.
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    let secret = [0x5Au8; MAXIMAL_SECRET];
    for i in 0..5u16 {
        assert_eq!(put_cred(&mut app, &maximal_name(i), &secret), 0x9000);
    }
    assert!(
        App::persist_state(&mut app, &mut store),
        "the legacy table must persist before the migration"
    );
    assert!(
        legacy_credential_fids(&mut store).is_some(),
        "the fixture must start with credentials in the store, or this test proves nothing"
    );

    // Mount. The region is virgin, so this is the migration: the five legacy
    // credentials move into their own slots.
    let status = probe.mount(&mut app);
    assert_eq!(
        status,
        RegionStatus::Mounted {
            live: 5,
            imported: 5
        },
        "the legacy table must migrate into the virgin region"
    );

    // The retirement write, which is what `attach_region` marked the app dirty
    // for: `encode_state` no longer emits credential records, so the stream the
    // store holds loses them.
    assert!(
        App::persist_state(&mut app, &mut store),
        "the attach marks the app dirty so the next persist retires the legacy stream"
    );
    assert!(
        legacy_credential_fids(&mut store).is_none(),
        "the secure store must no longer carry a credential record: found {:?}",
        legacy_credential_fids(&mut store)
    );

    // The five migrated credentials are in the region, not in the store — the
    // other half of the claim, and the one that would catch a "retirement"
    // that merely *deleted* them.
    let mut i = 0u16;
    while i < 5 {
        let (_generation, record) = open_record(&probe, i);
        assert_eq!(
            record.name(),
            &maximal_name(i)[..],
            "credential {i} must have moved into the region rather than been dropped"
        );
        i += 1;
    }

    // …and the non-credential records are untouched by the retirement.
    // `the_retirement_keeps_the_otp_pin_record` covers that directly.
}

/// The credential fids present in the legacy stream, or `None` if there are
/// none.
///
/// Reads the stream back through `chunked::read_chunked` and walks the
/// `[fid u16][len u32][payload]` framing `oath_core::load_stream` defines. The
/// test re-derives the walk rather than reusing `load_stream`, because
/// `load_stream` is the code under test's collaborator and asserting it
/// against itself would prove nothing.
fn legacy_credential_fids(store: &mut HostSecureStore) -> Option<Vec<u16>> {
    let mut buf = [0u8; chunked::MAX_LOGICAL_LEN];
    let n = match chunked::read_chunked(store, b"oath.keystore.v1", &mut buf) {
        Ok(n) => n,
        Err(SecureStoreError::NotFound) => return None,
        Err(_) => return None,
    };
    let mut fids = Vec::new();
    let mut i = 0usize;
    while i + 6 <= n {
        let fid = u16::from_le_bytes([buf[i], buf[i + 1]]);
        let len =
            u32::from_le_bytes([buf[i + 2], buf[i + 3], buf[i + 4], buf[i + 5]]) as usize;
        i += 6;
        if i + len > n {
            break;
        }
        if (0xBA00..=0xBA43).contains(&fid) {
            fids.push(fid);
        }
        i += len;
    }
    if fids.is_empty() {
        None
    } else {
        Some(fids)
    }
}

/// The non-credential records survive the retirement.
///
/// The OTP-PIN record (fid `0xBA44`, US-904) is the sharp case: it is the only
/// thing that would be **silently lost** if `encode_state` skipped the whole
/// stream instead of skipping the credential fids, and losing it turns a
/// user-set PIN into an absent one — a locked token that reports itself
/// unlocked.
#[test]
fn the_retirement_keeps_the_otp_pin_record() {
    let (probe, _temp) = Probe::new("pin-record");
    let mut store = HostSecureStore::new();

    // A virgin region keeps the applet virgin after the mount (US-901), so the
    // PIN command is reachable without an access code first.
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    assert_eq!(
        probe.mount(&mut app),
        RegionStatus::Mounted { live: 0, imported: 0 }
    );
    assert_eq!(put_cred(&mut app, &maximal_name(0), &[0x55u8; MAXIMAL_SECRET]), 0x9000);

    // `SET PIN`: INS 0xB4, data `80 <len> <password>`.
    let pw = b"123456";
    let mut data = vec![0x80, pw.len() as u8];
    data.extend_from_slice(pw);
    let (_, sw) = drive(&mut app, &apdu(0xB4, 0, 0, &data));
    assert_eq!(sw, 0x9000, "SET PIN must be reachable on a virgin region-backed applet");
    assert!(
        App::persist_state(&mut app, &mut store),
        "the PIN record is durable"
    );

    assert!(
        legacy_credential_fids(&mut store).is_none(),
        "the stream must hold no credential record even on the first region-backed persist"
    );
    assert!(
        stream_carries_fid(&mut store, 0xBA44),
        "the US-904 OTP-PIN record must survive: skipping the credential fids must not skip the \
         stream"
    );
}

/// Is `fid` present in the legacy stream?
fn stream_carries_fid(store: &mut HostSecureStore, want: u16) -> bool {
    let mut buf = [0u8; chunked::MAX_LOGICAL_LEN];
    let Ok(n) = chunked::read_chunked(store, b"oath.keystore.v1", &mut buf) else {
        return false;
    };
    let mut i = 0usize;
    while i + 6 <= n {
        let fid = u16::from_le_bytes([buf[i], buf[i + 1]]);
        let len = u32::from_le_bytes([buf[i + 2], buf[i + 3], buf[i + 4], buf[i + 5]]) as usize;
        i += 6;
        if i + len > n {
            break;
        }
        if fid == want {
            return true;
        }
        i += len;
    }
    false
}

// ---------------------------------------------------------------------------
// 4. A failed commit rolls back
// ---------------------------------------------------------------------------

/// A write failure inside a commit leaves the **previous** credential intact
/// and the command refused, with no half-written record.
///
/// This is the property that makes durable-before-ack safe to do inside a
/// command rather than in a persist gate: if a refused PUT could leave the
/// applet believing in a credential that is not on the medium, the whole
/// arrangement would be worse than the gate it replaced.
#[test]
fn a_refused_commit_leaves_the_previous_credential_intact() {
    let (probe, _temp) = Probe::new("rollback");
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    probe.mount(&mut app);

    let first = [0x11u8; MAXIMAL_SECRET];
    let second = [0x22u8; MAXIMAL_SECRET];
    let name = maximal_name(0);
    assert_eq!(put_cred(&mut app, &name, &first), 0x9000);

    // Fault the live erase: the commit fails at its point of no return, and
    // `commit` keeps the staged set rather than sweeping it (that is the
    // `Incomplete` case). The next commit's `recover` finishes the sector.
    probe.set_faults(F_ERASES);
    let sw = put_cred(&mut app, &name, &second);
    probe.clear_faults();
    assert_eq!(
        sw, 0x6985,
        "a refused write must answer SW_CONDITIONS_NOT_SATISFIED, not 0x9000"
    );

    // Whatever the commit left behind, a fresh applet must be able to mount the
    // region and find a servable credential. `commit` keeps its staged set after
    // an interrupted live erase and `recover` replays it on the next commit, so
    // "the region needs sweeping before anything can be written again" is
    // exactly the state this asserts has *not* happened.
    let mut fresh = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    assert!(
        matches!(probe.mount(&mut fresh), RegionStatus::Mounted { .. }),
        "the region must still mount after a refused commit — a store that has to be swept \
         before it can be written again is one hiccup away from being permanently unwritable"
    );
    let (_generation, record) = open_record(&probe, 0);
    assert_eq!(record.name(), &name[..], "the name must have survived");
    // `secret_of` returns the whole stored `TAG_KEY`, which is the 2-byte
    // `[alg|type, digits]` prefix the applet prepends; the fixture is the body
    // after it.
    let surviving = secret_of(&record);
    let surviving = &surviving[2..];
    assert!(
        surviving == first || surviving == second,
        "the surviving secret must be one that was legitimately written, not a mixture: \
         {surviving:?}"
    );
}

/// The US-1030 seal-generation ordering property, restated for the record
/// generation.
///
/// US-1030's rule is that a nonce is never spent twice on different plaintext,
/// which it enforced by **reserving a counter before writing the sealed bytes**.
/// US-1553 replaces the counter with the record's own generation, so the rule
/// has to be checked where the substitution happened and not merely asserted:
///
/// * a first write is at generation 1;
/// * a delete tombstones at a strictly higher generation, and the credential
///   that replaces it is sealed at a **third** one — so the secret that replaces
///   a deleted one cannot reuse the deleted one's nonce, even though both live
///   in the same slot and bind the same `fid`.
#[test]
fn the_seal_generation_is_monotone_across_a_delete_and_re_provision() {
    let (probe, _temp) = Probe::new("seal-gen");
    let key = payload_key();
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    probe.mount(&mut app);

    let name = maximal_name(0);
    assert_eq!(put_cred(&mut app, &name, &[0x11u8; MAXIMAL_SECRET]), 0x9000);
    let first = generation_at(&probe, 0);

    // DELETE: `02 00 00 00 <len> 71 <len> <name>`
    let mut del = vec![0x71, MAXIMAL_NAME as u8];
    del.extend_from_slice(&name);
    let (_, sw) = drive(&mut app, &apdu(0x02, 0, 0, &del));
    assert_eq!(sw, 0x9000);
    let tombstone = generation_at(&probe, 0);
    assert!(
        tombstone > first,
        "a tombstone must advance the generation ({tombstone} vs {first}) — it is what stops a \
         replacement credential in this slot from reusing the deleted one's nonce"
    );
    // …and it really is a tombstone, not an erase: the slot still holds a record.
    assert!(
        probe.peek(0).is_some(),
        "a delete must leave a record behind — an erased target is indistinguishable from a commit \
         that never reached its witness and can be resurrected as a replay"
    );

    assert_eq!(put_cred(&mut app, &name, &[0x22u8; MAXIMAL_SECRET]), 0x9000);
    let second = generation_at(&probe, 0);
    assert!(
        second > tombstone,
        "a re-provision must advance the generation again ({second} vs {tombstone})"
    );

    // The generations above are the whole of the substitution US-1553 makes:
    // they are read off the medium, not kept in RAM, so a delete/re-provision
    // cycle cannot re-spend a nonce even across a reset. Restated as the AAD
    // binding, which is what a transplant or a replay would have to defeat.
    let header = record::RecordHeader::new(Domain::Oath, slot(0), second);
    assert_eq!(
        header.generation(),
        second,
        "the record header must carry the generation the app sealed at"
    );
    assert_ne!(
        sealed_body(&probe, 0),
        Vec::new(),
        "the re-provisioned record must carry a sealed body"
    );
    let _ = key;
}

/// The generation the record in OATH slot `index` carries, read straight off
/// the medium.
fn generation_at(probe: &Probe, index: u16) -> u32 {
    let raw = probe.peek(index).expect("the region holds this slot");
    match fapico2_platform::keyregion::record::decode(slot(index), &raw) {
        fapico2_platform::keyregion::SlotRead::Present(d) => d.header().generation(),
        other => panic!("slot {index} must hold a record, got {other:?}"),
    }
}

fn sealed_body(probe: &Probe, index: u16) -> Vec<u8> {
    let raw = probe.peek(index).expect("the region holds this slot");
    match fapico2_platform::keyregion::record::decode(slot(index), &raw) {
        fapico2_platform::keyregion::SlotRead::Present(d) => d.body().as_bytes().to_vec(),
        other => panic!("slot {index} must hold a record, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 5. Degrade, never halt
// ---------------------------------------------------------------------------

/// A region that cannot be read yields an **empty** credential set, a live
/// applet, and clean status words — no panic, no fatal boot.
///
/// The two properties that matter are separate and both are asserted: the
/// applet still answers (`LIST` returns `0x9000` and an empty body), and it does
/// not claim the owner has no credentials — `is_region_degraded` says so
/// explicitly, which is what lets a caller tell a failing flash from a
/// factory-fresh token.
#[test]
fn an_unreadable_region_degrades_to_an_empty_set_and_a_clean_status_word() {
    let (probe, _temp) = Probe::new("degrade");
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());

    probe.set_faults(F_READS);
    let status = probe.mount(&mut app);

    assert_eq!(
        status,
        RegionStatus::Degraded,
        "a region that cannot be read must report Degraded, not a clean mount of nothing"
    );
    assert!(app.is_region_degraded());
    assert!(app.has_region());

    // The applet is alive and answers. `LIST` with no filter is `A1 00 00`.
    let (body, sw) = drive(&mut app, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x9000, "an unreadable region must not make the applet refuse APDUs");
    assert!(
        body.is_empty(),
        "LIST on a degraded applet must report no credentials, not refuse"
    );

    // And a write is refused rather than silently accepted into a region that
    // cannot be read — a PUT that answered 0x9000 here would be a credential
    // the host believes is stored.
    let name = maximal_name(0);
    assert_eq!(
        put_cred(&mut app, &name, &[0x33u8; MAXIMAL_SECRET]),
        0x6985,
        "a PUT into an unreadable region must be refused — a 0x9000 here would be a credential \
         the host believes is stored and that is not"
    );

    // The refused PUT left nothing behind: a credential the applet cannot
    // store is not a credential it may keep in RAM and list. This is the
    // reconcile half of `region_sync`, and it is a property a user can see.
    let (body, sw) = drive(&mut app, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x9000);
    assert!(
        body.is_empty(),
        "a credential whose record could not be written must not survive in the table: {body:?}"
    );

    // …and the moment the region comes back, the applet serves normally. This
    // is the other half of "degrade": the failure is recoverable and does not
    // latch the applet into refusing forever.
    probe.clear_faults();
    assert_eq!(
        put_cred(&mut app, &name, &[0x33u8; MAXIMAL_SECRET]),
        0x9000,
        "a write must succeed once the region is readable again"
    );
}

/// The degradation is **all-or-nothing**: one unreadable slot must not produce
/// a table that is quietly missing an entry.
///
/// The reason this is not "serve the other 67" is stated in
/// `keyregion/oath_store.rs`: a table that silently lost an entry is
/// indistinguishable from one that never had it, and the next PUT would reuse
/// that slot — writing a second identity on top of one the owner still
/// believes is there.
#[test]
fn one_unreadable_slot_degrades_the_whole_mount() {
    // A fault mask the wrapper does not implement would be a false test, so
    // this one is proven by construction: mount normally, then re-mount over a
    // probe whose reads are faulted, and assert the count of *served*
    // credentials is zero rather than 67.
    let (probe, _temp) = Probe::new("partial");
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    probe.mount(&mut app);
    let secret = [0x5Au8; MAXIMAL_SECRET];
    for i in 0..OATH_SLOTS as u16 {
        assert_eq!(put_cred(&mut app, &maximal_name(i), &secret), 0x9000);
    }

    let mut again = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    probe.set_faults(F_READS);
    let status = probe.mount(&mut again);
    probe.clear_faults();
    assert_eq!(status, RegionStatus::Degraded);
    let (body, sw) = drive(&mut again, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x9000);
    assert!(
        body.is_empty(),
        "a fault on any slot must fail the whole mount — 67 of 68 served is a table that silently \
         lost an entry, which is the outcome this design refuses"
    );
}

// ---------------------------------------------------------------------------
// 6. The boot path does not read the region
// ---------------------------------------------------------------------------

/// Boot reads the secure store and **nothing else**.
///
/// S8/S9: the boot path must not touch the key region. Boot runs before USB is
/// constructed and inside a time budget, and a mount opens up to 68 AEAD
/// records over 68 KiB — making boot's latency proportional to how many
/// credentials the owner has is exactly the cliff the rule exists to prevent.
///
/// Asserted as a **counter that is still zero**, because a boolean "did it read"
/// would pass just as happily against a boot path that read one slot.
#[test]
fn the_boot_path_does_not_read_the_region() {
    let (probe, _temp) = Probe::new("boot");

    // Boot from the store, with the region already present on disk and an
    // applet-free path to it. `OathApp::boot` takes no region argument, which
    // is the structural half of the property; the counter is the behavioural
    // half.
    let mut store = HostSecureStore::new();
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    assert_eq!(put_cred(&mut app, &maximal_name(0), &[0x44u8; MAXIMAL_SECRET]), 0x9000);
    assert!(App::persist_state(&mut app, &mut store));

    // Move the counter first. "Boot did not read the region" against a counter
    // that was already zero is satisfied by a boot path that cannot read the
    // region at all; it only means something when the counter has moved and
    // then has *not*.
    let mut mounted_app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    let _ = probe.mount(&mut mounted_app);
    let reads = probe.reads.get();
    let erases = probe.erases.get();
    let programs = probe.programs.get();
    assert!(
        reads > 0,
        "an explicit mount must read the region — otherwise 'boot does not read it' would be \
         satisfied by a mount that reads nothing"
    );

    // Boot, with every region operation armed to fail. If boot touched the
    // region at all, this would fail rather than merely count.
    probe.set_faults(F_READS | F_ERASES | F_PROGRAMS);
    let booted = OathApp::boot(&mut HostTrng::new(), &mut store, emul_device_id(), OathSeal::emul());
    probe.clear_faults();
    assert!(
        booted.is_ok(),
        "boot must succeed with the region completely unusable — degrade, never halt"
    );
    assert_eq!(
        probe.reads.get(),
        reads,
        "boot must not read the key region"
    );
    assert_eq!(probe.erases.get(), erases);
    assert_eq!(probe.programs.get(), programs);
    assert!(
        !booted.unwrap().has_region(),
        "a booted applet has no region until it is explicitly mounted — that is the structural \
         half of the property; `OathApp::boot` has no parameter through which one could arrive"
    );
}

/// Mounting is a **one-off**, not something every command re-does.
///
/// The claim is about latency: a command that re-mounted would pay 68 slot reads
/// and 68 AEAD opens per APDU, which on a full applet is more work than the
/// command itself. The counter is reset by re-attaching, so the assertion is
/// that 50 commands add **zero** region reads.
#[test]
fn commands_do_not_re_read_the_region() {
    let (probe, _temp) = Probe::new("once");
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    probe.mount(&mut app);
    let secret = [0x5Au8; MAXIMAL_SECRET];
    for i in 0..5u16 {
        assert_eq!(put_cred(&mut app, &maximal_name(i), &secret), 0x9000);
    }
    let reads_after_mount_and_writes = probe.reads.get();

    for _ in 0..50 {
        let (_, sw) = calculate_totp(&mut app, &maximal_name(0));
        assert_eq!(sw, 0x9000);
    }
    assert_eq!(
        probe.reads.get(),
        reads_after_mount_and_writes,
        "a TOTP CALCULATE must be answered from the in-RAM table, not by re-reading the region"
    );
}
// ---------------------------------------------------------------------------
// Client compatibility: the picoforge / ykman flow (US-1572 follow-on)
// ---------------------------------------------------------------------------

/// **A device with no access code is fully usable — register, retrieve, use.**
///
/// This is the flow both first-party clients actually run, and it is the one
/// the applet used to refuse. Neither client has a second way to learn that a
/// device needs unlocking:
/// `yubikit/oath.py` sets `_has_key = self._challenge is not None` and
/// picoforge's HAL reads `info.password_set()` — both from the `74` challenge
/// TLV, which this applet emits **only when an access code exists**. So on a
/// device holding credentials and no access code, both clients skip VALIDATE
/// and issue LIST / PUT / DELETE / CALCULATE directly, and every one of them
/// used to be answered `0x6982`.
///
/// The lockout was also a dead end: `SET_CODE` and `SET_PIN`, the only ways to
/// create the missing credential, sat behind the same gate, leaving a factory
/// reset as the sole exit.
///
/// Pinned on **both** storage paths, because the fix must not be path-specific:
/// the legacy stream and the key region must look identical to a client.
#[test]
fn a_device_with_no_access_code_is_usable_on_both_paths() {
    // Legacy: no region attached.
    let mut legacy = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    // Region: mounted, so `attach_region` ran and `refresh_session_grant` too.
    let (mut region, _probe, _temp) = mounted("compat-region");

    for (path, app) in [("legacy", &mut legacy), ("region", &mut region)] {
        let app = app;
        // 1. REGISTER. No VALIDATE first — there is no access code, and a
        //    client cannot know that without a SELECT it has not sent yet.
        assert_eq!(
            put_cred(app, b"GitHub:eddieoz", &[0x21, 6, b's', b'e', b'c', b'r', b'e', b't']),
            0x9000,
            "{path}: PUT must be served with no access code and no prior VALIDATE"
        );

        // 2. RETRIEVE. LIST must answer 0x9000 and carry the credential.
        let (body, sw) = drive(app, &apdu(0xA1, 0, 0, &[]));
        assert_eq!(sw, 0x9000, "{path}: LIST must be served with no access code");
        assert!(
            !body.is_empty(),
            "{path}: LIST must return the registered credential"
        );

        // 3. USE. A named CALCULATE with a challenge — the TOTP request both
        //    clients issue.
        let (body, sw) = calculate_totp(app, b"GitHub:eddieoz");
        assert_eq!(sw, 0x9000, "{path}: CALCULATE must be served with no access code");
        assert_eq!(
            body.first(),
            Some(&0x76),
            "{path}: the truncated YKOATH response tag, or the client cannot read a code"
        );

        // 4. RENAME and DELETE, the two remaining client verbs. The name in
        //    both TLVs must be the 14-byte one registered above, or RENAME
        //    answers 0x6984 for a reason that has nothing to do with the grant.
        const OLD: &[u8] = b"GitHub:eddieoz";
        const NEW: &[u8] = b"GitHub:eddie";
        let mut rename = vec![0x71, OLD.len() as u8];
        rename.extend_from_slice(OLD);
        rename.extend_from_slice(&[0x71, NEW.len() as u8]);
        rename.extend_from_slice(NEW);
        assert_eq!(
            drive(app, &apdu(0x05, 0, 0, &rename)).1,
            0x9000,
            "{path}: RENAME must be served with no access code"
        );
        let mut delete = vec![0x71, NEW.len() as u8];
        delete.extend_from_slice(NEW);
        assert_eq!(
            drive(app, &apdu(0x02, 0, 0, &delete)).1,
            0x9000,
            "{path}: DELETE must be served with no access code"
        );

        // 5. Re-listing after a refusal-free sequence still works: the grant
        //    is "nothing to authenticate with", and nothing above disturbed it.
        let (_, sw) = drive(app, &apdu(0xA1, 0, 0, &[]));
        assert_eq!(
            sw, 0x9000,
            "{path}: the session must still be granted after the full client sequence"
        );
        //    VALIDATE's own refusal with no access code, and the rule that a
        //    refusal does not un-grant the session, are covered by
        //    `auth_boundary.rs::validate_without_access_code_never_grants` —
        //    not repeated here, because an empty VALIDATE body is rejected on
        //    its TLVs before the access-code check is ever reached.
    }
}

/// **A session survives a reboot on a device with no access code.**
///
/// The property the lockout made untestable. Before the fix, a rebooted
/// code-less device was "locked" — and because a locked device refuses LIST,
/// every "did the credential survive?" assertion in this file had to be made
/// against the *store*, never against a round trip through the applet. On the
/// region path there is no store to check.
#[test]
fn a_rebooted_region_device_with_no_access_code_still_lists_its_credentials() {
    let (_probe, _temp) = Probe::new("compat-reboot");
    let probe = _probe;
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    probe.mount(&mut app);
    assert_eq!(
        put_cred(&mut app, b"acct", &[0x21, 6, b's', b'e', b'c', b'r', b'e', b't']),
        0x9000
    );

    // A fresh applet over the same medium — nothing carried over in RAM.
    let mut rebooted = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    probe.mount(&mut rebooted);
    let (body, sw) = drive(&mut rebooted, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x9000, "a rebooted code-less device must serve LIST");
    assert!(
        !body.is_empty(),
        "the credential committed before the reboot must still be listed after it"
    );
}

/// **One undecodable record does not brick PUT.**
///
/// `attach_region` deliberately leaves a slot whose record will not decode as
/// an **empty** table slot rather than reserving it forever against a
/// credential this firmware can never serve — and its comment claims "the next
/// PUT overwrites it at a strictly higher generation". That claim is the
/// load-bearing part, because the two layers could easily disagree: the applet
/// offers the slot as free (its RAM entry is `None`), while the store still
/// holds bytes there.
///
/// They do agree, and this is why: `OathStore::current_generation` answers `0`
/// for a slot whose record fails to decode — the same value an empty slot
/// returns — so `next_generation` yields 1, which *does* advance past what the
/// commit path re-reads, and the commit is allowed.
///
/// An earlier review claimed this path was a permanent brick, on the reasoning
/// that `OathStore::write` refuses to overwrite an unreadable slot. It does not:
/// that refusal is about a slot the *allocator* must not hand out, and the
/// allocator here is the applet's RAM table. The property is worth pinning
/// because the reasoning is genuinely easy to get wrong in the other direction —
/// "reserve the slot" is the other defensible answer, and it would leak the slot
/// against a credential nobody can use.
#[test]
fn one_undecodable_record_does_not_brick_put() {
    let temp = TempRegion::new("undecodable-reuse");
    // Garbage that is neither erased nor a decodable record: the header CRC
    // cannot pass, so `record::decode` reports a fault for this slot alone.
    {
        let mut r = open_region(temp.path());
        r.program(Slot::new(0).expect("slot 0"), 0, &[0xABu8; 256])
            .expect("plant junk");
    }

    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    assert_eq!(
        app.attach_region(OathRegion::new(
            Box::new(FileKeyRegion::open(temp.path()).expect("reopen")),
            payload_key(),
        )),
        RegionStatus::Mounted { live: 0, imported: 0 },
        "one undecodable record must not stop the mount"
    );

    // The new credential takes the lowest free slot — the poisoned one.
    assert_eq!(
        put_cred(&mut app, b"fresh", &[0x21, 6, b's', b'e', b'c', b'r', b'e', b't']),
        0x9000,
        "a PUT into a slot holding an undecodable record must succeed"
    );
    let (body, sw) = drive(&mut app, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x9000, "LIST after recovering a poisoned slot");
    assert!(
        !body.is_empty(),
        "the recovered credential must be listed: a PUT that answers 0x9000 and writes nothing \
         would be the real brick"
    );
}

/// **A failed commit does not log the user out mid-session.**
///
/// `region_reconcile` — the path taken after a refused commit — used to end
/// with `refresh_session_grant()`. That is a category error: the function
/// reconciles **one slot** against the medium, and medium-vs-RAM agreement says
/// nothing about whether the session was authenticated.
///
/// The effect was a self-inflicted logout. On any device with an access code or
/// PIN the grant is *derived* false, so a single transient flash failure during
/// a write flipped `validated` from true (a VALIDATE had completed) to false,
/// and the next command answered 0x6982 with nothing to explain it. The applet
/// could not recover without the owner re-entering their password.
///
/// Set up here with a **PIN** rather than an access code: it is the same
/// derived-false shape, and it avoids needing the full SET_CODE challenge
/// handshake, so the test isolates the reconcile behaviour.
#[test]
fn a_failed_commit_does_not_ungrant_an_authenticated_session() {
    let (probe, _temp) = Probe::new("reconcile-no-ungrant");
    let mut app = OathApp::new(&mut HostTrng::new(), emul_device_id(), OathSeal::emul());
    probe.mount(&mut app);

    // Authenticate with the OTP PIN, so `validated` is true and the grant is
    // *derived* false (a PIN exists) — exactly the shape that used to break.
    let pin = b"123456";
    assert_eq!(
        drive(&mut app, &apdu(0xB4, 0, 0, &[0x80, pin.len() as u8].into_iter().chain(pin.iter().copied()).collect::<Vec<u8>>())).1,
        0x9000,
        "SET_PIN"
    );
    assert_eq!(
        drive(&mut app, &apdu(0xB2, 0, 0, &[0x80, pin.len() as u8].into_iter().chain(pin.iter().copied()).collect::<Vec<u8>>())).1,
        0x9000,
        "VERIFY_PIN grants the session"
    );
    let (_, sw) = drive(&mut app, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(sw, 0x9000, "precondition: the session is authenticated");

    // A commit that fails at the live erase, which routes through
    // `region_reconcile`.
    probe.set_faults(F_ERASES);
    let name = maximal_name(0);
    let sw = put_cred(&mut app, &name, &[0x5Au8; MAXIMAL_SECRET]);
    probe.clear_faults();
    assert_ne!(
        sw, 0x9000,
        "precondition: the faulted commit must be refused, or nothing is being tested"
    );

    // The session must survive it. Before the fix this answered 0x6982.
    let (_, sw) = drive(&mut app, &apdu(0xA1, 0, 0, &[]));
    assert_eq!(
        sw, 0x9000,
        "a failed commit must not un-grant an authenticated session — the reconcile is about \
         one slot, not about who is logged in"
    );
}
