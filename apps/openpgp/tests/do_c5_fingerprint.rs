//! US-972: DO C5 (Fingerprints) must describe the key the card actually
//! holds.
//!
//! The defect: `Persistent::set_key` cleared the fingerprint on the *removal*
//! path but wrote none on the *set* path, so C5 was only ever filled by the
//! host's `PUT DATA C5` or by the migration import. A card-side `GENERATE`
//! therefore replaced the public key and left C5 byte-identical. Measured on
//! hardware (RP2350, serial `88B0BD40`, `docs/tasks/evidence/us972-c5/`): a
//! raw `00 47 80 00 02 B6 00` returned a new point and C5 did not move. For a
//! *migrated* slot the stale value is worse than none, because the host
//! believes it.
//!
//! What the card can and cannot do here is the whole story. A v4 fingerprint
//! hashes the creation timestamp, and US-972 measured that the card does
//! **not** set that timestamp at GENERATE — the host `PUT DATA CD`s it
//! afterwards. So a fingerprint cannot be assembled inside `set_key`. The
//! fix is therefore in two moves:
//!
//!   * `set_key` clears the slot, so a new key can never inherit the previous
//!     one's fingerprint (the honest intermediate state is "none", not
//!     "wrong");
//!   * the fingerprint is computed when the creation date arrives, in
//!     `set_keygen_date`, which is the first moment every input is known.
//!
//! The expected values are computed here independently of the card, from the
//! packet layout GnuPG actually emits — established on hardware, not
//! reasoned about. `gpg --list-packets` on keys GnuPG generated, cross-checked
//! against the bytes GnuPG itself wrote into C5 and holds in its keyring.

use fapico2_openpgp::{OpenPgpApp, OPENPGP_AID};
use fapico2_platform::{
    dispatch::{Dispatcher, MAX_RESPONSE},
    trusted_backend::{
        dispatch::OpcardDispatch,
        host::{HostPlatform, HostStore, leak_buf, mount_fs},
        runner::with_backend,
    },
};
use sha1::{Digest, Sha1};

const SW_OK: u16 = 0x9000;
const FACTORY_PW1: &[u8] = b"123456";
const FACTORY_PW3: &[u8] = b"12345678";
const NEW_PW1: &[u8] = b"654321";
const NEW_PW3: &[u8] = b"87654321";

/// Ed25519 curve OID, as GnuPG writes it into the v4 packet.
const OID_ED25519: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];

// ---------------------------------------------------------------------------
// Reference fingerprint, computed the way GnuPG computes it.
// ---------------------------------------------------------------------------

/// `SHA-1( 0x99 || u16be(len) || body )` over a v4 public-key packet body.
fn v4_fingerprint(body: &[u8]) -> [u8; 20] {
    let mut preimage = Vec::with_capacity(3 + body.len());
    preimage.push(0x99);
    preimage.extend_from_slice(&(body.len() as u16).to_be_bytes());
    preimage.extend_from_slice(body);
    let digest = Sha1::digest(&preimage);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest);
    out
}

/// Bit length of a big-endian MPI value.
fn mpi_bit_len(value: &[u8]) -> u16 {
    for (i, byte) in value.iter().enumerate() {
        if *byte != 0 {
            return ((value.len() - i) * 8 - byte.leading_zeros() as usize) as u16;
        }
    }
    0
}

/// The Ed25519 v4 public-key packet body GnuPG builds:
/// `04 || created || 22 || 09 <oid> || mpi(0x40 || point)`.
fn ed25519_v4_body(created: u32, point: &[u8]) -> Vec<u8> {
    let mut mpi = Vec::with_capacity(1 + point.len());
    mpi.push(0x40);
    mpi.extend_from_slice(point);

    let mut body = Vec::new();
    body.push(4);
    body.extend_from_slice(&created.to_be_bytes());
    body.push(22);
    body.push(OID_ED25519.len() as u8);
    body.extend_from_slice(OID_ED25519);
    body.extend_from_slice(&mpi_bit_len(&mpi).to_be_bytes());
    body.extend_from_slice(&mpi);
    body
}

fn ed25519_fingerprint(created: u32, point: &[u8]) -> [u8; 20] {
    v4_fingerprint(&ed25519_v4_body(created, point))
}

/// SHA-1 against the FIPS 180-4 vectors, so a reference that silently stops
/// hashing cannot make every assertion below pass.
#[test]
fn reference_sha1_is_correct() {
    let hex = |d: &[u8]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(hex(&Sha1::digest(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_eq!(hex(&Sha1::digest(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");

    // The two MPI shapes GnuPG emits, at their real lengths: 0x40-prefixed
    // 25519 (33 bytes) and an uncompressed P-256 point (65 bytes).
    let mut m25519 = [0u8; 33];
    m25519[0] = 0x40;
    assert_eq!(mpi_bit_len(&m25519), 263, "GnuPG's 25519 MPI is 263 bits");
    let mut p256 = [0u8; 65];
    p256[0] = 0x04;
    assert_eq!(mpi_bit_len(&p256), 515, "GnuPG's P-256 MPI is 515 bits");
}

// ---------------------------------------------------------------------------
// Card plumbing, mirroring the helpers `rsa_attr_scrub.rs` already uses.
// ---------------------------------------------------------------------------

fn apdu(dispatcher: &mut Dispatcher<1>, apdu: &[u8]) -> (Vec<u8>, u16) {
    let mut resp = heapless::Vec::<u8, MAX_RESPONSE>::new();
    dispatcher.dispatch(apdu, &mut resp);
    assert!(resp.len() >= 2, "response too short for {:x?}", apdu);
    let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
    (resp[..resp.len() - 2].to_vec(), sw)
}

fn get(dispatcher: &mut Dispatcher<1>, tag: u8) -> Vec<u8> {
    let (body, sw) = apdu(dispatcher, &[0x00, 0xCA, 0x00, tag, 0x00]);
    assert_eq!(sw, SW_OK, "GET DATA {tag:02X} must answer 9000, got {sw:04x}");
    body
}

fn put_data(dispatcher: &mut Dispatcher<1>, tag: u8, data: &[u8]) {
    let mut command = vec![0x00, 0xDA, 0x00, tag, data.len() as u8];
    command.extend_from_slice(data);
    let (_, sw) = apdu(dispatcher, &command);
    assert_eq!(sw, SW_OK, "PUT DATA {tag:02X} must answer 9000, got {sw:04x}");
}

fn change_pin(dispatcher: &mut Dispatcher<1>, tag: u8, old: &[u8], new: &[u8]) {
    let mut payload = Vec::from(old);
    payload.extend_from_slice(new);
    let mut command = vec![0x00, 0x24, 0x00, tag, payload.len() as u8];
    command.extend_from_slice(&payload);
    let (_, sw) = apdu(dispatcher, &command);
    assert_eq!(sw, SW_OK, "CHANGE {tag:02X} must answer 9000, got {sw:04x}");
}

/// Boot the OpenPGP app over a fresh remount and hand it to `f`.
fn boot<F, R>(f: F) -> R
where
    F: FnOnce(&mut Dispatcher<1>) -> R,
{
    let internal = leak_buf(256 * 4096);
    let ram = HostStore::fresh();
    with_backend(
        HostPlatform::with_store(HostStore::new(
            mount_fs::<256>(internal),
            ram.efs,
            ram.vfs,
        )),
        OpcardDispatch::new(),
        "opcard",
        |client| {
            let mut app = OpenPgpApp::new(client);
            let mut dispatcher = Dispatcher::<1>::new();
            assert!(dispatcher.register(&mut app));
            f(&mut dispatcher)
        },
    )
}

/// The Ed25519 public point out of a GENERATE reply: `7F49 <len> 86 20 <32>`.
fn ed25519_point_from_generate(reply: &[u8]) -> [u8; 32] {
    assert_eq!(&reply[..2], &[0x7f, 0x49], "GENERATE reply must carry the 7F49 template");
    assert_eq!(reply[2], 0x22, "7F49 length for a 25519 point is 0x22");
    assert_eq!(reply[3], 0x86, "extended public key template");
    assert_eq!(reply[4], 0x20, "point length 32");
    let mut point = [0u8; 32];
    point.copy_from_slice(&reply[5..37]);
    point
}

const KEYGEN_DATE: u32 = 0x6ab9_42f8;

/// A card that has been selected, personalized and verified, ready to
/// GENERATE. The SELECT comes first: CHANGE REFERENCE DATA needs the OpenPGP
/// application selected or the card answers `6A82`.
fn ready_card(dispatcher: &mut Dispatcher<1>) {
    let mut select = vec![0x00, 0xA4, 0x04, 0x00, 0x06];
    select.extend_from_slice(OPENPGP_AID);
    let (_, sw) = apdu(dispatcher, &select);
    assert_eq!(sw, SW_OK, "SELECT must answer 9000");
    change_pin(dispatcher, 0x81, FACTORY_PW1, NEW_PW1);
    change_pin(dispatcher, 0x83, FACTORY_PW3, NEW_PW3);
    let mut verify = vec![0x00, 0x20, 0x00, 0x83, NEW_PW3.len() as u8];
    verify.extend_from_slice(NEW_PW3);
    let (_, sw) = apdu(dispatcher, &verify);
    assert_eq!(sw, SW_OK, "VERIFY PW3 must answer 9000");
}

// ---------------------------------------------------------------------------
// The tests.
// ---------------------------------------------------------------------------

/// The core of US-972. A card-side GENERATE must leave C5 *describing the key
/// the card actually holds*.
///
/// The host writes one slot at a time through C7/C8/C9 — C5 is the read-only
/// 60-byte aggregate of the three, which is why "the host populated C5" and
/// "the host PUT DATA C5" are the same thing on this card.
#[test]
fn generated_key_does_not_inherit_a_stale_fingerprint() {
    boot(|dispatcher| {
        ready_card(dispatcher);

        // First key, and the fingerprint the host records for it.
        let (body, sw) = apdu(dispatcher, &[0x00, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00]);
        assert_eq!(sw, SW_OK, "first GENERATE must answer 9000, got {sw:04x}");
        let first_point = ed25519_point_from_generate(&body);
        put_data(dispatcher, 0xCE, &KEYGEN_DATE.to_be_bytes());
        let first_expected = ed25519_fingerprint(KEYGEN_DATE, &first_point);
        put_data(dispatcher, 0xC7, &first_expected);

        let c5 = get(dispatcher, 0xC5);
        assert_eq!(c5.len(), 60, "C5 layout is 60 bytes");
        assert_eq!(c5[..20], first_expected[..], "C5 must serve what the host put");

        // Now the card generates a *different* key over the top. This is the
        // US-972 defect: C5 kept the previous key's bytes, and a host reading
        // them got a confident, stale answer.
        let (body, sw) = apdu(dispatcher, &[0x00, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00]);
        assert_eq!(sw, SW_OK, "second GENERATE must answer 9000, got {sw:04x}");
        let second_point = ed25519_point_from_generate(&body);
        assert_ne!(first_point, second_point, "the card must have made a new key");

        let c5 = get(dispatcher, 0xC5);
        assert_eq!(c5.len(), 60, "C5 layout is 60 bytes");
        assert_ne!(
            c5[..20],
            first_expected[..],
            "US-972: the signature slot still holds the previous key's fingerprint"
        );
        assert_eq!(
            c5[..20],
            [0u8; 20],
            "between GENERATE and the host's PUT DATA CD the card cannot know the \
             creation date, so the slot must read as 'none' rather than 'wrong'"
        );

        // The host supplies a new creation date -- the moment every input to
        // the fingerprint exists. The card must now compute the real one.
        put_data(dispatcher, 0xCE, &KEYGEN_DATE.to_be_bytes());
        let c5 = get(dispatcher, 0xC5);
        assert_eq!(
            c5[..20],
            ed25519_fingerprint(KEYGEN_DATE, &second_point)[..],
            "US-972: C5 must hold the v4 fingerprint of the key the card generated"
        );
    });
}

/// A regenerated key must not inherit a fingerprint, whether the previous one
/// arrived from the host or from the card itself.
#[test]
fn card_written_fingerprint_is_replaced_not_inherited() {
    boot(|dispatcher| {
        ready_card(dispatcher);

        let (body, sw) = apdu(dispatcher, &[0x00, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00]);
        assert_eq!(sw, SW_OK, "first GENERATE must answer 9000, got {sw:04x}");
        let first_point = ed25519_point_from_generate(&body);
        put_data(dispatcher, 0xCE, &KEYGEN_DATE.to_be_bytes());

        let first = get(dispatcher, 0xC5)[..20].to_vec();
        assert_eq!(
            first[..],
            ed25519_fingerprint(KEYGEN_DATE, &first_point)[..],
            "the card must compute the fingerprint itself once the date is known"
        );

        let (body, sw) = apdu(dispatcher, &[0x00, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00]);
        assert_eq!(sw, SW_OK, "second GENERATE must answer 9000, got {sw:04x}");
        let second_point = ed25519_point_from_generate(&body);

        put_data(dispatcher, 0xCE, &KEYGEN_DATE.to_be_bytes());
        let second = get(dispatcher, 0xC5)[..20].to_vec();
        assert_eq!(
            second[..],
            ed25519_fingerprint(KEYGEN_DATE, &second_point)[..],
            "US-972: after a replace, C5 must describe the NEW key"
        );
        assert_ne!(
            first[..], second[..],
            "US-972: a regenerated key must never inherit the old fingerprint"
        );
    });
}

/// Only the signature slot moves, and the 60-byte layout is untouched.
#[test]
fn only_the_signature_slot_moves_and_layout_is_unchanged() {
    boot(|dispatcher| {
        ready_card(dispatcher);

        let (body, sw) = apdu(dispatcher, &[0x00, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00]);
        assert_eq!(sw, SW_OK, "GENERATE must answer 9000, got {sw:04x}");
        let point = ed25519_point_from_generate(&body);

        // Host-written values in the two untouched slots.
        let dec = [0x11u8; 20];
        let aut = [0x22u8; 20];
        put_data(dispatcher, 0xC8, &dec);
        put_data(dispatcher, 0xC9, &aut);
        let before = get(dispatcher, 0xC5);
        let mut expect_other = Vec::new();
        expect_other.extend_from_slice(&dec);
        expect_other.extend_from_slice(&aut);
        assert_eq!(&before[20..60], &expect_other[..]);

        put_data(dispatcher, 0xCE, &KEYGEN_DATE.to_be_bytes());
        let after = get(dispatcher, 0xC5);
        assert_eq!(after.len(), 60, "C5 stays 60 bytes");
        assert_eq!(&after[20..60], &before[20..60], "Dec and Aut slots must not move");
        assert_eq!(
            after[..20],
            ed25519_fingerprint(KEYGEN_DATE, &point)[..],
            "the signature slot must carry the real fingerprint"
        );
    });
}
