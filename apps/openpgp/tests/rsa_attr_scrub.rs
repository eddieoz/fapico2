//! US-962 (I1): a keyless card whose algorithm attributes say RSA-2048 is
//! scrubbed back to the ECC defaults when the persistent state is reloaded.
//!
//! S-724 deleted that scrub on the belief that "GENERATE on it works". It
//! does not: measured on the RP2350, on-card RSA-2048 generation runs into a
//! PC/SC transaction timeout (`0x80100016`) after ~1750 s, while X25519
//! returns `9000` in 0.09 s (`docs/known-gate-divergences.md`). A card
//! left holding `C1/C2/C3 = RSA-2048` with no keys — flashed by the C firmware
//! or an earlier session — is therefore wedged: the fail-closed allow-list
//! still accepts the attribute (`RSA_2048 ∈ allowed_generation`), the host
//! believes the capability exists, and `gpg --card-edit generate` blocks for
//! about half an hour and fails. The only escape is a flash erase that
//! destroys card state.
//!
//! Restoring the scrub removes the wedge *without* withdrawing RSA from the
//! allow-list: an operator can still select RSA at run time, and the moment a
//! key exists the attributes are left alone (see
//! `rsa_attributes_with_a_key_survive_a_reflash`).
//!
//! Both paths are covered, because `Persistent::load` is shared but the
//! clients are not: the virt twin drives opcard's own trussed-virt dispatch,
//! the device twin drives the platform `OpcardDispatch` on the host backend —
//! the client type the RP2350 actually builds — and each reboots by building
//! a fresh app over the *same* backing store, which is what a reflash is.
//!
//! US-964 added the fourth state, the one the first three could not reach: a
//! card that has already *signed*. `delete_key` does not reset the signature
//! counter, so the ordinary `gpg --card-edit` flow (generate, sign, then
//! `key-attr` to RSA-2048) lands on the wedged state with a non-zero counter,
//! and the scrub's then-present `sign_count == 0` clause silently declined to
//! clean it up. `signed_card_left_on_rsa_attributes_is_scrubbed_on_reflash`
//! performs that whole flow with real commands and pins the result.

use fapico2_openpgp::{OpenPgpApp, OPENPGP_AID};
use fapico2_platform::{
    dispatch::{Dispatcher, MAX_RESPONSE},
    trusted_backend::{
        dispatch::OpcardDispatch,
        host::{HostPlatform, HostStore, leak_buf, mount_fs},
        runner::with_backend,
    },
};

/// RSA-2048 attribute, standard (non-CRT) format — types.rs `RSA_2K_ATTRIBUTES`.
const RSA_2K: &[u8] = &[0x01, 0x08, 0x00, 0x00, 0x20, 0x00];
/// The factory defaults the scrub reverts to: Ed255 under C1/C3, X255 under
/// C2 — the exact bytes `FACTORY_FA` in `tests/dispatch.rs` pins for those
/// two algorithms, so this test cannot drift away from the advertisement.
const ED255_PK: &[u8] = &[
    0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01, 0xFF,
];
const X25519_PK: &[u8] = &[
    0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01, 0xFF,
];

const SW_OK: u16 = 0x9000;
/// Factory PINs, and the values the card is personalized to. They differ on
/// purpose: personalizing to the factory value would leave boot 2 unable to
/// tell "the PIN change took" from "the PIN change was silently dropped",
/// which is exactly the kind of signal a durability test must not blur.
const FACTORY_PW1: &[u8] = b"123456";
const FACTORY_PW3: &[u8] = b"12345678";
const NEW_PW1: &[u8] = b"654321";
const NEW_PW3: &[u8] = b"87654321";

/// One raw APDU through the dispatcher; returns `(body, SW)`.
fn apdu(dispatcher: &mut Dispatcher<1>, apdu: &[u8]) -> (Vec<u8>, u16) {
    let mut resp = heapless::Vec::<u8, MAX_RESPONSE>::new();
    dispatcher.dispatch(apdu, &mut resp);
    assert!(resp.len() >= 2, "response too short for {:x?}", apdu);
    let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
    (resp[..resp.len() - 2].to_vec(), sw)
}

/// One APDU plus GET RESPONSE (INS C0) continuation while the card reports
/// `61XX` — the way scd's apdu.c drains a chunked reply (Le = SW2).
fn apdu_read(dispatcher: &mut Dispatcher<1>, first: &[u8]) -> (Vec<u8>, u16) {
    let (mut body, mut sw) = apdu(dispatcher, first);
    while sw & 0xFF00 == 0x6100 {
        let le = (sw & 0xFF) as u8;
        let (chunk, next) = apdu(dispatcher, &[0x00, 0xC0, 0x00, 0x00, le]);
        body.extend_from_slice(&chunk);
        sw = next;
    }
    (body, sw)
}

/// GET DATA for a simple DO (Le = 0, i.e. "up to 256", which always fits).
fn get(dispatcher: &mut Dispatcher<1>, tag: u8) -> Vec<u8> {
    let (body, sw) = apdu(dispatcher, &[0x00, 0xCA, 0x00, tag, 0x00]);
    assert_eq!(sw, SW_OK, "GET DATA {tag:02X} must answer 9000, got {sw:04x}");
    body
}

/// PUT DATA of an algorithm attribute.
fn put_attr(dispatcher: &mut Dispatcher<1>, tag: u8, attr: &[u8]) {
    let mut command = vec![0x00, 0xDA, 0x00, tag, attr.len() as u8];
    command.extend_from_slice(attr);
    let (_, sw) = apdu(dispatcher, &command);
    assert_eq!(sw, SW_OK, "PUT DATA {tag:02X} must answer 9000, got {sw:04x}");
}

/// CHANGE REFERENCE DATA for PW1 then PW3 — US-912 refuses GENERATE while the
/// factory PINs are in force, so every GENERATE below personalizes first. The
/// payload is the factory PIN followed by its reverse (CHANGE REFERENCE DATA's
/// `new || repeat`), byte for byte what `tests/dispatch.rs` personalizes with.
fn personalize_pins(dispatcher: &mut Dispatcher<1>) {
    change_pin(dispatcher, 0x81, FACTORY_PW1, NEW_PW1);
    change_pin(dispatcher, 0x83, FACTORY_PW3, NEW_PW3);
}

/// CHANGE REFERENCE DATA (INS 24) for one PIN. opcard splits the payload at
/// the *current* PIN length and verifies the first half as the old value
/// (`vendor/opcard/src/command.rs` `change_reference_data`), so the command
/// is `old || new` — not the `new || repeat` spelling of the spec's
/// pinpad/verified-session form, which opcard takes only when a verified
/// session is already open and the payload is exactly one PIN long.
fn change_pin(dispatcher: &mut Dispatcher<1>, tag: u8, old: &[u8], new: &[u8]) {
    let mut payload = Vec::from(old);
    payload.extend_from_slice(new);
    let mut command = vec![0x00, 0x24, 0x00, tag, payload.len() as u8];
    command.extend_from_slice(&payload);
    let (_, sw) = apdu(dispatcher, &command);
    assert_eq!(sw, SW_OK, "CHANGE {tag:02X} must answer 9000, got {sw:04x}");
}

/// SELECT + admin VERIFY, the precondition every attribute PUT needs.
fn verified_card(dispatcher: &mut Dispatcher<1>, pw3: &[u8], label: &str) {
    let mut select = vec![0x00, 0xA4, 0x04, 0x00, 0x06];
    select.extend_from_slice(OPENPGP_AID);
    let (_, sw) = apdu(dispatcher, &select);
    assert_eq!(sw, SW_OK, "SELECT must answer 9000");
    let mut verify = vec![0x00, 0x20, 0x00, 0x83, pw3.len() as u8];
    verify.extend_from_slice(pw3);
    let (_, sw) = apdu(dispatcher, &verify);
    assert_eq!(sw, SW_OK, "VERIFY PW3 must answer 9000 [{label}]");
}

/// Switch all three usage DOs to RSA-2048 on a card that holds no keys —
/// exactly the state the C firmware (and any S-724-era firmware) leaves behind.
fn set_rsa_attributes(dispatcher: &mut Dispatcher<1>) {
    for tag in [0xC1u8, 0xC2, 0xC3] {
        put_attr(dispatcher, tag, RSA_2K);
    }
}

/// Boot the OpenPGP app over a remount of `internal` (the persisted internal
/// FS) and hand it to `f` — the `pw_status_resume.rs` reboot shape: one
/// backing buffer leaked for the process lifetime, remounted per boot with
/// fresh volatile state.
fn boot<F, R>(internal: *mut [u8], f: F) -> R
where
    F: FnOnce(&mut Dispatcher<1>) -> R,
{
    let ram = HostStore::fresh();
    with_backend(
        HostPlatform::with_store(HostStore::new(mount_fs::<256>(internal), ram.efs, ram.vfs)),
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

// ---------------------------------------------------------------------------
// Device path (the RP2350 client, on the host backend).
// ---------------------------------------------------------------------------

/// The wedge itself, on the device path: a keyless card carrying the
/// RSA-2048 attribute triple must come back from a reflash on the ECC
/// defaults, and must then be *usable* — a GENERATE of the signature key
/// answers `9000` with a real Ed25519 public key instead of running into the
/// ~1750 s RSA keygen that wedges the card today.
#[test]
fn rsa_attributes_without_keys_are_scrubbed_on_reflash() {
    let internal = leak_buf(256 * 4096);

    // Boot 1: a factory card, personalized, switched to RSA with no keys.
    boot(internal, |dispatcher| {
        verified_card(dispatcher, FACTORY_PW3, "boot1");
        // Personalize first (US-912 refuses GENERATE on factory PINs); the
        // attribute PUTs below are what actually wedge the card.
        personalize_pins(dispatcher);
        set_rsa_attributes(dispatcher);
        assert_eq!(get(dispatcher, 0xC1), RSA_2K, "C1 must be RSA-2048");
        assert_eq!(get(dispatcher, 0xC2), RSA_2K, "C2 must be RSA-2048");
        assert_eq!(get(dispatcher, 0xC3), RSA_2K, "C3 must be RSA-2048");
    });

    // Boot 2 (the reflash): the scrub fires, and the card is immediately
    // usable — the whole point, since "usable" is what the wedge denies.
    boot(internal, |dispatcher| {
        verified_card(dispatcher, NEW_PW3, "boot2");
        assert_eq!(
            get(dispatcher, 0xC1),
            ED255_PK,
            "a keyless RSA card must come back on the factory Ed255 attribute"
        );
        assert_eq!(
            get(dispatcher, 0xC2),
            X25519_PK,
            "a keyless RSA card must come back on the factory X255 attribute"
        );
        assert_eq!(
            get(dispatcher, 0xC3),
            ED255_PK,
            "a keyless RSA card must come back on the factory Ed255 attribute"
        );

        // Usable: GENERATE the signature key (Crt B6). With the wedge in
        // place this is the call that hangs for ~1750 s before failing.
        let mut verify_pw1 = vec![0x00, 0x20, 0x00, 0x81, NEW_PW1.len() as u8];
        verify_pw1.extend_from_slice(NEW_PW1);
        let (_, sw) = apdu(dispatcher, &verify_pw1);
        assert_eq!(sw, SW_OK, "VERIFY PW1 must answer 9000");
        let (body, sw) = apdu(dispatcher, &[0x00, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00]);
        assert_eq!(
            sw, SW_OK,
            "GENERATE on the scrubbed card must answer 9000, got {sw:04x}"
        );
        // The reply is the `7F 49` keygen template carrying a raw public
        // point (`86 20 <32 bytes>` for Ed25519 — gen.rs `serialize_25519`).
        // The curve OID lives in the *algorithm attribute*, which the
        // assertions above already pinned, not in the generated key.
        assert_eq!(
            &body[..4],
            &[0x7F, 0x49, 0x22, 0x86],
            "the scrubbed card must return a 7F49 template with a public point, got {body:02x?}"
        );
        assert_eq!(
            body[4], 0x20,
            "an Ed25519 public point is the raw 32-byte form, got {body:02x?}"
        );
        assert_eq!(body.len(), 37, "7F49 + 86 20 + 32 bytes, got {body:02x?}");
    });

    // Boot 3: the scrub is durable — a second reflash does not resurrect
    // the wedge from flash.
    boot(internal, |dispatcher| {
        verified_card(dispatcher, NEW_PW3, "boot3");
        assert_eq!(get(dispatcher, 0xC1), ED255_PK, "the scrub must persist");
    });
}

/// The over-scrub guard: a card that *does* hold a key is a working card,
/// even if its attributes say RSA. Its attributes must survive the reflash —
/// reverting them would silently reinterpret an existing key.
///
/// The state is built with an RSA key *import* rather than a GENERATE, and
/// that is not a stylistic choice: PUT DATA of a usage's algorithm attribute
/// deletes that usage's key (spec §4.4.3 — after the PUT, READ PUBLIC KEY on
/// the same Crt answers 6A88), so "all three attributes say RSA and some key
/// is still present" is unreachable by generating a key first. Importing the
/// RSA key *after* the attributes are set is the way a card reaches it, and it
/// is also how the C-firmware migration path populates a card.
#[test]
fn rsa_attributes_with_a_key_survive_a_reflash() {
    let internal = leak_buf(256 * 4096);

    boot(internal, |dispatcher| {
        verified_card(dispatcher, FACTORY_PW3, "k-boot1");
        personalize_pins(dispatcher);
        set_rsa_attributes(dispatcher);
        // A real RSA-2048 key in the signature slot: this card now carries
        // the RSA-2048 attribute triple *and* a key, so it is not wedged.
        let key = rsa_test_key();
        let (body, sw) = apdu(dispatcher, &put_key_rsa_apdu(&[0xB6, 0x00], &key.e, &key.p, &key.q));
        assert_eq!(sw, SW_OK, "PUT KEY RSA must answer 9000, got {sw:04x}");
        assert!(body.is_empty(), "PUT KEY answers 9000 with no body, got {body:02x?}");
        assert_eq!(get(dispatcher, 0xC1), RSA_2K, "C1 must be RSA-2048");
    });

    boot(internal, |dispatcher| {
        verified_card(dispatcher, NEW_PW3, "k-boot2");
        // The key is really there — otherwise this test would be proving
        // nothing, because "no key" is the state the scrub is allowed to fix.
        let (body, sw) = apdu_read(dispatcher, &[0x00, 0x47, 0x81, 0x00, 0x02, 0xB6, 0x00]);
        assert_eq!(
            sw, SW_OK,
            "the imported RSA key must survive the reflash, got {sw:04x}"
        );
        // `7F 49 <len> 81 <len> <modulus> 82 <len> <e>` — an RSA public key,
        // not an EC point.
        assert_eq!(
            &body[..2],
            &[0x7F, 0x49],
            "READ PUBLIC KEY must return the keygen template, got {body:02x?}"
        );
        assert!(
            body.windows(2).any(|w| w == [0x82, 0x03]),
            "the surviving key must be the imported RSA public key, got {body:02x?}"
        );
        for tag in [0xC1u8, 0xC2, 0xC3] {
            assert_eq!(
                get(dispatcher, tag),
                RSA_2K,
                "a card that holds a key must keep its RSA attribute across a reflash"
            );
        }
    });
}

/// US-964: the scrub must also fire on a card that has *signed*.
///
/// The three tests above only ever set the RSA attributes on a fresh card, so
/// every one of them ran with `sign_count == 0` — the exact value the scrub
/// used to require. That requirement was not free: `set_sign_alg` deletes the
/// usage's key before storing the new attribute, and `delete_key` does not
/// touch the counter, so the ordinary `gpg --card-edit` flow leaves the card
/// in the wedged state *with a non-zero counter*:
///
/// 1. personalize, GENERATE the Ed25519 signature key (Crt B6);
/// 2. sign once — PSO:CDS — so the signature counter is 1;
/// 3. `key-attr`, setting C1/C2/C3 to RSA-2048. Each PUT deletes that usage's
///    key (spec §4.4.3), so all three slots end up `None` and the counter
///    stays at 1;
/// 4. power-cycle.
///
/// With the counter clause in place the scrub did not fire, the card came
/// back still holding three RSA-2048 attributes and no keys, and
/// `gpg --card-edit generate` blocked for ~1750 s. Steps 1-4 are what this
/// test performs, so the state is reached by the real commands and not by
/// writing the counter into the store.
#[test]
fn signed_card_left_on_rsa_attributes_is_scrubbed_on_reflash() {
    let internal = leak_buf(256 * 4096);

    // Boot 1: a personalized card that generates a key, signs with it, and is
    // then switched to RSA-2048 by the same command sequence an operator uses.
    boot(internal, |dispatcher| {
        verified_card(dispatcher, FACTORY_PW3, "s-boot1");
        personalize_pins(dispatcher);
        // GENERATE the signature key: C1 is still the factory Ed255 attribute.
        let (_, sw) = apdu(dispatcher, &[0x00, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00]);
        assert_eq!(sw, SW_OK, "GENERATE must answer 9000, got {sw:04x}");
        // Sign once with it, so the signature counter is genuinely non-zero.
        // PSO:CDS (INS 2A, P1 9E, P2 9A) over a 32-byte digest, after VERIFY
        // PW1 — the path tests/device_pso.rs exercises.
        let mut verify_pw1 = vec![0x00, 0x20, 0x00, 0x81, NEW_PW1.len() as u8];
        verify_pw1.extend_from_slice(NEW_PW1);
        let (_, sw) = apdu(dispatcher, &verify_pw1);
        assert_eq!(sw, SW_OK, "VERIFY PW1 must answer 9000");
        let mut digest = [0x5Au8; 32];
        digest[0..8].copy_from_slice(b"US-964 s");
        let mut sign = vec![0x00, 0x2A, 0x9E, 0x9A, digest.len() as u8];
        sign.extend_from_slice(&digest);
        let (signature, sw) = apdu(dispatcher, &sign);
        assert_eq!(
            sw, SW_OK,
            "PSO:CDS on the generated key must answer 9000, got {sw:04x}"
        );
        assert_eq!(signature.len(), 64, "an Ed25519 signature is 64 bytes");

        // The counter really moved — otherwise this test would be proving
        // nothing, because a zero counter is the state the other three tests
        // already cover. Tag 0x93 is the digital-signature counter DO.
        assert_eq!(
            get(dispatcher, 0x93),
            [0x00, 0x00, 0x01],
            "the signature counter must read 1 after one PSO:CDS"
        );

        // `key-attr`: C1/C2/C3 to RSA-2048. Every PUT deletes that usage's
        // key, so the card ends this boot keyless while still holding a
        // non-zero counter — the state the scrub has to handle.
        set_rsa_attributes(dispatcher);
        for tag in [0xC1u8, 0xC2, 0xC3] {
            assert_eq!(get(dispatcher, tag), RSA_2K, "{tag:02X} must be RSA-2048");
        }
        assert_eq!(
            get(dispatcher, 0x93),
            [0x00, 0x00, 0x01],
            "the attribute PUTs must not have reset the signature counter — if they \
             did, this test would no longer reach the state it exists to pin"
        );
    });

    // Boot 2 (the reflash): the scrub fires even though the card has signed.
    boot(internal, |dispatcher| {
        verified_card(dispatcher, NEW_PW3, "s-boot2");
        assert_eq!(
            get(dispatcher, 0xC1),
            ED255_PK,
            "a signed card left on RSA-2048 attributes with no keys must come back \
             on the factory Ed255 attribute, not on the wedge"
        );
        assert_eq!(
            get(dispatcher, 0xC2),
            X25519_PK,
            "a signed card left on RSA-2048 attributes with no keys must come back \
             on the factory X255 attribute"
        );
        assert_eq!(
            get(dispatcher, 0xC3),
            ED255_PK,
            "a signed card left on RSA-2048 attributes with no keys must come back \
             on the factory Ed255 attribute"
        );
        // The counter is *not* scrubbed: only the attributes are. gpg reads
        // the counter to detect a cloned card, and a card that really did
        // sign must not lose that history to a firmware fix.
        assert_eq!(
            get(dispatcher, 0x93),
            [0x00, 0x00, 0x01],
            "the scrub reverts the attributes only; the signature counter is history"
        );
    });
}

/// The deterministic RSA-2048 (e, p, q) the over-scrub guard imports: a
/// fixed-seed keygen, so the test is hermetic and a failure is reproducible.
/// Import skips the prime search the card's own GENERATE would run, which is
/// precisely the operation that is too slow to use in a test.
struct RsaTestKey {
    e: Vec<u8>,
    p: Vec<u8>,
    q: Vec<u8>,
}

fn rsa_test_key() -> &'static RsaTestKey {
    use std::sync::LazyLock;
    static KEY: LazyLock<RsaTestKey> = LazyLock::new(|| {
        use rand::SeedableRng as _;
        use rsa::traits::{PrivateKeyParts as _, PublicKeyParts as _};

        let mut rng = rand::rngs::StdRng::seed_from_u64(0x4641_5049_434F_3936);
        let private = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("deterministic RSA-2048 keygen");
        let primes = private.primes();
        assert_eq!(primes.len(), 2, "RSA-2048 has exactly two primes");
        let pad = |mut v: Vec<u8>| -> Vec<u8> {
            while v.len() < 128 {
                v.insert(0, 0);
            }
            v
        };
        RsaTestKey {
            e: private.e().to_bytes_be(),
            p: pad(primes[0].to_bytes_be()),
            q: pad(primes[1].to_bytes_be()),
        }
    });
    &KEY
}

/// DER length for a definite-form length (opcard's import template needs the
/// one-byte form, or 81 <len> when it does not fit).
fn der_len(len: usize) -> Vec<u8> {
    if len <= 0x7f {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

/// PUT KEY (INS DB, extended header list 3FFF) for the always-`91,92,93`
/// (e, p, q) RSA private-key template, signature slot (Crt B6).
fn put_key_rsa_apdu(crt: &[u8], e: &[u8], p: &[u8], q: &[u8]) -> Vec<u8> {
    let mut template = Vec::new();
    for (tag, part) in [(0x91u8, e), (0x92, p), (0x93, q)] {
        template.push(tag);
        template.extend_from_slice(&der_len(part.len()));
    }
    let mut key_data = Vec::from(e);
    key_data.extend_from_slice(p);
    key_data.extend_from_slice(q);

    let mut content = Vec::from(crt);
    for (tag, value) in [
        (&[0x7Fu8, 0x48][..], template),
        (&[0x5Fu8, 0x48][..], key_data),
    ] {
        content.extend_from_slice(tag);
        content.extend_from_slice(&der_len(value.len()));
        content.extend_from_slice(&value);
    }

    let mut blob = vec![0x4Du8];
    blob.extend_from_slice(&der_len(content.len()));
    blob.extend_from_slice(&content);

    let mut apdu = vec![0x00u8, 0xDB, 0x3F, 0xFF, 0x00];
    apdu.extend_from_slice(&(blob.len() as u16).to_be_bytes());
    apdu.extend_from_slice(&blob);
    apdu
}

// ---------------------------------------------------------------------------
// Virt path (opcard's own trussed-virt dispatch). A filesystem-backed store
// is what makes the second boot possible here: opcard's `Client` handle is
// not `Copy`, so a single `with_ram_client` closure can only ever build one
// app. Two `with_fs_client` mounts over one backing file is the virt analog of
// the remount the device twin uses (trussed's `StorageConfig::filesystem`
// wants a preallocated single file, and sizes it itself on first mount).
// ---------------------------------------------------------------------------

#[test]
fn rsa_attributes_without_keys_are_scrubbed_on_reflash_virt() {
    let store = std::env::temp_dir().join(format!(
        "fapico2-us962-scrub-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let path = store.to_str().expect("utf-8 temp path").to_owned();

    opcard::virt::with_fs_client(&path, "fapico2-openpgp-us962", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        verified_card(&mut dispatcher, FACTORY_PW3, "v-boot1");
        personalize_pins(&mut dispatcher);
        set_rsa_attributes(&mut dispatcher);
        assert_eq!(get(&mut dispatcher, 0xC1), RSA_2K, "C1 must be RSA-2048");
    });

    opcard::virt::with_fs_client(&path, "fapico2-openpgp-us962", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        verified_card(&mut dispatcher, NEW_PW3, "v-boot2");
        assert_eq!(
            get(&mut dispatcher, 0xC1),
            ED255_PK,
            "a keyless RSA card must come back on the factory Ed255 attribute"
        );
        assert_eq!(
            get(&mut dispatcher, 0xC2),
            X25519_PK,
            "a keyless RSA card must come back on the factory X255 attribute"
        );
        assert_eq!(
            get(&mut dispatcher, 0xC3),
            ED255_PK,
            "a keyless RSA card must come back on the factory Ed255 attribute"
        );
    });

    std::fs::remove_file(&store).ok();
}

