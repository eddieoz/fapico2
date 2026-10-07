//! Reproduction of the PAM login flow on a **region-backed** device twin.
//!
//! `pamu2fcfg` registers a non-resident credential through a PIN-secured
//! makeCredential; pam_u2f (with `nodetect`) then authenticates with a
//! token-backed getAssertion over an allowList. The user's board failed that
//! final step with CTAP2_ERR_NO_CREDENTIALS (0x2E) after the token had been
//! accepted and the key touched. The existing region fixtures enrol
//! **resident** credentials directly into the region; this drives the command
//! path end to end, over the same region, including across a reboot.

mod region_boot;

use fapico2_fido::cbor::no_heap::{self as nh, Item, Parser};
use fapico2_platform::secure_store::SecureStore as _;
use heapless::Vec as HV;
use region_boot::*;

const RP: &str = "pam://ShadowL";

/// pamu2fcfg -N's registration: non-resident ES256 (no `rk` option),
/// pinUvAuthParam present, no extensions.
fn make_cred_nonresident(device: &mut Device, pin: &[u8]) -> (u8, Vec<u8>) {
    let challenge = [0xCCu8; 32];
    let mut r: HV<u8, 512> = HV::new();
    nh::push_map_header(&mut r, 6).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    nh::push_bstr(&mut r, &challenge).unwrap();
    nh::push_uint(&mut r, 2).unwrap();
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_tstr(&mut r, RP).unwrap();
    nh::push_uint(&mut r, 3).unwrap();
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_bstr(&mut r, pin).unwrap();
    nh::push_uint(&mut r, 4).unwrap();
    nh::push_array_header(&mut r, 1).unwrap();
    nh::push_map_header(&mut r, 2).unwrap();
    nh::push_tstr(&mut r, "type").unwrap();
    nh::push_tstr(&mut r, "public-key").unwrap();
    nh::push_tstr(&mut r, "alg").unwrap();
    nh::push_neg(&mut r, -7).unwrap();
    nh::push_uint(&mut r, 8).unwrap();
    nh::push_bstr(&mut r, &device.pin_auth(&challenge)).unwrap();
    nh::push_uint(&mut r, 9).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    device.call(0x01, r.as_slice())
}

/// The credential ID out of a makeCredential reply's authData.
fn cred_id_of(cbor: &[u8]) -> Vec<u8> {
    let mut p = Parser::new(cbor);
    assert!(matches!(p.next(), Ok(Item::Map(3))));
    let mut auth_data = None;
    while p.remaining() > 0 {
        let Item::U(k) = p.next().unwrap() else { panic!() };
        match k {
            2 => auth_data = Some(p.next().unwrap()),
            _ => p.skip().unwrap(),
        }
    }
    let Item::B(ad) = auth_data.unwrap() else { panic!() };
    let id_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    ad[55..55 + id_len].to_vec()
}

#[test]
fn pam_nonresident_on_region_backed_device() {
    let _guard = lock();
    let _region_file = install("pam-nr");
    let mut device = Device::boot(keyed_store());
    device.grant_presence_always();
    device.set_pin(b"123456");
    assert!(device.persist(), "the PIN write must reach the secure store");
    assert_eq!(
        device.backend(),
        fapico2_fido::device_keystore::CredentialBackend::KeyRegion,
        "the fixture must be region-backed, or it would be testing the snapshot path"
    );

    // pamu2fcfg -N: non-resident, PIN-secured registration.
    let (status, cbor) = make_cred_nonresident(&mut device, b"eddieoz");
    assert_eq!(status, 0x00, "makeCredential failed");
    let cred_id = cred_id_of(&cbor);

    // The assertion pam_u2f sends after the PIN prompt: token-backed, with the
    // allowList. `get_assertion` carries no `up` option, so presence is the
    // default grant.
    let (status, assertion) = device.get_assertion(RP, Some(&cred_id));
    assert_eq!(
        status, 0x00,
        "token-backed GA with allowList must be served on a region-backed device: {assertion:02x?}"
    );

    // The board's failing shape: a SECOND registration under the SAME RP, and
    // assertions against both. ssh: (one record) works on the board while
    // pam://ShadowL (several) does not — this is the minimal host version of
    // that asymmetry.
    let (status, cbor2) = make_cred_nonresident(&mut device, b"eddieoz-2");
    assert_eq!(status, 0x00, "second makeCredential failed");
    let cred_id2 = cred_id_of(&cbor2);

    let (status, _a) = device.get_assertion(RP, Some(&cred_id));
    assert_eq!(status, 0x00, "GA for the first of two same-RP credentials");
    let (status, _a) = device.get_assertion(RP, Some(&cred_id2));
    assert_eq!(status, 0x00, "GA for the second of two same-RP credentials");

    // And it must survive a power cut: persist, drop the app, boot again over
    // the same store and the same region file.
    let store = device.into_store();
    let mut device2 = Device::boot(store);
    device2.grant_presence_always();
    device2.unlock_with_pin(b"123456");
    let (status, assertion2) = device2.get_assertion(RP, Some(&cred_id));
    assert_eq!(
        status, 0x00,
        "the credential must survive a reboot on a region-backed device: {assertion2:02x?}"
    );
}

/// A record sealed under a **stale payload key** — what a board carries after
/// its snapshot was re-sealed (reset, nuke, a format re-seal) — must not make
/// the by-ID lookup refuse the region: the candidate fails to open and is
/// skipped, and the credential written under the live keys is still served.
#[test]
fn stale_record_under_the_same_rp_does_not_fault_the_lookup() {
    let _guard = lock();
    let region_file = install("pam-stale");
    let mut device = Device::boot(keyed_store());
    device.grant_presence_always();
    device.set_pin(b"123456");
    assert!(device.persist());

    // Poison first: a FIDO record under the same RP whose index entry
    // authenticates (real index key) but whose payload key is wrong — the
    // board's orphan shape.
    let poison_keys = device.with_store(|store| {
        // The load itself is the assertion — the snapshot must be readable and
        // present before the payload key is poisoned; the value is not used.
        let _ks = fapico2_fido::device_keystore::DeviceKeystore::load(store)
            .expect("readable")
            .expect("snapshot present");
        let root = store.store_key().expect("store key");
        use fapico2_platform::keyregion::crypto;
        let index = crypto::derive_index_key_from_root(&root);
        let fake_secret = [0xA5u8; 32];
        RegionKeys {
            index,
            payload: crypto::derive_payload_key_from_root(&root, &fake_secret),
        }
    });
    let mut stale = credential(1, false);
    stale.rp_id_hash = fapico2_fido::crypto::sha256(RP.as_bytes());
    region_file.with(|region| {
        let mut creds = RegionCredentials::new(region, &poison_keys);
        creds
            .put(&nonce(0xB0), &stale)
            .expect("the poison record must write");
    });

    // The real credential, through the command path, under the live keys.
    let (status, cbor) = make_cred_nonresident(&mut device, b"eddieoz");
    assert_eq!(status, 0x00, "makeCredential failed");
    let cred_id = cred_id_of(&cbor);

    let (status, assertion) = device.get_assertion(RP, Some(&cred_id));
    assert_eq!(
        status, 0x00,
        "a stale same-RP record must not fault the lookup: {assertion:02x?}"
    );
}
