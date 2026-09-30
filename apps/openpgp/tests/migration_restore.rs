//! End-to-end C migration acceptance tests. Fixtures use the merged producer,
//! not the upstream OpenPGP physical-file layout.
use fapico2_openpgp::{OpenPgpApp, OPENPGP_AID};
use fapico2_platform::secure_store::{SecureStore, Rp2350SecureStore, chunked};
use fapico2_platform::{
    cflash::{fallback_partition_reserved, DataPartition},
    cfs::{CFlashSource, PoolBounds},
    migration::{self, MigrationBuffers},
    secure_store::HostSecureStore,
    trusted_backend::host::{with_host_backend, with_host_backend_and_migration,
        with_host_store_and_migration},
    dispatch::{Dispatcher, MAX_RESPONSE},
};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use sha2::{Digest, Sha256};

const UID: &[u8] = &[1,2,3,4,5,6,7,8];
const OTP: [u8;32] = hex_literal::hex!("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
const PW1: &[u8] = b"654321";
// US-917: fixed test nonce for the AEAD DEK rewrap (production draws it
// from the platform TRNG; US-380).
const NONCE: [u8; 12] = [0x5u8; 12];
const PUBLIC: &[u8] = include_bytes!("fixtures/c-merged-p256-public.bin");
const STREAM: &[u8] = include_bytes!("fixtures/c-merged-p256.bin");

struct Flash { bytes: Vec<u8>, part: DataPartition }
impl CFlashSource for Flash {
    fn read(&self, addr: u32, out: &mut [u8]) {
        let o = (addr - self.part.start) as usize;
        out.copy_from_slice(&self.bytes[o..o+out.len()]);
    }
}
fn fixture() -> Flash {
    fixture_from_stream(STREAM)
}
fn fixture_from_stream(mut stream: &[u8]) -> Flash {
    let part = fallback_partition_reserved();
    let b = PoolBounds::from_partition(part);
    let mut f = Flash { bytes: vec![0xff; part.size_bytes() as usize], part };
    let mut put = |addr: u32, data: &[u8]| {
        let o = (addr-part.start) as usize;
        f.bytes[o..o+data.len()].copy_from_slice(data);
    };
    put(b.end_rom_pool, &[0;8]);
    let mut cursor = b.data_end;
    let mut previous = 0u32;
    while !stream.is_empty() {
        let fid = &stream[..2];
        let n = u32::from_le_bytes(stream[2..6].try_into().unwrap()) as usize;
        cursor -= (12+n) as u32;
        put(cursor, &previous.to_le_bytes());
        put(cursor+4, &[0;4]);
        put(cursor+8, fid);
        put(cursor+10, &(n as u16).to_le_bytes());
        put(cursor+12, &stream[6..6+n]);
        previous=cursor;
        stream=&stream[6+n..];
    }
    put(b.data_end, &previous.to_le_bytes());
    f
}

/// US-918: seed the boot-entropy slot with the fixed test vector so the
/// bound device root is derivable; harmless where derivation never happens.
fn seed_entropy<K: SecureStore>(store: &mut K) {
    use fapico2_platform::ckey;
    use fapico2_platform::migration::SLOT_BOOT_ENTROPY;
    const ENTROPY: [u8; ckey::BOOT_ENTROPY_LEN] = [0xA5u8; ckey::BOOT_ENTROPY_LEN];
    store.write(SLOT_BOOT_ENTROPY, &ENTROPY).unwrap();
}

fn cmd(d: &mut Dispatcher<'_,1>, ins: u8, p1: u8, p2: u8, data: &[u8], sw: u16) -> Vec<u8> {
    let mut apdu=vec![0,ins,p1,p2];
    if !data.is_empty() { apdu.push(data.len() as u8); apdu.extend_from_slice(data); }
    apdu.push(0);
    let mut r=heapless::Vec::<u8,MAX_RESPONSE>::new();
    d.dispatch(&apdu,&mut r);
    assert_eq!(&r[r.len()-2..],&sw.to_be_bytes(),"INS {ins:02x} response {r:02x?}");
    r[..r.len()-2].to_vec()
}
fn exercise(complete: bool) {
    let flash=fixture();
    let mut store=HostSecureStore::new();
    let mut b=MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash,flash.part,&mut store,&OTP,UID,&mut b).unwrap();
    if complete {
        assert_eq!(migration::complete_passphrase_class(&flash,flash.part,&mut store,&OTP,UID,&mut b,1,&NONCE,PW1).unwrap(),migration::ClassStatus::Migrated);
    }
    let mut dek = zeroize::Zeroizing::new([0; 48]);
    if complete {
        migration::read_openpgp_dek(&mut store, &OTP, UID, &mut dek).unwrap();
    }
    let capture = migration::read_openpgp_capture(
        &mut store, &OTP, UID, &mut b.scratch,
    ).unwrap();
    // US-918: the kek is the bound device root — derive it where the store
    // is reachable (the closure below cannot borrow it mutably).
    let kek = migration::native_openpgp_wrapping_key(&mut store, &OTP, UID, &capture.source()).unwrap();
    with_host_backend_and_migration("opcard", &mut store, &OTP, UID, |client| {
        let mut app=OpenPgpApp::new(client);
        // Consume the captured source through the same production entry point
        // used by the device app, rather than constructing a fresh native card.
        app.restore_captured_public_metadata(&capture, &OTP, UID).unwrap();
        if complete {
            app.restore_captured_private_key(&kek, &capture, &OTP, UID, &dek).unwrap();
        }
        let mut d=Dispatcher::<1>::new();
        assert!(d.register(&mut app));
        cmd(&mut d,0xa4,4,0,OPENPGP_AID,0x9000);
        assert_eq!(cmd(&mut d,0xca,0,0x5b,&[],0x9000),b"Migrated User");
        assert_eq!(cmd(&mut d,0x47,0x81,0,&[0xb6,0],0x9000),PUBLIC);
        cmd(&mut d,0x20,0,0x81,PW1,0x9000);
        let digest=Sha256::digest(b"original migrated identity");
        if complete {
            let sig=cmd(&mut d,0x2a,0x9e,0x9a,&digest,0x9000);
            let key=p256::ecdsa::VerifyingKey::from_sec1_bytes(&PUBLIC[5..]).unwrap();
            key.verify_prehash(&digest,&p256::ecdsa::Signature::from_slice(&sig).unwrap()).unwrap();
        } else {
            cmd(&mut d,0x2a,0x9e,0x9a,&digest,0x6a88);
        }
    }).unwrap();
}
#[test]
fn decryption_key_restored_deciphers() {
    use fapico2_platform::persist::{ImageSink, WindowedImageSource};
    use fapico2_platform::trusted_backend::host::HostStore;
    struct Sink;
    impl ImageSink for Sink {
        fn program(&mut self, _: &mut dyn WindowedImageSource) -> bool { true }
    }
    let flash = fixture_from_stream(include_bytes!("fixtures/c-merged-x25519.bin"));
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    {
        let capture = migration::read_openpgp_capture(
            &mut store, &OTP, UID, &mut bufs.scratch,
        ).unwrap();
        let mut public = [0; 37];
        assert_eq!(capture.read_public_key(0x10d2, &OTP, UID, &mut public).unwrap(), Some(37));
        assert_eq!(&public, include_bytes!("fixtures/c-merged-x25519-public.bin"));
        let dek = core::array::from_fn(|i| 0x60 + i as u8);
        let mut private = zeroize::Zeroizing::new([0; 33]);
        assert_eq!(capture.read_private_key(0x10d2, &OTP, UID, &dek, &mut private[..]).unwrap(), Some(33));
        let mut expected = [0; 33];
        expected[0] = 9;
        for (i, byte) in expected[1..].iter_mut().enumerate() { *byte = i as u8; }
        expected[32] = 0x5f;
        assert_eq!(&private[..], &expected);
    }
    let cell = core::cell::RefCell::new(store);
    let mut shared = fapico2_platform::secure_store::SharedStore::new(&cell);
    let mut auth = fapico2_platform::secure_store::SharedStore::new(&cell);
    with_host_store_and_migration(HostStore::fresh(), "opcard", &mut auth, &OTP, UID, |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_at_boot(&mut shared, &OTP, UID, &mut bufs).unwrap();
        assert_eq!(app.complete_migration(
            &flash, flash.part, &mut shared, &OTP, UID, &mut bufs, PW1, &NONCE, &mut Sink,
        ).unwrap(), migration::ClassStatus::Migrated);
        let mut d = Dispatcher::<1>::new();
        assert!(d.register(&mut app));
        cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        cmd(&mut d, 0x20, 0, 0x82, PW1, 0x9000);
        let mut cipher = vec![0xa6, 0x25, 0x7f, 0x49, 0x22, 0x86, 0x20];
        cipher.extend_from_slice(include_bytes!("fixtures/c-merged-x25519-peer.bin"));
        let shared_secret = cmd(&mut d, 0x2a, 0x80, 0x86, &cipher, 0x9000);
        assert_eq!(shared_secret, include_bytes!("fixtures/c-merged-x25519-shared.bin"));
    }).unwrap();
}

#[test]
fn authentication_key_restored_authenticates() {
    use fapico2_platform::persist::{ImageSink, WindowedImageSource};
    use fapico2_platform::trusted_backend::host::HostStore;
    struct Sink;
    impl ImageSink for Sink {
        fn program(&mut self, _: &mut dyn WindowedImageSource) -> bool { true }
    }
    let public = include_bytes!("fixtures/c-merged-auth-p256-public.bin");
    let flash = fixture_from_stream(include_bytes!("fixtures/c-merged-auth-p256.bin"));
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    {
        let capture = migration::read_openpgp_capture(
            &mut store, &OTP, UID, &mut bufs.scratch,
        ).unwrap();
        let mut captured_public = [0; 70];
        assert_eq!(capture.read_public_key(0x10d3, &OTP, UID, &mut captured_public).unwrap(), Some(70));
        assert_eq!(&captured_public, public);
        let dek = core::array::from_fn(|i| 0x60 + i as u8);
        let mut private = zeroize::Zeroizing::new([0; 33]);
        assert_eq!(capture.read_private_key(0x10d3, &OTP, UID, &dek, &mut private[..]).unwrap(), Some(33));
        assert_eq!(private[0], 3);
        assert_eq!(&private[1..], &(1u8..=32).collect::<Vec<_>>());
    }
    let cell = core::cell::RefCell::new(store);
    let mut shared = fapico2_platform::secure_store::SharedStore::new(&cell);
    let mut auth = fapico2_platform::secure_store::SharedStore::new(&cell);
    with_host_store_and_migration(HostStore::fresh(), "opcard", &mut auth, &OTP, UID, |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_at_boot(&mut shared, &OTP, UID, &mut bufs).unwrap();
        assert_eq!(app.complete_migration(
            &flash, flash.part, &mut shared, &OTP, UID, &mut bufs, PW1, &NONCE, &mut Sink,
        ).unwrap(), migration::ClassStatus::Migrated);
        let mut d = Dispatcher::<1>::new();
        assert!(d.register(&mut app));
        cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        let digest = Sha256::digest(b"captured authentication identity challenge");
        cmd(&mut d, 0x88, 0, 0, &digest, 0x6982);
        cmd(&mut d, 0x20, 0, 0x82, PW1, 0x9000);
        let signature = cmd(&mut d, 0x88, 0, 0, &digest, 0x9000);
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&public[5..]).unwrap();
        key.verify_prehash(&digest, &p256::ecdsa::Signature::from_slice(&signature).unwrap()).unwrap();
        let signing_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&PUBLIC[5..]).unwrap();
        assert!(signing_key.verify_prehash(&digest, &p256::ecdsa::Signature::from_slice(&signature).unwrap()).is_err());
    }).unwrap();
}

const THREE_KEY_STREAM: &[u8] = include_bytes!("fixtures/c-merged-three-key.bin");

fn assert_later_private_refused(stream: &[u8]) {
    use fapico2_platform::trusted_backend::{host::{HostStore, HostPlatform}, runner::with_backend, OpcardDispatch};
    use trussed_core::types::PathBuf;
    let flash = fixture_from_stream(stream);
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    migration::complete_passphrase_class(
        &flash, flash.part, &mut store, &OTP, UID, &mut bufs, 1, &NONCE, PW1,
    ).unwrap();
    let mut dek = zeroize::Zeroizing::new([0; 48]);
    migration::read_openpgp_dek(&mut store, &OTP, UID, &mut dek).unwrap();
    let capture = migration::read_openpgp_capture(&mut store, &OTP, UID, &mut bufs.scratch).unwrap();
    let fs = HostStore::fresh();
    // US-918: the kek is the bound device root — derive it where the store
    // is reachable (the closure below cannot borrow it mutably).
    let kek = migration::native_openpgp_wrapping_key(&mut store, &OTP, UID, &capture.source()).unwrap();
    with_backend(HostPlatform::with_store(fs), OpcardDispatch::new(), "opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_captured_public_metadata(&capture, &OTP, UID).unwrap();
        assert!(app.restore_captured_private_key(&kek, &capture, &OTP, UID, &dek).is_err());
    });
    // Public metadata is allowed. The actual wrapped private file must NOT be
    // installed, even though SIGN precedes the refused DEC/AUT object.
    assert!(fs.ifs.exists(&PathBuf::try_from("opcard/dat/persistent-state.cbor").unwrap()));
    for path in ["signing_key.bin", "migration-signing-ready",
        "conf_key.bin", "migration-decryption-ready",
        "auth_key.bin", "migration-authentication-ready"] {
        assert!(!fs.ifs.exists(&PathBuf::try_from(format!("opcard/dat/{path}").as_str()).unwrap()),
            "earlier SIGN must NOT be installed on later private refusal: {path}");
    }
}

#[test]
fn later_private_key_refused_before_any_private_install() {
    for stream in [include_bytes!("fixtures/c-merged-later-tag.bin").as_slice(),
        include_bytes!("fixtures/c-merged-later-length.bin").as_slice()] {
        assert_later_private_refused(stream);
    }
}

#[test]
fn later_private_key_mismatch_refused_before_any_private_install() {
    for stream in [include_bytes!("fixtures/c-merged-later-auth-mismatch.bin").as_slice(),
        include_bytes!("fixtures/c-merged-later-dec-mismatch.bin").as_slice()] {
        assert_later_private_refused(stream);
    }
}

// Test-local transport wrapper: real host crypto/filesystem, with one failed
// volatile delete reply. No production fault-injection hooks are needed.
#[derive(Default)]
struct CleanupTrace {
    armed: bool,
    private: Vec<trussed_core::types::KeyId>,
    derived: Vec<trussed_core::types::KeyId>,
    deleted: Vec<trussed_core::types::KeyId>,
}

struct DeleteFailureClient<C> {
    inner: C,
    trace: std::rc::Rc<std::cell::RefCell<CleanupTrace>>,
    fail_delete: usize,
    reply: Option<Result<trussed_core::api::Reply, trussed_core::Error>>,
}

impl<C: trussed_core::PollClient> trussed_core::PollClient for DeleteFailureClient<C> {
    fn request<Rq: trussed_core::api::RequestVariant>(&mut self, request: Rq)
        -> trussed_core::ClientResult<'_, Rq::Reply, Self>
    {
        use trussed_core::{api::{Request, Reply}, types::Location};
        let request: Request = request.into();
        let mut trace = self.trace.borrow_mut();
        let fail = if trace.armed {
            // Any installer request (including reading its state/ready marker)
            // is forbidden after private preflight starts in these refusal cases.
            match &request {
                Request::UnsafeInjectKey(req) => assert_eq!(req.attributes.persistence, Location::Volatile),
                Request::DeriveKey(req) => assert_eq!(req.attributes.persistence, Location::Volatile),
                Request::SerializeKey(_) => (),
                Request::Delete(req) => trace.deleted.push(req.key),
                _ => panic!("unexpected request during private preflight: {request:?}"),
            }
            matches!(&request, Request::Delete(_)) && trace.deleted.len() == self.fail_delete
        } else { false };
        let reply = if fail {
            Err(trussed_core::Error::FilesystemWriteFailure)
        } else {
            let typed = Rq::try_from(request).ok().unwrap();
            trussed_core::try_syscall!(self.inner.request(typed)).map(Into::into)
        };
        if trace.armed {
            match &reply {
                Ok(Reply::UnsafeInjectKey(reply)) => trace.private.push(reply.key),
                Ok(Reply::DeriveKey(reply)) => trace.derived.push(reply.key),
                _ => (),
            }
        }
        drop(trace);
        self.reply = Some(reply);
        Ok(trussed_core::FutureResult::new(self))
    }

    fn poll(&mut self) -> core::task::Poll<Result<trussed_core::api::Reply, trussed_core::Error>> {
        core::task::Poll::Ready(self.reply.take().expect("one pending test request"))
    }
}
impl<C: trussed_core::PollClient> trussed_core::CryptoClient for DeleteFailureClient<C> {}
impl<C: trussed_core::PollClient> trussed_core::FilesystemClient for DeleteFailureClient<C> {}
impl<C: trussed_core::PollClient> trussed_core::UiClient for DeleteFailureClient<C> {}
impl<C, E> trussed_core::serde_extensions::ExtensionClient<E> for DeleteFailureClient<C>
where
    E: trussed_core::serde_extensions::Extension,
    C: trussed_core::serde_extensions::ExtensionClient<E>,
{
    fn id() -> u8 { C::id() }
}

fn assert_private_cleanup_failure(stream: &[u8], key_index: usize) {
    use fapico2_platform::trusted_backend::{host::{HostStore, HostPlatform}, runner::with_backend, OpcardDispatch};
    use fapico2_platform::secure_store::SecureStoreError;
    use trussed_core::types::PathBuf;
    // Fail either derived or private cleanup; the first failure must never
    // suppress the second attempt, including the shared mismatch cleanup path.
    for cleanup in 1..=2 {
        let flash = fixture_from_stream(stream);
        let mut store = Rp2350SecureStore::new();
        let mut bufs = MigrationBuffers::new();
        seed_entropy(&mut store);
        migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
        let capture = migration::read_openpgp_capture(&mut store, &OTP, UID, &mut bufs.scratch).unwrap();
        let dek = core::array::from_fn(|i| 0x60 + i as u8);
        let fs = HostStore::fresh();
        let trace = std::rc::Rc::new(std::cell::RefCell::new(CleanupTrace::default()));
        // US-918: the kek is the bound device root — derive it where the
        // store is reachable (the closure below cannot borrow it mutably).
        let kek = migration::native_openpgp_wrapping_key(&mut store, &OTP, UID, &capture.source()).unwrap();
        let result = with_backend(HostPlatform::with_store(fs), OpcardDispatch::new(), "opcard", |client| {
            let client = DeleteFailureClient {
                inner: client, trace: trace.clone(), fail_delete: key_index * 2 + cleanup, reply: None,
            };
            let mut app = OpenPgpApp::new(client);
            app.restore_captured_public_metadata(&capture, &OTP, UID).unwrap();
            trace.borrow_mut().armed = true;
            app.restore_captured_private_key(&kek, &capture, &OTP, UID, &dek)
        });
        let trace = trace.borrow();
        assert_eq!(trace.private.len(), key_index + 1);
        assert_eq!(trace.derived.len(), key_index + 1);
        let expected: Vec<_> = trace.derived.iter().zip(&trace.private)
            .flat_map(|(&derived, &private)| [derived, private]).collect();
        assert_eq!(trace.deleted, expected, "both distinct handles must get cleanup attempts");
        assert_ne!(trace.derived[key_index], trace.private[key_index]);
        assert!(fs.ifs.exists(&PathBuf::try_from("opcard/dat/persistent-state.cbor").unwrap()));
        for path in ["signing_key.bin", "migration-signing-ready",
            "conf_key.bin", "migration-decryption-ready",
            "auth_key.bin", "migration-authentication-ready"] {
            assert!(!fs.ifs.exists(&PathBuf::try_from(format!("opcard/dat/{path}").as_str()).unwrap()),
                "cleanup failure must not install private files/markers: {path}");
        }
        assert!(matches!(result, Err(migration::MigrationError::Store(SecureStoreError::Corrupt))),
            "cleanup {cleanup} must preserve exact Store(Corrupt), got {result:?}");
    }
}

#[test]
fn private_preflight_cleanup_failure_p256() {
    assert_private_cleanup_failure(THREE_KEY_STREAM, 0);
}

#[test]
fn private_preflight_cleanup_failure_x25519() {
    assert_private_cleanup_failure(THREE_KEY_STREAM, 1);
}

#[test]
fn private_preflight_cleanup_failure_p256_mismatch() {
    assert_private_cleanup_failure(include_bytes!("fixtures/c-merged-later-auth-mismatch.bin"), 2);
}

#[test]
fn private_preflight_cleanup_failure_x25519_mismatch() {
    assert_private_cleanup_failure(include_bytes!("fixtures/c-merged-later-dec-mismatch.bin"), 1);
}

#[test]
fn full_three_key_capture_restores_all_operations() {
    use fapico2_platform::persist::{ImageSink, WindowedImageSource};
    use fapico2_platform::trusted_backend::host::HostStore;
    struct Sink(Vec<u8>);
    impl ImageSink for Sink {
        fn program(&mut self, src: &mut dyn WindowedImageSource) -> bool {
            self.0 = fapico2_platform::persist::pull_image(src); true
        }
    }
    assert_eq!(THREE_KEY_STREAM.len(), 1724);
    assert_eq!(THREE_KEY_STREAM.len().div_ceil(chunked::PART_PAYLOAD_MAX), 4);
    let flash = fixture_from_stream(THREE_KEY_STREAM);
    let before = flash.bytes.clone();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs)
        .expect("initial four-part three-key capture must fit");
    // Reboot from the capture before any native backend has been initialized.
    let mut image = vec![0; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    let n = store.snapshot_partition(&mut image).unwrap();
    store = Rp2350SecureStore::new();
    store.from_partition_image(&image[..n]);
    let fs = HostStore::fresh();
    let mut sink = Sink(Vec::new());
    for completed in [false, true] {
        let cell = core::cell::RefCell::new(store);
        let mut shared = fapico2_platform::secure_store::SharedStore::new(&cell);
        let mut auth = fapico2_platform::secure_store::SharedStore::new(&cell);
        with_host_store_and_migration(fs, "opcard", &mut auth, &OTP, UID, |client| {
            let mut app = OpenPgpApp::new(client);
            app.restore_at_boot(&mut shared, &OTP, UID, &mut bufs).unwrap();
            if !completed {
                assert_eq!(app.complete_migration(
                    &flash, flash.part, &mut shared, &OTP, UID, &mut bufs, PW1, &NONCE, &mut sink,
                ).unwrap(), migration::ClassStatus::Migrated);
            }
            let mut d = Dispatcher::<1>::new();
            assert!(d.register(&mut app));
            cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
            for (tag, public) in [
                (0xb6, PUBLIC),
                (0xb8, include_bytes!("fixtures/c-merged-x25519-public.bin").as_slice()),
                (0xa4, include_bytes!("fixtures/c-merged-auth-p256-public.bin").as_slice()),
            ] {
                assert_eq!(cmd(&mut d, 0x47, 0x81, 0, &[tag, 0], 0x9000), public);
            }
            let digest = Sha256::digest(b"full three-key migrated identity");
            cmd(&mut d, 0x2a, 0x9e, 0x9a, &digest, 0x6982);
            cmd(&mut d, 0x88, 0, 0, &digest, 0x6982);
            cmd(&mut d, 0x20, 0, 0x81, PW1, 0x9000);
            let sig = cmd(&mut d, 0x2a, 0x9e, 0x9a, &digest, 0x9000);
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&PUBLIC[5..]).unwrap()
                .verify_prehash(&digest, &p256::ecdsa::Signature::from_slice(&sig).unwrap()).unwrap();
            cmd(&mut d, 0x20, 0, 0x82, PW1, 0x9000);
            let mut cipher = vec![0xa6, 0x25, 0x7f, 0x49, 0x22, 0x86, 0x20];
            cipher.extend_from_slice(include_bytes!("fixtures/c-merged-x25519-peer.bin"));
            assert_eq!(cmd(&mut d, 0x2a, 0x80, 0x86, &cipher, 0x9000),
                include_bytes!("fixtures/c-merged-x25519-shared.bin"));
            let sig = cmd(&mut d, 0x88, 0, 0, &digest, 0x9000);
            let public = include_bytes!("fixtures/c-merged-auth-p256-public.bin");
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&public[5..]).unwrap()
                .verify_prehash(&digest, &p256::ecdsa::Signature::from_slice(&sig).unwrap()).unwrap();
        }).unwrap();
        store = Rp2350SecureStore::new();
        store.from_partition_image(&sink.0);
    }
    assert_eq!(flash.bytes, before);
}

#[test]
fn empty_rc_record_returns_bad_length_not_panic() {
    let mut stream = STREAM.to_vec();
    stream.extend_from_slice(&0x1082u16.to_le_bytes());
    stream.extend_from_slice(&0u32.to_le_bytes());
    let flash = fixture_from_stream(&stream);
    let mut store = HostSecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    let capture = migration::read_openpgp_capture(&mut store, &OTP, UID, &mut bufs.scratch).unwrap();
    assert_eq!(capture.record(0x1082).unwrap(), Some(&[][..]));
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        assert!(matches!(
            app.restore_captured_public_metadata(&capture, &OTP, UID),
            Err(migration::MigrationError::CKey(fapico2_platform::ckey::CKeyError::BadLength))
        ));
    });
}

#[test]
fn production_boot_restores_captured_public_identity() {
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_at_boot(&mut store, &OTP, UID, &mut bufs).unwrap();
        let mut dispatcher = Dispatcher::<1>::new();
        assert!(dispatcher.register(&mut app));
        cmd(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        assert_eq!(cmd(&mut dispatcher, 0xca, 0, 0x5b, &[], 0x9000), b"Migrated User");
        assert_eq!(cmd(&mut dispatcher, 0x47, 0x81, 0, &[0xb6, 0], 0x9000), PUBLIC);
    });
}

#[test]
fn production_completion_flushes_dek_and_native_pin_survives_restart() {
    use fapico2_platform::persist::{ImageSink, WindowedImageSource};
    use fapico2_platform::trusted_backend::{host::{HostStore, HostPlatform}, runner::with_backend, dispatch::OpcardDispatch};
    struct Sink(Vec<u8>);
    impl ImageSink for Sink {
        fn program(&mut self, src: &mut dyn WindowedImageSource) -> bool {
            self.0 = fapico2_platform::persist::pull_image(src); true
        }
    }
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    let fs = HostStore::fresh();
    let mut sink = Sink(Vec::new());
    with_backend(HostPlatform::with_store(fs), OpcardDispatch::new(), "opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_at_boot(&mut store, &OTP, UID, &mut bufs).unwrap();
        assert_eq!(app.complete_migration(&flash, flash.part, &mut store, &OTP, UID, &mut bufs, PW1, &NONCE, &mut sink).unwrap(), migration::ClassStatus::Migrated);
    });
    let mut reboot = Rp2350SecureStore::new();
    reboot.from_partition_image(&sink.0);
    assert!(reboot.contains(migration::SLOT_OPENPGP_DEK));
    with_backend(HostPlatform::with_store(fs), OpcardDispatch::new(), "opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_at_boot(&mut reboot, &OTP, UID, &mut bufs).unwrap();
        let mut d = Dispatcher::<1>::new();
        assert!(d.register(&mut app));
        cmd(&mut d,0xa4,4,0,OPENPGP_AID,0x9000);
        cmd(&mut d,0x20,0,0x81,b"wrong!",0x63c2);
        cmd(&mut d,0x20,0,0x81,PW1,0x9000);
        let digest=Sha256::digest(b"production migrated identity");
        let sig=cmd(&mut d,0x2a,0x9e,0x9a,&digest,0x9000);
        let key=p256::ecdsa::VerifyingKey::from_sec1_bytes(&PUBLIC[5..]).unwrap();
        key.verify_prehash(&digest,&p256::ecdsa::Signature::from_slice(&sig).unwrap()).unwrap();
    });
}

#[test]
fn production_boot_and_completion_survive_sink_restart_with_shared_budget() {
    use fapico2_platform::persist::{ImageSink, WindowedImageSource};
    use fapico2_platform::trusted_backend::{
        dispatch::OpcardDispatch, host::{HostStore, HostPlatform}, runner::with_backend,
    };
    struct Sink(Vec<u8>);
    impl ImageSink for Sink {
        fn program(&mut self, src: &mut dyn WindowedImageSource) -> bool { self.0 = fapico2_platform::persist::pull_image(src); true }
    }
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    let fs = HostStore::fresh();
    let mut sink = Sink(Vec::new());
    let cell = core::cell::RefCell::new(store);
    let mut store = fapico2_platform::secure_store::SharedStore::new(&cell);
    let mut auth_store = fapico2_platform::secure_store::SharedStore::new(&cell);
    // Keep the authority attached throughout boot and management completion,
    // exactly as DeviceBackend::boot does. Store borrows end before callbacks.
    with_host_store_and_migration(fs, "opcard", &mut auth_store, &OTP, UID, |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_at_boot(&mut store, &OTP, UID, &mut bufs).unwrap();
        {
            let mut d = Dispatcher::<1>::new();
            assert!(d.register(&mut app));
            cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
            cmd(&mut d, 0x20, 0, 0x81, b"wrong!", 0x63c2);
        }
        assert_eq!(migration::captured_openpgp_pw1_retries(
            &mut store, &OTP, UID, &mut bufs).unwrap(), 2);
        assert_eq!(app.complete_migration(
            &flash, flash.part, &mut store, &OTP, UID, &mut bufs, PW1, &NONCE, &mut sink,
        ).unwrap(), migration::ClassStatus::Migrated);
    }).unwrap();
    let mut reboot = Rp2350SecureStore::new();
    reboot.from_partition_image(&sink.0);
    assert!(reboot.contains(migration::SLOT_OPENPGP_HANDOFF));
    with_backend(HostPlatform::with_store(fs), OpcardDispatch::new(), "opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_at_boot(&mut reboot, &OTP, UID, &mut bufs).unwrap();
        let mut d = Dispatcher::<1>::new();
        assert!(d.register(&mut app));
        cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        cmd(&mut d, 0x20, 0, 0x81, b"nope00", 0x63c2);
        assert_eq!(migration::captured_openpgp_pw1_retries(
            &mut reboot, &OTP, UID, &mut bufs).unwrap(), 3);
        cmd(&mut d, 0x20, 0, 0x81, PW1, 0x9000);
        let digest = Sha256::digest(b"production shared budget");
        let sig = cmd(&mut d, 0x2a, 0x9e, 0x9a, &digest, 0x9000);
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&PUBLIC[5..]).unwrap();
        key.verify_prehash(&digest, &p256::ecdsa::Signature::from_slice(&sig).unwrap()).unwrap();
    });
}

#[test]
fn completion_resumes_after_durable_handoff_before_native_pin_install() {
    exercise_interrupted_handoff(false);
}

#[test]
fn pending_handoff_preserves_exhaustion_across_reboots() {
    exercise_interrupted_handoff(true);
}

fn exercise_interrupted_handoff(exhaust: bool) {
    use fapico2_platform::persist::{ImageSink, WindowedImageSource};
    use fapico2_platform::trusted_backend::{
        dispatch::OpcardDispatch, host::{HostStore, HostPlatform}, runner::with_backend,
    };
    struct InterruptedSink {
        image: Vec<u8>,
        writes: usize,
    }
    impl ImageSink for InterruptedSink {
        fn program(&mut self, src: &mut dyn WindowedImageSource) -> bool {
            self.image = fapico2_platform::persist::pull_image(src);
            self.writes += 1;
            // Model a durable write followed by interruption before acknowledgement.
            self.writes != 2
        }
    }
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    let fs = HostStore::fresh();
    let mut sink = InterruptedSink { image: Vec::new(), writes: 0 };
    with_backend(HostPlatform::with_store(fs), OpcardDispatch::new(), "opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_at_boot(&mut store, &OTP, UID, &mut bufs).unwrap();
        assert!(app.complete_migration(
            &flash, flash.part, &mut store, &OTP, UID, &mut bufs, PW1, &NONCE, &mut sink,
        ).is_err());
    });
    assert_eq!(sink.writes, 2);
    let mut reboot = Rp2350SecureStore::new();
    reboot.from_partition_image(&sink.image);
    assert!(reboot.contains(migration::SLOT_OPENPGP_HANDOFF));
    if exhaust {
        for _ in 0..3 {
            with_backend(HostPlatform::with_store(fs), OpcardDispatch::new(), "opcard", |client| {
                let mut app = OpenPgpApp::new(client);
                app.restore_at_boot(&mut reboot, &OTP, UID, &mut bufs).unwrap();
                assert_eq!(app.complete_migration(
                    &flash, flash.part, &mut reboot, &OTP, UID, &mut bufs, b"wrong!", &NONCE, &mut sink,
                ).unwrap(), migration::ClassStatus::NeedsPassphrase);
            });
            reboot = Rp2350SecureStore::new();
            reboot.from_partition_image(&sink.image);
        }
        with_backend(HostPlatform::with_store(fs), OpcardDispatch::new(), "opcard", |client| {
            let mut app = OpenPgpApp::new(client);
            app.restore_at_boot(&mut reboot, &OTP, UID, &mut bufs).unwrap();
            assert_eq!(app.complete_migration(
                &flash, flash.part, &mut reboot, &OTP, UID, &mut bufs, PW1, &NONCE, &mut sink,
            ).unwrap(), migration::ClassStatus::NeedsPassphrase);
        });
        assert!(migration::captured_openpgp_pw1_handoff_pending(&mut reboot).unwrap());
        return;
    }
    with_backend(HostPlatform::with_store(fs), OpcardDispatch::new(), "opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_at_boot(&mut reboot, &OTP, UID, &mut bufs).unwrap();
        assert_eq!(app.complete_migration(
            &flash, flash.part, &mut reboot, &OTP, UID, &mut bufs, PW1, &NONCE, &mut sink,
        ).expect("durable handoff without native PIN must remain recoverable"),
            migration::ClassStatus::Migrated);
        let mut d = Dispatcher::<1>::new();
        assert!(d.register(&mut app));
        cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        cmd(&mut d, 0x20, 0, 0x81, PW1, 0x9000);
    });
}

#[test]
fn captured_pw3_verifier_survives_native_pw1_handoff() {
    use fapico2_platform::persist::{ImageSink, WindowedImageSource};
    use fapico2_platform::trusted_backend::host::HostStore;
    struct Sink(Vec<u8>);
    impl ImageSink for Sink {
        fn program(&mut self, src: &mut dyn WindowedImageSource) -> bool {
            self.0 = fapico2_platform::persist::pull_image(src);
            true
        }
    }
    let flash = fixture();
    let mut initial = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut initial);
    migration::run(&flash, flash.part, &mut initial, &OTP, UID, &mut bufs).unwrap();
    let fs = HostStore::fresh();
    let cell = core::cell::RefCell::new(initial);
    let mut store = fapico2_platform::secure_store::SharedStore::new(&cell);
    let mut auth_store = fapico2_platform::secure_store::SharedStore::new(&cell);
    let mut sink = Sink(Vec::new());
    with_host_store_and_migration(fs, "opcard", &mut auth_store, &OTP, UID, |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_at_boot(&mut store, &OTP, UID, &mut bufs).unwrap();
        assert_eq!(app.complete_migration(
            &flash, flash.part, &mut store, &OTP, UID, &mut bufs, PW1, &NONCE, &mut sink,
        ).unwrap(), migration::ClassStatus::Migrated);
    }).unwrap();
    let mut reboot = Rp2350SecureStore::new();
    reboot.from_partition_image(&sink.0);
    let cell = core::cell::RefCell::new(reboot);
    let mut store = fapico2_platform::secure_store::SharedStore::new(&cell);
    let mut auth_store = fapico2_platform::secure_store::SharedStore::new(&cell);
    with_host_store_and_migration(fs, "opcard", &mut auth_store, &OTP, UID, |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_at_boot(&mut store, &OTP, UID, &mut bufs).unwrap();
        let mut d = Dispatcher::<1>::new();
        assert!(d.register(&mut app));
        cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        cmd(&mut d, 0x20, 0, 0x83, b"12345678", 0x63c2);
        cmd(&mut d, 0x20, 0, 0x83, b"87654321", 0x9000);
    }).unwrap();
}

#[test]
fn captured_pw3_retries_survive_persisted_reboots() {
    use fapico2_platform::{dispatch::App, persist::{persist_apps, ImageSink, WindowedImageSource}};
    use fapico2_platform::trusted_backend::host::HostStore;
    struct Sink(Vec<u8>);
    impl ImageSink for Sink {
        fn program(&mut self, src: &mut dyn WindowedImageSource) -> bool {
            self.0 = fapico2_platform::persist::pull_image(src);
            true
        }
    }
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    let fs = HostStore::fresh();
    let mut sink = Sink(Vec::new());
    for (pin, status) in [(b"wrong!!!".as_slice(), 0x63c2),
        (b"wrong!!!".as_slice(), 0x63c1), (b"wrong!!!".as_slice(), 0x6983),
        (b"87654321".as_slice(), 0x6983)] {
        let cell = core::cell::RefCell::new(store);
        let mut shared = fapico2_platform::secure_store::SharedStore::new(&cell);
        let mut auth = fapico2_platform::secure_store::SharedStore::new(&cell);
        with_host_store_and_migration(fs, "opcard", &mut auth, &OTP, UID, |client| {
            let mut app = OpenPgpApp::new(client);
            app.restore_at_boot(&mut shared, &OTP, UID, &mut bufs).unwrap();
            {
                let mut d = Dispatcher::<1>::new();
                assert!(d.register(&mut app));
                cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
                cmd(&mut d, 0x20, 0, 0x83, pin, status);
            }
            let mut apps: [&mut dyn App; 1] = [&mut app];
            assert!(persist_apps(&mut apps, &mut shared, &mut sink));
        }).unwrap();
        store = Rp2350SecureStore::new();
        store.from_partition_image(&sink.0);
        assert_eq!(migration::captured_openpgp_pw1_retries(
            &mut store, &OTP, UID, &mut bufs,
        ).unwrap(), 3, "PW3 must not spend PW1 attempts");
    }
}

#[test]
fn admin_pw3_resets_native_pw1_and_original_key_still_signs() {
    use fapico2_platform::persist::{ImageSink, WindowedImageSource};
    use fapico2_platform::trusted_backend::host::HostStore;
    struct Sink(Vec<u8>);
    impl ImageSink for Sink {
        fn program(&mut self, src: &mut dyn WindowedImageSource) -> bool {
            self.0 = fapico2_platform::persist::pull_image(src);
            true
        }
    }
    let flash = fixture();
    let mut initial = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut initial);
    migration::run(&flash, flash.part, &mut initial, &OTP, UID, &mut bufs).unwrap();
    let fs = HostStore::fresh();
    let cell = core::cell::RefCell::new(initial);
    let mut store = fapico2_platform::secure_store::SharedStore::new(&cell);
    let mut auth_store = fapico2_platform::secure_store::SharedStore::new(&cell);
    let mut sink = Sink(Vec::new());
    with_host_store_and_migration(fs, "opcard", &mut auth_store, &OTP, UID, |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_at_boot(&mut store, &OTP, UID, &mut bufs).unwrap();
        assert_eq!(app.complete_migration(
            &flash, flash.part, &mut store, &OTP, UID, &mut bufs, PW1, &NONCE, &mut sink,
        ).unwrap(), migration::ClassStatus::Migrated);
    }).unwrap();
    let mut reboot = Rp2350SecureStore::new();
    reboot.from_partition_image(&sink.0);
    let cell = core::cell::RefCell::new(reboot);
    let mut store = fapico2_platform::secure_store::SharedStore::new(&cell);
    let mut auth_store = fapico2_platform::secure_store::SharedStore::new(&cell);
    with_host_store_and_migration(fs, "opcard", &mut auth_store, &OTP, UID, |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_at_boot(&mut store, &OTP, UID, &mut bufs).unwrap();
        let mut d = Dispatcher::<1>::new();
        assert!(d.register(&mut app));
        cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        cmd(&mut d, 0x20, 0, 0x83, b"87654321", 0x9000);
        cmd(&mut d, 0x2c, 2, 0x81, b"222222", 0x9000);
        cmd(&mut d, 0x2c, 2, 0x81, b"111111", 0x9000);
        cmd(&mut d, 0x20, 0, 0x81, b"111111", 0x9000);
        let digest = Sha256::digest(b"original migrated identity");
        let sig = cmd(&mut d, 0x2a, 0x9e, 0x9a, &digest, 0x9000);
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&PUBLIC[5..]).unwrap();
        key.verify_prehash(&digest, &p256::ecdsa::Signature::from_slice(&sig).unwrap()).unwrap();
    }).unwrap();
}

#[test]
fn captured_reset_code_resets_pw1_only_after_handoff() {
    use fapico2_platform::{ckey, persist::{persist_apps, ImageSink}};
    use fapico2_platform::{dispatch::App, persist::WindowedImageSource};
    use fapico2_platform::trusted_backend::host::HostStore;
    struct Sink(Vec<u8>);
    impl ImageSink for Sink {
        fn program(&mut self, src: &mut dyn WindowedImageSource) -> bool {
            self.0 = fapico2_platform::persist::pull_image(src);
            true
        }
    }
    let sh = ckey::serial_hash(UID);
    let kbase = ckey::derive_kbase_c(&OTP, &sh).unwrap();
    let verifier = ckey::pin_verifier(&sh, &ckey::derive_kver(&kbase, b"reset123"));
    let mut stream = STREAM.to_vec();
    let mut offset = 0;
    while offset < stream.len() {
        let fid = u16::from_le_bytes(stream[offset..offset + 2].try_into().unwrap());
        let n = u32::from_le_bytes(stream[offset + 2..offset + 6].try_into().unwrap()) as usize;
        if fid == 0x10c4 { stream[offset + 6 + 5] = 3; }
        offset += 6 + n;
    }
    stream.extend_from_slice(&0x1082u16.to_le_bytes());
    stream.extend_from_slice(&34u32.to_le_bytes());
    stream.extend_from_slice(&[8, 1]);
    stream.extend_from_slice(&verifier);
    let flash = fixture_from_stream(&stream);
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    let capture = migration::read_openpgp_capture(&mut store, &OTP, UID, &mut bufs.scratch).unwrap();
    assert_eq!(capture.record(0x1082).unwrap().unwrap()[2..], verifier);
    let fs = HostStore::fresh();
    let mut sink = Sink(Vec::new());
    for completed in [false, true] {
        let cell = core::cell::RefCell::new(store);
        let mut shared = fapico2_platform::secure_store::SharedStore::new(&cell);
        let mut auth = fapico2_platform::secure_store::SharedStore::new(&cell);
        with_host_store_and_migration(fs, "opcard", &mut auth, &OTP, UID, |client| {
            let mut app = OpenPgpApp::new(client);
            app.restore_at_boot(&mut shared, &OTP, UID, &mut bufs).unwrap();
            {
                let mut d = Dispatcher::<1>::new();
                assert!(d.register(&mut app));
                cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
                if completed {
                    cmd(&mut d, 0x2c, 0, 0x81, b"wrong!!!111111", 0x63c2);
                    cmd(&mut d, 0x2c, 0, 0x81, b"reset123222222", 0x9000);
                    cmd(&mut d, 0x20, 0, 0x81, b"222222", 0x9000);
                } else {
                    for code in [b"wrong!!!", b"reset123"] {
                        let mut reset = code.to_vec();
                        reset.extend_from_slice(b"111111");
                        cmd(&mut d, 0x2c, 0, 0x81, &reset, 0x6982);
                    }
                }
                assert_eq!(migration::captured_openpgp_rc_retries(&mut shared, &OTP, UID, &mut bufs).unwrap(), Some(3));
                assert_eq!(migration::captured_openpgp_pw1_retries(&mut shared, &OTP, UID, &mut bufs).unwrap(), 3);
                assert_eq!(migration::captured_openpgp_pw3_retries(&mut shared, &OTP, UID, &mut bufs).unwrap(), 3);
                assert_eq!(migration::captured_openpgp_rc_retries(&mut shared, &OTP, UID, &mut bufs).unwrap(), Some(3));
                cmd(&mut d, 0x20, 0, 0x81, b"111111", 0x63c2);
                cmd(&mut d, 0x20, 0, 0x81, if completed { b"222222" } else { PW1 }, 0x9000);
                if !completed {
                    // PW1 VERIFY alone must not authorize the RC recovery route.
                    cmd(&mut d, 0x2c, 0, 0x81, b"wrong!!!111111", 0x6982);
                    cmd(&mut d, 0x2c, 0, 0x81, b"reset123111111", 0x6982);
                    assert_eq!(migration::captured_openpgp_rc_retries(
                        &mut shared, &OTP, UID, &mut bufs).unwrap(), Some(3));
                }
                assert_eq!(cmd(&mut d, 0x47, 0x81, 0, &[0xb6, 0], 0x9000), PUBLIC);
                if completed {
                    let digest = Sha256::digest(b"ResetCode rejection preserves identity");
                    let sig = cmd(&mut d, 0x2a, 0x9e, 0x9a, &digest, 0x9000);
                    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&PUBLIC[5..]).unwrap();
                    key.verify_prehash(&digest, &p256::ecdsa::Signature::from_slice(&sig).unwrap()).unwrap();
                }
            }
            assert_eq!(migration::captured_openpgp_pw1_retries(&mut shared, &OTP, UID, &mut bufs).unwrap(), 3);
            assert_eq!(migration::captured_openpgp_pw3_retries(&mut shared, &OTP, UID, &mut bufs).unwrap(), 3);
            if !completed {
                assert_eq!(app.complete_migration(
                    &flash, flash.part, &mut shared, &OTP, UID, &mut bufs, PW1, &NONCE, &mut sink,
                ).unwrap(), migration::ClassStatus::Migrated);
            }
            let mut apps: [&mut dyn App; 1] = [&mut app];
            assert!(persist_apps(&mut apps, &mut shared, &mut sink));
        }).unwrap();
        store = Rp2350SecureStore::new();
        store.from_partition_image(&sink.0);
    }
    // The RC-installed native PIN and original signing key survive a reboot.
    let cell = core::cell::RefCell::new(store);
    let mut shared = fapico2_platform::secure_store::SharedStore::new(&cell);
    let mut auth = fapico2_platform::secure_store::SharedStore::new(&cell);
    with_host_store_and_migration(fs, "opcard", &mut auth, &OTP, UID, |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_at_boot(&mut shared, &OTP, UID, &mut bufs).unwrap();
        let mut d = Dispatcher::<1>::new();
        assert!(d.register(&mut app));
        cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        cmd(&mut d, 0x20, 0, 0x81, PW1, 0x63c2);
        cmd(&mut d, 0x20, 0, 0x81, b"222222", 0x9000);
        let digest = Sha256::digest(b"RC-installed PIN survives reboot");
        let sig = cmd(&mut d, 0x2a, 0x9e, 0x9a, &digest, 0x9000);
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&PUBLIC[5..]).unwrap();
        key.verify_prehash(&digest, &p256::ecdsa::Signature::from_slice(&sig).unwrap()).unwrap();
    }).unwrap();
}

fn fixture_with_reset_code() -> Flash {
    use fapico2_platform::ckey;
    let sh = ckey::serial_hash(UID);
    let kbase = ckey::derive_kbase_c(&OTP, &sh).unwrap();
    let verifier = ckey::pin_verifier(&sh, &ckey::derive_kver(&kbase, b"reset123"));
    let mut stream = STREAM.to_vec();
    let mut offset = 0;
    while offset < stream.len() {
        let fid = u16::from_le_bytes(stream[offset..offset + 2].try_into().unwrap());
        let n = u32::from_le_bytes(stream[offset + 2..offset + 6].try_into().unwrap()) as usize;
        if fid == 0x10c4 { stream[offset + 6 + 5] = 3; }
        offset += 6 + n;
    }
    stream.extend_from_slice(&0x1082u16.to_le_bytes());
    stream.extend_from_slice(&34u32.to_le_bytes());
    stream.extend_from_slice(&[8, 1]);
    stream.extend_from_slice(&verifier);
    fixture_from_stream(&stream)
}

#[test]
fn captured_reset_code_wrong_attempt_spends_budget() {
    use fapico2_platform::{dispatch::App, persist::{persist_apps, ImageSink, WindowedImageSource}};
    use fapico2_platform::trusted_backend::host::HostStore;
    struct Sink(Vec<u8>);
    impl ImageSink for Sink {
        fn program(&mut self, src: &mut dyn WindowedImageSource) -> bool {
            self.0 = fapico2_platform::persist::pull_image(src); true
        }
    }
    let flash = fixture_with_reset_code();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    let fs = HostStore::fresh();
    let mut sink = Sink(Vec::new());
    for (index, (status, remaining)) in [(0x63c2, 2), (0x63c1, 1)].into_iter().enumerate() {
        let cell = core::cell::RefCell::new(store);
        let mut shared = fapico2_platform::secure_store::SharedStore::new(&cell);
        let mut auth = fapico2_platform::secure_store::SharedStore::new(&cell);
        with_host_store_and_migration(fs, "opcard", &mut auth, &OTP, UID, |client| {
            let mut app = OpenPgpApp::new(client);
            app.restore_at_boot(&mut shared, &OTP, UID, &mut bufs).unwrap();
            if index == 0 {
                assert_eq!(app.complete_migration(
                    &flash, flash.part, &mut shared, &OTP, UID, &mut bufs, PW1, &NONCE, &mut sink,
                ).unwrap(), migration::ClassStatus::Migrated);
            }
            {
                let mut d = Dispatcher::<1>::new();
                assert!(d.register(&mut app));
                cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
                cmd(&mut d, 0x2c, 0, 0x81, b"wrong!!!111111", status);
            }
            assert_eq!(migration::captured_openpgp_rc_retries(
                &mut shared, &OTP, UID, &mut bufs).unwrap(), Some(remaining));
            assert!(App::is_dirty(&app), "RC attempts must request transport persistence");
            let mut apps: [&mut dyn App; 1] = [&mut app];
            assert!(persist_apps(&mut apps, &mut shared, &mut sink));
            assert!(!App::is_dirty(&app));
        }).unwrap();
        store = Rp2350SecureStore::new();
        store.from_partition_image(&sink.0);
        assert_eq!(migration::captured_openpgp_rc_retries(
            &mut store, &OTP, UID, &mut bufs).unwrap(), Some(remaining));
        assert_eq!(migration::captured_openpgp_pw1_retries(
            &mut store, &OTP, UID, &mut bufs).unwrap(), 3);
        assert_eq!(migration::captured_openpgp_pw3_retries(
            &mut store, &OTP, UID, &mut bufs).unwrap(), 3);
    }
}

#[test]
fn reset_code_absent_means_6982() {
    use fapico2_platform::persist::{ImageSink, WindowedImageSource};
    use fapico2_platform::trusted_backend::host::HostStore;
    struct Sink;
    impl ImageSink for Sink {
        fn program(&mut self, _: &mut dyn WindowedImageSource) -> bool { true }
    }
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    let capture = migration::read_openpgp_capture(&mut store, &OTP, UID, &mut bufs.scratch).unwrap();
    assert_eq!(capture.record(0x1082).unwrap(), None);
    let cell = core::cell::RefCell::new(store);
    let mut shared = fapico2_platform::secure_store::SharedStore::new(&cell);
    let mut auth = fapico2_platform::secure_store::SharedStore::new(&cell);
    with_host_store_and_migration(HostStore::fresh(), "opcard", &mut auth, &OTP, UID, |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_at_boot(&mut shared, &OTP, UID, &mut bufs).unwrap();
        for completed in [false, true] {
            if completed {
                assert_eq!(app.complete_migration(
                    &flash, flash.part, &mut shared, &OTP, UID, &mut bufs, PW1, &NONCE, &mut Sink,
                ).unwrap(), migration::ClassStatus::Migrated);
            }
            let mut d = Dispatcher::<1>::new();
            assert!(d.register(&mut app));
            cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
            cmd(&mut d, 0x20, 0, 0x81, PW1, 0x9000);
            cmd(&mut d, 0x20, 0, 0x83, b"87654321", 0x9000);
            cmd(&mut d, 0x2c, 0, 0x81, b"reset123111111", 0x6982);
            assert_eq!(migration::captured_openpgp_rc_retries(
                &mut shared, &OTP, UID, &mut bufs).unwrap(), None);
        }
    }).unwrap();
}

#[test]
fn compatibility_verify_persists_retry_before_transport_reply() {
    use fapico2_platform::{dispatch::App, persist::{persist_apps, ImageSink, WindowedImageSource}};
    use fapico2_platform::trusted_backend::host::HostStore;
    struct Sink { image: Vec<u8>, fail: bool }
    impl ImageSink for Sink {
        fn program(&mut self, src: &mut dyn WindowedImageSource) -> bool {
            if self.fail { return false; }
            self.image = fapico2_platform::persist::pull_image(src);
            true
        }
    }
    let flash = fixture();
    let mut initial = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut initial);
    migration::run(&flash, flash.part, &mut initial, &OTP, UID, &mut bufs).unwrap();
    let cell = core::cell::RefCell::new(initial);
    let mut store = fapico2_platform::secure_store::SharedStore::new(&cell);
    let mut auth_store = fapico2_platform::secure_store::SharedStore::new(&cell);
    let mut sink = Sink { image: Vec::new(), fail: true };
    with_host_store_and_migration(HostStore::fresh(), "opcard", &mut auth_store, &OTP, UID, |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_at_boot(&mut store, &OTP, UID, &mut bufs).unwrap();
        {
            let mut d = Dispatcher::<1>::new();
            assert!(d.register(&mut app));
            cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
            cmd(&mut d, 0x20, 0, 0x81, b"wrong!", 0x63c2);
        }
        assert!(App::is_dirty(&app), "VERIFY must request transport persistence");
        let mut apps: [&mut dyn App; 1] = [&mut app];
        let persisted = persist_apps(&mut apps, &mut store, &mut sink);
        let reply = if persisted || apps.iter().all(|app| !app.is_dirty()) {
            0x63c2
        } else {
            0x6f00
        };
        assert_eq!(reply, 0x6f00, "failed sink must suppress the ordinary reply");
        assert!(apps[0].is_dirty());
        sink.fail = false;
        assert!(persist_apps(&mut apps, &mut store, &mut sink));
        assert!(!App::is_dirty(&app));
    }).unwrap();
    let mut reboot = Rp2350SecureStore::new();
    reboot.from_partition_image(&sink.image);
    assert_eq!(migration::captured_openpgp_pw1_retries(
        &mut reboot, &OTP, UID, &mut bufs,
    ).unwrap(), 2);
}

#[test]
fn failed_capture_persistence_never_reaches_backend_format() {
    use fapico2_platform::persist::{ImageSink, WindowedImageSource, with_durable_boot};
    struct FailingSink;
    impl ImageSink for FailingSink {
        fn program(&mut self, _: &mut dyn WindowedImageSource) -> bool { false }
    }
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut before = vec![0; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    let n = store.snapshot_partition(&mut before).unwrap();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    let mut formatted = false;
    assert!(with_durable_boot(&mut store, &before[..n], &mut FailingSink, || {
        formatted = true;
    }).is_none());
    assert!(!formatted);
    // The failed persist must leave the captured source intact in the store.
    migration::read_openpgp_capture(&mut store, &OTP, UID, &mut bufs.scratch).unwrap();
}

#[test]
fn capture_fits_real_device_store_and_survives_snapshot() {
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    let mut image = vec![0; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    let n = store.snapshot_partition(&mut image).unwrap();
    let mut reboot = Rp2350SecureStore::new();
    reboot.from_partition_image(&image[..n]);
    let mut out = [0; 2048];
    let n = chunked::read_chunked(&mut reboot, migration::SLOT_OPENPGP, &mut out).unwrap();
    assert_eq!(n, STREAM.len());
    assert!(reboot.contains(migration::MIGRATION_MARKER));
}

#[test]
fn occupied_destination_keeps_two_generation_capacity_budget() {
    let flash = fixture_from_stream(include_bytes!("fixtures/c-merged-three-key.bin"));
    let mut store = Rp2350SecureStore::new();
    store.write(b"unrelated-owner", b"retained").unwrap();
    assert!(!store.is_empty().unwrap());
    seed_entropy(&mut store);
    let mut before = vec![0; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    let n = store.snapshot_partition(&mut before).unwrap();
    let mut bufs = MigrationBuffers::new();
    assert!(matches!(
        migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs),
        Err(migration::MigrationError::SlotOverflow)
    ));
    let mut after = vec![0; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    let m = store.snapshot_partition(&mut after).unwrap();
    assert_eq!(&before[..n], &after[..m]);
}

#[test]
fn interrupted_four_chunk_capture_is_not_empty_after_reboot() {
    let stream = include_bytes!("fixtures/c-merged-three-key.bin");
    let flash = fixture_from_stream(stream);
    for written_parts in 1..=3 {
        let mut store = Rp2350SecureStore::new();
        seed_entropy(&mut store);
        for index in (0..4).rev().take(written_parts) {
            let (key, key_len) = chunked::physical_part_key(migration::SLOT_OPENPGP, 0, index).unwrap();
            let start = index * chunked::PART_PAYLOAD_MAX;
            let end = (start + chunked::PART_PAYLOAD_MAX).min(stream.len());
            let mut record = [0; chunked::PART_HEADER_LEN + chunked::PART_PAYLOAD_MAX];
            let n = chunked::encode_part_record(
                1, index, 4, stream.len(), &stream[start..end], &mut record,
            ).unwrap();
            store.write(&key[..key_len], &record[..n]).unwrap();
        }
        let mut image = vec![0; Rp2350SecureStore::PARTITION_IMAGE_MAX];
        let n = store.snapshot_partition(&mut image).unwrap();
        let mut reboot = Rp2350SecureStore::new();
        reboot.from_partition_image(&image[..n]);
        assert!(!reboot.is_empty().unwrap());
        assert!(!reboot.contains(migration::MIGRATION_MARKER));
        let mut bufs = MigrationBuffers::new();
            seed_entropy(&mut reboot);
        assert!(matches!(
            migration::run(&flash, flash.part, &mut reboot, &OTP, UID, &mut bufs),
            Err(migration::MigrationError::SlotOverflow)
        ));
        let mut after = vec![0; Rp2350SecureStore::PARTITION_IMAGE_MAX];
        let m = reboot.snapshot_partition(&mut after).unwrap();
        assert_eq!(&image[..n], &after[..m]);
    }
}

#[test]
fn oversized_capture_is_rejected_without_store_writes() {
    let mut flash = fixture();
    let bounds = PoolBounds::from_partition(flash.part);
    // Add one valid but oversized cardholder-name record to the actual chain.
    let head_offset = (bounds.data_end - flash.part.start) as usize;
    let old_head = u32::from_le_bytes(flash.bytes[head_offset..head_offset + 4].try_into().unwrap());
    let n = 4096usize;
    let addr = old_head - (12 + n) as u32;
    let at = (addr - flash.part.start) as usize;
    flash.bytes[at..at + 4].copy_from_slice(&old_head.to_le_bytes());
    flash.bytes[at + 4..at + 8].fill(0);
    flash.bytes[at + 8..at + 10].copy_from_slice(&0x005bu16.to_le_bytes());
    flash.bytes[at + 10..at + 12].copy_from_slice(&(n as u16).to_le_bytes());
    flash.bytes[at + 12..at + 12 + n].fill(b'a');
    flash.bytes[head_offset..head_offset + 4].copy_from_slice(&addr.to_le_bytes());
    let mut store = HostSecureStore::new();
    seed_entropy(&mut store);
    let before = store.partition_image();
    let mut bufs = MigrationBuffers::new();
    assert!(migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).is_err());
    assert_eq!(store.partition_image(), before);
}

#[test]
fn captured_pw1_completion_does_not_read_original_flash() {
    struct Unavailable;
    impl CFlashSource for Unavailable {
        fn read(&self, _: u32, _: &mut [u8]) {
            panic!("completion accessed the original C region after capture");
        }
    }
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    let mut before = [0; 2048];
    let n = chunked::read_chunked(&mut store, migration::SLOT_OPENPGP, &mut before).unwrap();
    assert_eq!(migration::complete_passphrase_class(
        &Unavailable, flash.part, &mut store, &OTP, UID, &mut bufs, 1, &NONCE, PW1
    ).unwrap(), migration::ClassStatus::Migrated);
    let mut dek = [0; 48];
    migration::read_openpgp_dek(&mut store, &OTP, UID, &mut dek).unwrap();
    assert_eq!(dek, core::array::from_fn(|i| 0x60 + i as u8));
    let mut after = [0; 2048];
    assert_eq!(chunked::read_chunked(&mut store, migration::SLOT_OPENPGP, &mut after).unwrap(), n);
    assert_eq!(&after[..n], &before[..n], "completion must retain captured source");
}

#[test]
fn captured_pw1_retries_survive_reboot_and_block_correct_pin() {
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    for _ in 0..3 {
        assert_eq!(migration::complete_passphrase_class(
            &flash, flash.part, &mut store, &OTP, UID, &mut bufs, 1, &NONCE, b"wrong!"
        ).unwrap(), migration::ClassStatus::NeedsPassphrase);
        let mut image = vec![0; Rp2350SecureStore::PARTITION_IMAGE_MAX];
        let n = store.snapshot_partition(&mut image).unwrap();
        let mut reboot = Rp2350SecureStore::new();
        reboot.from_partition_image(&image[..n]);
        store = reboot;
    }
    assert_eq!(migration::complete_passphrase_class(
        &flash, flash.part, &mut store, &OTP, UID, &mut bufs, 1, &NONCE, PW1
    ).unwrap(), migration::ClassStatus::NeedsPassphrase);
    assert!(!store.contains(migration::SLOT_OPENPGP_DEK));
}

#[test]
fn captured_source_tamper_is_rejected_without_dek() {
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    let mut source = [0; 2048];
    let n = chunked::read_chunked(&mut store, migration::SLOT_OPENPGP, &mut source).unwrap();
    source[n - 1] ^= 1;
    chunked::write_chunked(&mut store, migration::SLOT_OPENPGP, &source[..n]).unwrap();
    assert!(migration::complete_passphrase_class(
        &flash, flash.part, &mut store, &OTP, UID, &mut bufs, 1, &NONCE, PW1
    ).is_err());
    assert!(!store.contains(migration::SLOT_OPENPGP_DEK));
}

#[test]
fn malformed_retry_records_fail_capture_before_writes() {
    let mut flash = fixture();
    let marker = [0xc5, 0x10, 7, 0];
    let offset = flash.bytes.windows(4).position(|bytes| bytes == marker).unwrap();
    // PW1 maximum lower than remaining attempts in 10C4.
    flash.bytes[offset + 5] = 1;
    let mut store = HostSecureStore::new();
    seed_entropy(&mut store);
    let before = store.partition_image();
    let mut bufs = MigrationBuffers::new();
    assert!(migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).is_err());
    assert_eq!(store.partition_image(), before);
}

#[test]
fn captured_verify_and_completion_share_pw1_attempts() {
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    assert_eq!(migration::verify_captured_openpgp_pw1(
        &mut store, &OTP, UID, &mut bufs, b"wrong!"
    ).unwrap(), migration::CapturedPinResult::Rejected { remaining: 2 });
    assert_eq!(migration::complete_passphrase_class(
        &flash, flash.part, &mut store, &OTP, UID, &mut bufs, 1, &NONCE, b"wrong!"
    ).unwrap(), migration::ClassStatus::NeedsPassphrase);
    assert_eq!(migration::verify_captured_openpgp_pw1(
        &mut store, &OTP, UID, &mut bufs, b"wrong!"
    ).unwrap(), migration::CapturedPinResult::Rejected { remaining: 0 });
    assert_eq!(migration::verify_captured_openpgp_pw1(
        &mut store, &OTP, UID, &mut bufs, PW1
    ).unwrap(), migration::CapturedPinResult::Blocked);
    assert_eq!(migration::complete_passphrase_class(
        &flash, flash.part, &mut store, &OTP, UID, &mut bufs, 1, &NONCE, PW1
    ).unwrap(), migration::ClassStatus::NeedsPassphrase);
    assert!(!store.contains(migration::SLOT_OPENPGP_DEK));
}

#[test]
fn captured_verify_does_not_release_dek() {
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    assert_eq!(migration::verify_captured_openpgp_pw1(
        &mut store, &OTP, UID, &mut bufs, PW1
    ).unwrap(), migration::CapturedPinResult::Verified);
    assert!(!store.contains(migration::SLOT_OPENPGP_DEK));
    // A successful verification restores the source maximum, just like C.
    assert_eq!(migration::verify_captured_openpgp_pw1(
        &mut store, &OTP, UID, &mut bufs, b"wrong!"
    ).unwrap(), migration::CapturedPinResult::Rejected { remaining: 2 });
}

#[test]
fn completion_exhaustion_blocks_opcard_verify() {
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    for _ in 0..3 {
        assert_eq!(migration::complete_passphrase_class(
            &flash, flash.part, &mut store, &OTP, UID, &mut bufs, 1, &NONCE, b"wrong!"
        ).unwrap(), migration::ClassStatus::NeedsPassphrase);
    }
    let capture = migration::read_openpgp_capture(
        &mut store, &OTP, UID, &mut bufs.scratch,
    ).unwrap();
    with_host_backend_and_migration("opcard", &mut store, &OTP, UID, |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_captured_public_metadata(&capture, &OTP, UID).unwrap();
        let mut d = Dispatcher::<1>::new();
        assert!(d.register(&mut app));
        cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        // A migrated card shares the completion budget, including after reboot.
        cmd(&mut d, 0x20, 0, 0x81, PW1, 0x6983);
    }).unwrap();
}

#[test]
fn missing_capture_never_falls_back_to_original_flash() {
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    assert!(migration::complete_passphrase_class(
        &flash, flash.part, &mut store, &OTP, UID, &mut bufs, 1, &NONCE, PW1
    ).is_err());
    assert!(!store.contains(migration::SLOT_OPENPGP_DEK));
}

#[test]
fn captured_metadata_initializes_opcard_without_factory_credentials() {
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_public_metadata(&mut store, &OTP, UID, &mut bufs).unwrap();
        let mut d = Dispatcher::<1>::new();
        assert!(d.register(&mut app));
        cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        assert_eq!(cmd(&mut d, 0xca, 0, 0x5b, &[], 0x9000), b"Migrated User");
        // Missing compatibility credentials are not an exhausted retry budget.
        // Fail closed without creating defaults, including empty VERIFY queries.
        cmd(&mut d, 0x20, 0, 0x81, &[], 0x6985);
        cmd(&mut d, 0x20, 0, 0x81, b"123456", 0x6985);
        cmd(&mut d, 0x20, 0, 0x83, b"12345678", 0x6985);
    });
}

#[test]
fn metadata_restore_refuses_existing_native_card() {
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        {
            let mut d = Dispatcher::<1>::new();
            assert!(d.register(&mut app));
            cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
            cmd(&mut d, 0xca, 0, 0x5b, &[], 0x9000);
        }
        assert!(app.restore_public_metadata(&mut store, &OTP, UID, &mut bufs).is_err());
        let mut d = Dispatcher::<1>::new();
        assert!(d.register(&mut app));
        cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        assert!(cmd(&mut d, 0xca, 0, 0x5b, &[], 0x9000).is_empty());
        cmd(&mut d, 0x20, 0, 0x81, b"123456", 0x9000);
    });
}

#[test]
fn restored_public_identity_is_readable_before_verify() {
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_public_metadata(&mut store, &OTP, UID, &mut bufs).unwrap();
        let mut d = Dispatcher::<1>::new();
        assert!(d.register(&mut app));
        cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        assert_eq!(cmd(&mut d, 0xca, 0, 0x5b, &[], 0x9000), b"Migrated User");
        assert_eq!(cmd(&mut d, 0x47, 0x81, 0, &[0xb6, 0], 0x9000), PUBLIC);
        let fingerprints = cmd(&mut d, 0xca, 0, 0xc5, &[], 0x9000);
        assert_eq!(&fingerprints[..20], &(0..20).collect::<Vec<u8>>());
        let dates = cmd(&mut d, 0xca, 0, 0xcd, &[], 0x9000);
        assert_eq!(&dates[..4], &[0x65, 1, 2, 3]);
        assert!(!store.contains(migration::SLOT_OPENPGP_DEK));
    });
}

#[test]
fn authenticated_capture_reads_producer_public_key_without_dek() {
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    let capture = migration::read_openpgp_capture(&mut store, &OTP, UID, &mut bufs.scratch).unwrap();
    let mut public = [0; 128];
    let n = capture.read_public_key(0x10d1, &OTP, UID, &mut public).unwrap().unwrap();
    assert_eq!(&public[..n], PUBLIC);
    assert!(!store.contains(migration::SLOT_OPENPGP_DEK));
}

#[test]
fn captured_private_scalar_matches_producer_after_completion() {
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    migration::complete_passphrase_class(
        &flash, flash.part, &mut store, &OTP, UID, &mut bufs, 1, &NONCE, PW1,
    ).unwrap();
    let mut dek = zeroize::Zeroizing::new([0; 48]);
    migration::read_openpgp_dek(&mut store, &OTP, UID, &mut dek).unwrap();
    let capture = migration::read_openpgp_capture(
        &mut store, &OTP, UID, &mut bufs.scratch,
    ).unwrap();
    let mut private = zeroize::Zeroizing::new([0; 64]);
    let n = capture.read_private_key(0x10d1, &OTP, UID, &dek, &mut private[..])
        .unwrap().unwrap();
    assert_eq!(n, 33);
    assert_eq!(private[0], 3);
    let signing = p256::ecdsa::SigningKey::from_slice(&private[1..n]).unwrap();
    assert_eq!(signing.verifying_key().to_encoded_point(false).as_bytes(), &PUBLIC[5..]);
    dek[16] ^= 1;
    assert!(capture.read_private_key(0x10d1, &OTP, UID, &dek, &mut private[..]).is_err());
}

#[test]
fn private_restore_survives_backend_restart_without_resetting_counter() {
    use fapico2_platform::trusted_backend::host::{HostStore, with_host_store_and_migration};
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    migration::complete_passphrase_class(&flash, flash.part, &mut store, &OTP, UID, &mut bufs, 1, &NONCE, PW1).unwrap();
    let mut dek = zeroize::Zeroizing::new([0; 48]);
    migration::read_openpgp_dek(&mut store, &OTP, UID, &mut dek).unwrap();
    let capture = migration::read_openpgp_capture(&mut store, &OTP, UID, &mut bufs.scratch).unwrap();
    let filesystem = HostStore::fresh();
    for expected_count in [8u8, 9] {
        // Retain internal files but discard volatile key cache and service state.
        let fresh = HostStore::fresh();
        let reboot = HostStore::new(filesystem.ifs, fresh.efs, fresh.vfs);
        // US-918: the kek is the bound device root — derive it where the
        // store is reachable (the closure below cannot borrow it mutably).
        let kek = migration::native_openpgp_wrapping_key(&mut store, &OTP, UID, &capture.source()).unwrap();
        with_host_store_and_migration(reboot, "opcard", &mut store, &OTP, UID, |client| {
            let mut app = OpenPgpApp::new(client);
            app.restore_captured_public_metadata(&capture, &OTP, UID).unwrap();
            app.restore_captured_private_key(&kek, &capture, &OTP, UID, &dek).unwrap();
            let mut d = Dispatcher::<1>::new();
            assert!(d.register(&mut app));
            cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
            cmd(&mut d, 0x20, 0, 0x81, PW1, 0x9000);
            let digest = Sha256::digest(b"reboot identity");
            let sig = cmd(&mut d, 0x2a, 0x9e, 0x9a, &digest, 0x9000);
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&PUBLIC[5..]).unwrap()
                .verify_prehash(&digest, &p256::ecdsa::Signature::from_slice(&sig).unwrap()).unwrap();
            let counter = cmd(&mut d, 0xca, 0, 0x7a, &[], 0x9000);
            assert_eq!(counter, [0x93, 3, 0, 0, expected_count]);
        }).unwrap();
    }
}

#[test]
fn private_import_rejects_public_mismatch_without_publishing_key() {
    // Exercise the narrow vendor seam with a different valid scalar, rather
    // than corrupting ciphertext (which would test GCM, not derive/compare).
    use fapico2_platform::trusted_backend::{host::{HostStore, HostPlatform}, runner::with_backend, OpcardDispatch};
    let filesystem = HostStore::fresh();
    with_backend(HostPlatform::with_store(filesystem), OpcardDispatch::new(), "opcard", |client| {
        let mut options = opcard::Options::default();
        options.storage = trussed_core::types::Location::Internal;
        let mut card = opcard::Card::new(client, options);
        card.restore_public_metadata([1; 32], b"Mismatch", 6, 8, None, Some(opcard::MigrationSigningIdentity {
            point: PUBLIC[6..].try_into().unwrap(), fingerprint: &[0; 20], date: &[0; 4], count: 7,
        })).unwrap();
        assert!(card.restore_migration_signing_key([1; 32], &[1; 32], &[2; 32]).is_err());
        assert!(card.restore_migration_signing_key([3; 32], &[1; 32], &[2; 32]).is_err());
    });
    use trussed_core::types::PathBuf;
    assert!(filesystem.ifs.exists(&PathBuf::try_from("opcard/dat/persistent-state.cbor").unwrap()));
    assert!(!filesystem.ifs.exists(&PathBuf::try_from("opcard/dat/signing_key.bin").unwrap()));
    assert!(!filesystem.ifs.exists(&PathBuf::try_from("opcard/dat/migration-signing-ready").unwrap()));
}

#[test]
fn dek_restored_private_key_signs() { exercise(true); }
#[test]
fn no_dek_means_no_private_key() { exercise(false); }

fn supported_alias(tag: u16) -> &'static [u8] {
    match tag {
        0x00c1 | 0x10c1 => &[0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7][..],
        0x00c2 | 0x10c2 => &[0x12, 0x2b, 6, 1, 4, 1, 0x97, 0x55, 1, 5, 1][..],
        _ => &[0x13, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7][..],
    }
}

/// STREAM minus private/public key containers, so every advertised algorithm
/// slot is keyless while name and PIN verifiers keep the capture valid.
fn keyless_stream() -> Vec<u8> {
    let mut stream = Vec::new();
    let mut rest = STREAM;
    while !rest.is_empty() {
        let n = u32::from_le_bytes(rest[2..6].try_into().unwrap()) as usize;
        let fid = u16::from_le_bytes(rest[..2].try_into().unwrap());
        // Remove every key object and algorithm attribute so each test can
        // install exactly its requested aliases without duplicate records.
        let key_or_attribute = (0xe8..=0xed).contains(&(fid >> 8))
            || (0x10d1..=0x10d6).contains(&fid)
            || (0x10c1..=0x10c3).contains(&fid) || (0x00c1..=0x00c3).contains(&fid);
        if !key_or_attribute {
            stream.extend_from_slice(&rest[..6 + n]);
        }
        rest = &rest[6 + n..];
    }
    stream
}

#[test]
fn algorithm_alias_payloads_retained_by_real_capture() {
    for tag in [0x00c1u16, 0x00c2, 0x00c3, 0x10c1, 0x10c2, 0x10c3] {
        let value = supported_alias(tag);
        let mut stream = keyless_stream();
        stream.extend_from_slice(&tag.to_le_bytes());
        stream.extend_from_slice(&(value.len() as u32).to_le_bytes());
        stream.extend_from_slice(value);
        let flash = fixture_from_stream(&stream);
        let mut store = Rp2350SecureStore::new();
        let mut bufs = MigrationBuffers::new();
        seed_entropy(&mut store);
        migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
        let capture = migration::read_openpgp_capture(&mut store, &OTP, UID, &mut bufs.scratch).unwrap();
        assert_eq!(capture.record(tag).unwrap(), Some(value), "alias {tag:04x}");
        // Supported alias control: the keyless capture must restore natively.
        with_host_backend("opcard", |client| {
            let mut app = OpenPgpApp::new(client);
            app.restore_captured_public_metadata(&capture, &OTP, UID).unwrap_or_else(|e|
                panic!("supported alias {tag:04x} must not refuse: {e:?}"));
        });
    }
}

#[test]
fn unsupported_algorithm_alias_refused_with_long_form_or_keyless() {
    use fapico2_platform::trusted_backend::{host::{HostStore, HostPlatform}, runner::with_backend, OpcardDispatch};
    use trussed_core::types::PathBuf;
    for tag in [0x00c1u16, 0x00c2, 0x00c3] {
        for with_long_form in [false, true] {
            // Replace only the short alias record with an unsupported payload;
            // the long form stays valid. All slots remain keyless, so in the
            // second case the bad short alias must not hide behind the good
            // long one.
            for short_value in [supported_alias(tag), b"unsupported".as_slice()] {
                let supported_control = short_value == supported_alias(tag);
                let mut stream = keyless_stream();
                for (fid, value) in [(tag, short_value), (tag | 0x1000, supported_alias(tag))] {
                    if fid != tag && !with_long_form { continue; }
                    stream.extend_from_slice(&fid.to_le_bytes());
                    stream.extend_from_slice(&(value.len() as u32).to_le_bytes());
                    stream.extend_from_slice(value);
                }
                let flash = fixture_from_stream(&stream);
                let mut store = Rp2350SecureStore::new();
                let mut bufs = MigrationBuffers::new();
                seed_entropy(&mut store);
                migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
                let fs = HostStore::fresh();
                for _ in 0..2 {
                    let capture = migration::read_openpgp_capture(&mut store, &OTP, UID, &mut bufs.scratch).unwrap();
                    assert_eq!(capture.record(tag).unwrap(), Some(short_value));
                    for fid in 0x10d1..=0x10d3 {
                        assert_eq!(capture.read_public_key(fid, &OTP, UID, &mut [0; 128]).unwrap(), None);
                    }
                    if with_long_form {
                        assert_eq!(capture.record(tag | 0x1000).unwrap(), Some(supported_alias(tag)));
                    }
                    with_backend(HostPlatform::with_store(fs), OpcardDispatch::new(), "opcard", |client| {
                        let mut app = OpenPgpApp::new(client);
                        let result = app.restore_captured_public_metadata(&capture, &OTP, UID);
                        assert_eq!(result.is_ok(), supported_control,
                            "alias {tag:04x}, long form {with_long_form}, supported {supported_control}: {result:?}");
                    });
                    assert_eq!(fs.ifs.exists(&PathBuf::try_from("opcard/dat/persistent-state.cbor").unwrap()),
                        supported_control);
                    for name in ["migration-signing-ready", "migration-decryption-ready",
                        "migration-authentication-ready", "migration-pw1-ready"] {
                        assert!(!fs.ifs.exists(&PathBuf::try_from(format!("opcard/dat/{name}").as_str()).unwrap()));
                    }
                    assert!(!store.contains(migration::SLOT_OPENPGP_DEK));
                    let mut image = vec![0; Rp2350SecureStore::PARTITION_IMAGE_MAX];
                    let n = store.snapshot_partition(&mut image).unwrap();
                    store = Rp2350SecureStore::new();
                    store.from_partition_image(&image[..n]);
                }
            }
        }
    }
}

fn unsupported_profile_fixture() -> Flash {
    fixture_from_stream(include_bytes!("fixtures/c-merged-unsupported-algorithm.bin"))
}

#[test]
fn profile_dos_restored_natively() {
    let flash = fixture_from_stream(include_bytes!("fixtures/c-merged-profile.bin"));
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_at_boot(&mut store, &OTP, UID, &mut bufs).unwrap();
        let mut d = Dispatcher::<1>::new();
        assert!(d.register(&mut app));
        cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        for (tag, expected) in [(0x005bu16, b"Migrated User".as_slice()),
            (0x5f2d, b"enpt"), (0x5f35, b"2"),
            (0x0101, b"public private DO one"), (0x0102, b"public private DO two")] {
            assert_eq!(cmd(&mut d, 0xca, (tag >> 8) as u8, tag as u8, &[], 0x9000), expected,
                "native DO {tag:04x}");
        }
    });
}

#[test]
fn unsupported_profile_dos_refused_before_native_write() {
    for (tag, value) in [(0x0103u16, b"secret".as_slice()), (0x0104, b"secret"),
        (0x1099, b"legacy"), (0x5f2d, b"eng"), (0x5f35, b"3"),
        (0x005b, b"123456789012345678901234567890123456789012")] {
        let mut stream = STREAM.to_vec();
        stream.extend_from_slice(&tag.to_le_bytes());
        stream.extend_from_slice(&(value.len() as u32).to_le_bytes());
        stream.extend_from_slice(value);
        let flash = fixture_from_stream(&stream);
        let mut store = Rp2350SecureStore::new();
        let mut bufs = MigrationBuffers::new();
        seed_entropy(&mut store);
        migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
        with_host_backend("opcard", |client| {
            let mut app = OpenPgpApp::new(client);
            assert!(app.restore_at_boot(&mut store, &OTP, UID, &mut bufs).is_err(),
                "unsupported DO {tag:04x} must refuse");
        });
    }
}

#[test]
fn unsupported_algorithm_refused_not_silently_dropped() {
    let flash = unsupported_profile_fixture();
    let before = flash.bytes.clone();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    let capture = migration::read_openpgp_capture(&mut store, &OTP, UID, &mut bufs.scratch).unwrap();
    assert!(capture.record(0x10c2).unwrap().is_some());
    with_host_backend("opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        assert!(app.restore_captured_public_metadata(&capture, &OTP, UID).is_err(),
            "unsupported keyless algorithm must refuse before native metadata writes");
    });
    assert!(!store.contains(migration::SLOT_OPENPGP_DEK));
    assert_eq!(flash.bytes, before);
}

#[test]
fn refusal_survives_reboot_without_partial_state() {
    use fapico2_platform::trusted_backend::{host::{HostStore, HostPlatform}, runner::with_backend, OpcardDispatch};
    let flash = unsupported_profile_fixture();
    let mut store = Rp2350SecureStore::new();
    let mut bufs = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut bufs).unwrap();
    let fs = HostStore::fresh();
    for _ in 0..2 {
        with_backend(HostPlatform::with_store(fs), OpcardDispatch::new(), "opcard", |client| {
            let mut app = OpenPgpApp::new(client);
            assert!(app.restore_at_boot(&mut store, &OTP, UID, &mut bufs).is_err(),
                "unsupported profile must refuse on every boot");
        });
        let path = trussed_core::types::PathBuf::try_from("opcard/dat/persistent-state.cbor").unwrap();
        assert!(!fs.ifs.exists(&path), "refusal must not publish native metadata");
        let mut image = vec![0; Rp2350SecureStore::PARTITION_IMAGE_MAX];
        let n = store.snapshot_partition(&mut image).unwrap();
        store = Rp2350SecureStore::new();
        store.from_partition_image(&image[..n]);
    }
    with_backend(HostPlatform::with_store(fs), OpcardDispatch::new(), "opcard", |client| {
        let mut app = OpenPgpApp::new(client);
        let mut d = Dispatcher::<1>::new();
        assert!(d.register(&mut app));
        cmd(&mut d, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
        assert!(cmd(&mut d, 0xca, 0, 0x5b, &[], 0x9000).is_empty());
        cmd(&mut d, 0x47, 0x81, 0, &[0xb6, 0], 0x6a88);
    });
}
