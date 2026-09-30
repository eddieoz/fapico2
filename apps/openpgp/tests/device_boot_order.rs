//! S-722-6: device-order integration on the host, NOT execution of DeviceBackend
//! or the ARM HAL. Host littlefs/crypto use the real MigrationAuthority,
//! OpcardDispatch and SyscallRunner. Migration and image scratch are fixed arrays.
use core::cell::RefCell;
use fapico2_openpgp::{OpenPgpApp, OPENPGP_AID};
use fapico2_platform::{
    cflash::{fallback_partition_reserved, DataPartition},
    cfs::{CFlashSource, PoolBounds},
    dispatch::{Dispatcher, MAX_RESPONSE},
    migration::{self, MigrationBuffers},
    persist::{persist_boot_change_with_scratch, persist_reply_with_scratch, pull_image, ImageSink, WindowedImageSource},
    secure_store::{Rp2350SecureStore, SecureStore, SecureStoreError, SharedStore},
    trusted_backend::host::{with_host_store_and_migration, HostStore},
};

const IMAGE_MAX: usize = Rp2350SecureStore::PARTITION_IMAGE_MAX;

/// US-918: seed the boot-entropy slot with the fixed test vector so the
/// bound device root is derivable; harmless where derivation never happens.
fn seed_entropy<K: SecureStore>(store: &mut K) {
    use fapico2_platform::ckey;
    use fapico2_platform::migration::SLOT_BOOT_ENTROPY;
    const ENTROPY: [u8; ckey::BOOT_ENTROPY_LEN] = [0xA5u8; ckey::BOOT_ENTROPY_LEN];
    store.write(SLOT_BOOT_ENTROPY, &ENTROPY).unwrap();
}

const OTP: [u8; 32] =
    hex_literal::hex!("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
const UID: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
const PW1: &[u8] = b"654321";
const PW3: &[u8] = b"87654321";
const PUBLIC: &[u8] = include_bytes!("fixtures/c-merged-p256-public.bin");
type Reply = heapless::Vec<u8, MAX_RESPONSE>;

struct Flash {
    bytes: Vec<u8>,
    part: DataPartition,
}
impl CFlashSource for Flash {
    fn read(&self, addr: u32, out: &mut [u8]) {
        let offset = (addr - self.part.start) as usize;
        out.copy_from_slice(&self.bytes[offset..offset + out.len()]);
    }
}
fn capture(bufs: &mut MigrationBuffers) -> Rp2350SecureStore {
    // Synthetic merged-C producer records, reconstructed as a C flash list.
    let part = fallback_partition_reserved();
    let bounds = PoolBounds::from_partition(part);
    let mut flash = Flash {
        bytes: vec![0xff; part.size_bytes() as usize],
        part,
    };
    let mut put = |addr: u32, data: &[u8]| {
        let offset = (addr - part.start) as usize;
        flash.bytes[offset..offset + data.len()].copy_from_slice(data);
    };
    put(bounds.end_rom_pool, &[0; 8]);
    let mut stream = include_bytes!("fixtures/c-merged-p256.bin").as_slice();
    let mut cursor = bounds.data_end;
    let mut previous = 0u32;
    while !stream.is_empty() {
        let len = u32::from_le_bytes(stream[2..6].try_into().unwrap()) as usize;
        cursor -= (12 + len) as u32;
        put(cursor, &previous.to_le_bytes());
        put(cursor + 4, &[0; 4]);
        put(cursor + 8, &stream[..2]);
        put(cursor + 10, &(len as u16).to_le_bytes());
        put(cursor + 12, &stream[6..6 + len]);
        previous = cursor;
        stream = &stream[6 + len..];
    }
    put(bounds.data_end, &previous.to_le_bytes());
    let mut store = Rp2350SecureStore::new();
    seed_entropy(&mut store);
    migration::run(&flash, part, &mut store, &OTP, UID, bufs).unwrap();
    store
}

struct Sink {
    image: [u8; IMAGE_MAX],
    len: usize,
    attempts: usize,
    fail: bool,
}
impl Sink {
    fn new() -> Self {
        Self {
            image: [0; IMAGE_MAX],
            len: 0,
            attempts: 0,
            fail: false,
        }
    }
    fn reboot(&self) -> Rp2350SecureStore {
        assert_ne!(self.len, 0, "boot must reload an actually programmed image");
        let mut store = Rp2350SecureStore::new();
        store.from_partition_image(&self.image[..self.len]);
        store
    }
}
impl ImageSink for Sink {
    fn program(&mut self, src: &mut dyn WindowedImageSource) -> bool {
        self.attempts += 1;
        let image = pull_image(src);
        let len = image.len();
        if self.fail {
            return false;
        } // previous good image remains intact
        self.image[..len].copy_from_slice(&image);
        self.len = len;
        true
    }
}
fn dispatch(d: &mut Dispatcher<'_, 1>, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Reply {
    let mut apdu = heapless::Vec::<u8, 256>::new();
    apdu.extend_from_slice(&[0, ins, p1, p2]).unwrap();
    if !data.is_empty() {
        apdu.push(data.len() as u8).unwrap();
        apdu.extend_from_slice(data).unwrap();
    }
    apdu.push(0).unwrap();
    let mut reply = Reply::new();
    d.dispatch(&apdu, &mut reply);
    reply
}
fn sw(reply: &[u8], expected: u16) {
    assert!(reply.len() >= 2);
    assert_eq!(&reply[reply.len() - 2..], &expected.to_be_bytes());
}
fn serve(
    d: &mut Dispatcher<'_, 1>,
    store: &mut dyn SecureStore,
    sink: &mut Sink,
    scratch: &mut [u8],
    mut reply: Reply,
    expected: u16,
) -> Reply {
    persist_reply_with_scratch(d.apps_mut(), store, sink, scratch, &mut reply).unwrap();
    sw(&reply, expected); // only inspect the externally eligible reply AFTER the gate
    reply
}
fn pending(store: &mut impl SecureStore, bufs: &mut MigrationBuffers, pw3: u8) {
    assert_eq!(
        migration::captured_openpgp_pw1_retries(store, &OTP, UID, bufs).unwrap(),
        3
    );
    assert_eq!(
        migration::captured_openpgp_pw3_retries(store, &OTP, UID, bufs).unwrap(),
        pw3
    );
    assert!(!migration::captured_openpgp_pw1_handed_off(store).unwrap());
    assert!(!store.contains(migration::SLOT_OPENPGP_DEK));
}

#[test]
fn device_boot_order_restores_and_serves() {
    let mut bufs = MigrationBuffers::new();
    let mut scratch = [0; IMAGE_MAX];
    let mut loaded = [0; IMAGE_MAX];
    let mut store = capture(&mut bufs);
    let mut sink = Sink::new();
    // Capture must reach the medium before backend construction can touch C data.
    persist_boot_change_with_scratch(&mut store, &[], &mut sink, &mut scratch).unwrap();
    let mut fs = HostStore::fresh();
    for boot in 0..2 {
        store = sink.reboot();
        let loaded_len = store.snapshot_partition(&mut loaded).unwrap();
        let cell = RefCell::new(store);
        let mut shared = SharedStore::new(&cell);
        let mut auth = SharedStore::new(&cell);
        with_host_store_and_migration(fs, "opcard", &mut auth, &OTP, UID, |client| {
            // Authority attached BEFORE new, then restore BEFORE registration.
            let mut app = OpenPgpApp::new(client);
            app.restore_at_boot(&mut shared, &OTP, UID, &mut bufs)
                .unwrap();
            let mut d = Dispatcher::<1>::new();
            assert!(d.register(&mut app));
            persist_boot_change_with_scratch(
                &mut shared,
                &loaded[..loaded_len],
                &mut sink,
                &mut scratch,
            )
            .unwrap();
            pending(&mut shared, &mut bufs, if boot == 0 { 3 } else { 2 });
            let r = dispatch(&mut d, 0xa4, 4, 0, OPENPGP_AID);
            serve(&mut d, &mut shared, &mut sink, &mut scratch, r, 0x9000);
            let r = dispatch(&mut d, 0xca, 0, 0x5b, &[]);
            let r = serve(&mut d, &mut shared, &mut sink, &mut scratch, r, 0x9000);
            assert_eq!(&r[..r.len() - 2], b"Migrated User");
            let r = dispatch(&mut d, 0x47, 0x81, 0, &[0xb6, 0]);
            let r = serve(&mut d, &mut shared, &mut sink, &mut scratch, r, 0x9000);
            assert_eq!(&r[..r.len() - 2], PUBLIC);
            if boot == 0 {
                let r = dispatch(&mut d, 0x20, 0, 0x83, PW3);
                serve(&mut d, &mut shared, &mut sink, &mut scratch, r, 0x9000);
                pending(&mut shared, &mut bufs, 3);
                let r = dispatch(&mut d, 0x2c, 0, 0x81, b"resetcod654321");
                serve(&mut d, &mut shared, &mut sink, &mut scratch, r, 0x6982);
                // PW3 authentication neither converts PW1 nor supplies a private key.
                let r = dispatch(&mut d, 0x20, 0, 0x81, PW1);
                serve(&mut d, &mut shared, &mut sink, &mut scratch, r, 0x9000);
                let r = dispatch(&mut d, 0x2a, 0x9e, 0x9a, &[0x42; 32]);
                serve(&mut d, &mut shared, &mut sink, &mut scratch, r, 0x6a88);
            }
            let r = dispatch(&mut d, 0x20, 0, 0x83, b"wrong!!!");
            serve(
                &mut d,
                &mut shared,
                &mut sink,
                &mut scratch,
                r,
                if boot == 0 { 0x63c2 } else { 0x63c1 },
            );
            pending(&mut shared, &mut bufs, if boot == 0 { 2 } else { 1 });
        })
        .unwrap();
        // Preserve native durable files, replace volatile storage on reboot.
        fs.vfs = HostStore::fresh().vfs;
    }
    pending(&mut sink.reboot(), &mut bufs, 1);
}

#[test]
fn program_failure_returns_corrupt_no_ack() {
    let mut bufs = MigrationBuffers::new();
    let mut scratch = [0; IMAGE_MAX];
    let mut store = capture(&mut bufs);
    let mut sink = Sink::new();
    sink.fail = true;
    let mut served = false;
    let boot = persist_boot_change_with_scratch(&mut store, &[], &mut sink, &mut scratch)
        .map(|()| served = true);
    assert_eq!(boot, Err(SecureStoreError::Corrupt));
    assert!(!served, "failed boot must not reach serving");
    assert_eq!(sink.attempts, 1);
    sink.fail = false;
    persist_boot_change_with_scratch(&mut store, &[], &mut sink, &mut scratch).unwrap();
    let cell = RefCell::new(sink.reboot());
    let mut shared = SharedStore::new(&cell);
    let mut auth = SharedStore::new(&cell);
    with_host_store_and_migration(
        HostStore::fresh(),
        "opcard",
        &mut auth,
        &OTP,
        UID,
        |client| {
            let mut app = OpenPgpApp::new(client);
            app.restore_at_boot(&mut shared, &OTP, UID, &mut bufs)
                .unwrap();
            let mut d = Dispatcher::<1>::new();
            assert!(d.register(&mut app));
            persist_boot_change_with_scratch(&mut shared, &[], &mut sink, &mut scratch).unwrap();
            let r = dispatch(&mut d, 0xa4, 4, 0, OPENPGP_AID);
            serve(&mut d, &mut shared, &mut sink, &mut scratch, r, 0x9000);
            let r = dispatch(&mut d, 0x20, 0, 0x83, b"wrong!!!");
            serve(&mut d, &mut shared, &mut sink, &mut scratch, r, 0x63c2);
            let good = sink.image;
            let good_len = sink.len;
            let attempts = sink.attempts;
            let mut r = dispatch(&mut d, 0x20, 0, 0x83, PW3);
            sw(&r, 0x9000); // staged success is NOT an ACK yet
            sink.fail = true;
            assert_eq!(
                persist_reply_with_scratch(
                    d.apps_mut(),
                    &mut shared,
                    &mut sink,
                    &mut scratch,
                    &mut r
                ),
                Err(SecureStoreError::Corrupt)
            );
            assert_eq!(
                r.as_slice(),
                &[0x6f, 0x00],
                "no data or success ACK may escape"
            );
            assert!(
                d.apps_mut()[0].is_dirty(),
                "failed program must remain retryable"
            );
            assert_eq!(sink.attempts, attempts + 1);
            assert_eq!(sink.len, good_len);
            assert_eq!(sink.image, good);
            pending(&mut sink.reboot(), &mut bufs, 2);
            sink.fail = false;
            // Failure revoked volatile administrator authentication too.
            let r = dispatch(&mut d, 0xda, 0, 0x5b, b"Unauthorized");
            serve(&mut d, &mut shared, &mut sink, &mut scratch, r, 0x6982);
            assert!(!d.apps_mut()[0].is_dirty());
            // Bounded snapshot failure also fails closed without touching the sink.
            let mut r = dispatch(&mut d, 0x20, 0, 0x83, PW3);
            sw(&r, 0x9000);
            let attempts = sink.attempts;
            assert_eq!(
                persist_reply_with_scratch(d.apps_mut(), &mut shared, &mut sink, &mut [], &mut r),
                Err(SecureStoreError::Corrupt)
            );
            assert_eq!(r.as_slice(), &[0x6f, 0x00]);
            assert_eq!(sink.attempts, attempts);
            assert!(d.apps_mut()[0].is_dirty());
        },
    )
    .unwrap();
}
