//! Profile installation evidence belongs to the migration source, not live DO values.
use fapico2_openpgp::{OpenPgpApp, OPENPGP_AID};
use fapico2_platform::{
    cflash::{fallback_partition_reserved, DataPartition},
    cfs::{CFlashSource, PoolBounds},
    dispatch::{Dispatcher, MAX_RESPONSE},
    migration::{self, MigrationBuffers},
    secure_store::{Rp2350SecureStore, SharedStore},
    trusted_backend::{
        dispatch::OpcardDispatch,
        host::{HostPlatform, HostStore, with_host_store_and_migration},
        runner::with_backend,
    },
};
use trussed_core::{FilesystemClient, types::{Location, PathBuf}};

const SOURCE: [u8; 32] = [0x42; 32];
const VERSION_FIELD: &[u8] = b"migration_profile_version";
const UID: &[u8] = &[1,2,3,4,5,6,7,8];
const OTP: [u8;32] = hex_literal::hex!("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf");

fn profile() -> opcard::MigrationProfile<'static> {
    opcard::MigrationProfile {
        language: b"en", sex: Some(b'1'),
        private_use_1: Some(b"one"), private_use_2: Some(b"two"),
    }
}
fn options() -> opcard::Options {
    let mut options = opcard::Options::default();
    options.storage = Location::Internal;
    options
}
fn restore<C: opcard::Client>(card: &mut opcard::Card<C>, profile: opcard::MigrationProfile<'_>) -> Result<(), iso7816::Status> {
    card.restore_public_metadata_with_profile(SOURCE, b"Migrated User", 6, 8, None, None, None, None, profile)
}
fn state_bytes(fs: HostStore, remove_version: bool) -> Vec<u8> {
    with_backend(HostPlatform::with_store(fs), OpcardDispatch::new(), "opcard", |mut client| {
        let path = PathBuf::try_from("persistent-state.cbor").unwrap();
        let mut data = trussed_core::syscall!(client.read_file(Location::Internal, path.clone())).data;
        if remove_version {
            // Test-local old-format fixture: remove the serialized optional u8
            // field and decrement the definite CBOR map count. No production hook.
            if let Some(key) = data.windows(VERSION_FIELD.len()).position(|v| v == VERSION_FIELD) {
                let prefix = if VERSION_FIELD.len() < 24 { 1 } else { 2 };
                let start = key - prefix;
                if prefix == 2 {
                    assert_eq!(&data[start..key], &[0x78, VERSION_FIELD.len() as u8]);
                }
                let end = key + VERSION_FIELD.len() + 1;
                assert_eq!(data[end - 1], 1);
                let mut old = data.to_vec();
                old.drain(start..end);
                match old[0] {
                    0xa1..=0xb7 => old[0] -= 1,
                    0xb8 if old[1] > 24 => old[1] -= 1,
                    0xb8 if old[1] == 24 => { old.drain(0..2); old.insert(0, 0xb7); }
                    _ => panic!("expected a nonempty definite CBOR map"),
                }
                data.clear();
                data.extend_from_slice(&old).unwrap();
                trussed_core::syscall!(client.write_file(Location::Internal, path, data.clone(), None));
            }
            assert!(!data.windows(VERSION_FIELD.len()).any(|v| v == VERSION_FIELD));
        }
        data.to_vec()
    })
}
fn get<C: opcard::Client>(card: &mut opcard::Card<C>, tag: u16) -> Vec<u8> {
    let apdu = [0, 0xca, (tag >> 8) as u8, tag as u8, 0];
    let mut reply = heapless09::Vec::<u8, 64>::new();
    card.handle(iso7816::command::CommandView::try_from(&apdu[..]).unwrap(), &mut reply).unwrap();
    reply.to_vec()
}

#[test]
fn truly_old_same_source_refuses_richer_capture_without_backfill_even_if_values_match() {
    for captured in [
        opcard::MigrationProfile { language: b"en", ..Default::default() },
        opcard::MigrationProfile { sex: Some(b'1'), ..Default::default() },
        opcard::MigrationProfile { private_use_1: Some(b"one"), ..Default::default() },
        opcard::MigrationProfile { private_use_2: Some(b"two"), ..Default::default() },
    ] {
        for installed in [opcard::MigrationProfile::default(), captured] {
            let fs = HostStore::fresh();
            with_backend(HostPlatform::with_store(fs), OpcardDispatch::new(), "opcard", |client| {
                restore(&mut opcard::Card::new(client, options()), installed).unwrap();
            });
            let before = state_bytes(fs, true);
            with_backend(HostPlatform::with_store(fs), OpcardDispatch::new(), "opcard", |client| {
                let mut card = opcard::Card::new(client, options());
                assert_eq!(restore(&mut card, captured), Err(iso7816::Status::ConditionsOfUseNotSatisfied));
                assert_eq!(get(&mut card, 0x5f2d), installed.language);
                assert_eq!(get(&mut card, 0x5f35), &[installed.sex.unwrap_or(b'0')]);
                assert_eq!(get(&mut card, 0x0101), installed.private_use_1.unwrap_or_default());
                assert_eq!(get(&mut card, 0x0102), installed.private_use_2.unwrap_or_default());
            });
            assert_eq!(state_bytes(fs, false), before, "refusal must not backfill evidence");
        }
    }
}

#[test]
fn truly_old_default_capture_remains_read_only_compatible() {
    let fs = HostStore::fresh();
    with_backend(HostPlatform::with_store(fs), OpcardDispatch::new(), "opcard", |client| {
        restore(&mut opcard::Card::new(client, options()), Default::default()).unwrap();
    });
    let before = state_bytes(fs, true);
    with_backend(HostPlatform::with_store(fs), OpcardDispatch::new(), "opcard", |client| {
        restore(&mut opcard::Card::new(client, options()), Default::default()).unwrap();
    });
    assert_eq!(state_bytes(fs, false), before);
}

#[test]
fn current_matching_restore_survives_restart_read_only() {
    let fs = HostStore::fresh();
    with_backend(HostPlatform::with_store(fs), OpcardDispatch::new(), "opcard", |client| {
        restore(&mut opcard::Card::new(client, options()), profile()).unwrap();
    });
    let before = state_bytes(fs, false);
    with_backend(HostPlatform::with_store(fs), OpcardDispatch::new(), "opcard", |client| {
        restore(&mut opcard::Card::new(client, options()), profile()).unwrap();
    });
    assert_eq!(state_bytes(fs, false), before);
}

struct Flash { bytes: Vec<u8>, part: DataPartition }
impl CFlashSource for Flash {
    fn read(&self, addr: u32, out: &mut [u8]) {
        let offset = (addr - self.part.start) as usize;
        out.copy_from_slice(&self.bytes[offset..offset + out.len()]);
    }
}

/// US-918: seed the boot-entropy slot with the fixed test vector so the
/// bound device root is derivable; harmless where derivation never happens.
fn seed_entropy<K: fapico2_platform::secure_store::SecureStore>(store: &mut K) {
    use fapico2_platform::ckey;
    use fapico2_platform::migration::SLOT_BOOT_ENTROPY;
    const ENTROPY: [u8; ckey::BOOT_ENTROPY_LEN] = [0xA5u8; ckey::BOOT_ENTROPY_LEN];
    store.write(SLOT_BOOT_ENTROPY, &ENTROPY).unwrap();
}

fn fixture() -> Flash {
    let mut stream = &include_bytes!("fixtures/c-merged-profile.bin")[..];
    let part = fallback_partition_reserved();
    let bounds = PoolBounds::from_partition(part);
    let mut flash = Flash { bytes: vec![0xff; part.size_bytes() as usize], part };
    let mut put = |addr: u32, data: &[u8]| {
        let offset = (addr - part.start) as usize;
        flash.bytes[offset..offset + data.len()].copy_from_slice(data);
    };
    put(bounds.end_rom_pool, &[0; 8]);
    let mut cursor = bounds.data_end;
    let mut previous = 0u32;
    while !stream.is_empty() {
        let n = u32::from_le_bytes(stream[2..6].try_into().unwrap()) as usize;
        cursor -= (12 + n) as u32;
        put(cursor, &previous.to_le_bytes());
        put(cursor + 4, &[0; 4]);
        put(cursor + 8, &stream[..2]);
        put(cursor + 10, &(n as u16).to_le_bytes());
        put(cursor + 12, &stream[6..6 + n]);
        previous = cursor;
        stream = &stream[6 + n..];
    }
    put(bounds.data_end, &previous.to_le_bytes());
    flash
}
fn cmd(d: &mut Dispatcher<'_, 1>, ins: u8, tag: u16, data: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0, ins, (tag >> 8) as u8, tag as u8];
    if !data.is_empty() { apdu.push(data.len() as u8); apdu.extend_from_slice(data); }
    apdu.push(0);
    let mut reply = heapless::Vec::<u8, MAX_RESPONSE>::new();
    d.dispatch(&apdu, &mut reply);
    assert_eq!(&reply[reply.len() - 2..], &[0x90, 0], "INS {ins:02x} tag {tag:04x}: {reply:02x?}");
    reply[..reply.len() - 2].to_vec()
}

#[test]
fn native_profile_edits_survive_backend_restart_and_restore_at_boot() {
    let flash = fixture();
    let mut store = Rp2350SecureStore::new();
    let mut buffers = MigrationBuffers::new();
    seed_entropy(&mut store);
    migration::run(&flash, flash.part, &mut store, &OTP, UID, &mut buffers).unwrap();
    let cell = core::cell::RefCell::new(store);
    let mut shared = SharedStore::new(&cell);
    let mut auth = SharedStore::new(&cell);
    let fs = HostStore::fresh();
    let changed: [(u16, &[u8]); 4] = [(0x5f2d, b"frde"), (0x5f35, b"9"),
        (0x0101, b"native one"), (0x0102, b"native two")];
    with_host_store_and_migration(fs, "opcard", &mut auth, &OTP, UID, |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_at_boot(&mut shared, &OTP, UID, &mut buffers).unwrap();
        let mut d = Dispatcher::<1>::new();
        assert!(d.register(&mut app));
        cmd(&mut d, 0xa4, 0x0400, OPENPGP_AID);
        cmd(&mut d, 0x20, 0x0082, b"654321");
        cmd(&mut d, 0x20, 0x0083, b"87654321");
        for (tag, value) in changed {
            cmd(&mut d, 0xda, tag, value);
            assert_eq!(cmd(&mut d, 0xca, tag, &[]), value);
        }
    }).unwrap();
    let before = state_bytes(fs, false);
    // New runner, dispatch, client, card and volatile filesystem; persistent
    // filesystem alone survives, as on a backend restart.
    let reboot_fs = HostStore { vfs: HostStore::fresh().vfs, ..fs };
    with_host_store_and_migration(reboot_fs, "opcard", &mut auth, &OTP, UID, |client| {
        let mut app = OpenPgpApp::new(client);
        app.restore_at_boot(&mut shared, &OTP, UID, &mut buffers).unwrap();
        let mut d = Dispatcher::<1>::new();
        assert!(d.register(&mut app));
        cmd(&mut d, 0xa4, 0x0400, OPENPGP_AID);
        for (tag, value) in changed { assert_eq!(cmd(&mut d, 0xca, tag, &[]), value); }
    }).unwrap();
    assert_eq!(state_bytes(fs, false), before);
}
