//! US-423 (SECURE-PERSIST Phase A): persist boot-time store changes.
//!
//! `persist_boot_change` compares the store's current partition image with
//! `loaded_img` — the canonical re-serialization taken right after the boot
//! load, before migration / app boot mutated the store — and programs the
//! sink only if they differ. These host tests pin the contract:
//!
//! * a boot that mutated the store programs exactly one (loadable) image;
//! * an unchanged boot programs nothing (gate-level idempotency, zero flash
//!   wear);
//! * a failing sink reports the boot-time state as not durable;
//! * the two-boot simulations are the ground-truth proof of the EPIC's
//!   next-boot paths: a fresh board's second boot skips the migration with
//!   [`SkipReason::StoreNotEmpty`] (the migration log line itself is
//!   device-only — the emulation build never runs the migration, having no
//!   C partition / CFlashSource), and a migrated board's second boot skips
//!   with [`SkipReason::AlreadyMigrated`] while the gate stays a no-op.

use fapico2_platform::cflash::DataPartition;
use fapico2_platform::cfs::CFlashSource;
use fapico2_platform::migration::{
    self, MigrationBuffers, MigrationOutcome, SkipReason, MIGRATION_MARKER, SLOT_FIDO_HKEY,
};
use fapico2_platform::persist::{persist_boot_change, pull_image, ImageSink, WindowedImageSource};
use fapico2_platform::secure_store::{HostSecureStore, SecureStore};

/// A C data partition that was never initialized: every read returns erased
/// flash (0xFF) → `CState::FactoryFresh`. The skip paths in
/// `migration::run` run before key derivation, so the OTP key and the flash
/// UID can be anything.
struct FactoryFreshCFlash;

impl CFlashSource for FactoryFreshCFlash {
    fn read(&self, _addr: u32, buf: &mut [u8]) {
        buf.fill(0xFF);
    }
}

/// Any sane range: range-insensitive for the paths exercised (the skip
/// gates run before the C walk, and the walk sees only 0xFF).
const PART: DataPartition = DataPartition {
    start: 0x1000_0000,
    end: 0x1004_0000,
};

/// Records every image programmed through the sink.
#[derive(Default)]
struct InMemorySink {
    images: Vec<Vec<u8>>,
}

impl InMemorySink {
    fn program_count(&self) -> usize {
        self.images.len()
    }
}

impl ImageSink for InMemorySink {
    fn program(&mut self, src: &mut dyn WindowedImageSource) -> bool {
        self.images.push(pull_image(src));
        true
    }
}

/// A sink whose program always fails (and counts its calls).
#[derive(Default)]
struct FailingSink {
    calls: usize,
}

impl ImageSink for FailingSink {
    fn program(&mut self, _src: &mut dyn WindowedImageSource) -> bool {
        self.calls += 1;
        false
    }
}

#[test]
fn boot_change_programs_and_survives_reboot() {
    let mut store = HostSecureStore::new();
    let loaded = store.partition_image();
    // The boot mutated the store (first-boot hkey derivation — the
    // FidoApp::boot equivalent).
    store.write(b"fido.hkey", &[7; 32]).unwrap();
    let mut sink = InMemorySink::default();

    assert!(
        persist_boot_change(&mut store, &loaded, &mut sink),
        "a changed boot must report a durable state"
    );
    assert_eq!(sink.program_count(), 1, "exactly one image programmed");

    // A fresh store reloaded from the programmed image carries the mutation.
    let mut restored = HostSecureStore::new();
    restored.from_partition_image(&sink.images[0]);
    assert!(
        restored.contains(b"fido.hkey"),
        "the programmed image must load back into a fresh store"
    );
    let mut buf = [0u8; 64];
    let n = restored.read(b"fido.hkey", &mut buf).unwrap();
    assert_eq!(&buf[..n], &[7; 32], "the value must survive intact");
}

#[test]
fn unchanged_boot_programs_nothing() {
    let mut store = HostSecureStore::new();
    let loaded = store.partition_image();
    let mut sink = InMemorySink::default();

    assert!(
        persist_boot_change(&mut store, &loaded, &mut sink),
        "an unchanged boot is durable (it is exactly what is in the medium)"
    );
    assert_eq!(
        sink.program_count(),
        0,
        "the compare must short-circuit: zero flash wear on an unchanged boot"
    );
}

#[test]
fn failing_sink_returns_false() {
    let mut store = HostSecureStore::new();
    let loaded = store.partition_image();
    store.write(b"fido.hkey", &[7; 32]).unwrap();
    let mut sink = FailingSink::default();

    assert!(
        !persist_boot_change(&mut store, &loaded, &mut sink),
        "a sink program failure means the boot-time state is NOT durable"
    );
    assert_eq!(sink.calls, 1, "the image was handed to the sink");
}

#[test]
fn fresh_board_second_boot_skips_store_not_empty() {
    let src = FactoryFreshCFlash;
    let zero_otp = [0u8; 32];
    let uid = [0x01, 0x02, 0x03, 0x04]; // any flash_uid (skip paths run first)
    let mut bufs = MigrationBuffers::new();

    // Boot 1 (fresh board): the C partition is factory-fresh, so the
    // migration skips without writing a marker; the FIDO app boot then
    // derives its hkey. The canonical post-load image is captured first,
    // exactly where the device takes its snapshot.
    let mut store = HostSecureStore::new();
    let loaded = store.partition_image();
    let out = migration::run(&src, PART, &mut store, &zero_otp, &uid, &mut bufs).unwrap();
    assert_eq!(
        out,
        MigrationOutcome::Skipped(SkipReason::CStateFactoryFresh),
        "a factory-fresh C partition skips migration (no marker written)"
    );
    store.write(SLOT_FIDO_HKEY, &[9; 32]).unwrap(); // FidoApp::boot equivalent
    let mut sink = InMemorySink::default();
    assert!(persist_boot_change(&mut store, &loaded, &mut sink));
    assert_eq!(sink.program_count(), 1, "boot 1 programs the new hkey");

    // Boot 2: the store loads with the hkey and no marker — the migration's
    // StoreNotEmpty gate engages (the EPIC's next-boot path), and the boot
    // persist gate is idempotent (the store is unchanged from load).
    let mut store = HostSecureStore::new();
    store.from_partition_image(&sink.images[0]);
    let loaded = store.partition_image(); // re-serialize the post-load image
    let out = migration::run(&src, PART, &mut store, &zero_otp, &uid, &mut bufs).unwrap();
    assert_eq!(
        out,
        MigrationOutcome::Skipped(SkipReason::StoreNotEmpty),
        "a store holding app secrets but no marker is not a first boot"
    );
    assert!(
        persist_boot_change(&mut store, &loaded, &mut sink),
        "an unchanged second boot is durable"
    );
    assert_eq!(
        sink.program_count(),
        1,
        "an unchanged second boot programs nothing (zero wear)"
    );
}

#[test]
fn migrated_board_second_boot_skips_marker_and_gate_is_noop() {
    let src = FactoryFreshCFlash;
    let zero_otp = [0u8; 32];
    let uid = [0x01, 0x02, 0x03, 0x04];
    let mut bufs = MigrationBuffers::new();

    // Boot 1 (C-Used device after a completed migration): the migration
    // wrote the marker (a 4-byte report blob — the migration-equivalent
    // done state) and the FIDO hkey.
    let mut store = HostSecureStore::new();
    let loaded = store.partition_image();
    store.write(MIGRATION_MARKER, &[1, 0, 1, 0]).unwrap();
    store.write(SLOT_FIDO_HKEY, &[9; 32]).unwrap();
    let mut sink = InMemorySink::default();
    assert!(persist_boot_change(&mut store, &loaded, &mut sink));
    assert_eq!(sink.program_count(), 1);

    // Boot 2: the marker makes the migration a no-op and the gate programs
    // nothing.
    let mut store = HostSecureStore::new();
    store.from_partition_image(&sink.images[0]);
    let loaded = store.partition_image();
    let out = migration::run(&src, PART, &mut store, &zero_otp, &uid, &mut bufs).unwrap();
    assert_eq!(
        out,
        MigrationOutcome::Skipped(SkipReason::AlreadyMigrated),
        "the marker slot makes every later boot a no-op"
    );
    assert!(
        persist_boot_change(&mut store, &loaded, &mut sink),
        "an unchanged second boot is durable"
    );
    assert_eq!(
        sink.program_count(),
        1,
        "the gate is a no-op on the second boot (zero wear)"
    );
}
