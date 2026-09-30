//! US-388 TDD — device reboot persistence through the platform `SecureStore`.
//!
//! Mirrors `apps/fido/tests/restart.rs` (US-322) and
//! `tests/harness/test_restart.py` (US-322/FX-409): persistent state —
//! Management `EF_DEV_CONF`, OTP slot contents + access code, the FIDO
//! keystore root — survives a power cycle; volatile session state (OTP
//! program sequence, FIDO `clear_session_state`) is freshly initialized.
//!
//! Reboot is simulated through the same seam the device firmware drives
//! (US-387): snapshot the secure partition (`partition_image`) and restore it
//! into a fresh store (`from_partition_image`), then boot fresh app objects.
//!
//! The FIDO credential/PIN-counter reboot behaviour is covered end-to-end by
//! `apps/fido/tests/restart.rs` (FileSecureStore re-open) and the fido device
//! shell's boot tests (partition-image path); this file covers the CCID-side
//! app state.

use fapico2_mgmt::ManagementApp;
use fapico2_oath::OtpApp;
use fapico2_platform::dispatch::{App, MAX_RESPONSE};
use fapico2_platform::secure_store::HostSecureStore;
use heapless::Vec as HeaplessVec;

/// Drive one APDU through an app; returns (response data, SW).
fn drive<A: App>(app: &mut A, apdu: &[u8]) -> (Vec<u8>, u16) {
    let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
    app.process(apdu, &mut resp);
    let bytes = resp.as_slice();
    let sw = u16::from_be_bytes([bytes[bytes.len() - 2], bytes[bytes.len() - 1]]);
    (bytes[..bytes.len() - 2].to_vec(), sw)
}

/// Snapshot + drop + restore: the power-cycle seam.
fn reboot(store: &HostSecureStore) -> HostSecureStore {
    let image = store.partition_image();
    let mut restored = HostSecureStore::new();
    restored.from_partition_image(&image);
    restored
}

// Management INS 0x1C/0x1D (matches `management.c`).
const INS_WRITE_CONFIG: u8 = 0x1C;
const INS_READ_CONFIG: u8 = 0x1D;
const INS_RESET: u8 = 0x1E;

/// A user-written `EF_DEV_CONF` blob survives a reboot: WRITE_CONFIG → save →
/// power cycle → boot → READ_CONFIG returns the stored bytes verbatim (C
/// `file_has_data(EF_DEV_CONF)` echo path).
#[test]
fn management_config_survives_reboot() {
    let mut store = HostSecureStore::new();
    {
        let mut app = ManagementApp::boot(&mut store);
        let config = [0xAB, 0xCD, 0xEF];
        let mut apdu = vec![
            0x00, INS_WRITE_CONFIG, 0x00, 0x00,
            (1 + config.len()) as u8, config.len() as u8,
        ];
        apdu.extend_from_slice(&config);
        let (_, sw) = drive(&mut app, &apdu);
        assert_eq!(sw, 0x9000, "WRITE_CONFIG must succeed");
        app.save(&mut store).unwrap();
    } // power cycle: app dropped

    let mut rebooted = reboot(&store);
    let mut app = ManagementApp::boot(&mut rebooted);
    let (data, sw) = drive(&mut app, &[0x00, INS_READ_CONFIG, 0x00, 0x00, 0x00]);
    assert_eq!(sw, 0x9000);
    assert_eq!(
        &data[..],
        &[0x03, 0xAB, 0xCD, 0xEF],
        "the user config must survive the reboot (stored blob echoed verbatim)"
    );
    assert!(app.has_config());
}

/// RESET is durable too: reset → save → reboot → the default caps blob is
/// emitted again (the stored blob is gone, not resurrected).
#[test]
fn management_reset_survives_reboot() {
    let mut store = HostSecureStore::new();
    {
        let mut app = ManagementApp::boot(&mut store);
        let apdu = [0x00, INS_WRITE_CONFIG, 0x00, 0x00, 2, 1, 0x00];
        let (_, sw) = drive(&mut app, &apdu);
        assert_eq!(sw, 0x9000);
        let (_, sw) = drive(&mut app, &[0x00, INS_RESET, 0x00, 0x00, 0x00]);
        assert_eq!(sw, 0x9000);
        app.save(&mut store).unwrap();
    } // power cycle

    let mut rebooted = reboot(&store);
    let mut app = ManagementApp::boot(&mut rebooted);
    let (data, sw) = drive(&mut app, &[0x00, INS_READ_CONFIG, 0x00, 0x00, 0x00]);
    assert_eq!(sw, 0x9000);
    assert!(!app.has_config(), "reset must survive the reboot");
    // data[1] is the first TLV tag of the default caps blob (TAG_USB_SUPPORTED).
    assert_eq!(data[1], 0x01);
}

/// CRC-16 (YubiKey slot-config checksum, same polynomial as `otp.rs`).
fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for value in data {
        crc ^= *value as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x8408
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// A valid 52-byte OTP slot config (CRC placed so `cmd_configure` accepts it;
/// mirrors the layout in `otp.rs`'s tests).
fn make_config() -> [u8; 52] {
    let mut c = [0u8; 52];
    c[16..22].copy_from_slice(&[1, 2, 3, 4, 5, 6]); // uid
    c[22..38].copy_from_slice(&[7u8; 16]); // aes key
    c[46] = 0x20; // tkt_flags: HMAC-SHA1 mode marker
    let stored = !crc16(&c[..50]);
    c[50..52].copy_from_slice(&stored.to_le_bytes());
    c
}

/// Program `slot` (0/1) with a valid config.
fn configure_slot(app: &mut OtpApp, slot: u8) {
    let config = make_config();
    let mut apdu = vec![0x00, 0x01, 0x01, slot, config.len() as u8];
    apdu.extend_from_slice(&config);
    let (_, sw) = drive(app, &apdu);
    assert_eq!(sw, 0x9000, "slot configure must succeed");
}

/// OTP slot contents + access code survive a reboot; the volatile program
/// sequence counter does NOT (fresh at boot, like a real power cycle).
#[test]
fn otp_slots_survive_reboot_and_program_sequence_is_fresh() {
    let mut store = HostSecureStore::new();
    {
        let mut app = OtpApp::boot(&mut store);
        // The volatile program sequence starts fresh on a freshly booted app.
        assert_eq!(
            app.program_sequence(),
            0,
            "a freshly booted OTP app starts with a fresh program sequence"
        );
        configure_slot(&mut app, 0);

        // US-712 C parity: a successful SLOT_CONFIGURE bumps the sequence
        // counter (C otp.c `config_seq++` — the status body configure
        // returns reports the new value).
        assert_eq!(
            app.program_sequence(),
            1,
            "configure must advance the program sequence like C config_seq++"
        );
        app.save(&mut store).unwrap();
    } // power cycle

    let mut rebooted = reboot(&store);
    let app = OtpApp::boot(&mut rebooted);
    // Slot 1 must still be configured after the reboot (status flags bit 0).
    assert!(
        app.slot_configured(0),
        "OTP slot 1 must survive the reboot"
    );
    assert_eq!(
        app.program_sequence(),
        0,
        "the volatile program sequence must NOT survive the reboot"
    );
}

/// A slot swap before the reboot stays swapped (persistence is the full
/// slot state, not a grow-only log).
#[test]
fn otp_slot_swap_survives_reboot() {
    let mut store = HostSecureStore::new();
    {
        let mut app = OtpApp::boot(&mut store);
        configure_slot(&mut app, 0);
        app.save(&mut store).unwrap();
    }
    {
        let mut rebooted = reboot(&store);
        let mut app = OtpApp::boot(&mut rebooted);
        assert!(app.slot_configured(0));
        // SLOT_SWAP (P1=0x06) moves slot 1's content to slot 2. Configuring
        // the slot installed access code [0;6] (config[38..44]), so the
        // protected swap carries it: data = [slot(1), 0, access(6)].
        let mut swap = vec![0x00, 0x01, 0x06, 0x00, 8, 0x00, 0x00];
        swap.extend_from_slice(&[0u8; 6]);
        let (_, sw) = drive(&mut app, &swap);
        assert_eq!(sw, 0x9000, "slot swap must succeed");
        app.save(&mut store).unwrap();
    }
    let mut rebooted = reboot(&store);
    let app = OtpApp::boot(&mut rebooted);
    assert!(
        !app.slot_configured(0) && app.slot_configured(1),
        "the swap must be durable: slot 1 empty, slot 2 configured"
    );
}
