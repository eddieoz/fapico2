//! US-913: PW-status secure defaults survive a reboot (host remount).
//!
//! The PW-status flag (`pw1_valid_multiple`, DO 0xC4 byte0) is part of the
//! persistent card state: a relaxation performed by the admin must still be
//! in force after a reboot, and a fresh card must always boot with the
//! strict "PW1 required" default (byte0 == 0x00 — PW1 valid once per
//! PSO:CDS). The emulation binary keeps the OpenPGP partition in RAM, so
//! reboot durability is exercised here against the real filesystem stack
//! (same remount shape as `device_pso.rs`'s cross-cycle test).
//!
//! PUT DATA 0xC4 must stay admin-authenticated (PW3): refused with no
//! session and with a PW1-only session.

use fapico2_openpgp::{OpenPgpApp, OPENPGP_AID};
use fapico2_platform::{
    dispatch::{Dispatcher, MAX_RESPONSE},
    trusted_backend::{
        dispatch::OpcardDispatch,
        host::{HostPlatform, HostStore, leak_buf, mount_fs},
        runner::with_backend,
    },
};

fn command(
    dispatcher: &mut Dispatcher<'_, 1>,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
    sw: u16,
) -> Vec<u8> {
    let mut apdu = vec![0, ins, p1, p2];
    if !data.is_empty() {
        apdu.push(u8::try_from(data.len()).unwrap());
        apdu.extend_from_slice(data);
    }
    apdu.push(0);
    let mut response = heapless::Vec::<u8, MAX_RESPONSE>::new();
    dispatcher.dispatch(&apdu, &mut response);
    assert!(response.len() >= 2);
    let body_len = response.len() - 2;
    assert_eq!(
        u16::from_be_bytes(response[body_len..].try_into().unwrap()),
        sw,
        "INS={ins:02x} P1={p1:02x} P2={p2:02x}"
    );
    response[..body_len].to_vec()
}

/// PUT PW-status payload: flag byte + the three max-length bytes the card
/// requires unchanged (0x7F = MAX_PIN_LENGTH).
const RELAXED: &[u8] = &[0x01, 0x7f, 0x7f, 0x7f];

#[test]
fn pw_status_flag_is_durable_across_reboot() {
    let internal = leak_buf(256 * 4096);

    // Boot 1: fresh card ships the strict default; PW3 relaxes the flag.
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
            command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
            // Fresh default: byte0 == 0x00 (PW1 valid once per PSO:CDS).
            let c4 = command(&mut dispatcher, 0xca, 0, 0xc4, &[], 0x9000);
            assert_eq!(c4[0], 0x00, "fresh card must ship PW1-required");
            // Relaxing is admin-authenticated.
            command(&mut dispatcher, 0xda, 0, 0xc4, RELAXED, 0x6982);
            command(&mut dispatcher, 0x20, 0, 0x81, b"123456", 0x9000);
            command(&mut dispatcher, 0xda, 0, 0xc4, RELAXED, 0x6982);
            command(&mut dispatcher, 0x20, 0, 0x83, b"12345678", 0x9000);
            command(&mut dispatcher, 0xda, 0, 0xc4, RELAXED, 0x9000);
            let c4 = command(&mut dispatcher, 0xca, 0, 0xc4, &[], 0x9000);
            assert_eq!(c4[0], 0x01, "relaxed flag must read back");
        },
    );

    // Boot 2: the relaxed state survives the reboot (fresh volatile state,
    // reloaded persistent state).
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
            command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
            let c4 = command(&mut dispatcher, 0xca, 0, 0xc4, &[], 0x9000);
            assert_eq!(c4[0], 0x01, "relaxed state must survive the reboot");
        },
    );
}
