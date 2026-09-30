//! Host-runnable seam tests for the trussed-core backend (S-721-1, US-331).
//!
//! These prove the full client↔runner↔service round-trip on the host without
//! a device: the fake platform (lifted into
//! [`fapico2_platform::trusted_backend::host`], S-721-2 — the same module
//! the emulation binary and the `apps/openpgp` device-path tests run the
//! real `opcard` on) mirrors the device's rules — entropy comes from the OS
//! (the platform's sole randomness source; the device's "no software PRNG"
//! rule), and storage is littlefs2 filesystems over heap-backed buffers
//! (host-only; `alloc` is fine in tests, the CI no-heap grep exempts
//! `*/tests`).
//!
//! BDD: "signs with P-256 and reads entropy → signatures verify and entropy
//! never repeats", plus power-cycle persistence of the internal filesystem.

use fapico2_platform::trusted_backend::host::{leak_buf, mount_fs, HostPlatform, HostStore};
use fapico2_platform::trusted_backend::{with_backend, OpcardDispatch};
use trussed_core::types::{
    KeySerialization, Location, Mechanism, Message, SignatureSerialization, StorageAttributes,
};
use trussed_core::{CryptoClient, FilesystemClient};

/// Draw 32 bytes of client-visible entropy through the service.
///
/// `CryptoClient::random_bytes` is the client-visible entropy draw in
/// trussed 0.2.x (served by the service's DRBG, which mixes in the platform
/// TRNG and persists `rng-state.bin`). The `Trng` mechanism's
/// `generate_key` (a 32-byte symmetric key) has no client-side read-back —
/// `serialize_key` is not implemented for it — so the distinctness
/// assertion uses `random_bytes`.
fn draw_entropy<C>(client: &mut C) -> [u8; 32]
where
    C: CryptoClient,
{
    let bytes = trussed_core::syscall!(client.random_bytes(32)).bytes;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    out
}

// ---------------------------------------------------------------------------
// The three seam tests.
// ---------------------------------------------------------------------------

/// Fixed P-256 test vector (d, Q = d·G), generated 2026-09-15. The secret
/// scalar is injected, the public point is deserialized, so `verify` (which
/// loads the *public* half in trussed 0.2.x — see the test doc) has
/// material to work with.
const P256_D: [u8; 32] = [
    0x8b, 0xe7, 0x40, 0x8c, 0x77, 0x33, 0x8b, 0xb4, 0x4a, 0x60, 0xe1, 0xa9,
    0x77, 0x92, 0x94, 0x4b, 0x30, 0x8e, 0x0e, 0x09, 0xf2, 0xfe, 0x8f, 0xfc,
    0xb7, 0xdc, 0x37, 0x7d, 0x87, 0x5e, 0x00, 0xd1,
];
const P256_Q: [u8; 64] = [
    0xd6, 0xe1, 0x47, 0x43, 0xaa, 0x19, 0x47, 0x07, 0x31, 0x3d, 0x6f, 0x50,
    0xfd, 0x5e, 0x56, 0x5b, 0xa7, 0x02, 0xa7, 0x9e, 0xd1, 0x6a, 0x5e, 0xe8,
    0x46, 0x89, 0x76, 0xbf, 0x7e, 0x1a, 0xb1, 0x8b, 0x9a, 0x6f, 0xf8, 0x72,
    0xe0, 0xf0, 0x68, 0xef, 0x19, 0xc3, 0xc6, 0xd9, 0x80, 0x77, 0x70, 0x8e,
    0x6b, 0x2c, 0xfe, 0xc6, 0x8c, 0x98, 0x67, 0x38, 0x2d, 0xa8, 0x62, 0x99,
    0xd7, 0x32, 0x7b, 0xbf,
];

/// BDD: "signs with P-256 and reads entropy → signatures verify and entropy
/// never repeats." Exercises the whole stack through the "call thyself"
/// runner: client request → `Syscall::syscall` → service → reply.
///
/// trussed 0.2.x key model (registry ground truth — the brief assumed a
/// single keypair handle): `generate_key` stores only the *secret* half;
/// `verify`/`serialize_key` load the *public* half by key ID, which only
/// `deserialize_key` (or host-side import) ever stores. opcard itself only
/// ever calls `generate_key`/`sign`/`random_bytes` (verification is
/// host-side in OpenPGP), so this test covers both halves explicitly: the
/// fixed-vector inject+deserialize path proves `verify` end-to-end, and the
/// `generate_key` path proves the TRNG-derived secret the card actually
/// uses.
#[test]
fn syscall_roundtrip_sign_and_random() {
    let out = with_backend(
        HostPlatform::new(),
        OpcardDispatch::new(),
        "opcard",
        |mut client| {
            let message = b"fapico2 trussed seam (US-331)";

            // 1. Secret half in, public half in (the only in-band verify
            //    setup in trussed 0.2.x).
            let id_sec = trussed_core::syscall!(client.unsafe_inject_key(
                Mechanism::P256,
                &P256_D,
                Location::Internal,
                KeySerialization::Raw
            ))
            .key;
            let id_pub = trussed_core::syscall!(client.deserialize_key(
                Mechanism::P256,
                &P256_Q,
                KeySerialization::Raw,
                StorageAttributes::new().set_persistence(Location::Internal)
            ))
            .key;

            // 2. Sign with the secret half, verify with the public half.
            let sig = trussed_core::syscall!(client.sign(
                Mechanism::P256,
                id_sec,
                message,
                SignatureSerialization::Raw
            ))
            .signature;
            let valid = trussed_core::syscall!(client.verify(
                Mechanism::P256,
                id_pub,
                message,
                &sig,
                SignatureSerialization::Raw
            ))
            .valid;
            assert!(valid, "P-256 signature must verify");

            // 3. Negative control: a tampered message must NOT verify
            //    (guards against a rubber-stamp `verify`).
            let valid_tampered = trussed_core::syscall!(client.verify(
                Mechanism::P256,
                id_pub,
                b"fapico2 trussed seam (US-331)! ",
                &sig,
                SignatureSerialization::Raw
            ))
            .valid;
            assert!(!valid_tampered, "tampered message must not verify");

            // 4. The TRNG-generated-key path (what opcard's gen.rs does):
            //    the service's DRBG must produce a usable P-256 secret.
            let id_gen = trussed_core::syscall!(client.generate_key(
                Mechanism::P256,
                StorageAttributes::new().set_persistence(Location::Internal)
            ))
            .key;
            let sig_gen = trussed_core::syscall!(client.sign(
                Mechanism::P256,
                id_gen,
                message,
                SignatureSerialization::Raw
            ))
            .signature;
            assert_eq!(
                sig_gen.len(),
                64,
                "P-256 raw signature must be 64 bytes"
            );

            // 5. Trng-mechanism key generation must also round-trip (it is
            //    the device's entropy path end-to-end), and drawn entropy
            //    differs.
            trussed_core::syscall!(client.generate_key(
                Mechanism::Trng,
                StorageAttributes::new().set_persistence(Location::Internal)
            ));
            let e1 = draw_entropy(&mut client);
            let e2 = draw_entropy(&mut client);
            (valid, e1, e2)
        },
    );
    assert!(out.0, "P-256 signature must verify");
    assert_ne!(out.1, out.2, "entropy must never repeat");
}

/// Repeated entropy draws never repeat across N ≥ 8 draws (all distinct).
#[test]
fn entropy_differs() {
    with_backend(
        HostPlatform::new(),
        OpcardDispatch::new(),
        "opcard",
        |mut client| {
            let draws: Vec<[u8; 32]> = (0..8).map(|_| draw_entropy(&mut client)).collect();
            for i in 0..draws.len() {
                for j in (i + 1)..draws.len() {
                    assert_ne!(
                        draws[i], draws[j],
                        "entropy draw {i} must differ from draw {j}"
                    );
                }
            }
        },
    );
}

/// A file written on `Location::Internal` by the client survives dropping the
/// whole backend (runner + client + stores) and reopening from the same
/// backing buffer — the host analog of power-cycle persistence (on device the
/// internal FS lives on QSPI flash, so this holds for free).
#[test]
fn storage_survives_reopen() {
    let path = littlefs2_core::PathBuf::try_from("seam-persist.txt")
        .expect("test: valid path");
    let data: &[u8] = b"survive the power cycle";
    // The one backing buffer both "power cycles" mount (raw pointer, see
    // `trusted_backend::host::BufStorage` — the cycles are strictly
    // sequential).
    let internal = leak_buf(256 * 4096);

    // First "power cycle": write the file through the client (fresh RAM
    // efs/vfs; the internal FS is the one shared backing buffer).
    let ram = HostStore::fresh();
    with_backend(
        HostPlatform::with_store(HostStore::new(
            mount_fs::<256>(internal),
            ram.efs,
            ram.vfs,
        )),
        OpcardDispatch::new(),
        "opcard",
        |mut client| {
            let msg = Message::try_from(data).expect("test: message fits");
            trussed_core::syscall!(client.write_file(
                Location::Internal,
                path.clone(),
                msg,
                None
            ));
        },
    );

    // Second "power cycle": rebuild the backend from the same backing
    // buffer; the file must be present with identical content.
    let ram = HostStore::fresh();
    with_backend(
        HostPlatform::with_store(HostStore::new(
            mount_fs::<256>(internal),
            ram.efs,
            ram.vfs,
        )),
        OpcardDispatch::new(),
        "opcard",
        |mut client| {
            let reply =
                trussed_core::syscall!(client.read_file(Location::Internal, path.clone()));
            assert_eq!(&reply.data[..], data, "file must survive the reopen");
        },
    );
}
