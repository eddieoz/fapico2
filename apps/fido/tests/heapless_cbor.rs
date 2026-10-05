//! S-701-1 TDD: no-heap CTAP2 CBOR foundation.
//!
//! `cbor_roundtrip_heapless_no_alloc` — encode the getInfo map plus a
//! makeCredential request into fixed buffers via the no-heap codec and parse
//! them back with the zero-copy parser. The device command ABI is
//! additionally pinned (compile-time, below) to heapless types only — no
//! `Vec`/`String` anywhere in the public device surface.

use fapico2_fido::cbor::no_heap::{self, Item, Parser};
use heapless::Vec as HeaplessVec;

#[test]
fn cbor_roundtrip_heapless_no_alloc() {
    // --- getInfo map: Ctap2Info serialized straight into a fixed buffer ---
    let info = fapico2_fido::ctap2::Ctap2Info::default();
    let mut buf: HeaplessVec<u8, 1024> = HeaplessVec::new();
    info.write_cbor_into(&mut buf)
        .expect("getInfo map fits the fixed buffer");

    let mut p = Parser::new(buf.as_slice());
    // 20 pairs = the 19 unconditional keys plus maxLargeBlob (0x0B). This was
    // 21 until key 0x15 (`vendorPrototypeConfigCommands`) was dropped: its value
    // is an array of 64-bit ids, which needs a `0x1B` CBOR head that `yubikit`
    // cannot decode — see AGENTS.md section 6.
    assert!(matches!(p.next(), Ok(Item::Map(20))), "getInfo is map(20)");
    // versions (key 1): array of tstr, contains FIDO_2_0.
    assert_eq!(p.next().unwrap(), Item::U(0x01));
    let Item::Array(n_versions) = p.next().unwrap() else {
        panic!("versions must be an array");
    };
    assert!(n_versions >= 3);
    for _ in 0..n_versions {
        assert!(matches!(p.next(), Ok(Item::T(_))));
    }
    // aaguid (key 3): 16-byte bstr matching the crate AAGUID.
    while !matches!(p.next(), Ok(Item::U(0x03))) {}
    let Item::B(aaguid) = p.next().unwrap() else {
        panic!("aaguid must be a bstr");
    };
    assert_eq!(aaguid, fapico2_fido::AAGUID.as_slice());
    // maxMsgSize (key 5): the CTAPHID_MAX_MSG claim, now honored end to end.
    while !matches!(p.next(), Ok(Item::U(0x05))) {}
    assert_eq!(p.next().unwrap(), Item::U(7609));
    // The remaining key/value pairs (6..=0x1F) must be well-formed and the
    // parser must consume the whole map.
    while p.remaining() > 0 {
        p.skip().expect("remaining getInfo pairs are well-formed CBOR");
    }

    // --- makeCredential request, encoded + parsed with fixed buffers only ---
    let mut req: HeaplessVec<u8, 256> = HeaplessVec::new();
    // {1: "example.com", 2: {1: b"user-id", 2: "user"}, 3: [{1: 2, 3: -7}], 4: h"challenge", 7: false}
    no_heap::push_map_header(&mut req, 5).unwrap();
    no_heap::push_uint(&mut req, 1).unwrap();
    no_heap::push_tstr(&mut req, "example.com").unwrap();
    no_heap::push_uint(&mut req, 2).unwrap();
    no_heap::push_map_header(&mut req, 2).unwrap();
    no_heap::push_uint(&mut req, 1).unwrap();
    no_heap::push_bstr(&mut req, b"user-id").unwrap();
    no_heap::push_uint(&mut req, 2).unwrap();
    no_heap::push_tstr(&mut req, "user").unwrap();
    no_heap::push_uint(&mut req, 3).unwrap();
    no_heap::push_array_header(&mut req, 1).unwrap();
    no_heap::push_map_header(&mut req, 2).unwrap();
    no_heap::push_uint(&mut req, 1).unwrap();
    no_heap::push_uint(&mut req, 2).unwrap();
    no_heap::push_uint(&mut req, 3).unwrap();
    no_heap::push_neg(&mut req, -7).unwrap();
    no_heap::push_uint(&mut req, 4).unwrap();
    no_heap::push_bstr(&mut req, &[0xABu8; 32]).unwrap();
    no_heap::push_uint(&mut req, 7).unwrap();
    no_heap::push_bool(&mut req, false).unwrap();

    let mut p = Parser::new(req.as_slice());
    assert_eq!(p.next().unwrap(), Item::Map(5));
    assert_eq!(p.next().unwrap(), Item::U(1));
    assert_eq!(p.next().unwrap(), Item::T("example.com"));
    assert_eq!(p.next().unwrap(), Item::U(2));
    assert_eq!(p.next().unwrap(), Item::Map(2));
    assert_eq!(p.next().unwrap(), Item::U(1));
    assert_eq!(p.next().unwrap(), Item::B(&[0x75, 0x73, 0x65, 0x72, 0x2d, 0x69, 0x64]));
    assert_eq!(p.next().unwrap(), Item::U(2));
    assert_eq!(p.next().unwrap(), Item::T("user"));
    assert_eq!(p.next().unwrap(), Item::U(3));
    assert_eq!(p.next().unwrap(), Item::Array(1));
    assert_eq!(p.next().unwrap(), Item::Map(2));
    assert_eq!(p.next().unwrap(), Item::U(1));
    assert_eq!(p.next().unwrap(), Item::U(2));
    assert_eq!(p.next().unwrap(), Item::U(3));
    assert_eq!(p.next().unwrap(), Item::N(-7));
    assert_eq!(p.next().unwrap(), Item::U(4));
    let Item::B(challenge) = p.next().unwrap() else {
        panic!("challenge must be a bstr");
    };
    assert_eq!(challenge.len(), 32);
    assert_eq!(p.next().unwrap(), Item::U(7));
    assert_eq!(p.next().unwrap(), Item::Bool(false));
    assert_eq!(p.remaining(), 0);
}

/// The device command ABI is heapless-only: pin the exact signatures of the
/// public `FidoApp` device surface at compile time so no `alloc` type can
/// creep back into the no-heap path (static_assertions-style check).
#[cfg(feature = "device")]
#[test]
fn device_abi_is_heapless_only() {
    let process_ctap2: fn(&mut fapico2_fido::FidoApp, u8, &[u8], [u8; 4],
        &mut HeaplessVec<u8, { fapico2_fido::CTAP2_MAX_MSG }>) -> usize =
        fapico2_fido::FidoApp::process_ctap2;
    let process_u2f: fn(&mut fapico2_fido::FidoApp, &[u8],
        &mut HeaplessVec<u8, { fapico2_fido::CTAP2_MAX_MSG }>) -> usize =
        fapico2_fido::FidoApp::process_u2f;
    let process_vendor_vault: fn(&mut fapico2_fido::FidoApp, &[u8],
        &mut HeaplessVec<u8, { fapico2_fido::CTAP2_MAX_MSG }>) -> usize =
        fapico2_fido::FidoApp::process_vendor_vault;
    // The bindings are the assertion: a signature drift to `Vec` fails to
    // compile. Keep them observed so the check is never optimized away.
    assert_eq!(process_ctap2 as usize as u8 & 0, 0);
    assert_eq!(process_u2f as usize as u8 & 0, 0);
    assert_eq!(process_vendor_vault as usize as u8 & 0, 0);
}
