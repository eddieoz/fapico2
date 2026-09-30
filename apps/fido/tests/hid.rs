//! Tests for CTAPHID framing (FX-402).

use fapico2_fido::hid::{
    reassemble_hid_packets, split_to_hid_packets, HID_REPORT_SIZE,
};

const CID: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

fn cid_of(pkt: &[u8]) -> [u8; 4] {
    [pkt[0], pkt[1], pkt[2], pkt[3]]
}

#[test]
fn test_reassemble_3_packet_message() {
    // 120-byte payload: init packet carries 57 B, so 63 B spill into
    // continuation packets.
    let payload: Vec<u8> = (0..120).map(|i| (i * 7 % 251) as u8).collect();
    let packets = split_to_hid_packets(CID, 0x10, &payload);

    assert!(packets.len() >= 3, "expected >= 3 packets, got {}", packets.len());
    for pkt in &packets {
        assert_eq!(pkt.len(), HID_REPORT_SIZE);
        assert_eq!(cid_of(pkt), CID, "every packet must carry the CID");
    }

    let (cmd, reassembled) = reassemble_hid_packets(&packets).expect("reassemble must succeed");
    assert_eq!(cmd, 0x10);
    assert_eq!(reassembled, payload, "reassembled payload must be byte-exact");
    assert!(
        !reassembled.windows(4).any(|w| w == CID),
        "no interleaved CID bytes in the payload"
    );
}

#[test]
fn test_continuation_chunk_is_59_bytes() {
    // 108-byte payload: 57 B in the init packet, 51 B remaining.
    // A 59-byte continuation chunk fits it in one continuation packet;
    // a 50-byte chunk (the old bug) would need two.
    let payload: Vec<u8> = (0..108).map(|i| i as u8).collect();
    let packets = split_to_hid_packets(CID, 0x10, &payload);
    assert_eq!(packets.len(), 2, "57 + 51 must fit one 59-byte continuation");

    let (_, reassembled) = reassemble_hid_packets(&packets).expect("reassemble must succeed");
    assert_eq!(reassembled, payload);
}

#[test]
fn test_reassemble_rejects_wrong_sequence() {
    let payload: Vec<u8> = vec![0xAB; 200];
    let mut packets = split_to_hid_packets(CID, 0x10, &payload);

    // First continuation must carry seq 0; tamper it to 1.
    packets[1][4] = 1;
    assert!(
        reassemble_hid_packets(&packets).is_none(),
        "continuation sequence must start at 0"
    );

    // Restore seq 0, but break the second continuation's seq.
    packets[1][4] = 0;
    if packets.len() > 2 {
        packets[2][4] = 5;
        assert!(
            reassemble_hid_packets(&packets).is_none(),
            "continuation sequence must increment"
        );
    }
}

#[test]
fn test_reassemble_rejects_cid_mismatch() {
    let payload: Vec<u8> = vec![0xCD; 200];
    let mut packets = split_to_hid_packets(CID, 0x10, &payload);
    packets[1][0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    assert!(
        reassemble_hid_packets(&packets).is_none(),
        "continuation from another channel must be rejected"
    );
}

#[test]
fn test_reassemble_single_packet() {
    let payload: Vec<u8> = vec![0x42; 30];
    let packets = split_to_hid_packets(CID, 0x10, &payload);
    assert_eq!(packets.len(), 1);
    let (cmd, reassembled) = reassemble_hid_packets(&packets).expect("reassemble must succeed");
    assert_eq!(cmd, 0x10);
    assert_eq!(reassembled, payload);
}

#[test]
fn test_reassemble_empty_is_none() {
    assert!(reassemble_hid_packets(&[]).is_none());
}
