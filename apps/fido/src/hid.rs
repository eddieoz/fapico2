//! CTAP2 HID transport.

/// CTAP HID commands.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum CtapHidCommand {
    Ping = 0x01,
    Keepalive = 0x03,
    Msg = 0x10,
    Init = 0x06,
    Wink = 0x08,
    Cancel = 0x11,
    Error = 0x3F,
    VendorFirst = 0x40,
}

/// CTAP HID error codes.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum CtapHidError {
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    InvalidSeq = 0x04,
    Timeout = 0x05,
    ChannelBusy = 0x06,
    LockRequired = 0x07,
    InvalidChannel = 0x08,
    Unknown = 0x0F,
}

impl CtapHidError {
    pub fn code(self) -> u8 {
        self as u8
    }
}

impl From<u8> for CtapHidError {
    fn from(code: u8) -> Self {
        match code {
            0x01 => CtapHidError::InvalidCommand,
            0x02 => CtapHidError::InvalidParameter,
            0x03 => CtapHidError::InvalidLength,
            0x04 => CtapHidError::InvalidSeq,
            0x05 => CtapHidError::Timeout,
            0x06 => CtapHidError::ChannelBusy,
            0x07 => CtapHidError::LockRequired,
            0x08 => CtapHidError::InvalidChannel,
            0x0F => CtapHidError::Unknown,
            _ => CtapHidError::Unknown,
        }
    }
}

/// CTAP HID report size.
pub const HID_REPORT_SIZE: usize = 64;

/// Maximum HID payload in the init (first) packet: CID(4) ‖ cmd(1) ‖ len(2).
pub const HID_MAX_PAYLOAD: usize = HID_REPORT_SIZE - 7;

/// Maximum HID payload in a continuation packet: CID(4) ‖ seq(1).
pub const HID_CONT_PAYLOAD: usize = HID_REPORT_SIZE - 5;

/// Split a payload into HID packets.
pub fn split_to_hid_packets(channel_id: [u8; 4], cmd: u8, payload: &[u8]) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    let first_chunk_len = core::cmp::min(HID_MAX_PAYLOAD, payload.len());
    let mut first = Vec::with_capacity(HID_REPORT_SIZE);
    first.extend_from_slice(&channel_id);
    first.push(cmd | 0x80);
    first.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    first.extend_from_slice(&payload[..first_chunk_len]);
    while first.len() < HID_REPORT_SIZE {
        first.push(0);
    }
    packets.push(first);

    let mut offset = first_chunk_len;
    let mut seq = 0;
    while offset < payload.len() {
        let chunk_len = core::cmp::min(HID_CONT_PAYLOAD, payload.len() - offset);
        let mut cont = Vec::with_capacity(HID_REPORT_SIZE);
        cont.extend_from_slice(&channel_id);
        cont.push(seq);
        cont.extend_from_slice(&payload[offset..offset + chunk_len]);
        while cont.len() < HID_REPORT_SIZE {
            cont.push(0);
        }
        packets.push(cont);
        offset += chunk_len;
        seq += 1;
    }

    packets
}

/// Reassemble HID packets into a payload.
///
/// Packets are full 64-byte reports: init packets are
/// `CID(4) ‖ cmd|0x80(1) ‖ bcnt(2) ‖ data(≤57)`, continuation packets are
/// `CID(4) ‖ seq(1) ‖ data(≤59)`. Returns `None` on any framing error
/// (CID mismatch, bad sequence, truncated init).
pub fn reassemble_hid_packets(packets: &[Vec<u8>]) -> Option<(u8, Vec<u8>)> {
    let first = packets.first()?;
    if first.len() < HID_REPORT_SIZE {
        return None;
    }

    let cid: [u8; 4] = [first[0], first[1], first[2], first[3]];
    let cmd = first[4] & 0x7F;
    if first[4] & 0x80 == 0 {
        return None;
    }
    let total_len = u16::from_be_bytes([first[5], first[6]]) as usize;
    let mut payload = Vec::with_capacity(total_len);

    payload.extend_from_slice(&first[7..]);

    for (expected_seq, pkt) in packets[1..].iter().enumerate() {
        if pkt.len() < HID_REPORT_SIZE {
            return None;
        }
        let pkt_cid: [u8; 4] = [pkt[0], pkt[1], pkt[2], pkt[3]];
        if pkt_cid != cid {
            return None;
        }
        if pkt[4] != expected_seq as u8 {
            return None;
        }
        payload.extend_from_slice(&pkt[5..]);
    }

    if payload.len() < total_len {
        return None;
    }

    payload.truncate(total_len);

    Some((cmd, payload))
}
