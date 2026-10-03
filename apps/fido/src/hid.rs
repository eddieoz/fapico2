//! CTAP2 HID transport.

/// CTAP HID commands.
///
/// US-1528 follow-up: `Keepalive` and `Msg` were transposed here — `0x03`
/// and `0x10` — which is the same class of transcription error US-1528 fixed
/// in the two tables below, in a third private copy of the same data. The
/// correction, from the constants `fido2` 2.2.1 actually decodes
/// (`fido2.hid.CTAPHID`, verified by running the enum rather than by reading
/// a header):
///
/// | command | value | note |
/// |---|---|---|
/// | `PING` | `0x01` | |
/// | `MSG` | `0x03` | CTAP1/U2F APDU over HID — was `0x10` here |
/// | `CBOR` | `0x10` | CTAP2 — was `Keepalive` here |
/// | `INIT` | `0x06` | |
/// | `WINK` | `0x08` | |
/// | `CANCEL` | `0x11` | |
/// | `ERROR` | `0x3F` | |
/// | `VENDOR_FIRST` | `0x40` | |
///
/// **`KEEPALIVE` is deliberately not a member of this enum.** There is no
/// CTAPHID keepalive *command*: `0x3B` is a CTAP2 *status byte* the
/// authenticator puts in a CBOR response while a consent window is open
/// (`firmware/src/ctap_hid.rs:28`, `CTAP_HID_KEEPALIVE = 0x3B`, and
/// `CTAPHID_KEEPALIVE_PROCESSING`/`_UPNEEDED` for its two values). Having it
/// here as `0x03` alongside a real command is how the transposition survived
/// review: an enum of "commands" containing an entry that is not one reads as
/// a complete list of commands, and the value looked plausible beside `0x03`.
///
/// Dead code today — nothing outside this file names `CtapHidCommand`, and
/// the firmware's own live constants are in `firmware/src/ctap_hid.rs`. It is
/// kept because it is a public type of a published crate, and it is now pinned
/// by `tests/ctap_hid_tables.rs` so a future edit cannot silently re-transpose
/// it the way three tables in this repo already managed to do to each other.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum CtapHidCommand {
    Ping = 0x01,
    Msg = 0x03,
    Init = 0x06,
    Wink = 0x08,
    Cbor = 0x10,
    Cancel = 0x11,
    Error = 0x3F,
    VendorFirst = 0x40,
}

/// CTAP HID error codes.
///
/// US-1528: the last two were `0x07`/`0x08` and are now `0x0A`/`0x0B`. Same
/// transcription error as [`crate::ctap2::Ctap2Response`], and it is recorded
/// here because the two tables used to agree with each other and disagree with
/// the reference together — which is what made it invisible. `fido2` 2.2.1
/// `CtapError.ERR` has `LOCK_REQUIRED = 0x0A` / `INVALID_CHANNEL = 0x0B`; the
/// C SDK agrees at `pico-keys-sdk/src/usb/hid/ctap_hid.h:157-158`
/// (`CTAP1_ERR_LOCK_REQUIRED 0x0a`, `CTAP1_ERR_INVALID_CHANNEL 0x0b`).
/// `firmware/src/ctap_hid.rs:37` in the firmware worktree already emits `0x0B`
/// for the same condition, so the `0x08` here was a third, private spelling of
/// a value two other files in this project had already got right.
///
/// `Unknown` (`0x0F`) is not a CTAP HID code; it is this crate's catch-all for
/// a byte it does not recognise, deliberately outside the reference range so it
/// cannot be mistaken for one.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum CtapHidError {
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    InvalidSeq = 0x04,
    Timeout = 0x05,
    ChannelBusy = 0x06,
    LockRequired = 0x0A,
    InvalidChannel = 0x0B,
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
            0x0A => CtapHidError::LockRequired,
            0x0B => CtapHidError::InvalidChannel,
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
