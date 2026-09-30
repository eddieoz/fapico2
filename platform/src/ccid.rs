//! CCID message framing.
//!
//! The C emulator's CCID interface (`pico-keys-sdk/src/usb/emulation/emulation.c`,
//! `pico-fido2/tests/harness/ccid.py`) wraps every CCID message in a
//! `[u16 BE length]` frame. The bytes inside are the raw CCID PCB header
//! (10 bytes: bMessageType, dwLength, bSlot, bSeq, abRFU0, abRFU1, apdu...).
//!
//! This codec handles only the length-prefixed frame; the PCB layout is a
//! pure data concern for the app crates. No alloc needed — encode/decode
//! operate on slices.

/// Max frame body (APDU + PCB header) we accept. C's USB_BUFFER_SIZE is 2048;
/// CCID message data offset is 10 bytes, so the max CCID message fits.
const MAX_FRAME: usize = 2048 + 16;

/// Encode a CCID frame (length-prefixed).
///
/// Returns the number of bytes written to `buf` (2 + `data.len()`), or
/// `None` if `data` is too large for the buffer.
pub fn encode(data: &[u8], buf: &mut [u8]) -> Option<usize> {
    let total = data.len().checked_add(2)?;
    if total > buf.len() || data.len() > MAX_FRAME {
        return None;
    }
    buf[..2].copy_from_slice(&(data.len() as u16).to_be_bytes());
    buf[2..total].copy_from_slice(data);
    Some(total)
}

/// Decode a CCID frame from a buffer.
///
/// Returns the body bytes (the length-prefix is consumed), or `None` if the
/// buffer is too short or the length is inconsistent.
pub fn decode(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let total = len.checked_add(2)?;
    if total > buf.len() {
        return None;
    }
    Some(&buf[2..total])
}

/// Standard CCID 1.10 message framing (US-391 E7): the 10-byte bulk
/// headers pcscd's CCID driver speaks over the USB bulk endpoints.
///
/// The [`encode`]/[`decode`] above are the *emulation-socket* codec
/// (length-prefixed, mirroring the C `ccid.py` harness) and stay the
/// emulation transport. This module is the on-hardware framing: PC_to_RDR
/// request parsing and RDR_to_PC response encoding, byte-compatible with the
/// C firmware's `pico-keys-sdk/src/usb/ccid/ccid.c` (bStatus semantics, gnuk
/// T=1 parameters, `6F 00` overflow reply).
pub mod message {
    /// CCID message header size (both directions).
    pub const HEADER: usize = 10;

    // PC_to_RDR message types (CCID 1.10, Table 6.01-3).
    pub const PC_TO_RDR_ICC_POWER_ON: u8 = 0x62;
    pub const PC_TO_RDR_ICC_POWER_OFF: u8 = 0x63;
    pub const PC_TO_RDR_GET_SLOT_STATUS: u8 = 0x65;
    pub const PC_TO_RDR_GET_PARAMETERS: u8 = 0x6C;
    pub const PC_TO_RDR_SET_PARAMETERS: u8 = 0x61;
    pub const PC_TO_RDR_XFR_BLOCK: u8 = 0x6F;
    pub const PC_TO_RDR_ABORT: u8 = 0x71;

    // RDR_to_PC message types (CCID 1.10, Table 6.02-3).
    pub const RDR_TO_PC_DATA_BLOCK: u8 = 0x80;
    pub const RDR_TO_PC_SLOT_STATUS: u8 = 0x81;
    pub const RDR_TO_PC_PARAMETERS: u8 = 0x82;

    /// bStatus byte (CCID 6.2-3): bits 7-6 command status (0 = OK),
    /// bits 1-0 ICC status.
    pub const ICC_PRESENT_ACTIVE: u8 = 0x00;
    /// ICC present but inactive (before IccPowerOn / after IccPowerOff —
    /// the C firmware's `ccid_status` lifecycle).
    pub const ICC_PRESENT_INACTIVE: u8 = 0x01;

    /// T=1 protocol parameters reported for GET/SET_PARAMETERS — the gnuk
    /// values the C firmware answers (`ccid.c`), bytes of the
    /// abProtocolDataStructure for protocol T=1.
    pub const T1_PARAMS: [u8; 7] = [
        0x11, // bmFindexDindex
        0x10, // bmTCCKST1
        0xFE, // bGuardTimeT1
        0x55, // bmWaitingIntegersT1
        0x03, // bClockStop
        0xFE, // bIFSC
        0x00, // bNadValue
    ];

    /// One parsed PC_to_RDR bulk-OUT message.
    #[derive(Debug, PartialEq, Eq)]
    pub enum Request<'a> {
        IccPowerOn { slot: u8, seq: u8 },
        IccPowerOff { slot: u8, seq: u8 },
        GetSlotStatus { slot: u8, seq: u8 },
        GetParameters { slot: u8, seq: u8 },
        SetParameters { slot: u8, seq: u8, params: &'a [u8] },
        XfrBlock { slot: u8, seq: u8, data: &'a [u8] },
        Abort { slot: u8, seq: u8 },
    }

    /// Parse a complete PC_to_RDR message (`buf` must be exactly one
    /// message: 10-byte header + `dwLength` payload). Returns `None` for a
    /// truncated buffer or an unsupported message type.
    pub fn parse(buf: &[u8]) -> Option<Request<'_>> {
        if buf.len() < HEADER {
            return None;
        }
        let msg_type = buf[0];
        let dw_length = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        let slot = buf[5];
        let seq = buf[6];
        let data = buf.get(HEADER..HEADER + dw_length)?;
        match msg_type {
            PC_TO_RDR_ICC_POWER_ON => Some(Request::IccPowerOn { slot, seq }),
            PC_TO_RDR_ICC_POWER_OFF => Some(Request::IccPowerOff { slot, seq }),
            PC_TO_RDR_GET_SLOT_STATUS => Some(Request::GetSlotStatus { slot, seq }),
            PC_TO_RDR_GET_PARAMETERS => Some(Request::GetParameters { slot, seq }),
            PC_TO_RDR_SET_PARAMETERS => Some(Request::SetParameters { slot, seq, params: data }),
            PC_TO_RDR_XFR_BLOCK => Some(Request::XfrBlock { slot, seq, data }),
            PC_TO_RDR_ABORT => Some(Request::Abort { slot, seq }),
            _ => None,
        }
    }

    /// Write the 10-byte RDR_to_PC header: type, dwLength (LE), slot, seq,
    /// bStatus, bError=0, bRFU=0.
    fn write_header(
        msg_type: u8,
        dw_length: usize,
        slot: u8,
        seq: u8,
        status: u8,
        buf: &mut [u8],
    ) -> bool {
        if buf.len() < HEADER {
            return false;
        }
        buf[0] = msg_type;
        buf[1..5].copy_from_slice(&(dw_length as u32).to_le_bytes());
        buf[5] = slot;
        buf[6] = seq;
        buf[7] = status;
        buf[8] = 0; // bError: no error
        buf[9] = 0; // bRFU / bChainParameter / bProtocolNum placeholder
        true
    }

    /// Encode an RDR_to_PC_DataBlock (0x80) — IccPowerOn / XfrBlock reply —
    /// into `buf`. Returns the encoded length, or `None` if `data` does not
    /// fit (`buf` must hold 10 + `data.len()`).
    pub fn data_block(slot: u8, seq: u8, status: u8, data: &[u8], buf: &mut [u8]) -> Option<usize> {
        let total = HEADER.checked_add(data.len())?;
        if total > buf.len() {
            return None;
        }
        if !write_header(RDR_TO_PC_DATA_BLOCK, data.len(), slot, seq, status, buf) {
            return None;
        }
        buf[HEADER..total].copy_from_slice(data);
        Some(total)
    }

    /// Encode an RDR_to_PC_SlotStatus (0x81) — GetSlotStatus / PowerOff /
    /// Abort reply (always 10 bytes).
    pub fn slot_status(slot: u8, seq: u8, status: u8, buf: &mut [u8]) -> Option<usize> {
        if write_header(RDR_TO_PC_SLOT_STATUS, 0, slot, seq, status, buf) {
            Some(HEADER)
        } else {
            None
        }
    }

    /// Encode an RDR_to_PC_Parameters (0x82) with the gnuk T=1 parameters
    /// (bProtocolNum = 1, mirroring the C firmware).
    pub fn parameters(slot: u8, seq: u8, status: u8, buf: &mut [u8]) -> Option<usize> {
        let total = HEADER + T1_PARAMS.len();
        if total > buf.len() {
            return None;
        }
        if !write_header(RDR_TO_PC_PARAMETERS, T1_PARAMS.len(), slot, seq, status, buf) {
            return None;
        }
        buf[9] = 1; // bProtocolNum: T=1
        buf[HEADER..total].copy_from_slice(&T1_PARAMS);
        Some(total)
    }

    #[cfg(all(test, not(target_arch = "arm")))]
    mod tests {
        use super::*;

        /// C-parity test ATR (`atr_openpgp`, `openpgp.c:294` — T=1).
        const ATR: &[u8] = &[
            0x3B, 0xDA, 0x18, 0xFF, 0x81, 0xB1, 0xFE, 0x75, 0x1F, 0x03, 0x00, 0x31,
            0xF5, 0x73, 0xC0, 0x01, 0x60, 0x00, 0x90, 0x00, 0x1C,
        ];

        /// A live IccPowerOn from pcscd's CCID driver (observed on the E6c
        /// image as the probe that was mis-dispatched as an APDU, answering
        /// `6E00`) must parse as IccPowerOn, not fall through to dispatch.
        /// Layout: bMessageType(0), dwLength(1-4), bSlot(5), bSeq(6).
        #[test]
        fn parses_icc_power_on() {
            let msg = [0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00];
            assert_eq!(
                parse(&msg),
                Some(Request::IccPowerOn { slot: 0, seq: 0x2A })
            );
        }

        /// XfrBlock carries the APDU after the 10-byte header.
        #[test]
        fn parses_xfr_block_with_apdu() {
            let msg = [
                0x6F, 0x03, 0x00, 0x00, 0x00, 0x00, 0x7B, 0x00, 0x00, 0x00, 0x00, 0xA4, 0x04,
            ];
            assert_eq!(
                parse(&msg),
                Some(Request::XfrBlock {
                    slot: 0,
                    seq: 0x7B,
                    data: &[0x00, 0xA4, 0x04],
                })
            );
        }

        /// The remaining PC_to_RDR types parse with slot/seq.
        #[test]
        fn parses_power_off_slot_status_params_abort() {
            let mk = |t: u8, seq: u8| [t, 0, 0, 0, 0, 0, seq, 0, 0, 0];
            assert_eq!(parse(&mk(0x63, 1)), Some(Request::IccPowerOff { slot: 0, seq: 1 }));
            assert_eq!(parse(&mk(0x65, 2)), Some(Request::GetSlotStatus { slot: 0, seq: 2 }));
            assert_eq!(parse(&mk(0x6C, 3)), Some(Request::GetParameters { slot: 0, seq: 3 }));
            assert_eq!(parse(&mk(0x71, 4)), Some(Request::Abort { slot: 0, seq: 4 }));
        }

        /// SetParameters carries the T=1 protocol data structure.
        #[test]
        fn parses_set_parameters() {
            let mut msg = [0u8; 10 + 7];
            msg[0] = 0x61;
            msg[1] = 7; // dwLength LE
            msg[6] = 9; // bSeq
            msg[10..].copy_from_slice(&T1_PARAMS);
            assert_eq!(
                parse(&msg),
                Some(Request::SetParameters { slot: 0, seq: 9, params: &T1_PARAMS })
            );
        }

        /// A buffer shorter than the 10-byte header is rejected.
        #[test]
        fn parse_rejects_short_header() {
            assert_eq!(parse(&[0x62, 0x00]), None);
        }

        /// dwLength larger than the available payload is rejected.
        #[test]
        fn parse_rejects_truncated_payload() {
            // dwLength = 4 but only 2 payload bytes follow.
            let msg = [0x6F, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 1, 0, 0, 0xAA, 0xBB];
            assert_eq!(parse(&msg), None);
        }

        /// Unknown message types are rejected (the caller logs and resyncs).
        #[test]
        fn parse_rejects_unknown_type() {
            let msg = [0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 1, 0, 0];
            assert_eq!(parse(&msg), None);
        }

        /// The IccPowerOn reply: DataBlock carrying the ATR, bSeq echoed.
        #[test]
        fn data_block_encodes_atr_reply() {
            let mut buf = [0u8; 64];
            let n = data_block(0, 0x2A, ICC_PRESENT_ACTIVE, ATR, &mut buf).unwrap();
            let mut expected = [0u8; 10 + ATR.len()];
            expected[0] = RDR_TO_PC_DATA_BLOCK;
            expected[1] = ATR.len() as u8;
            // dwLength = 10 LE (bytes 2..5 stay zero)
            expected[6] = 0x2A; // bSeq
            expected[7] = ICC_PRESENT_ACTIVE;
            // bError (8), bRFU/bChainParameter (9) stay zero
            expected[10..].copy_from_slice(ATR);
            assert_eq!(&buf[..n], &expected);
        }

        /// The XfrBlock reply wraps the APDU response in a DataBlock.
        #[test]
        fn data_block_encodes_apdu_response() {
            let mut buf = [0u8; 64];
            let resp = [0x61, 0x0F];
            let n = data_block(0, 0x7B, ICC_PRESENT_ACTIVE, &resp, &mut buf).unwrap();
            assert_eq!(n, 12);
            assert_eq!(buf[0], RDR_TO_PC_DATA_BLOCK);
            assert_eq!(u32::from_le_bytes(buf[1..5].try_into().unwrap()), 2);
            assert_eq!(buf[6], 0x7B); // bSeq echoed
            assert_eq!(&buf[10..12], &resp);
        }

        /// dwLength over the C firmware's 2048-byte USB buffer is answered
        /// with the `6F 00` error DataBlock (`ccid.c` invalid-length path).
        #[test]
        fn oversized_dwlength_error_reply_vector() {
            let mut buf = [0u8; 64];
            let n = data_block(0, 0x44, ICC_PRESENT_ACTIVE, &[0x6F, 0x00], &mut buf).unwrap();
            assert_eq!(n, 12);
            assert_eq!(buf[0], RDR_TO_PC_DATA_BLOCK);
            assert_eq!(u32::from_le_bytes(buf[1..5].try_into().unwrap()), 2);
            assert_eq!(buf[6], 0x44);
            assert_eq!(&buf[10..12], &[0x6F, 0x00]);
        }

        /// Data that does not fit the output buffer is refused (the caller
        /// logs; the response is dropped — the C-parity 2048-byte cap).
        #[test]
        fn data_block_rejects_overflow() {
            let mut buf = [0u8; 12];
            let data = [0u8; 100];
            assert_eq!(data_block(0, 1, ICC_PRESENT_ACTIVE, &data, &mut buf), None);
        }

        /// SlotStatus is always a bare 10-byte header with bStatus set.
        #[test]
        fn slot_status_encodes() {
            let mut buf = [0u8; 16];
            let n = slot_status(0, 0x55, ICC_PRESENT_ACTIVE, &mut buf).unwrap();
            assert_eq!(n, 10);
            assert_eq!(buf[0], RDR_TO_PC_SLOT_STATUS);
            assert_eq!(u32::from_le_bytes(buf[1..5].try_into().unwrap()), 0);
            assert_eq!(buf[6], 0x55);
            assert_eq!(buf[7], ICC_PRESENT_ACTIVE);
            assert_eq!(buf[8], 0); // bError
            assert_eq!(buf[9], 0); // bRFU
        }

        /// Parameters reply: bProtocolNum = 1 (T=1) + the gnuk parameter set.
        #[test]
        fn parameters_encodes_gnuk_t1() {
            let mut buf = [0u8; 32];
            let n = parameters(0, 0x66, ICC_PRESENT_ACTIVE, &mut buf).unwrap();
            assert_eq!(n, 10 + T1_PARAMS.len());
            assert_eq!(buf[0], RDR_TO_PC_PARAMETERS);
            assert_eq!(u32::from_le_bytes(buf[1..5].try_into().unwrap()), 7);
            assert_eq!(buf[6], 0x66);
            assert_eq!(buf[7], ICC_PRESENT_ACTIVE);
            assert_eq!(buf[9], 1); // bProtocolNum (T=1)
            assert_eq!(&buf[10..n], &T1_PARAMS);
        }
    }
}

#[cfg(all(test, not(target_arch = "arm")))]
mod tests {
    extern crate std;

    use super::*;

    /// Round-trip: encode then decode must reproduce the input.
    #[test]
    fn round_trip_empty() {
        let mut buf = [0u8; 64];
        let n = encode(&[], &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(decode(&buf[..n]).unwrap(), &[0u8; 0]);
    }

    /// Round-trip with a sample CCID PCB + APDU.
    #[test]
    fn round_trip_with_data() {
        // C sample: CCID header (10 bytes) + APDU 00 A4 04 00 ... (SELECT)
        let apdu: &[u8] = &[
            0x6F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA4, 0x04, 0x00,
        ];
        let mut buf = [0u8; 64];
        let n = encode(apdu, &mut buf).unwrap();
        let decoded = decode(&buf[..n]).unwrap();
        assert_eq!(decoded, apdu);
    }

    /// ATR reset command: C sends a single byte 0x04 which the frame layer
    /// carries as a 1-byte body. Verify the prefix matches the C harness's
    /// expectation (`_RESET = bytes([0x04])` → frame is `[0x00, 0x04, 0x04]`,
    /// i.e. length-prefix `0x0004` ... wait, C sends `_RESET` as the raw
    /// command 0x04 inside a length-prefixed frame).
    #[test]
    fn atr_reset_frame_vector() {
        // From ccid.py: `_RESET = bytes([0x04])`, `_send` frames it.
        // So the wire bytes are: [0x00, 0x01, 0x04] (length=1, body=0x04).
        let reset = [0x04u8];
        let mut buf = [0u8; 16];
        let n = encode(&reset, &mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x00, 0x01, 0x04]);
        assert_eq!(decode(&buf[..n]).unwrap(), &reset[..]);
    }

    /// Decode rejects a truncated buffer.
    #[test]
    fn decode_rejects_truncated() {
        // length says 10 but only 3 bytes follow the prefix
        let buf = [0x00, 0x0A, 0x01, 0x02, 0x03];
        assert!(decode(&buf).is_none());
    }

    /// Decode rejects a buffer with too-short prefix.
    #[test]
    fn decode_rejects_short_prefix() {
        let buf = [0x00];
        assert!(decode(&buf).is_none());
    }

    /// Encode rejects data that overflows the buffer.
    #[test]
    fn encode_rejects_overflow() {
        let data = [0u8; 128];
        let mut buf = [0u8; 10]; // too small
        assert!(encode(&data, &mut buf).is_none());
    }
}
