//! CBOR codecs for CTAP2.
//!
//! Two layers (S-701-1, US-324 no-heap foundation):
//!
//! * [`no_heap`] — always-compiled, `no_std`, zero-alloc: a canonical-CBOR
//!   writer over caller-owned fixed buffers and a zero-copy streaming parser
//!   over borrowed input. The device command path and the heapless
//!   `Ctap2Info` serialization use this exclusively.
//! * the alloc `Value` tree (`Value`/`encode`/`decode`) — host-only
//!   (`feature = "host"`); the host CTAP2 stack (`app.rs` and friends) is
//!   std-based and keeps using it.

#[cfg(feature = "host")]
use heapless::Vec as HeaplessVec;

// ---------------------------------------------------------------------------
// No-heap layer (always compiled — device + host)
// ---------------------------------------------------------------------------

/// Zero-alloc canonical-CBOR primitives (S-701-1).
pub mod no_heap {
    use heapless::Vec as HeaplessVec;

    /// Errors of the no-heap CBOR layer.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum CborError {
        /// The fixed output buffer overflowed.
        BufferFull,
        /// Input ended mid-item.
        Eof,
        /// Structurally invalid CBOR (indefinite lengths, unknown simple
        /// values, tags — CTAP2 uses none of them).
        InvalidCbor,
        /// A text string was not valid UTF-8.
        InvalidUtf8,
    }

    impl core::fmt::Display for CborError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                CborError::BufferFull => write!(f, "CBOR output buffer full"),
                CborError::Eof => write!(f, "unexpected end of CBOR input"),
                CborError::InvalidCbor => write!(f, "invalid CBOR"),
                CborError::InvalidUtf8 => write!(f, "invalid UTF-8 in CBOR text string"),
            }
        }
    }

    // `std::error::Error` is host-side sugar only; the device build has no
    // `std`. The Display impl above is enough for diagnostics on both sides.
    #[cfg(feature = "host")]
    impl std::error::Error for CborError {}

    /// Write one CBOR head (major type + argument, minimal encoding) into a
    /// fixed buffer.
    pub fn push_head<const N: usize>(
        out: &mut HeaplessVec<u8, N>,
        major: u8,
        v: u64,
    ) -> Result<(), CborError> {
        let tag = major << 5;
        if v < 24 {
            out.push(tag | v as u8).map_err(|_| CborError::BufferFull)
        } else if v < 256 {
            out.push(tag | 24).map_err(|_| CborError::BufferFull)?;
            out.push(v as u8).map_err(|_| CborError::BufferFull)
        } else if v < 65536 {
            out.push(tag | 25).map_err(|_| CborError::BufferFull)?;
            out.extend_from_slice(&(v as u16).to_be_bytes())
                .map_err(|_| CborError::BufferFull)
        } else if v < 4294967296 {
            out.push(tag | 26).map_err(|_| CborError::BufferFull)?;
            out.extend_from_slice(&(v as u32).to_be_bytes())
                .map_err(|_| CborError::BufferFull)
        } else {
            out.push(tag | 27).map_err(|_| CborError::BufferFull)?;
            out.extend_from_slice(&v.to_be_bytes())
                .map_err(|_| CborError::BufferFull)
        }
    }

    /// Unsigned integer (major 0).
    pub fn push_uint<const N: usize>(
        out: &mut HeaplessVec<u8, N>,
        v: u64,
    ) -> Result<(), CborError> {
        push_head(out, 0, v)
    }

    /// Negative integer (major 1): CBOR value −1 − n.
    pub fn push_neg<const N: usize>(
        out: &mut HeaplessVec<u8, N>,
        v: i64,
    ) -> Result<(), CborError> {
        let u = if v == i64::MIN { 1u64 << 63 } else { (-1 - v) as u64 };
        push_head(out, 1, u)
    }

    /// Byte string (major 2).
    pub fn push_bstr<const N: usize>(
        out: &mut HeaplessVec<u8, N>,
        b: &[u8],
    ) -> Result<(), CborError> {
        push_head(out, 2, b.len() as u64)?;
        out.extend_from_slice(b).map_err(|_| CborError::BufferFull)
    }

    /// Text string (major 3).
    pub fn push_tstr<const N: usize>(
        out: &mut HeaplessVec<u8, N>,
        s: &str,
    ) -> Result<(), CborError> {
        push_head(out, 3, s.len() as u64)?;
        out.extend_from_slice(s.as_bytes())
            .map_err(|_| CborError::BufferFull)
    }

    /// Array header with `len` following items (major 4).
    pub fn push_array_header<const N: usize>(
        out: &mut HeaplessVec<u8, N>,
        len: usize,
    ) -> Result<(), CborError> {
        push_head(out, 4, len as u64)
    }

    /// Map header with `len` following key/value pairs (major 5).
    pub fn push_map_header<const N: usize>(
        out: &mut HeaplessVec<u8, N>,
        len: usize,
    ) -> Result<(), CborError> {
        push_head(out, 5, len as u64)
    }

    /// Encode an unsigned integer as a standalone CBOR item into a fixed
    /// buffer (used where the snapshot format nests encoded scalars inside
    /// byte strings). Returns the buffer and used length.
    pub fn uint_bytes(v: u64) -> ([u8; 9], usize) {
        let mut out = [0u8; 9];
        // push_head into a throwaway heapless vec: lengths ≤ 9 bytes.
        let mut tmp: HeaplessVec<u8, 9> = HeaplessVec::new();
        push_uint(&mut tmp, v).ok();
        let n = tmp.len();
        out[..n].copy_from_slice(&tmp);
        (out, n)
    }

    /// Boolean (major 7, simple values 20/21).
    pub fn push_bool<const N: usize>(
        out: &mut HeaplessVec<u8, N>,
        b: bool,
    ) -> Result<(), CborError> {
        out.push(if b { 0xF5 } else { 0xF4 })
            .map_err(|_| CborError::BufferFull)
    }

    /// Null (major 7, simple value 22).
    pub fn push_null<const N: usize>(out: &mut HeaplessVec<u8, N>) -> Result<(), CborError> {
        out.push(0xF6).map_err(|_| CborError::BufferFull)
    }

    /// One decoded CBOR item, borrowing the input — zero copy, zero alloc.
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum Item<'a> {
        /// Unsigned integer.
        U(u64),
        /// Negative integer.
        N(i64),
        /// Byte string (borrowed slice of the input).
        B(&'a [u8]),
        /// Text string (borrowed `&str` of the input).
        T(&'a str),
        /// Array — `n` following items.
        Array(u64),
        /// Map — `n` following key/value pairs.
        Map(u64),
        /// Boolean.
        Bool(bool),
        /// Null.
        Null,
    }

    /// Zero-copy streaming CBOR parser over borrowed input (S-701-1). The
    /// device command path walks request/response CBOR with this instead of
    /// materializing a `Value` tree.
    #[derive(Debug, Clone)]
    pub struct Parser<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> Parser<'a> {
        /// A parser over `buf`.
        pub fn new(buf: &'a [u8]) -> Self {
            Self { buf, pos: 0 }
        }

        /// Current read offset (for framing / remaining-bytes checks).
        pub fn pos(&self) -> usize {
            self.pos
        }

        /// Bytes left unread.
        pub fn remaining(&self) -> usize {
            self.buf.len() - self.pos
        }

        /// Decode the next head + payload at the cursor.
        #[allow(clippy::should_implement_trait)] // not an Iterator: fallible, no streaming trait
        pub fn next(&mut self) -> Result<Item<'a>, CborError> {
            let b = *self.buf.get(self.pos).ok_or(CborError::Eof)?;
            let major = b >> 5;
            let (arg, hlen) = self.read_arg()?;
            let start = self.pos + hlen;
            match major {
                0 => {
                    self.pos = start;
                    Ok(Item::U(arg))
                }
                1 => {
                    self.pos = start;
                    let n = if arg == u64::MAX { i64::MIN } else { -1 - (arg as i64) };
                    Ok(Item::N(n))
                }
                2 => {
                    let len = usize::try_from(arg).map_err(|_| CborError::InvalidCbor)?;
                    let end = start.checked_add(len).ok_or(CborError::InvalidCbor)?;
                    if end > self.buf.len() {
                        return Err(CborError::Eof);
                    }
                    self.pos = end;
                    Ok(Item::B(&self.buf[start..end]))
                }
                3 => {
                    let len = usize::try_from(arg).map_err(|_| CborError::InvalidCbor)?;
                    let end = start.checked_add(len).ok_or(CborError::InvalidCbor)?;
                    if end > self.buf.len() {
                        return Err(CborError::Eof);
                    }
                    let s = core::str::from_utf8(&self.buf[start..end])
                        .map_err(|_| CborError::InvalidUtf8)?;
                    self.pos = end;
                    Ok(Item::T(s))
                }
                4 => {
                    self.pos = start;
                    Ok(Item::Array(arg))
                }
                5 => {
                    self.pos = start;
                    Ok(Item::Map(arg))
                }
                7 => {
                    self.pos = start;
                    // Only the single-byte simple values CTAP2 uses are
                    // supported; two-byte and extended forms are rejected.
                    if hlen == 1 {
                        match arg {
                            20 => Ok(Item::Bool(false)),
                            21 => Ok(Item::Bool(true)),
                            22 => Ok(Item::Null),
                            _ => Err(CborError::InvalidCbor),
                        }
                    } else {
                        Err(CborError::InvalidCbor)
                    }
                }
                // Tags (major 6) and any other major are not in the CTAP2
                // subset.
                _ => Err(CborError::InvalidCbor),
            }
        }

        /// Skip the item at the cursor, descending into arrays/maps. Used to
        /// pass over keys or unhandled values without materializing them.
        pub fn skip(&mut self) -> Result<(), CborError> {
            match self.next()? {
                Item::Array(n) => self.skip_nested(n, 1),
                Item::Map(n) => self.skip_nested(n, 2),
                _ => Ok(()),
            }
        }

        /// Consume `count` compound children of `per` items each (iterative,
        /// fixed-depth-descent — CBOR nesting beyond 16 is not a CTAP2 shape).
        fn skip_nested(&mut self, count: u64, per: u64) -> Result<(), CborError> {
            let mut stack: HeaplessVec<(u64, u64), 16> = HeaplessVec::new();
            stack.push((count, per)).map_err(|_| CborError::InvalidCbor)?;
            while let Some(top) = stack.last_mut() {
                if top.0 == 0 {
                    stack.pop();
                    continue;
                }
                top.0 -= 1;
                let per = top.1;
                for _ in 0..per {
                    match self.next()? {
                        Item::Array(n) => stack.push((n, 1)).map_err(|_| CborError::InvalidCbor)?,
                        Item::Map(n) => stack.push((n, 2)).map_err(|_| CborError::InvalidCbor)?,
                        _ => {}
                    }
                }
            }
            Ok(())
        }
    }

    impl<'a> Parser<'a> {
        fn read_arg(&self) -> Result<(u64, usize), CborError> {
            let b = self.buf[self.pos];
            let minor = b & 0x1F;
            let rest = &self.buf[self.pos + 1..];
            let take = |n: usize| -> Result<&[u8], CborError> {
                rest.get(..n).ok_or(CborError::Eof)
            };
            Ok(match minor {
                0..=23 => (minor as u64, 1),
                24 => (take(1)?[0] as u64, 2),
                25 => (u16::from_be_bytes(take(2)?.try_into().unwrap()) as u64, 3),
                26 => (u32::from_be_bytes(take(4)?.try_into().unwrap()) as u64, 5),
                27 => (
                    u64::from_be_bytes(take(8)?.try_into().unwrap()),
                    9,
                ),
                // Indefinite lengths (minor 31) are not in the CTAP2 subset.
                _ => return Err(CborError::InvalidCbor),
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::cbor::no_heap as nh;

        #[test]
        fn head_encoding_matches_alloc_encoder() {
            // Minimal-encoding parity with the alloc `encode_unsigned`.
            let cases: &[(u8, u64, &[u8])] = &[
                (0, 5, &[0x05]),
                (0, 255, &[0x18, 0xFF]),
                (0, 7609, &[0x19, 0x1D, 0xB9]),
                (2, 16, &[0x50]),
                (5, 0, &[0xA0]),
            ];
            for (major, v, want) in cases {
                let mut out: HeaplessVec<u8, 16> = HeaplessVec::new();
                nh::push_head(&mut out, *major, *v).unwrap();
                assert_eq!(out.as_slice(), *want, "major {major} v {v}");
            }
        }

        #[test]
        fn buffer_overflow_is_an_error_not_a_panic() {
            let mut out: HeaplessVec<u8, 2> = HeaplessVec::new();
            assert_eq!(nh::push_uint(&mut out, 7609), Err(CborError::BufferFull));
        }
    }
}

pub use no_heap::CborError;

// ---------------------------------------------------------------------------
// Alloc layer (host only)
// ---------------------------------------------------------------------------

/// A CBOR value.
#[cfg(feature = "host")]
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Unsigned integer.
    U(u64),
    /// Negative integer.
    N(i64),
    /// Byte string.
    B(Vec<u8>),
    /// Text string.
    T(String),
    /// Array.
    A(Vec<Value>),
    /// Map.
    M(Vec<(Value, Value)>),
    /// Bool.
    Bool(bool),
    /// Null.
    Null,
}

/// Encode a CBOR value to bytes.
#[cfg(feature = "host")]
pub fn encode(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_to(value, &mut buf);
    buf
}

#[cfg(feature = "host")]
fn encode_to(value: &Value, buf: &mut Vec<u8>) {
    fn push_head(buf: &mut Vec<u8>, major: u8, v: u64) {
        let tag = major << 5;
        if v < 24 {
            buf.push(tag | v as u8);
        } else if v < 256 {
            buf.push(tag | 24);
            buf.push(v as u8);
        } else if v < 65536 {
            buf.push(tag | 25);
            buf.extend_from_slice(&(v as u16).to_be_bytes());
        } else if v < 4294967296 {
            buf.push(tag | 26);
            buf.extend_from_slice(&(v as u32).to_be_bytes());
        } else {
            buf.push(tag | 27);
            buf.extend_from_slice(&v.to_be_bytes());
        }
    }
    match value {
        Value::U(v) => push_head(buf, 0, *v),
        Value::N(v) => {
            let u = if *v == i64::MIN {
                1u64 << 63
            } else {
                (-1 - *v) as u64
            };
            push_head(buf, 1, u);
        }
        Value::B(v) => {
            push_head(buf, 2, v.len() as u64);
            buf.extend_from_slice(v);
        }
        Value::T(v) => {
            push_head(buf, 3, v.len() as u64);
            buf.extend_from_slice(v.as_bytes());
        }
        Value::A(v) => {
            push_head(buf, 4, v.len() as u64);
            for item in v {
                encode_to(item, buf);
            }
        }
        Value::M(v) => {
            // Canonical CBOR: sort keys by encoded representation
            let mut sorted: Vec<_> = v.iter().collect();
            sorted.sort_by(|a, b| {
                let a_enc = encode(&a.0);
                let b_enc = encode(&b.0);
                a_enc.cmp(&b_enc)
            });
            push_head(buf, 5, sorted.len() as u64);
            for (k, val) in sorted {
                encode_to(k, buf);
                encode_to(val, buf);
            }
        }
        Value::Bool(true) => buf.push(0xF5),
        Value::Bool(false) => buf.push(0xF4),
        Value::Null => buf.push(0xF6),
    }
}

/// Decode a CBOR value from bytes.
#[cfg(feature = "host")]
pub fn decode(bytes: &[u8]) -> Result<(Value, usize), Error> {
    if bytes.is_empty() {
        return Err(Error::Eof);
    }
    decode_at(bytes, 0)
}

#[cfg(feature = "host")]
fn decode_at(bytes: &[u8], pos: usize) -> Result<(Value, usize), Error> {
    if pos >= bytes.len() {
        return Err(Error::Eof);
    }

    let b = bytes[pos];
    let major = b >> 5;
    let minor = b & 0x1F;

    match major {
        0 => {
            let (v, hlen) = read_unsigned(bytes, pos)?;
            Ok((Value::U(v), pos + hlen))
        }
        1 => {
            let (v, hlen) = read_unsigned(bytes, pos)?;
            let n = if v == u64::MAX {
                i64::MIN
            } else {
                -1 - (v as i64)
            };
            Ok((Value::N(n), pos + hlen))
        }
        2 => {
            let (len, hlen) = read_unsigned(bytes, pos)?;
            let start = pos + hlen;
            let end = checked_end(bytes.len(), start, len)?;
            Ok((Value::B(bytes[start..end].to_vec()), end))
        }
        3 => {
            let (len, hlen) = read_unsigned(bytes, pos)?;
            let start = pos + hlen;
            let end = checked_end(bytes.len(), start, len)?;
            let s = core::str::from_utf8(&bytes[start..end])
                .map_err(|_| Error::InvalidUtf8)?
                .to_string();
            Ok((Value::T(s), end))
        }
        4 => {
            let (len, hlen) = read_unsigned(bytes, pos)?;
            let mut arr = Vec::new();
            let mut cur = pos + hlen;
            for _ in 0..len {
                let (item, next) = decode_at(bytes, cur)?;
                arr.push(item);
                cur = next;
            }
            Ok((Value::A(arr), cur))
        }
        5 => {
            let (len, hlen) = read_unsigned(bytes, pos)?;
            let mut map = Vec::new();
            let mut cur = pos + hlen;
            for _ in 0..len {
                let (k, next1) = decode_at(bytes, cur)?;
                let (v, next2) = decode_at(bytes, next1)?;
                map.push((k, v));
                cur = next2;
            }
            Ok((Value::M(map), cur))
        }
        7 => match minor {
            20 => Ok((Value::Bool(false), pos + 1)),
            21 => Ok((Value::Bool(true), pos + 1)),
            22 => Ok((Value::Null, pos + 1)),
            _ => Err(Error::Other),
        },
        _ => Err(Error::Other),
    }
}

/// Compute the end offset of a bstr/tstr payload, rejecting lengths that
/// do not fit in `usize`, overflow the offset arithmetic, or exceed input.
#[cfg(feature = "host")]
fn checked_end(input_len: usize, start: usize, len: u64) -> Result<usize, Error> {
    let len = usize::try_from(len).map_err(|_| Error::Eof)?;
    let end = start.checked_add(len).ok_or(Error::Eof)?;
    if end > input_len {
        return Err(Error::Eof);
    }
    Ok(end)
}

#[cfg(feature = "host")]
fn read_unsigned(bytes: &[u8], pos: usize) -> Result<(u64, usize), Error> {
    if pos >= bytes.len() {
        return Err(Error::Eof);
    }
    let b = bytes[pos];
    let minor = b & 0x1F;

    if minor < 24 {
        Ok((minor as u64, 1))
    } else if minor == 24 {
        if pos + 2 > bytes.len() {
            return Err(Error::Eof);
        }
        Ok((bytes[pos + 1] as u64, 2))
    } else if minor == 25 {
        if pos + 3 > bytes.len() {
            return Err(Error::Eof);
        }
        let v = u16::from_be_bytes([bytes[pos + 1], bytes[pos + 2]]);
        Ok((v as u64, 3))
    } else if minor == 26 {
        if pos + 5 > bytes.len() {
            return Err(Error::Eof);
        }
        let v = u32::from_be_bytes([
            bytes[pos + 1],
            bytes[pos + 2],
            bytes[pos + 3],
            bytes[pos + 4],
        ]);
        Ok((v as u64, 5))
    } else if minor == 27 {
        if pos + 9 > bytes.len() {
            return Err(Error::Eof);
        }
        let v = u64::from_be_bytes([
            bytes[pos + 1], bytes[pos + 2], bytes[pos + 3], bytes[pos + 4],
            bytes[pos + 5], bytes[pos + 6], bytes[pos + 7], bytes[pos + 8],
        ]);
        Ok((v, 9))
    } else {
        Err(Error::Other)
    }
}

/// CBOR decoding errors (alloc layer, host).
#[cfg(feature = "host")]
#[derive(Debug)]
pub enum Error {
    /// Unexpected end of input.
    Eof,
    /// Text string is not valid UTF-8.
    InvalidUtf8,
    /// Other error.
    Other,
}

#[cfg(feature = "host")]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Eof => write!(f, "unexpected end of input"),
            Error::InvalidUtf8 => write!(f, "invalid UTF-8 in text string"),
            Error::Other => write!(f, "invalid CBOR"),
        }
    }
}

#[cfg(feature = "host")]
impl std::error::Error for Error {}

/// Encode a value to a heapless vec.
#[cfg(feature = "host")]
#[allow(clippy::result_unit_err)] // heapless encode has a single failure mode: overflow
pub fn encode_heapless<const N: usize>(value: &Value) -> Result<HeaplessVec<u8, N>, ()> {
    let mut v = HeaplessVec::new();
    let bytes = encode(value);
    for b in bytes {
        v.push(b).map_err(|_| ())?;
    }
    Ok(v)
}
