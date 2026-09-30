//! ISO 7816-4 command chaining on the **receive** side (US-181,
//! `PICOForge-COMPAT` Phase J).
//!
//! # What the compatibility surface actually is
//!
//! PicoForge's `CcidSession::send_chained`
//! (`picoforge/src/hal/transport/ccid.rs:115-144`) fragments a body longer
//! than `CHAIN_CHUNK = 255` bytes (`picoforge/src/hal/apdu/mod.rs:26` is
//! `CLA_CHAIN = 0x10`) into a run of `cla | 0x10` fragments of exactly 255
//! bytes, **requires `9000` from every fragment** (`:129-131` — any other SW
//! is a hard `Err`), and then sends the tail as an ordinary APDU with the
//! original class byte. It is used by PIV `PUT DATA` and PIV `IMPORT`
//! (`picoforge/src/hal/applets/piv.rs:592` and `:673`) and by the OpenPGP
//! import stage. **That is the entire client behaviour this module exists to
//! satisfy** — a `9000` per fragment, then one final command whose data field
//! is the concatenation of all of them.
//!
//! # The trap a reader would otherwise believe
//!
//! `iso7816` 0.2.0 resolves chains on the **send** side only:
//! `Class::chain()` reads `cla & (1 << 4)`
//! (`iso7816-0.2.0/src/command/class.rs:88-95`), and the split lives in
//! `CommandBuilder::should_split` / `ChainedCommandIterator`
//! (`iso7816-0.2.0/src/command.rs:432` / `:415`). The **receive** side does
//! not resolve them: `TryFrom<&[u8]> for CommandView`
//! (`iso7816-0.2.0/src/command.rs:528-556`) accepts the chained class byte as
//! an ordinary class, and `parse_lengths` (`iso7816-0.2.0/src/command.rs:621`)
//! parses `cla|0x10 … Lc = 0xFF … 255 bytes` as a plain case-3S body with
//! `lc = 255`. **No error, no signal** — the only thing that says "this was a
//! fragment" is `command.class().chain()`.
//!
//! That is why an applet wired straight to `opcard::Card::handle` accepts a
//! fragment and then fails on the truncated body: opcard delegates the
//! decision to the caller by name (`vendor/opcard/src/card.rs:236` — "The
//! APDU command must be complete, i. e. chained commands must be resolved by
//! the caller"), and its own reference transport already does the check
//! (`vendor/opcard/src/vpicc.rs:103`, `RequestBuffer::handle`). On the wire
//! the failure is **fail-closed, not silent corruption**: opcard's TLV reader
//! returns `None` on a short remainder (`vendor/opcard/src/tlv.rs:32-34`),
//! which the `?` at `vendor/opcard/src/command/data.rs:878` turns into an
//! error status. A truncated fragment is never stored. This module keeps
//! that property while making the chain *work*.
//!
//! # Why the logic lives in `platform/`, not in each applet
//!
//! Two applets need byte-identical semantics here (OpenPGP `PUT DATA`, PIV
//! `PUT DATA`). A per-applet copy is the same anti-pattern the rest of this
//! workspace argues against; more importantly a second copy is a second place
//! for the fail-closed rules below to drift. The applets own the *storage*
//! (a [`ChainAssembler`] field), this module owns the *policy*.
//!
//! # The bound, and why there is one
//!
//! [`MAX_CHAINED_BODY`] is the largest body this firmware will reassemble.
//! It is derived, not guessed:
//!
//! * OpenPGP's largest writable DO is `Bytes<MAX_GENERIC_LENGTH>` =
//!   **4096** bytes (`vendor/opcard/src/state.rs:36` and `:2085`; the
//!   `put_arbitrary_do` check at `vendor/opcard/src/command/data.rs:1279`).
//!   Its wire body is a DO TLV, so the worst-case header is 2 tag bytes
//!   (the `b1 & 0x1f == 0x1f` two-byte form,
//!   `vendor/opcard/src/tlv.rs:41-46`) plus a 3-byte length (`82 hi lo`,
//!   which 4096 requires). `4096 + 2 + 3 = 4101`.
//! * PIV's `MAX_OBJECT_SIZE` is **2048** (`apps/piv/src/lib.rs:55`), plus a
//!   `53 <len>` (3 bytes) and a `5C 03 5F C1 <fid>` (5 bytes) — 2056, well
//!   inside.
//!
//! So `4101` is exactly "the largest body a conforming client can legally
//! need". A card that reassembles without a bound is a memory-exhaustion
//! surface: an attacker who can put a card on a reader controls how many
//! `cla|0x10` fragments it sends, and an unbounded accumulator turns that
//! into unbounded growth pressure against a `no_std` static budget with a
//! fixed stack zone. `heapless` only means the bound *must* be a compile-time
//! constant and the overflow must be a refusal, never an allocation failure
//! discovered late.
//!
//! # Fail-closed rules (the whole point)
//!
//! 1. A fragment whose header (`cla` with b4 cleared, INS, P1, P2) differs
//!    from the chain it claims to continue is **not** appended. The
//!    accumulated bytes are discarded and an error is answered.
//! 2. A chain whose accumulated body would exceed [`MAX_CHAINED_BODY`] is
//!    discarded and refused. The accumulator never presents a body it
//!    silently truncated.
//! 3. A pending chain is **discarded**, never flushed, on
//!    [`ChainAssembler::reset`] — which every applet calls on SELECT.
//!    Without that, the next unrelated command would be dispatched with a
//!    body the caller never sent.
//! 4. An APDU whose declared lengths do not add up to its own length is
//!    refused. (This is *free*: `iso7816`'s `parse_lengths` is exact-length
//!    by construction, so `CommandView::try_from` already rejects it. The
//!    check here is the second half — that the *re-encoded* command is well
//!    formed, and it is what makes a fragment whose own Lc overruns its
//!    buffer a refusal rather than an append.)

use heapless::Vec;
use iso7816::command::CommandView;

use crate::dispatch::Sw;

/// Largest command body that will be reassembled from a chain. See the module
/// docs for the derivation: OpenPGP's 4096-byte generic DO (`opcard
/// state.rs:36`) plus the worst-case 5-byte ISO 7816-4 TLV header.
pub const MAX_CHAINED_BODY: usize = 4101;

/// [`MAX_CHAINED_BODY`] plus the widest command envelope that can carry it:
/// `BODY_OFFSET` (4 header bytes + a 3-byte extended Lc) + a 2-byte extended
/// `Le` = 9. Rounded up to 12 so the number is not a tight sum someone has to
/// re-derive to change an offset.
pub const MAX_CHAINED_APDU: usize = MAX_CHAINED_BODY + 12;

/// The chain bit, CLA b4. `iso7816` reads the same bit
/// (`class.rs:88-95`); it is repeated here so the buffer code below reads
/// without importing the class module, and the `platform` tests assert the
/// two agree.
pub const CLA_CHAIN: u8 = 0x10;

/// Why a chain was refused. Every variant means **the accumulated bytes are
/// gone** — there is no recovery path, by construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainError {
    /// A fragment claimed to continue a chain but its `cla` (b4 cleared),
    /// INS, P1 or P2 disagreed with the chain's first fragment.
    HeaderMismatch,
    /// Appending this fragment would push the body past
    /// [`MAX_CHAINED_BODY`].
    TooLong,
    /// The arriving APDU is shorter than the 4-byte header, or its declared
    /// Lc/Le do not account for its own length.
    Malformed,
}

impl ChainError {
    /// The status word to answer: **`6700`, for all three.**
    ///
    /// The alternatives are traps, and the first one is a live hazard:
    ///
    /// * **`6Cxx` is actively dangerous here and must never be used.**
    ///   `6Cxx` means "wrong Le — resend with this Le". PicoForge's
    ///   `transceive_paged` (`ccid.rs:90-96`) handles `6Cxx` by re-sending
    ///   *the same command* with a corrected Le **before consuming any
    ///   data**. A chained fragment answered `6Cxx` would therefore be
    ///   re-sent, and the card — which cannot tell a resend from a new
    ///   fragment — would append the same 255 bytes a second time. The
    ///   chain would silently duplicate data. `6Cxx` on a case-3 fragment is
    ///   not a wrong answer, it is a corruption vector.
    /// * `6A80` ("incorrect parameters in the data field") is defensible for
    ///   [`ChainError::HeaderMismatch`] in isolation, but it is the status
    ///   both applets already use for *content* problems, and a caller that
    ///   sees `6A80` retries with different data. Here the data was never
    ///   wrong — the *framing* was, and no retry helps.
    /// * `6A86` (incorrect P1/P2) would be right for a P1/P2 mismatch alone,
    ///   but INS and CLA mismatches have no code of their own, and splitting
    ///   one failure class across two status words makes the US-182
    ///   conformance sweep harder for no gain.
    pub const fn status(self) -> Sw {
        crate::dispatch::SW_WRONG_LENGTH
    }
}

/// What [`ChainAssembler::push`] decided about one incoming APDU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// **No chain was in progress and this APDU is not part of one.**
    /// Dispatch the caller's own `apdu` slice, untouched.
    ///
    /// This variant exists so that "US-181 changes no existing behaviour" is
    /// *structural* rather than a claim. The accumulator does not parse, does
    /// not copy, and does not look at the lengths on this path — so a
    /// malformed ordinary APDU still reaches the applet and still gets the
    /// status the applet has always given it. (`Malformed` maps to `6700`,
    /// which is what PIV already answers for a `PUT DATA` with no body, so
    /// routing ordinary APDUs through the parser would have silently
    /// rewritten that; not routing them through it at all is the only way to
    /// be sure nothing else moved either.)
    Pass,
    /// A non-final fragment: its data field is now in the accumulator.
    /// **Dispatch nothing and answer `9000`** — PicoForge hard-fails on any
    /// other SW (`ccid.rs:129-131`).
    Buffered,
    /// A chain completed. The reassembled command is in
    /// [`ChainAssembler::apdu`]; dispatch that, not the caller's slice. The
    /// accumulator is empty again.
    Complete,
    /// The chain is broken; the accumulated bytes are gone. Answer
    /// [`ChainError::status`].
    Broken(ChainError),
}

/// ISO 7816-4 case, from the total length of a well-formed command APDU whose
/// data field is known. `iso7816`'s `parse_lengths` is exact-length by
/// construction (`iso7816-0.2.0/src/command.rs:621-712` — it returns
/// `InvalidSliceLength` unless the encoded lengths add up to the slice), so
/// once `CommandView` has accepted the APDU the data length is trustworthy;
/// all that is left is *which* of the shapes this is, and therefore how wide
/// Lc and Le are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// Case 1: 4-byte header, no Lc, no Le, no data.
    Case1,
    /// Case 2S: 4-byte header and a bare 1-byte `Le` — no Lc, no data.
    Case2Short,
    /// Case 3S: 4-byte header, 1-byte Lc, body.
    Case3Short,
    /// Case 4S: …body, 1-byte Le.
    Case4Short,
    /// Case 3E: 4-byte header, `00 hi lo`, body.
    Case3Extended,
    /// Case 4E: …body, 2-byte Le.
    Case4Extended,
}

impl Shape {
    const fn le_width(self) -> usize {
        match self {
            Self::Case1 | Self::Case3Short | Self::Case3Extended => 0,
            Self::Case2Short | Self::Case4Short => 1,
            Self::Case4Extended => 2,
        }
    }
}

/// Which of the six shapes an APDU of `apdu_len` bytes is, given a data field
/// of `body_len`. The totals are `n+4`, `n+5`, `n+6`, `n+7` and `n+9`
/// (header 4 + Lc 0/1/3 + Le 0/1/2), all distinct, so the match is unique.
///
/// Two cases need a second look rather than a length alone:
///
/// * `apdu_len - 4 - body_len == 1` with `body_len == 0` is **case 2S** (a
///   bare `Le`), not a case-3S with `Lc = 0`. They are the same length, and
///   `parse_lengths` tells them apart by the *value* — case 3S requires
///   `b1 != 0` (`iso7816-0.2.0/src/command.rs:650`) — so an `Lc` byte of zero
///   can only be a case-2 `Le`. Getting this wrong silently drops the `Le`
///   off a chain terminated by a bodyless command; no real client chains one,
///   which is exactly why it needs an arm of its own and a test rather than a
///   "harmless" omission.
/// * A 4-byte APDU (`apdu_len - 4 - body_len == 0`, `body_len == 0`) is case
///   1, and is a legal `cla|0x10` fragment that contributes no bytes.
const fn shape_of(apdu_len: usize, body_len: usize) -> Option<Shape> {
    match apdu_len.checked_sub(4 + body_len) {
        Some(0) => Some(Shape::Case1),
        Some(1) if body_len == 0 => Some(Shape::Case2Short),
        Some(1) => Some(Shape::Case3Short),
        Some(2) => Some(Shape::Case4Short),
        Some(3) => Some(Shape::Case3Extended),
        Some(5) => Some(Shape::Case4Extended),
        _ => None,
    }
}

/// Where the body sits inside [`ChainAssembler::buf`] while a chain is
/// pending: 4 header bytes + the full 3-byte extended Lc field. The maximum
/// extent, so no fragment ever has to move anything.
const BODY_OFFSET: usize = 4 + 3;

/// The header + reassembled body of one command APDU, in wire layout.
///
/// One buffer serves both roles. While a chain is pending the body sits at
/// [`BODY_OFFSET`]; on completion it moves down by two bytes if it fits the
/// short Lc form — a single `copy_within` on the *completing* command only,
/// never per fragment. Holding the finished APDU rather than the bare body
/// is what lets OpenPGP hand the result straight to `CommandView::try_from`
/// and PIV straight to its own `parse_data`, so neither applet needs a second
/// 4 KiB scratch buffer or its own copy of the ISO framing.
pub struct ChainAssembler<const N: usize = MAX_CHAINED_APDU> {
    buf: Vec<u8, N>,
    /// CLA (b4 cleared) / INS / P1 / P2 of the chain's first fragment.
    header: [u8; 4],
    /// A partial chain is accumulated.
    pending: bool,
    /// The terminating command's raw Le bytes, empty for case 1/3.
    le: Vec<u8, 2>,
}

impl<const N: usize> Default for ChainAssembler<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ChainAssembler<N> {
    pub const fn new() -> Self {
        Self {
            buf: Vec::new(),
            header: [0; 4],
            pending: false,
            le: Vec::new(),
        }
    }

    /// The complete command APDU, valid only after [`Step::Complete`].
    pub fn apdu(&self) -> &[u8] {
        &self.buf
    }

    /// Move the rendered command out of the assembler, leaving an empty one
    /// behind, for applets whose dispatch needs `&mut self` **while** the
    /// command is still in scope.
    ///
    /// PIV is the case that forces this: `cmd_get_data` / `cmd_put_data` take
    /// `&mut self` and the reassembled APDU, so a borrow of `self.chain`
    /// cannot outlive the call. OpenPGP does not need it — its dispatch
    /// touches only other fields, and disjoint field borrows are enough.
    ///
    /// `heapless::Vec` owns its storage inline, so this is a **move of a
    /// 4 KiB value**, not a copy — but it only ever happens on a resolved
    /// chain, i.e. once per long `PUT DATA`, next to an RSA or AES
    /// operation on the same object. The common path never reaches it.
    pub fn take_apdu(&mut self) -> Vec<u8, N> {
        core::mem::replace(&mut self.buf, Vec::new())
    }

    /// True while a chain is partially accumulated. Diagnostics and tests
    /// only; no decision anywhere depends on it.
    pub fn is_pending(&self) -> bool {
        self.pending
    }

    /// Bytes accumulated so far.
    pub fn pending_len(&self) -> usize {
        self.buf.len().saturating_sub(BODY_OFFSET)
    }

    /// Discard any partial chain. **Every applet must call this on SELECT.**
    ///
    /// A SELECT switches application, so a chain accumulated for the previous
    /// one has no business surviving into it. This is the rule that closes the
    /// dangerous case: without it, a client that abandons a chain mid-stream
    /// leaves bytes in the accumulator, and the *next* command — a `GET DATA`,
    /// say — would be dispatched carrying a body the caller never sent.
    ///
    /// OpenPGP calls it from `select` / `select_apdu` / `deselect` /
    /// `mark_dirty`; PIV from `reset_session`. All of those already exist and
    /// already reset per-selection state, so no new call site is invented.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.header = [0; 4];
        self.pending = false;
        self.le.clear();
    }

    /// Feed one incoming APDU and decide what to do with it.
    ///
    /// `apdu` is the raw wire APDU. On [`Step::Complete`] the reassembled
    /// command is in [`Self::apdu`]; on [`Step::Pass`] the caller's own slice
    /// is the command and nothing was copied; on [`Step::Buffered`] nothing is
    /// dispatched; on [`Step::Broken`] the accumulated bytes are gone.
    ///
    /// The chain bit is read from `apdu[0] & CLA_CHAIN` — the same bit
    /// `iso7816` reports as `Class::chain()` — but `CommandView` supplies the
    /// *fields*, so exactly one length parser is in play for both halves of
    /// the job. Reading the bit off the raw byte rather than off a
    /// `CommandView` is deliberate: a 4-byte `cla|0x10` APDU with no body is
    /// a legal case-1 APDU, parses fine, and must still be recognized as a
    /// fragment.
    pub fn push(&mut self, apdu: &[u8]) -> Step {
        // An empty APDU cannot be part of a chain — there is no class byte to
        // read — so it is not this module's business. PIV answers
        // `apdu.get(1) == None` with `6D00` and must keep doing so.
        let Some(&cla) = apdu.first() else {
            self.buf.clear();
            return Step::Pass;
        };
        // The whole point of `Step::Pass`: an ordinary command with no chain
        // in progress leaves here having been read, not parsed and not
        // copied. Everything downstream — including its status word on a
        // malformed body — is exactly what it was before this module existed.
        // The buffer is cleared rather than left stale so the postcondition
        // is uniform: after any `Step` other than `Complete`, `Self::apdu()`
        // is empty, and a caller that reads it anyway gets nothing rather
        // than the previous command.
        if cla & CLA_CHAIN == 0 && !self.pending {
            self.buf.clear();
            return Step::Pass;
        }
        // From here on the APDU is part of a chain and this module is
        // responsible for it. `CommandView::try_from` rejects anything under
        // the 4-byte header; this is the US-701 panic class it must not
        // reintroduce. Note a *chained* APDU under 4 bytes lands here and is
        // refused — a truncated fragment is never appended.
        let Ok(command) = CommandView::try_from(apdu) else {
            return self.fail(ChainError::Malformed);
        };
        let body = command.data();
        // Unreachable while `CommandView` is exact-length, but a fragment
        // that slipped past it must not be appended blind.
        let Some(shape) = shape_of(apdu.len(), body.len()) else {
            return self.fail(ChainError::Malformed);
        };

        let base = [cla & !CLA_CHAIN, apdu[1], apdu[2], apdu[3]];

        if cla & CLA_CHAIN != 0 {
            return self.push_fragment(&base, body);
        }

        // A non-chained command, and a chain is pending. Does it terminate
        // that chain?
        debug_assert!(self.pending, "reached the terminator branch without a chain");
        // Rule 1: the terminator must be *the same command*. Handing a
        // `GET DATA` the bytes of an abandoned `PUT DATA` is exactly the
        // corruption this module exists to prevent, and vpicc — the one
        // in-tree caller that already does this — does not check, so the
        // check is ours to make.
        //
        // **The limit of this rule, because it looks stronger than it is:**
        // ISO 7816-4 terminates a chain with the first command whose CLA b4
        // is clear, and offers nothing to say "this one is not really the
        // terminator". So an *unrelated* command that happens to share the
        // chain's INS/P1/P2 — a second `PUT DATA 3F FF` after a client
        // abandoned a first one — is the terminator by the standard's own
        // definition, and the two bodies are concatenated. There is no
        // signal on the wire to separate them, and inventing one (a timeout,
        // a magic byte) would be worse than the ambiguity. What the consumer
        // does with the merged body is the consumer's own bounds check, and
        // for both applets here that ends in a refusal rather than a store:
        // PIV's `tlv_iter` bounds-checks the `53` length and `cmd_put_data`
        // answers `SW_WRONG_DATA`; opcard's `put_arbitrary_do` re-checks
        // `MAX_GENERIC_LENGTH`. See
        // `apps/piv/src/lib.rs`'s
        // `an_abandoned_chain_followed_by_the_same_command_is_refused_not_stored`.
        if self.header != base {
            // The arriving command is a well-formed command *in its own
            // right*, so it is dispatched on its own merits below rather
            // than being poisoned by someone else's abandoned bytes. The
            // chain is simply dropped. Failing it instead would break
            // the ordinary client recovery — "my chain went wrong, let me
            // SELECT again and start over" — for no security gain.
            self.reset();
            return Step::Pass;
        }
        // The terminator's own data field, possibly empty: PicoForge's tail
        // can be as short as one byte, and an empty tail is legal ISO even
        // though its client never emits one.
        self.pending = false;
        self.le.clear();
        self.le
            .extend_from_slice(&apdu[apdu.len() - shape.le_width()..])
            .ok();
        if let Err(e) = self.append(body) {
            return self.fail(e);
        }
        self.render()
    }

    /// Append one `cla|0x10` fragment's data field.
    fn push_fragment(&mut self, base: &[u8; 4], body: &[u8]) -> Step {
        if self.pending {
            if self.header != *base {
                return self.fail(ChainError::HeaderMismatch);
            }
        } else {
            // Opening fragment. A chain that opens empty is legal, but there
            // is nothing to wait for if it is also the last — which the next
            // APDU decides.
            //
            // `buf` is cleared to exactly `BODY_OFFSET` bytes, not to zero:
            // the body lives *after* the header and the widest Lc field, so
            // the length that `pending_len` reports is `len - BODY_OFFSET`.
            // Clearing to zero would make every body look zero-length, which
            // silently disables the bound as well as the accounting.
            self.buf.clear();
            self.buf.extend_from_slice(&[0u8; BODY_OFFSET]).ok();
            self.header = *base;
            self.pending = true;
        }
        if let Err(e) = self.append(body) {
            return self.fail(e);
        }
        Step::Buffered
    }

    /// Append to the body region, refusing on overflow. The check is against
    /// the *post*-append length, so the buffer is never left holding a
    /// partially-appended fragment.
    fn append(&mut self, body: &[u8]) -> Result<(), ChainError> {
        if self.pending_len() + body.len() > MAX_CHAINED_BODY {
            return Err(ChainError::TooLong);
        }
        // `buf` is cleared to exactly `BODY_OFFSET` before any append, so the
        // slice can never be shorter than that here.
        self.buf
            .extend_from_slice(body)
            .map_err(|_| ChainError::TooLong)
    }

    /// Drop everything accumulated and report `error`.
    fn fail(&mut self, error: ChainError) -> Step {
        self.reset();
        Step::Broken(error)
    }

    /// Turn the accumulated body into a wire APDU: move the body down to the
    /// short-Lc offset if it fits, write the Lc field, and re-attach the
    /// terminator's Le at a width that matches the Lc field.
    fn render(&mut self) -> Step {
        let body_len = self.buf.len() - BODY_OFFSET;

        // Short Lc is legal only if the body fits one byte *and* the Le fits
        // one byte too — ISO 7816-4 forbids mixing, and `parse_lengths`
        // enforces it (`case 4E` reads a 2-byte Le, so a 1-byte one falls
        // through to `InvalidSliceLength`). A 1-byte Le always means "256 or
        // less" and a 2-byte one "65536 or less", so the width alone decides.
        let short = body_len <= 255 && self.le.len() <= 1;

        let dst = 4 + if short { 1 } else { 3 };
        // Overlapping, descending destination: `copy_within` is a memmove.
        if dst != BODY_OFFSET {
            let slice = self.buf.as_mut_slice();
            slice.copy_within(BODY_OFFSET..BODY_OFFSET + body_len, dst);
        }
        // Drop the two bytes of the unused part of the Lc field, and anything
        // above the rendered command.
        self.buf.truncate(dst + body_len);

        // The chain's own header — CLA with b4 cleared, INS, P1, P2 — goes in
        // front of the Lc field. It is written *after* the body move, but
        // the two ranges cannot overlap: the body starts at `dst >= 5` and
        // the header ends at 3.
        self.buf[..4].copy_from_slice(&self.header);
        if short {
            self.buf[4] = body_len as u8;
        } else {
            let [hi, lo] = (body_len as u16).to_be_bytes();
            self.buf[4] = 0;
            self.buf[5] = hi;
            self.buf[6] = lo;
        }
        // Case 1 has no Le and no data: a 4-byte command is all that remains,
        // which `truncate(4 + body_len)` has already produced.
        if !self.le.is_empty() {
            if short {
                self.buf.push(self.le[0]).ok();
            } else {
                // A 1-byte Le widened to 2 is a *different* Le, so the short
                // one has to be re-encoded, not copied: `Le = 0` means 256,
                // whose 2-byte extended spelling is `0x0100`, not `0x0000`.
                if self.le.len() == 1 {
                    let v = if self.le[0] == 0 { 256u16 } else { self.le[0] as u16 };
                    self.buf.extend_from_slice(&v.to_be_bytes()).ok();
                } else {
                    self.buf.extend_from_slice(&self.le).ok();
                }
            }
        }
        self.header = [0; 4];
        self.pending = false;
        self.le.clear();
        Step::Complete
    }
}
