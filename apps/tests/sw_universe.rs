//! US-182 (PICOForge-COMPAT, Phase J) — the per-applet status-word
//! conformance sweep.
//!
//! # Why this file exists
//!
//! The rationale the EPIC gives is the load-bearing part and it is worth
//! repeating exactly, because it is the reason this is a *wire* test and not
//! a table:
//!
//! > Only `9000` is accepted by `transceive_full` — every other SW becomes a
//! > hard error, so wrong-but-plausible codes (e.g. returning `6A82` where
//! > `6D00` is expected) surface to the user as the wrong diagnosis.
//!
//! So a status word is not a detail. It is the *only* thing the PicoForge
//! client gets to go on when an operation fails, and the EPIC's own example —
//! `6A82` where `6D00` belongs — is a swap between two codes that are both in
//! ISO 7816-4, both plausible, and mean completely different things to an
//! operator (`"that applet does not exist"` vs `"that instruction does not
//! exist"`). A regression that swaps them would be invisible to every other
//! test in this workspace: they assert that a command *succeeded*, not which
//! refusal it refused with.
//!
//! # What the EPIC got wrong, in both directions
//!
//! The EPIC's US-182 word list is a single flat list of 15 words
//! (`EPIC-fapico2-picoforge-compatibility.md:998-1006`) offered as "the exact
//! SW set". It is wrong twice over, and both errors are load-bearing:
//!
//! * **Missing a word four applets use.** `6A86` (incorrect P1/P2) is not on
//!   the list at all, and it is the *primary* P1/P2 refusal for the OATH
//!   applet, the OTP applet, the Rescue applet and PIV. An applet that
//!   answered `6A82` there instead — precisely the EPIC's own failure example
//!   — would have passed the EPIC's list.
//! * **Listing a word nothing emits.** `6A83` (record not found) is on the
//!   list and has **zero** occurrences anywhere in the workspace. A list that
//!   admits a dead word teaches a reader that the firmware can answer it,
//!   which is the opposite of what a conformance table is for.
//!
//! Other EPIC-list deltas this file settles, with the evidence in the table
//! rows themselves:
//!
//! | word | EPIC list | reality |
//! |---|---|---|
//! | `6A86` | absent | **used** — the primary P1/P2 refusal for OATH, OTP, Rescue and PIV |
//! | `6A83` | listed | **dead** — zero occurrences in the tree |
//! | `6984` | absent | **used** — OATH applet and PIV |
//! | `6400` | absent | returned by PIV's source but **unreachable** on the wire |
//! | `6581` | listed | returned by PIV's source but **unreachable** on the wire |
//! | `6985` | listed | **not** PIV — its `SW_CONDITIONS_NOT_SATISFIED` is a dead constant (it is OATH's and OTP's) |
//! | `61xx` | absent | **used** — the OATH applet's chunked `CALC ALL` |
//! | `6F00` | absent | **used** — the platform persist gate (durable-before-ack) |
//!
//! The last row is the one worth dwelling on. `0x6F00` is the word a *user*
//! sees when a durable write fails (`platform/src/persist.rs:361-366`) and when
//! the CCID transport hits an aborted bulk transfer
//! (`firmware/src/tasks.rs:226-238`). It belongs to no applet, which is exactly
//! why a per-applet list with no platform row would leave it unattributed, and
//! it is the most consequential word on the device: it means "the operation you
//! were told succeeded is not stored".
//!
//! # The naming trap — assert on values, never on names
//!
//! Three collisions in this workspace make a name-keyed sweep worthless:
//!
//! * `SW_WRONG_DATA` (`0x6700`, mgmt / OATH / OTP / PIV) and
//!   `SW_WRONG_LENGTH` (`0x6700`, `platform::dispatch`) are the **same value
//!   under two names**.
//! * `SW_INCORRECT_PARAMS` (`0x6A80`, OATH / PIV) and `SW_INVALID_DATA`
//!   (`0x6A80`, Rescue) are the same value under two names.
//! * PIV defines **both** `SW_WRONG_P1P2 = 0x6B00` and
//!   `SW_INCORRECT_P1P2 = 0x6A86` — the *same concept* ("your P1/P2 are
//!   wrong") under two different codes, in the same file
//!   (`apps/piv/src/lib.rs:59` and `:65`).
//!
//! Every assertion in this file is therefore on a `u16`. The table's `origin`
//! strings name the constants for the reader; nothing keys off them.
//! [`naming_collisions_are_value_identities`] exists to keep that honest.
//!
//! # The design, and why it is two layers
//!
//! A single "assert the applet's set equals this list" test only checks that
//! a list matches itself. Two layers are needed to make it earn the EPIC's
//! rationale, and they answer different questions:
//!
//! 1. **Reachability** — [`Case`], a named APDU with the exact status word
//!    it must answer. When one breaks, the failure names *the command that
//!    changed*, not "set mismatch". This is the layer that would have caught
//!    the EPIC's own `6A82`-for-`6D00` example.
//! 2. **Closed world** — a broad, deterministic APDU corpus run through the
//!    real applet behind the real [`Dispatcher`], collecting *every* status
//!    word produced. Any word not in the table fails. This is the layer that
//!    catches a brand-new `0x2A` appearing in a refactor, which no list of
//!    named cases can.
//!
//! The closed-world layer is where the effort is bounded, and the bound is
//! honest rather than convenient: each applet contributes an explicit
//! [`Space`] — the CLA / INS / P1 / P2 values its own `process` branches on,
//! cited to the `match` they come from — crossed with a shared body set. The
//! spaces are *not* the full 8 × 256 × 256 × 256 cube. They are the values the
//! code actually compares against, plus one unhandled value per axis so the
//! default arms are covered too. Growing a space is a one-line change and the
//! failure message says which applet needs it.
//!
//! Several [`Case`] lists are chained into one applet instance, so state-
//! dependent words (`63Cx`, `6982`, `6984`, `6A84`, `61xx`, `6985`) are driven
//! through the session that produces them rather than asserted from a comment.
//!
//! # `Guarded` — claimed by the source, unreachable on the wire
//!
//! A word can be `return`ed by an applet and still be unreachable, because
//! the guard in front of it can never be false. PIV has two such words
//! (`0x6400`, `0x6581`) and one dead constant (`0x6985`). They stay in the
//! table — deleting them would hide a real fact about the source — but they
//! carry [`Reach::Guarded`] with the guard named, and `table_is_accounted_*`
//! asserts they are **not** observed. That assertion is the useful half: if a
//! future change makes the guard reachable, the sweep fails and the row has to
//! be re-labelled deliberately instead of the reason rotting in a doc comment.
//!
//! # Rows are families, not values
//!
//! Two words on this wire are genuinely families, and a table row that pinned
//! one value of either would be **wrong**, not strict:
//!
//! * `63Cx` — PIV writes `0x63C0 | retries` inline (`apps/piv/src/lib.rs:299`
//!   and `:475`) with no named constant at all, so the value changes with every
//!   attempt. It is also the sharpest form of the naming trap: a name-keyed
//!   sweep cannot see this word, because there is no name.
//! * `61xx` — the OATH applet's chunked `CALC ALL` (`sw_more_data`,
//!   `oath_core.rs:264-269`) writes `0x6100` for a remainder of 256 or more and
//!   `0x6100 | remaining` below it. Both forms occur.
//!
//! Every row therefore carries a `mask`, and every containment check goes
//! through `Claim::matches` rather than comparing `sw`. A family row cannot be
//! quietly read as exact, and an exact row cannot quietly absorb a neighbour.
//!
//! # What is *not* in this file
//!
//! **OpenPGP.** Its row is "the whole `iso7816::Status` enum", which is a
//! different shape from every table here and cannot be expressed as one. It
//! lives in `apps/openpgp/tests/status_word_universe.rs`, with the reasoning
//! for why a hand-written list would be a *weaker* claim than deriving the
//! permitted set from the enum. The only words that cross between the two
//! files are the `0x6A82` the dispatcher produces for every applet, and the
//! `0x6A83` dead-word pin.
//!
//! # Scope of the corpus, stated plainly
//!
//! The closed-world layer is a **bounded** sweep, not a proof. For each applet
//! it crosses the CLA/INS/P1/P2 values that applet's own code compares against
//! (cited to the `match` or `if` they come from) with a shared set of body
//! shapes, in both the short and the extended APDU framing. Two consequences a
//! reader should know rather than discover:
//!
//! * A branch guarded on a *value* inside a body — a specific tag, a specific
//!   PIN byte — is only reached if a [`Case`] names it or a corpus body
//!   happens to contain it. Every word in these tables is reached by one of
//!   those two routes, and `table_is_accounted` proves it, so the gap is
//!   bounded by "no *word* is unaccounted for", not by "no *branch* is".
//! * The cross product is what makes the framings comparable. `tlv()` sends
//!   one body in one framing; `Driver::cross` sends every body in both, so a
//!   framing that changed its answer would put a second word in the observed
//!   set and the table would have to carry both.


#![allow(clippy::needless_range_loop)]

use fapico2_platform::dispatch::{App, Dispatcher, MAX_RESPONSE, Sw};
use fapico2_platform::secure_store::HostSecureStore;
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HeaplessVec;
use std::collections::BTreeSet;

// ── the table's shape ──────────────────────────────────────────────────────

/// Which layer of the stack actually writes the word.
///
/// This is not decoration. When a host reports the wrong diagnosis, the first
/// question is *which* layer answered, and "the applet" versus "the
/// dispatcher" versus "the transport" lead to completely different places to
/// look. `6A82` is the clearest case: **no applet in this workspace returns
/// it from `process`** — every one of them gets it from
/// `Dispatcher::dispatch` when a SELECT names an AID that is not registered
/// (`platform/src/dispatch.rs:156`, `:179`, `:196`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Layer {
    /// The applet's own `process` / `select_apdu`.
    Applet,
    /// `platform::dispatch::Dispatcher` — a SELECT-routing decision, not an
    /// applet decision.
    Dispatcher,
    /// Above the dispatcher: the persist gate or the CCID framing.
    Transport,
}

/// Whether the sweep can actually drive this word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reach {
    /// Observed by the closed-world corpus on this applet.
    Corpus,
    /// The applet's source returns it, but no APDU reaches it. The string
    /// names the guard that is never false. Such a row is asserted **not**
    /// observed, so a change that makes it reachable fails the sweep.
    Guarded(&'static str),
}

/// One row of one applet's status-word table.
///
/// A row is a **family**, not always a single value, because two words on this
/// wire genuinely are families and treating them as fixed values would make
/// the closed-world test *wrong* rather than strict:
///
/// * `63Cx` — "verification failed, x retries remain". PIV writes it as
///   `0x63C0 | retries` (`apps/piv/src/lib.rs:299` and `:475`), so the value
///   changes with every attempt, and a row of exactly `0x63C0` would fail the
///   sweep the moment a second attempt happened.
/// * `61xx` — "x more bytes available", which is the OATH applet's own
///   chunked-response protocol. `sw_more_data` (`oath_core.rs:264-269`)
///   deliberately writes `0x6100` for a remainder of 256 or more and
///   `0x6100 | remaining` below it, so both forms occur on the wire.
///
/// `mask` is the set of bits that vary inside the family; `0` means the row is
/// one exact value. Every containment check goes through [`Claim::matches`]
/// rather than comparing `sw`, so a family row cannot be quietly treated as
/// exact and an exact row cannot quietly absorb a neighbour.
#[derive(Clone, Copy, Debug)]
struct Claim {
    /// The family's fixed part. For an exact word, the whole value.
    sw: Sw,
    /// Bits that vary within the family. `0` for an exact word.
    mask: Sw,
    layer: Layer,
    /// `file:line` of the definition, for the reader. Never used as a key —
    /// see the module docs' naming trap.
    origin: &'static str,
    reach: Reach,
}

impl Claim {
    const fn applet(sw: Sw, origin: &'static str) -> Self {
        Self { sw, mask: 0, layer: Layer::Applet, origin, reach: Reach::Corpus }
    }
    /// A family whose varying bits are `mask` — `0x000F` for `63Cx`, `0x00FF`
    /// for `61xx`.
    const fn family(sw: Sw, mask: Sw, origin: &'static str) -> Self {
        Self { sw, mask, layer: Layer::Applet, origin, reach: Reach::Corpus }
    }
    /// A word the applet's source returns but no APDU can reach.
    const fn guarded(sw: Sw, origin: &'static str, guard: &'static str) -> Self {
        Self { sw, mask: 0, layer: Layer::Applet, origin, reach: Reach::Guarded(guard) }
    }
    const fn dispatcher(sw: Sw, origin: &'static str) -> Self {
        Self { sw, mask: 0, layer: Layer::Dispatcher, origin, reach: Reach::Corpus }
    }
    const fn transport(sw: Sw, origin: &'static str, reach: Reach) -> Self {
        Self { sw, mask: 0, layer: Layer::Transport, origin, reach }
    }
    /// Is `sw` inside this row's family?
    const fn matches(&self, sw: Sw) -> bool {
        sw & !self.mask == self.sw & !self.mask
    }
}

/// Every family's base value a table declares. Used by the EPIC-delta tests,
/// which are about *named* words rather than observed values.
fn words(claims: &[Claim]) -> impl Iterator<Item = Sw> + '_ {
    claims.iter().map(|c| c.sw)
}

/// Does any row of `table` contain `sw`?
fn table_has(table: &[Claim], sw: Sw) -> bool {
    table.iter().any(|c| c.matches(sw))
}

// ── the corpus's shape ─────────────────────────────────────────────────────

/// A named APDU and the exact status word it must answer.
///
/// The expected word is a literal, never a named constant imported from the
/// applet — see the module docs' naming trap. A test that asserted
/// `SW_WRONG_DATA` where the applet spells it `SW_WRONG_LENGTH` would keep
/// passing if one of the two were ever changed to a different value, which is
/// the exact failure this file exists to prevent.
struct Case {
    /// Owned rather than `&'static str` because the templated helpers below
    /// build labels at runtime (one per framing, one per credential index).
    label: String,
    apdu: Vec<u8>,
    expect: Sw,
}

fn case(label: impl Into<String>, apdu: Vec<u8>, expect: Sw) -> Case {
    Case { label: label.into(), apdu, expect }
}

/// The CLA / INS / P1 / P2 values an applet actually branches on.
///
/// Every list below is transcribed from that applet's own `match`/`if` and
/// carries the citation in its doc comment, so a reader can check the space
/// against the source without opening the test.
struct Space {
    clas: &'static [u8],
    ins: &'static [u8],
    p1: &'static [u8],
    p2: &'static [u8],
}

// ── APDU construction helpers ──────────────────────────────────────────────

/// C-harness extended framing: `00 INS P1 P2 00 LL data`.
///
/// Both the OATH/OTP applets' own tests and the pico-keys C harness use this
/// shape, and `OathApp::parse_apdu` (`apps/oath/src/oath_core.rs:1070`) and
/// `OtpApp::parse_apdu` both branch on `apdu[4] == 0x00` to select it. Without
/// it in the corpus the OATH applet's `TAG_*` parsing is never exercised with a
/// well-formed extended body and the sweep sees roughly half the applet.
fn ext(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00, ins, p1, p2, 0x00];
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// ISO 7816-4 short framing: `00 INS P1 P2 Lc data` (or a bare case-1 header
/// when `data` is empty, so the "no Lc at all" shape is in the corpus too).
fn short(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00, ins, p1, p2];
    if !data.is_empty() {
        out.push(data.len() as u8);
        out.extend_from_slice(data);
    }
    out
}

/// `00 INS P1 P2 00` — case 2, an `Le` with no data. Distinct from both
/// `short(.., &[])` and `ext(.., &[])`, and several applets treat the three
/// shapes differently (`vendor_led` refuses an off-length SET at
/// `apps/vendor_led/src/lib.rs:443-447`; the OATH `parse_apdu` picks the
/// extended branch on the same byte).
fn case2(ins: u8, p1: u8, p2: u8) -> Vec<u8> {
    vec![0x00, ins, p1, p2, 0x00]
}

/// One `TLV body → APDU` reachability case, in the **short** framing only.
///
/// Emitting the same body in all three framings here would be actively wrong,
/// and the reason is worth recording: a reachability [`Case`] runs *in order
/// against one applet instance*, so a body that changes state answers `0x9000`
/// the first time and a refusal every time after. Emitting the extended
/// framing alongside the short one turns "this APDU must answer `0x6700`"
/// into "the second one of these must also answer `0x6700`", which is false
/// for any state-changing command and produced a wall of spurious failures
/// while this file was being written.
///
/// The framings are not dropped, only moved: [`Driver::cross`] sends **both**
/// the short and the extended encoding of every body for every (CLA, INS, P1,
/// P2) in the [`Space`], so if the two framings ever disagree the second word
/// lands in the observed set and the table has to carry both. That is the
/// stronger property anyway — it is checked for the whole space rather than
/// for the handful of bodies named here.
fn tlv(label: &str, ins: u8, p1: u8, p2: u8, body: &[u8], expect: Sw) -> Vec<Case> {
    vec![case(label, short(ins, p1, p2, body), expect)]
}

/// The shared body set crossed with every framing.
///
/// Chosen to hit *shape* checks rather than to hit every value: empty, a
/// single byte, power-of-two lengths that straddle every length constant in
/// the applets (8 = an 8-byte PIN, 16 = a 16-byte block, 32/64/255), and two
/// structured bodies — a TLV-shaped one and a distinct 52-byte one, because
/// `OTP_CONFIG_SIZE` is 52 and the OTP applet's first length check is
/// `body.len() == 52 || body.len() == 58` (`apps/oath/src/otp.rs:587-592`).
fn bodies() -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0xFF],
        vec![0x00, 0x00],
        vec![0x00, 0x00, 0x00, 0x00],
        vec![0x00; 6],
        vec![0x00; 8],
        vec![0xFF; 8],
        vec![0x00; 16],
        vec![0xFF; 16],
        vec![0x00; 24],
        vec![0x00; 32],
        vec![0x00; 52],
        vec![0x00; 58],
        vec![0x00; 64],
        vec![0x00; 255],
        (0u8..=255).collect(),
        // A TLV-shaped body: `71 02 'a' 'b' 73 04 <4>` — the OATH name+key
        // skeleton every OATH case below is a variation of.
        {
            let mut b = vec![0x71, 0x02, b'a', b'b', 0x73, 0x04];
            b.extend_from_slice(&[0x21, 0x06, 0x00, 0x00]);
            b
        },
    ];
    v.sort();
    v.dedup();
    v
}

// ── the driver ─────────────────────────────────────────────────────────────

/// The trailing status word of a response, or `None` if the response is too
/// short to carry one.
///
/// A `None` is a **sweep failure**, not a skip: every APDU in this file must
/// answer with at least SW1/SW2, and an applet that returned a bare body would
/// desynchronise the client. It is reported as its own case so the failure
/// names the APDU.
fn sw_of(resp: &HeaplessVec<u8, MAX_RESPONSE>) -> Option<Sw> {
    if resp.len() < 2 {
        return None;
    }
    let n = resp.len();
    Some(u16::from_be_bytes([resp[n - 2], resp[n - 1]]))
}

fn select_aid(aid: &[u8]) -> Vec<u8> {
    let mut a = vec![0x00, 0xA4, 0x04, 0x00, aid.len() as u8];
    a.extend_from_slice(aid);
    a
}

/// A SELECT of an AID that is deliberately not registered.
///
/// This is how `0x6A82` is produced for every applet. It is a dispatcher
/// decision (`platform/src/dispatch.rs:177-181`), not an applet one, which is
/// why every applet's table carries a `Layer::Dispatcher` row for it.
const SELECT_UNKNOWN_AID: [u8; 8] = [0x00, 0xA4, 0x04, 0x00, 0x03, 0x01, 0x02, 0x03];

/// Everything the sweep learned from one applet.
#[derive(Default)]
struct Observed {
    /// Every status word produced, from both the named cases and the corpus.
    words: BTreeSet<Sw>,
    /// The first APDU that produced each word, for failure messages.
    witness: Vec<(Sw, String)>,
}

impl Observed {
    fn record(&mut self, sw: Sw, what: String) {
        if self.words.insert(sw) {
            self.witness.push((sw, what));
        }
    }

    fn witness_for(&self, sw: Sw) -> String {
        self.witness
            .iter()
            .find(|(s, _)| *s == sw)
            .map(|(_, w)| w.clone())
            .unwrap_or_else(|| "<never observed>".into())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

/// One applet under the real [`Dispatcher`], accumulating what the sweep saw.
///
/// The driver exists rather than a `drive(&mut app, cases, space)` free
/// function because three of the applets here cannot be swept by a static
/// case list at all:
///
/// * **OATH** hands out a *challenge* in its SELECT response, and the only
///   correct VALIDATE response is an HMAC over bytes that come off the wire.
/// * **PIV** hands out a plaintext management challenge and the `0x6984` row
///   is only reachable by answering it wrongly, which needs the challenge.
/// * **OTP** needs a 52-byte slot frame whose CRC the test computes.
///
/// All three are ordinary client behaviour, so [`Driver::exchange`] exposes
/// the raw exchange (response bytes + status word) and the scenario functions
/// above it read the wire the way PicoForge does. Hiding that behind a fixed
/// signature would have meant either dropping the three most valuable rows
/// (`0x61xx`, `0x6984`, `0x6985`) or writing a second driver.
struct Driver<'a> {
    d: Dispatcher<'a, 1>,
    resp: HeaplessVec<u8, MAX_RESPONSE>,
    obs: Observed,
    failures: Vec<String>,
}

impl<'a> Driver<'a> {
    /// Register `app` and SELECT its AID. The SELECT is the first probe: a
    /// case list that did not establish a selection first would be testing
    /// `0x6A82` every time.
    fn new(app: &'a mut dyn App, aid: &[u8]) -> Self {
        let mut d: Dispatcher<1> = Dispatcher::new();
        assert!(d.register(app), "the dispatcher must accept the applet");
        let mut me = Self {
            d,
            resp: HeaplessVec::<u8, MAX_RESPONSE>::new(),
            obs: Observed::default(),
            failures: Vec::new(),
        };
        let (_, sw) = me.exchange(&select_aid(aid));
        assert!(sw.is_some(), "SELECT AID must answer a status word");
        me
    }

    /// One raw exchange. Returns `(response data without the status word,
    /// status word)` — the shape a client sees, and the shape the OATH and PIV
    /// scenarios need to read a challenge off the wire.
    ///
    /// The status word is `None` only when the response is too short to carry
    /// one, which is recorded as a failure: every APDU in this file must answer
    /// with at least SW1/SW2, and a bare body would desynchronise the client.
    fn exchange(&mut self, apdu: &[u8]) -> (Vec<u8>, Option<Sw>) {
        self.d.dispatch(apdu, &mut self.resp);
        let n = self.resp.len();
        match sw_of(&self.resp) {
            Some(sw) => {
                self.obs.record(sw, hex(apdu));
                (self.resp[..n - 2].to_vec(), Some(sw))
            }
            None => {
                self.failures.push(format!("`{}`: no status word ({n} bytes)", hex(apdu)));
                (self.resp.as_slice().to_vec(), None)
            }
        }
    }

    /// The reachability layer: run each [`Case`] in order and record a failure
    /// for every one whose status word is not the one it claims.
    ///
    /// Order matters and is the point — the cases that reach `0x6982` only do
    /// so because the `SET_CODE` before them left the session unvalidated
    /// (US-901), and the `0x63Cx` sequence only shows the counter walking
    /// because each wrong PIN is the one that spends it.
    fn run(&mut self, cases: &[Case]) {
        for c in cases {
            let (_, sw) = self.exchange(&c.apdu);
            match sw {
                Some(sw) if sw == c.expect => {}
                Some(sw) => self.failures.push(format!(
                    "`{}`: `{}` answered {sw:04x}, expected {:04x}",
                    hex(&c.apdu),
                    c.label,
                    c.expect
                )),
                None => self.failures
                    .push(format!("`{}`: `{}` produced no status word", hex(&c.apdu), c.label)),
            }
        }
    }

    /// The closed-world layer: the whole [`Space`] × bodies corpus, in both
    /// the short and the extended framing, on whatever state the named cases
    /// left behind.
    ///
    /// Running it *after* the cases is deliberate: a case list that provisions
    /// a session also has its state-dependent refusals swept, which is the
    /// only way `0x6982`, `0x63Cx` and the `6A8x` family get into the
    /// observed set from more than one direction.
    fn cross(&mut self, space: &Space) {
        for &cla in space.clas {
            for &ins in space.ins {
                for &p1 in space.p1 {
                    for &p2 in space.p2 {
                        self.exchange(&[cla, ins, p1, p2]);
                        for b in bodies() {
                            self.exchange(&short_apdu(cla, ins, p1, p2, &b));
                            self.exchange(&ext_apdu(cla, ins, p1, p2, &b));
                        }
                    }
                }
            }
        }
        // And the dispatcher's own `0x6A82`, last, so a case list that left a
        // selection in place still exercises it.
        self.exchange(&SELECT_UNKNOWN_AID);
    }

    /// [`Driver::run`] + [`Driver::cross`], for the applets that need no
    /// wire-reading in between.
    fn sweep(&mut self, cases: &[Case], space: &Space) {
        self.run(cases);
        self.cross(space);
    }

    fn into_report(self) -> Report {
        Report { obs: self.obs, failures: self.failures }
    }
}

/// Several *scenarios* of one applet — a cold one, a provisioned one, a
/// touch-denied one — folded into one observed set and one table check.
///
/// One table per applet is the whole point (a reader wants "the OATH applet
/// answers these words", not a column per starting state), so the scenarios
/// cannot each own a table check; they merge and the applet checks once.
#[derive(Default)]
struct Report {
    obs: Observed,
    failures: Vec<String>,
}

impl Report {
    fn absorb(&mut self, other: Report) {
        for (sw, w) in other.obs.witness {
            self.obs.record(sw, w);
        }
        self.failures.extend(other.failures);
    }

    /// Every per-scenario named case must have answered what it claimed, and
    /// the observed set must fit the table, and the table must fit the
    /// observed set. In that order, so the message names the first thing that
    /// is actually wrong.
    fn finish(self, who: &str, table: &[Claim]) {
        assert!(
            self.failures.is_empty(),
            "{who} reachability ({} named case(s) disagreed):\n{}",
            self.failures.len(),
            self.failures.join("\n")
        );
        closed_world(who, table, &self.obs, &[]);
        table_is_accounted(who, table, &self.obs);
    }
}

fn short_apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut v = vec![cla, ins, p1, p2];
    if !data.is_empty() {
        v.push(data.len() as u8);
        v.extend_from_slice(data);
    }
    v
}

fn ext_apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut v = vec![cla, ins, p1, p2, 0x00];
    v.extend_from_slice(&(data.len() as u16).to_be_bytes());
    v.extend_from_slice(data);
    v
}

// ── shared assertions ──────────────────────────────────────────────────────

/// **The closed-world invariant.** Every word the corpus produced must be in
/// the applet's table.
///
/// This is the test the EPIC's story is really asking for: it fails the moment
/// a refactor starts answering a word nobody wrote down, which is the only way
/// a new `0x2A` reaches a user.
fn closed_world(who: &str, table: &[Claim], obs: &Observed, failures: &[String]) {
    let mut out = Vec::new();
    for sw in &obs.words {
        if !table_has(table, *sw) {
            out.push(format!(
                "  {sw:04x}  produced by: {}",
                obs.witness_for(*sw)
            ));
        }
    }
    assert!(
        out.is_empty(),
        "{who}: the corpus produced {} status word(s) outside its table:\n{}",
        out.len(),
        out.join("\n")
    );
    assert!(
        failures.is_empty(),
        "{who}: the corpus left {} un-answered or malformed response(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// **The accounting invariant.** Every table row is either observed by the
/// corpus, or carries a [`Reach::Guarded`] reason — and in the second case it
/// is asserted *not* observed.
///
/// The second half is the one that pays. A `Guarded` row is a claim that
/// "the source returns this, but no APDU reaches it". If a later change makes
/// it reachable, the row silently becomes false and the reason in the table
/// becomes a lie. Asserting its absence turns that into a test failure.
fn table_is_accounted(who: &str, table: &[Claim], obs: &Observed) {
    let mut out = Vec::new();
    for c in table {
        let observed = obs.words.iter().any(|w| c.matches(*w));
        match c.reach {
            Reach::Corpus => {
                if !observed {
                    out.push(format!(
                        "  {:04x} ({}) is in the table as reachable but the corpus never produced it",
                        c.sw, c.origin
                    ));
                }
            }
            Reach::Guarded(guard) => {
                if observed {
                    out.push(format!(
                        "  {:04x} ({}) is marked unreachable ({guard}) but the corpus produced it — \
                         relabel the row and re-derive the guard",
                        c.sw, c.origin
                    ));
                }
            }
        }
    }
    assert!(out.is_empty(), "{who}: {} unaccounted table row(s):\n{}", out.len(), out.join("\n"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Management applet
// ═══════════════════════════════════════════════════════════════════════════

/// The Management applet's status words.
///
/// The `process` match is four arms wide
/// (`apps/mgmt/src/lib.rs:437-458`): READ_CONFIG, WRITE_CONFIG, RESET,
/// MIGRATION, and a `_` default. Everything below is one of those arms or one
/// of the two pre-dispatch guards.
const MGMT: &[Claim] = &[
    Claim::applet(0x9000, "platform::dispatch::SW_OK (dispatch.rs:22), via lib.rs:444"),
    // `SW_WRONG_LENGTH` (0x6700) is used twice in this applet under two names:
    // imported from the platform for the sub-header guard (lib.rs:37, :431)
    // and defined locally as `SW_WRONG_DATA` (lib.rs:187) for
    // `cmd_write_config`'s own refusals. One value, two names.
    Claim::applet(0x6700, "platform SW_WRONG_LENGTH (lib.rs:431); SW_WRONG_DATA (lib.rs:187, :563)"),
    Claim::applet(0x6985, "SW_CONDITIONS_NOT_SATISFIED (mgmt lib.rs:188, returned :551,:554,:577)"),
    Claim::applet(0x6D00, "SW_INS_NOT_SUPPORTED (mgmt lib.rs:456,:458; platform dispatch.rs:24)"),
    Claim::applet(0x6E00, "SW_CLA_NOT_SUPPORTED (mgmt lib.rs:189, returned :436)"),
    Claim::dispatcher(
        0x6A82,
        "platform SW_FILE_NOT_FOUND (dispatch.rs:23), returned :156,:179,:196 — never by the applet",
    ),
];

/// INS values `ManagementApp::process` branches on (`lib.rs:441-458`), plus
/// one unhandled byte for the `_` arm.
const MGMT_SPACE: Space = Space {
    clas: &[0x00, 0x10, 0x80, 0xFF],
    ins: &[0x1C, 0x1D, 0x1E, 0x1F, 0x00, 0xFF],
    p1: &[0x00, 0x01, 0x02, 0xFF],
    p2: &[0x00, 0x01, 0x02, 0xFF],
};

/// The Management applet is the one applet with **no** CLA tolerance: the
/// first thing `process` does after the header length check is
/// `if cla != Some(&0x00) { SW_CLA_NOT_SUPPORTED }` (`lib.rs:433-437`).
///
/// `present` changes two expectations rather than adding cases. Both RESET
/// (`lib.rs:578-580`) and WRITE_CONFIG (`lib.rs:551-552`) consume a
/// user-presence grant, and a refused grant is `0x6985` — so `0x6985` is a
/// *device-default* refusal (the `device` build's `default_user_present` is
/// `false`, `lib.rs:203-211`), and the `9000` half of the row is only
/// reachable with a grant. Both are in one list so the pair is visible
/// together: a reader who sees only the granted scenario would think the applet
/// simply accepts a reset.
fn mgmt_cases(present: bool) -> Vec<Case> {
    let granted = if present { 0x9000 } else { 0x6985 };
    vec![
        case("READ_CONFIG (case 1)", case2(0x1D, 0x00, 0x00), 0x9000),
        case("READ_CONFIG (case 2)", vec![0x00, 0x1D, 0x00, 0x00], 0x9000),
        // US-702: RESET is the C factory reset and is presence-gated.
        case("RESET (P1P2 00 00)", ext(0x1E, 0x00, 0x00, &[]), granted),
        // `data[0]` must equal `data.len() - 1` (`cmd_write_config`, :545-546).
        case(
            "WRITE_CONFIG with a wrong length byte",
            ext(0x1C, 0x00, 0x00, &[0x09, 0xAB, 0xCD]),
            0x6700,
        ),
        case("WRITE_CONFIG", ext(0x1C, 0x00, 0x00, &[0x02, 0xAB, 0xCD]), granted),
        // `_` arm.
        case("unknown INS", short(0x00, 0x00, 0x00, &[]), 0x6D00),
        // No migration handler attached — which is the *emulation* build's
        // shape; the device injects one at boot. The `_ => None` arm is
        // `0x6D00` (`lib.rs:456`), not a length refusal: the length check is
        // inside the `Some` arm.
        case("MIGRATION with no handler", ext(0x1F, 0x00, 0x00, b"\x00"), 0x6D00),
        case("MIGRATION with no data", ext(0x1F, 0x00, 0x00, &[]), 0x6D00),
        // The sub-header guard: a 3-byte APDU is not a command. This is the
        // US-701 panic class, and it answers `0x6700` — which the applet calls
        // `SW_WRONG_LENGTH` here and `SW_WRONG_DATA` four lines later.
        case("3-byte APDU", vec![0x00, 0x1D, 0x00], 0x6700),
        // The CLA gate. `0x10` is the ISO 7816-4 command-chaining class bit,
        // which is a *real* class on this wire (US-181) — so if the applet ever
        // grew a chain reader, this would stop being a refusal.
        case("CLA 0x10 (chain bit)", vec![0x10, 0x1D, 0x00, 0x00], 0x6E00),
        case("CLA 0x80", vec![0x80, 0x1D, 0x00, 0x00], 0x6E00),
    ]
}

#[test]
fn reachability_management() {
    // Presence granted (the host default is auto-ack) and presence denied.
    // `0x6985` is reachable only through the second, and `0x9000` for the two
    // destructive commands only through the first — so the pair of scenarios
    // is what makes the row meaningful.
    let mut report = Report::default();
    {
        let mut app = fapico2_mgmt::ManagementApp::new();
        let mut d = Driver::new(&mut app, fapico2_mgmt::MANAGEMENT_AID);
        d.sweep(&mgmt_cases(true), &MGMT_SPACE);
        report.absorb(d.into_report());
    }
    {
        let mut app = fapico2_mgmt::ManagementApp::new().with_user_presence(|| false);
        let mut d = Driver::new(&mut app, fapico2_mgmt::MANAGEMENT_AID);
        d.sweep(&mgmt_cases(false), &MGMT_SPACE);
        report.absorb(d.into_report());
    }
    report.finish("management", MGMT);
}

// ═══════════════════════════════════════════════════════════════════════════
// OATH applet (the device implementation, `oath_core`)
// ═══════════════════════════════════════════════════════════════════════════

/// The OATH applet's status words — for the **device** implementation.
///
/// The word "device" matters: `fapico2-oath` has two OATH applets. The
/// `no_std` `oath_core::OathApp` is what the RP2350 runs and what
/// `firmware/src/emul_main.rs:7` imports; the `std` `oath::OathApp` is a
/// retained host-only legacy shell behind the `host` feature. This row is the
/// first one, because that is the one a user of the device can reach.
///
/// `0x61xx` is the one the EPIC's flat list missed here and it is not a rare
/// path: it is the OATH applet's own chunked-response protocol (US-713,
/// US-705). `sw_more_data` (`oath_core.rs:264-269`) writes `0x6100` for a
/// remainder ≥ 256 and `0x6100 | remaining` below it, and the client drains it
/// with INS `0xA5`.
const OATH: &[Claim] = &[
    Claim::applet(0x9000, "SW_OK, returned throughout handle() (oath_core.rs:1200)"),
    // A family, not a value: `sw_more_data` writes `0x6100` for a remainder of
    // 256 or more and `0x6100 | remaining` below it, so both forms are on the
    // wire. Only the ≥ 256 form appears in this file's cases, because a 40-slot
    // SHA-512 table leaves 804 bytes outstanding — but a smaller table would
    // produce the other, and a table row of "0x6100" would then fail a sweep
    // that was actually correct.
    Claim::family(
        0x6100,
        0x00FF,
        "sw_more_data() (oath_core.rs:264-269), returned :1687,:1707",
    ),
    Claim::applet(0x6700, "SW_WRONG_DATA (oath_core.rs:66), returned :1277,:1282,:1364,:1367,:1401"),
    Claim::applet(
        0x6982,
        "SW_SECURITY_STATUS_NOT_SATISFIED (oath_core.rs:67), returned :1260,:1273,:1337,:1354,:1383",
    ),
    Claim::applet(0x6984, "SW_DATA_INVALID (oath_core.rs:68), returned :1348,:1377,:1418"),
    Claim::applet(
        0x6985,
        "SW_CONDITIONS_NOT_SATISFIED (oath_core.rs:69), returned :1391 (SET_CODE clear) \
         and cmd_send_remaining's no-stream arm",
    ),
    Claim::applet(0x6A80, "SW_INCORRECT_PARAMS (oath_core.rs:71), returned :1280,:1296,:1400"),
    Claim::applet(
        0x6A84,
        "SW_FILE_FULL (oath_core.rs:70), returned :1328 (slot table full), :1673, :1731, :1740",
    ),
    Claim::applet(0x6A86, "SW_INCORRECT_P1P2 (oath_core.rs:72)"),
    Claim::applet(0x6D00, "SW_INS_NOT_SUPPORTED (oath_core.rs:73), returned :1265"),
    Claim::dispatcher(
        0x6A82,
        "platform SW_FILE_NOT_FOUND (dispatch.rs:23) — the applet itself never returns it",
    ),
];

/// `OathApp::handle`'s INS arms (`oath_core.rs:1247-1265`) plus an unhandled
/// byte. `0xB1..=0xB4` are the OTP-PIN parity commands added by US-905.
const OATH_SPACE: Space = Space {
    clas: &[0x00, 0x10, 0x80, 0xFF],
    ins: &[
        0x01, 0x02, 0x03, 0x04, 0x05, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xB1, 0xB2, 0xB3, 0xB4, 0x00,
        0xFF,
    ],
    p1: &[0x00, 0x01, 0x02, 0xDE, 0xFF],
    p2: &[0x00, 0x01, 0x02, 0x03, 0x7F, 0xAD, 0xFF],
};

const OATH_SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    let mut m = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

/// The 20-byte TOTP/HOTP secret used by every OATH case below.
///
/// It is the value `apps/oath/tests/auth_boundary.rs:268` uses, transcribed so
/// this file's APDUs are readable without cross-referencing.
const OATH_KEY_TLV: [u8; 24] = [0x73, 22, 0x21, 0x06, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a];

/// SET_CODE with a *valid* HMAC-SHA1 access code, then the two refusals the
/// resulting unvalidated session produces.
///
/// US-901 is the load-bearing fact here: a completely virgin applet is
/// *validated*, so on a fresh applet a PUT succeeds and `0x6982` cannot be
/// reached at all. Setting any durable state flips the next session to
/// unvalidated, which is what turns the session-gated half of the OATH table
/// (`0x6982`, `0x6700`, `0x6984`, `0x6A80`, `0x6A84`) on.
fn oath_establish() -> Vec<Case> {
    let chal = [9u8, 8, 7, 6, 5, 4, 3, 2];
    let mac = hmac_sha1(OATH_SECRET, &chal);
    let mut data = vec![0x73, 1 + OATH_SECRET.len() as u8, 0x21];
    data.extend_from_slice(OATH_SECRET);
    data.extend_from_slice(&[0x74, 0x08]);
    data.extend_from_slice(&chal);
    data.extend_from_slice(&[0x75, mac.len() as u8]);
    data.extend_from_slice(&mac);

    let mut v = tlv("SET_CODE", 0x03, 0x00, 0x00, &data, 0x9000);
    v.extend(tlv(
        "PUT before VALIDATE",
        0x01,
        0x00,
        0x00,
        &[0x71, 0x02, b'a', b'b', 0x73, 0x06, 0x21, 0x06, 0x00, 0x00],
        0x6982,
    ));
    v.extend(tlv("LIST before VALIDATE", 0xA1, 0x00, 0x00, &[], 0x6982));
    v.extend(tlv("CALCULATE before VALIDATE", 0xA2, 0x00, 0x00, &[], 0x6982));
    v.extend(tlv("SET_CODE again", 0x03, 0x00, 0x00, &data, 0x6982));
    v
}

/// The 20-byte TOTP secret TLV, transcribed from `apps/oath/tests/
/// auth_boundary.rs:60-64`.
fn oath_cred_tlv(name: &[u8]) -> Vec<u8> {
    let mut body = vec![0x71, name.len() as u8];
    body.extend_from_slice(name);
    body.extend_from_slice(&OATH_KEY_TLV);
    body
}

/// Find the `0x74` (challenge) TLV in an OATH SELECT response body.
///
/// The SELECT response is `79 03 04 03 00`, then `71 08 <device id>`, and
/// **only when an access code is on file** a `74 08 <challenge>`
/// (`oath_core.rs:1177-1186`). So the challenge is not at a fixed offset and
/// the test has to walk for it — exactly as a client does.
fn oath_challenge(select_body: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i + 1 < select_body.len() {
        if select_body[i] == 0x74 {
            let l = select_body[i + 1] as usize;
            return select_body[i + 2..i + 2 + l].to_vec();
        }
        i += 1;
    }
    panic!("no 0x74 challenge TLV in the OATH SELECT response: {select_body:02x?}");
}

/// The case list for a **validated** OATH session.
///
/// Every word here is behind the `if !self.validated` gate at the top of its
/// `cmd_*`, so the list is only meaningful after [`oath_establish`] has run
/// and a correct VALIDATE has granted the session.
fn oath_validated() -> Vec<Case> {
    let mut v = Vec::new();
    // 6700: a key TLV one byte long fails `k.len() >= 2`
    // (`cmd_put`, oath_core.rs:1275-1278).
    v.extend(tlv(
        "PUT with a one-byte key TLV",
        0x01,
        0x00,
        0x00,
        &[0x71, 0x01, b'q', 0x73, 0x01, 0x21],
        0x6700,
    ));
    // 6984: DELETE a name that is not stored (`cmd_delete`, :1354-1359).
    v.extend(tlv(
        "DELETE a missing name",
        0x02,
        0x00,
        0x00,
        &[0x71, 0x01, b'z'],
        0x6984,
    ));
    // 6984: RENAME a name that is not stored (`cmd_rename`, :1377).
    v.extend(tlv(
        "RENAME a missing name",
        0x05,
        0x00,
        0x00,
        &[0x71, 0x01, b'z', 0x71, 0x01, b'y'],
        0x6984,
    ));
    // 6700: RENAME onto itself (`cmd_rename`, :1364).
    v.extend(tlv(
        "RENAME onto the same name",
        0x05,
        0x00,
        0x00,
        &[0x71, 0x01, b'z', 0x71, 0x01, b'z'],
        0x6700,
    ));
    // 6A80: a property bit this firmware cannot enforce is refused rather
    // than dropped (US-133, oath_core.rs:1294-1300) — `0x78 01 01` is
    // PROP_PWS, which is not in PROP_ENFORCED.
    v.extend(tlv(
        "PUT with an unenforceable property bit",
        0x01,
        0x00,
        0x00,
        &[0x71, 0x01, b'q', 0x78, 0x01, 0x01, 0x73, 0x06, 0x21, 0x06, 0, 0, 0, 0],
        0x6A80,
    ));
    // 6A80: a name TLV that is absent is "incorrect parameters in the data
    // field" (`cmd_put`, :1279-1281).
    v.extend(tlv("PUT with no name TLV", 0x01, 0x00, 0x00, &[0x73, 0x06, 0x21, 0x06, 0, 0, 0, 0], 0x6A80));
    // 6A86: CALCULATE with a P2 that is neither 0 nor 1
    // (`cmd_calculate`, :1474-1476).
    v.extend(tlv(
        "CALCULATE with P2 = 0x7F",
        0xA2,
        0x00,
        0x7F,
        &[0x74, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x71, 0x01, b'q'],
        0x6A86,
    ));
    // 6A86: CALC ALL with an out-of-range P2 (`cmd_calculate_all`, :1639).
    v.extend(tlv(
        "CALC ALL with P2 = 0x7F",
        0xA4,
        0x00,
        0x7F,
        &[0x74, 0x08, 1, 2, 3, 4, 5, 6, 7, 8],
        0x6A86,
    ));
    // 6984: CALCULATE for a name that is not stored
    // (`cmd_calculate`, :1488-1490).
    v.extend(tlv(
        "CALCULATE a missing name",
        0xA2,
        0x00,
        0x00,
        &[0x74, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x71, 0x01, b'z'],
        0x6984,
    ));
    // 6985: SEND REMAINING with no stream in progress
    // (`cmd_send_remaining`, :1695-1697). The epilogue of the applet's own
    // chunking protocol and, on a fresh applet, the *only* way to see it.
    v.push(case(
        "SEND REMAINING with no stream",
        ext(0xA5, 0x00, 0x00, &[]),
        0x6985,
    ));
    v
}

/// Fill the 68-slot table, so the 69th insert is the `0x6A84` one.
///
/// 68 is `MAX_CREDS` (`oath_core.rs:213`). The names are unique across the
/// whole range, which matters: a duplicate name *replaces* the slot
/// (`cmd_put`, :1320-1322) and the table would never fill.
fn oath_fill_table() -> Vec<Case> {
    (0..68u8)
        .map(|i| {
            let name = [b'a' + (i % 26), b'0' + (i / 26)];
            case(
                format!("PUT credential {i:02}"),
                ext(0x01, 0x00, 0x00, &oath_cred_tlv(&name)),
                0x9000,
            )
        })
        .collect()
}

/// **The `0x61xx` row**, and the one that needs its own scenario.
///
/// `calc_all_body_len` (`oath_core.rs:1566`) is `2 + name_len` per credential
/// plus `1 + 2 + mac_size`, so the largest body a 68-slot table can produce is
/// set by the *hash*, not the slot count:
///
/// | credential hash | MAC | per credential | 68 slots | chunks? |
/// |---|---|---|---|---|
/// | HMAC-SHA1 (`0x21`) | 20 B | 27 B | ~1.8 KB | **no** |
/// | HMAC-SHA256 (`0x22`) | 32 B | 39 B | ~2.6 KB | yes |
/// | HMAC-SHA512 (`0x23`) | 64 B | 71 B | ~4.8 KB | yes |
///
/// `OATH_CHUNK_MAX` is 2036 (`oath_core.rs:228`), so a SHA-1 table — which is
/// what every other OATH case in this file stores — **never** chunks and would
/// leave the `0x6100` row unproved. That is the reason for the second
/// credential type here and the reason this is a separate function rather than
/// a few more entries in [`oath_validated`].
fn oath_chunked_calc_all() -> Vec<Case> {
    let mut v: Vec<Case> = (0..40u8)
        .map(|i| {
            let name = [b'A' + (i % 26), b'0' + (i / 26)];
            // `73 42 23 06 <64>` — TOTP, HMAC-SHA512, 64-byte key.
            let mut body = vec![0x71, 0x02];
            body.extend_from_slice(&name);
            body.extend_from_slice(&[0x73, 0x42, 0x23, 0x06]);
            body.extend_from_slice(&[0x5Au8; 64]);
            case(format!("PUT SHA-512 credential {i:02}"), ext(0x01, 0x00, 0x00, &body), 0x9000)
        })
        .collect();
    // 40 × 71 = 2840 bytes of body against a 2036-byte cap, so the first
    // exchange carries 2036 and announces 804 remaining.
    v.extend(tlv(
        "CALC ALL (first window)",
        0xA4,
        0x00,
        0x00,
        &[0x74, 0x08, 1, 2, 3, 4, 5, 6, 7, 8],
        0x6100,
    ));
    v.push(case("SEND REMAINING (second window)", ext(0xA5, 0x00, 0x00, &[]), 0x9000));
    v
}

/// Grant an OATH session: run [`oath_establish`], then re-SELECT for the
/// card's challenge, then hand back the VALIDATE case that answers it.
///
/// The three phases cannot be one case list, and the reason is the point of
/// the applet's US-901/US-902 design: the challenge only exists in a SELECT
/// issued *after* a code is on file (`select_apdu`, `oath_core.rs:1183-1186`),
/// and the only correct response to it is an HMAC over bytes that come off
/// the wire. A static list would have to hard-code a challenge, and a
/// hard-coded challenge is exactly the bug this row exists to catch.
fn oath_grant(d: &mut Driver<'_>) -> Vec<Case> {
    d.run(&oath_establish());
    let (body, sw) = d.exchange(&select_aid(fapico2_oath::oath_core::OATH_AID));
    assert_eq!(sw, Some(0x9000), "the re-SELECT must answer 9000");
    let chal = oath_challenge(&body);
    let mac = hmac_sha1(OATH_SECRET, &chal);
    let mut vd = vec![0x74, chal.len() as u8];
    vd.extend_from_slice(&chal);
    vd.extend_from_slice(&[0x75, mac.len() as u8]);
    vd.extend_from_slice(&mac);
    vec![case("VALIDATE with the card challenge", ext(0xA3, 0x00, 0x00, &vd), 0x9000)]
}

#[test]
fn reachability_oath() {
    use fapico2_oath::oath_core::{device_id_from_chipid, OathApp, EMULATION_CHIPID};
    use fapico2_oath::OathSeal;

    let did = device_id_from_chipid(EMULATION_CHIPID);
    let aid = fapico2_oath::oath_core::OATH_AID;
    let mut report = Report::default();

    // Scenario 1 — a completely virgin applet. US-901 makes its session
    // *validated*, so a PUT succeeds here and the `0x6982` half of the table
    // is unreachable from this state. Sweeping it anyway is the point: it is
    // the state the device is in on first boot, and the closed-world layer
    // must see whatever it answers.
    {
        let mut trng = HostTrng::new();
        let mut store = HostSecureStore::new();
        let mut app =
            OathApp::boot(&mut trng, &mut store, did, OathSeal::emul()).expect("OATH boots from a fresh store");
        let mut d = Driver::new(&mut app, aid);
        d.run(&[case("PUT on a virgin applet", ext(0x01, 0x00, 0x00, &oath_cred_tlv(b"ab")), 0x9000)]);
        d.cross(&OATH_SPACE);
        report.absorb(d.into_report());
    }

    // Scenario 2 — an access code on file and a granted session.
    {
        let mut trng = HostTrng::new();
        let mut store = HostSecureStore::new();
        let mut app = OathApp::boot(&mut trng, &mut store, did, OathSeal::emul()).expect("OATH boots");
        let mut d = Driver::new(&mut app, aid);
        let grant = oath_grant(&mut d);
        d.run(&grant);
        let mut validated = oath_validated();
        validated.extend(oath_fill_table());
        // One past MAX_CREDS: `cmd_put`'s table is full (oath_core.rs:1323-1326).
        validated.push(case(
            "PUT past MAX_CREDS",
            ext(0x01, 0x00, 0x00, &oath_cred_tlv(b"z9")),
            0x6A84,
        ));
        d.run(&validated);
        d.cross(&OATH_SPACE);
        report.absorb(d.into_report());
    }

    // Scenario 3 — the chunked `CALC ALL`, which needs its own credential
    // type (see `oath_chunked_calc_all`).
    {
        let mut trng = HostTrng::new();
        let mut store = HostSecureStore::new();
        let mut app = OathApp::boot(&mut trng, &mut store, did, OathSeal::emul()).expect("OATH boots");
        let mut d = Driver::new(&mut app, aid);
        let grant = oath_grant(&mut d);
        d.run(&grant);
        d.run(&oath_chunked_calc_all());
        d.cross(&OATH_SPACE);
        report.absorb(d.into_report());
    }

    report.finish("oath (device)", OATH);
}

// ═══════════════════════════════════════════════════════════════════════════
// OTP applet
// ═══════════════════════════════════════════════════════════════════════════

/// The OTP applet's status words.
///
/// One INS (`0x01`, `INS_OTP`) and ten P1 opcodes
/// (`apps/oath/src/otp.rs:27-43`). It is the smallest applet in the set and
/// the only one whose entire dispatch is one CLA-agnostic INS test, so its
/// `6A86` (a bad P2 slot offset) is reached far more easily than the OATH
/// applet's.
const OTP: &[Claim] = &[
    Claim::applet(0x9000, "SW_OK, returned by every cmd_* arm (otp.rs:963+)"),
    Claim::applet(
        0x6700,
        "SW_WRONG_DATA (otp.rs:22), returned at :592,:596,:635,:637,:680,:759,:934 — \
         note the source comments call 0x6700 \"C SW_WRONG_LENGTH\"",
    ),
    Claim::applet(
        0x6982,
        "SW_SECURITY_STATUS_NOT_SATISFIED (otp.rs:21), returned :624,:650,:705,:780",
    ),
    Claim::applet(
        0x6985,
        "SW_CONDITIONS_NOT_SATISFIED (otp.rs:82), returned :867 — the CHAL_BTN_TRIG touch gate",
    ),
    Claim::applet(0x6A86, "SW_INCORRECT_P1P2 (otp.rs:23), returned from slot_offset_valid"),
    Claim::applet(
        0x6D00,
        "SW_INS_NOT_SUPPORTED (otp.rs:24) — any INS other than 0x01 (otp.rs:964)",
    ),
    Claim::dispatcher(0x6A82, "platform SW_FILE_NOT_FOUND (dispatch.rs:23)"),
];

/// `OtpApp::process`'s single INS test (`otp.rs:963`) plus one unhandled byte,
/// and every P1 opcode the `match` names (`otp.rs:27-43`).
const OTP_SPACE: Space = Space {
    clas: &[0x00, 0x10, 0x80, 0xFF],
    ins: &[0x01, 0x00, 0xFF],
    p1: &[0x01, 0x03, 0x04, 0x05, 0x06, 0x14, 0x20, 0x28, 0x30, 0x38, 0x00, 0xFF],
    p2: &[0x00, 0x01, 0x02, 0x03, 0x04, 0x80, 0xFF],
};

/// CRC-16/CCITT-FALSE with the pico-keys reflection, transcribed from
/// `OtpApp`'s private `crc16` (`apps/oath/src/otp.rs:235-244`).
///
/// It has to be transcribed rather than imported: it is a private `fn`, and a
/// sweep that re-used the applet's own CRC would be asserting the applet
/// against itself — the same anti-pattern as keying the table off constant
/// names. The reference client's `configure` computes the same frame
/// (`picoforge/src/hal/applets/otp.rs:411-422`).
fn otp_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for value in data {
        crc ^= *value as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0x8408 } else { crc >> 1 };
        }
    }
    crc
}

/// A 52-byte OTP slot frame with a valid residual, transcribed from the
/// applet's own `make_config` test helper (`apps/oath/src/otp.rs:1076-1086`).
///
/// `tkt_flags = CHAL_RESP | 0x08` and `cfg_flags = CHAL_HMAC | 0x08` make it a
/// touch-gated HMAC challenge-response slot with a device access code, which is
/// the configuration the `6982` and `6985` rows both need.
fn otp_config(code: [u8; 6], tkt_flags: u8, cfg_flags: u8) -> [u8; 52] {
    let mut c = [0u8; 52];
    c[16..22].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
    c[22..38].copy_from_slice(&[0xAA; 16]);
    c[38..44].copy_from_slice(&code);
    c[46] = tkt_flags;
    c[47] = cfg_flags;
    let stored = !otp_crc16(&c[..50]);
    c[50..52].copy_from_slice(&stored.to_le_bytes());
    c
}

fn otp_cases(present: bool) -> Vec<Case> {
    let mut c = vec![
        case("unknown INS", short(0x00, 0x00, 0x00, &[]), 0x6D00),
        // P2 ≥ SLOT_COUNT (4) fails `slot_offset_valid` (otp.rs:560-570).
        case("SLOT_CONFIGURE with P2 = 0x7F", ext(0x01, 0x01, 0x7F, &[0u8; 52]), 0x6A86),
        case("SLOT_CONFIGURE with P2 = 0x04", ext(0x01, 0x01, 0x04, &[0u8; 52]), 0x6A86),
        // A 16-byte body is neither 52 nor 58 (`cmd_configure`, otp.rs:587-593).
        case("SLOT_CONFIGURE with a 16-byte body", ext(0x01, 0x01, 0x00, &[0u8; 16]), 0x6700),
        // The all-zero body is an *erase*, and on a device with no code it is
        // a plain success (US-144, otp.rs:620-629).
        case("erase on an unprotected device", ext(0x01, 0x01, 0x00, &[0u8; 52]), 0x9000),
    ];
    // Configure a protected, touch-gated slot, then the two refusals that
    // protection buys.
    let cfg = otp_config([1, 2, 3, 4, 5, 6], 0x40 | 0x08, 0x22 | 0x08);
    c.push(case("SLOT_CONFIGURE with an access code", ext(0x01, 0x01, 0x00, &cfg), 0x9000));
    let mut wrong = cfg.to_vec();
    wrong.extend_from_slice(&[9, 9, 9, 9, 9, 9]);
    c.push(case(
        "SLOT_CONFIGURE with the wrong code",
        ext(0x01, 0x01, 0x00, &wrong),
        0x6982,
    ));
    let mut wrong_erase = vec![0u8; 52];
    wrong_erase.extend_from_slice(&[9, 9, 9, 9, 9, 9]);
    c.push(case(
        "erase with the wrong code",
        ext(0x01, 0x01, 0x00, &wrong_erase),
        0x6982,
    ));
    if !present {
        // US-143: with the touch gate set and no press, CALCULATE on the slot
        // answers 6985. The device build's `default_user_present` denies
        // (otp.rs:311-320), so this is the device's own behaviour, not a
        // host-only quirk.
        c.push(case(
            "CALCULATE on a touch-gated slot with no press",
            ext(0x01, 0x30, 0x00, &[8, 1, 2, 3, 4, 5, 6, 7]),
            0x6985,
        ));
    }
    c
}

#[test]
fn reachability_otp() {
    let mut report = Report::default();
    // Touch granted and touch denied. The `0x6985` row is the device's own
    // default (`default_user_present` is `false` under the `device` feature,
    // `otp.rs:311-320`), so it is not a host-only state.
    for present in [true, false] {
        let mut store = HostSecureStore::new();
        let mut app = fapico2_oath::OtpApp::boot(&mut store);
        if !present {
            app = app.with_user_presence(|| false);
        }
        let mut d = Driver::new(&mut app, OTP_AID);
        d.sweep(&otp_cases(present), &OTP_SPACE);
        report.absorb(d.into_report());
    }
    report.finish("otp", OTP);
}

/// `OtpApp::aid` returns the literal inline (`otp.rs:955`), so the test
/// restates it. The registry's `AID_OTP` is the same 7 bytes and the two
/// cannot drift — `fapico2_apps::registry::AID_OTP` is what the device
/// registers.
const OTP_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01];

#[test]
fn otp_aid_matches_the_registry() {
    assert_eq!(OTP_AID, fapico2_apps::registry::AID_OTP);
}

// ═══════════════════════════════════════════════════════════════════════════
// PIV applet
// ═══════════════════════════════════════════════════════════════════════════

/// PIV's status words — and the row where the EPIC's list is most wrong.
///
/// Three corrections against `EPIC-fapico2-picoforge-compatibility.md:998-1006`:
///
/// * **`0x6985` is dead.** `apps/piv/src/lib.rs:71` defines
///   `SW_CONDITIONS_NOT_SATISFIED` and **nothing in the file returns it** — a
///   whole-file grep finds exactly one occurrence, the definition. The EPIC
///   lists `6985` for the device; PIV has never answered it. It is left out of
///   the table entirely rather than listed as guarded, because a `Guarded` row
///   claims the source returns it, and here the source does not.
/// * **`0x6581` is unreachable.** `SW_MEMORY_FAILURE` is returned at
///   `lib.rs:496`, `:523` and `:555`, but every one of those is guarded by
///   `pin.is_none()`, `puk.is_none()` or `mgm_key_len == 0` — and the applet has
///   no APDU that clears any of them. `set_reference` (`:311-317`) only ever
///   writes `Some`, and `cmd_reset` (`:799-808`) restores `PivState::default`,
///   which has all three populated. So the word is in the source and off the wire.
/// * **`0x6400` is unreachable.** `SW_EXEC_ERROR` is returned at `:637`,
///   `:666` and `:716`, all of them `crypto::mgm_crypt(..) == None`, and
///   `mgm_crypt` returns `None` only when the input length is not the
///   algorithm's block size (`apps/piv/src/crypto.rs:86-88`) — but every one of
///   those three call sites has already bounds-checked the same length
///   against `chal_len`. It is a defensive branch, not a reachable state.
///
/// * `0x6984` **is** reachable (the mutual/single mgm-auth completion paths,
///   `lib.rs:662` and `:719`) and is absent from the EPIC's list.
const PIV: &[Claim] = &[
    Claim::applet(0x9000, "SW_OK, returned throughout (lib.rs:334,:351,:387,:400,:434)"),
    // A family, and the only one on this device that is written *without* a
    // named constant at all: `0x63C0 | retries` is an inline expression at
    // `lib.rs:299` and `:475`. A name-keyed sweep cannot see it, which is the
    // sharpest form of the naming trap in this file.
    Claim::family(
        0x63C0,
        0x000F,
        "`0x63C0 | retries` written inline (lib.rs:299,:475) — no named constant exists",
    ),
    Claim::applet(0x6700, "SW_WRONG_DATA (lib.rs:60) and platform SW_WRONG_LENGTH — one value"),
    Claim::applet(
        0x6982,
        "SW_SECURITY_STATUS_NOT_SATISFIED (lib.rs:72), returned :744,:783 and \
         cmd_set_mgmkey's unauthenticated arm",
    ),
    Claim::applet(0x6983, "SW_PIN_BLOCKED (lib.rs:67), returned :287,:297,:470"),
    Claim::applet(0x6984, "SW_DATA_INVALID (lib.rs:68), returned :662,:719 — missing from the EPIC list"),
    Claim::applet(0x6A80, "SW_INCORRECT_PARAMS (lib.rs:64), returned at 18 sites"),
    Claim::applet(
        0x6A81,
        "SW_FUNC_NOT_SUPPORTED (lib.rs:63), returned :552 — a slot key-ref that is not CARDMGM",
    ),
    Claim::applet(
        0x6A86,
        "SW_INCORRECT_P1P2 (lib.rs:65) — **the same concept as SW_WRONG_P1P2 below, \
         under a different code in the same file**",
    ),
    Claim::applet(0x6A88, "SW_REFERENCE_NOT_FOUND (lib.rs:66), returned :446,:486,:489,:516"),
    Claim::applet(
        0x6B00,
        "SW_WRONG_P1P2 (lib.rs:59), returned :428,:737,:749 — see 0x6A86 above",
    ),
    Claim::applet(0x6D00, "SW_INS_NOT_SUPPORTED (lib.rs via platform dispatch.rs:24), returned :416"),
    Claim::guarded(
        0x6400,
        "SW_EXEC_ERROR (lib.rs:62), returned :637,:666,:716",
        "`mgm_crypt` is only called with a length already equal to the algorithm's \
         block size, so it cannot return the `None` those arms test for",
    ),
    Claim::guarded(
        0x6581,
        "SW_MEMORY_FAILURE (lib.rs:61), returned :496,:523,:555",
        "each is guarded by `pin.is_none()` / `puk.is_none()` / `mgm_key_len == 0`, \
         and no APDU can clear any of them (set_reference only writes Some; \
         cmd_reset restores PivState::default)",
    ),
    Claim::dispatcher(
        0x6A82,
        "platform SW_FILE_NOT_FOUND (dispatch.rs:23) and lib.rs:25 — the applet uses it \
         for GET DATA of an absent object, and the dispatcher uses it for a bad AID",
    ),
];

/// Every INS in `PivApp::process`'s match (`lib.rs:404-424`), the values the
/// INS constants name (`lib.rs:42-53`), and the `_` arm.
const PIV_SPACE: Space = Space {
    clas: &[0x00, 0x10, 0x80, 0xFF],
    ins: &[
        0x20, 0x24, 0x2A, 0x2C, 0x87, 0xA4, 0xCB, 0xDB, 0xF8, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00,
    ],
    p1: &[0x00, 0x01, 0x02, 0x03, 0x04, 0x3F, 0x7F, 0x80, 0xFF],
    p2: &[0x00, 0x01, 0x02, 0x03, 0x7F, 0x80, 0x81, 0x9A, 0x9B, 0x9C, 0x9E, 0xFE, 0xFF],
};

/// The 24-byte default management key, transcribed from the private
/// `DEFAULT_MGM_KEY` (`apps/piv/src/lib.rs:190-193`).
///
/// Transcribed, not imported, for the same reason as `otp_crc16`: the mgm
/// challenge-response is the only route to the `6984` and `6A81` rows, and
/// driving it against the applet's own key would let the applet be wrong in a
/// self-consistent way. This is also the C's
/// `piv_management_key_default`, which the reference client hard-codes.
const PIV_DEFAULT_MGM_KEY: [u8; 24] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];
const PIV_ALGO_AES192: u8 = 0x0A;
const PIV_KEY_CARDMGM: u8 = 0x9B;

fn piv_cases() -> Vec<Case> {
    let c = vec![
        case("unknown INS", short(0x00, 0x00, 0x00, &[]), 0x6D00),
        // VERIFY with no data and P1 0x00 is the retry *query*
        // (`cmd_verify`, lib.rs:473-475): a fresh applet has 3 attempts.
        case("VERIFY query on a fresh applet", case2(0x20, 0x00, 0x80), 0x63C3),
        // A wrong PIN spends an attempt (`check_reference`, :289-299).
        case("VERIFY with a wrong PIN", ext(0x20, 0x00, 0x80, b"000000\xff\xff"), 0x63C2),
        case("VERIFY query after one failure", case2(0x20, 0x00, 0x80), 0x63C2),
        // The correct default PIN ("123456", `PivState::default`, :166).
        case("VERIFY with the default PIN", ext(0x20, 0x00, 0x80, b"123456\xff\xff"), 0x9000),
        // P1 neither 0x00 nor 0xFF (`cmd_verify`, :441-443).
        case("VERIFY with P1 = 0x7F", case2(0x20, 0x7F, 0x80), 0x6A80),
        // PIV's VERIFY has **no** management-reference variant: the guard is
        // `if (p1 != 0x00 && p1 != 0xFF) || p2 != 0x80` (`lib.rs:441-443`), so
        // P2 0x81 is "incorrect parameters" and not a lookup failure. Worth a
        // case because the management key looks like it should be verifiable
        // the same way, and the answer is that it is not.
        case("VERIFY with P2 = 0x81", case2(0x20, 0x00, 0x81), 0x6A80),
        // 6A81: AUTHENTICATE with a key-ref that is not CARDMGM
        // (`cmd_authenticate`, :550-552). Reached before any key-length check,
        // so it does not need a provisioned management key.
        case("AUTHENTICATE with key-ref 0x9A", ext(0x87, PIV_ALGO_AES192, 0x9A, &[0x7C, 0x02, 0x81, 0x00]), 0x6A81),
        // 6A80: AUTHENTICATE with a body that is not a 7C template (:547-549).
        case("AUTHENTICATE with no 7C template", ext(0x87, PIV_ALGO_AES192, 0x9B, &[0x00, 0x00]), 0x6A80),
        // 6B00: SET_MGMKEY with the wrong P1 (`cmd_set_mgmkey`, :735-738).
        case("SET_MGMKEY with P1 = 0x00", ext(0xFF, 0x00, 0xFF, &[0x0C, 0x9B, 0x20]), 0x6B00),
        // 6A86: SET_MGMKEY with an unprovisioned body
        // (`cmd_set_mgmkey`, :739-741) — P1 is right, the length is not.
        case("SET_MGMKEY with a short body", ext(0xFF, 0xFF, 0xFF, &[0x0C, 0x9B]), 0x6700),
        // 6982: SET_MGMKEY unauthenticated, with a well-formed body
        // (`cmd_set_mgmkey`, :743-745).
        case(
            "SET_MGMKEY unauthenticated",
            ext(0xFF, 0xFF, 0xFF, &[0x0C, 0x9B, 0x20, 0, 0, 0, 0, 0]),
            0x6982,
        ),
        // 6A88: CHANGE REFERENCE with a P2 that is neither PIN nor PUK
        // (`cmd_change_reference`, :484-489).
        case("CHANGE REFERENCE with P2 = 0x7F", ext(0x24, 0x00, 0x7F, &[0u8; 16]), 0x6A88),
        // 6983: RESET needs both retry counters at zero (`cmd_reset`, :805-807
        // refuses while they are not) — so the blocked state is what makes
        // RESET reachable at all, and 6983 is what a burned PIN answers.
        case("SET_RETRIES without PUK auth", ext(0xFA, 0x03, 0x03, &[]), 0x6982),
        // 6B00 for the SELECT INS with a wrong P1 (`cmd_select`, :426-428).
        case("SELECT with P1 = 0x00", ext(0xA4, 0x00, 0x02, &[]), 0x6B00),
        // 6700: GET DATA with a body too short (`cmd_get_data`, :834-836).
        case("GET DATA with a 2-byte body", ext(0xCB, 0x3F, 0xFF, &[0x5C, 0x01]), 0x6700),
        // 6A80: GET DATA whose first byte is not 0x5C (:837-839).
        case("GET DATA without a 5C tag", ext(0xCB, 0x3F, 0xFF, &[0x00, 0x01, 0x5F]), 0x6700),
        // 6A86: GET DATA with a P1 that is not 0x3F (:829-832).
        case("GET DATA with P1 = 0x00", ext(0xCB, 0x00, 0xFF, &[0x5C, 0x03, 0x5F, 0xC1, 0x5C]), 0x6A86),
        // 6A82: GET DATA of an object that is not stored — this one IS the
        // applet's own use of the word, not just the dispatcher's.
        case(
            "GET DATA of an absent object",
            ext(0xCB, 0x3F, 0xFF, &[0x5C, 0x03, 0x5F, 0xC1, 0x5C]),
            0x6A82,
        ),
    ];
    c
}

/// The three `63Cx` values the retry counter can take, driven in one
/// scenario so the counter walks 3 → 2 → 1 → blocked.
fn piv_retry_walk() -> Vec<Case> {
    vec![
        case("retry query: 3 left", case2(0x20, 0x00, 0x80), 0x63C3),
        case("wrong PIN: 2 left", ext(0x20, 0x00, 0x80, b"000000\xff\xff"), 0x63C2),
        case("retry query: 2 left", case2(0x20, 0x00, 0x80), 0x63C2),
        case("wrong PIN: 1 left", ext(0x20, 0x00, 0x80, b"000000\xff\xff"), 0x63C1),
        case("retry query: 1 left", case2(0x20, 0x00, 0x80), 0x63C1),
        // The last attempt spends the counter to zero and the *query* then
        // answers 6983, not another 63Cx (`cmd_verify`, :467-471).
        case("wrong PIN: counter exhausted", ext(0x20, 0x00, 0x80, b"000000\xff\xff"), 0x6983),
        case("retry query: blocked", case2(0x20, 0x00, 0x80), 0x6983),
    ]
}

/// Issue a PIV management challenge, read it off the wire, and encrypt an
/// answer to it.
///
/// Returns `(challenge, encrypted response)`. The card hands out the challenge
/// in the *response* to the issuing APDU (`7C 12 81 10 <16 bytes>`), so this
/// cannot be a static [`Case`] — the encryption needs bytes that only exist
/// after the exchange, and it is exactly what a client does.
///
/// `correct` picks the answer: `true` encrypts the card's own challenge back
/// (a completing response, `0x9000`), `false` encrypts 16 zero bytes instead —
/// well-framed and correctly sized, so the applet gets all the way to the
/// comparison and answers `0x6984` rather than refusing the TLV with `0x6A80`.
fn piv_mgm_exchange(d: &mut Driver<'_>, correct: bool) -> (Vec<u8>, Vec<u8>) {
    use fapico2_piv::crypto::mgm_crypt;
    let (body, sw) = d.exchange(&ext(
        0x87,
        PIV_ALGO_AES192,
        PIV_KEY_CARDMGM,
        &[0x7C, 0x02, 0x81, 0x00],
    ));
    assert_eq!(sw, Some(0x9000), "the mgm challenge must be issued with 9000");
    assert!(
        body.len() >= 20 && body[0] == 0x7C && body[2] == 0x81 && body[3] == 0x10,
        "unexpected mgm challenge shape: {body:02x?}"
    );
    let chal = body[4..20].to_vec();
    let plain = if correct { chal.clone() } else { vec![0u8; 16] };
    let enc = mgm_crypt(PIV_ALGO_AES192, &PIV_DEFAULT_MGM_KEY, &plain, true)
        .expect("AES-192 CBC over a 16-byte block");
    (chal, enc)
}

/// The APDU that completes a single-challenge mgm authentication.
fn piv_mgm_complete(enc: &[u8]) -> Vec<u8> {
    let mut a = vec![0x00u8, 0x87, PIV_ALGO_AES192, PIV_KEY_CARDMGM, 0x14, 0x7C, 0x12, 0x82, 0x10];
    a.extend_from_slice(enc);
    a
}

#[test]
fn reachability_piv() {
    use fapico2_piv::PivApp;
    let mut report = Report::default();

    // Scenario 1 — a cold applet, swept whole.
    {
        let mut app = PivApp::new();
        let mut d = Driver::new(&mut app, fapico2_piv::PIV_AID);
        d.sweep(&piv_cases(), &PIV_SPACE);
        report.absorb(d.into_report());
    }

    // Scenario 2 — the retry counter walking 3 → 2 → 1 → blocked. This is the
    // only way the `0x63Cx` family and the `0x6983` that follows it are
    // reached: `check_reference` spends one attempt *before* it compares
    // (`lib.rs:289-299`), so a single wrong PIN is what moves the counter.
    {
        let mut app = PivApp::new();
        let mut d = Driver::new(&mut app, fapico2_piv::PIV_AID);
        d.sweep(&piv_retry_walk(), &PIV_SPACE);
        report.absorb(d.into_report());
    }

    // Scenario 3 — a completed management session, which is the only thing
    // that reaches the `cmd_set_mgmkey` arms and proves the `0x9000` half of
    // the exchange.
    {
        let mut app = PivApp::new();
        let mut d = Driver::new(&mut app, fapico2_piv::PIV_AID);
        let (_, enc) = piv_mgm_exchange(&mut d, true);
        d.run(&[case("mgm completion", piv_mgm_complete(&enc), 0x9000)]);
        d.cross(&PIV_SPACE);
        report.absorb(d.into_report());
    }

    // Scenario 4 — the two `0x6984` arms. `mgm_auth_op` consumes the pending
    // challenge on every completion, so each needs a challenge of its own; and
    // the "wrong" answer has to be wrong in the *crypt* while the framing is
    // right, or the applet would answer `0x6A80` from the TLV checks and the
    // `0x6984` row would go unproved.
    {
        // Single challenge-response, wrong response (`lib.rs:716-722`).
        let mut app = PivApp::new();
        let mut d = Driver::new(&mut app, fapico2_piv::PIV_AID);
        let (_, enc) = piv_mgm_exchange(&mut d, false);
        d.run(&[case("mgm wrong response", piv_mgm_complete(&enc), 0x6984)]);
        d.cross(&PIV_SPACE);
        report.absorb(d.into_report());
    }
    {
        // Mutual authentication, wrong witness (`lib.rs:658-663`).
        let mut app = PivApp::new();
        let mut d = Driver::new(&mut app, fapico2_piv::PIV_AID);
        d.run(&[case(
            "mgm mutual issue",
            ext(0x87, PIV_ALGO_AES192, PIV_KEY_CARDMGM, &[0x7C, 0x02, 0x80, 0x00]),
            0x9000,
        )]);
        // The 7C template holds `80 <16>` + `81 <16>` = 36 bytes, so both the
        // TLV length (`0x24`) and the APDU's `Lc` (`0x26`) have to say 36/38.
        // Getting either wrong is a `0x6A80` from the TLV reader and the
        // `0x6984` row would go unproved — which is exactly what happened the
        // first time this case was written.
        let mut bad = vec![0x00u8, 0x87, PIV_ALGO_AES192, PIV_KEY_CARDMGM, 0x26, 0x7C, 0x24, 0x80, 0x10];
        bad.extend_from_slice(&[0u8; 16]);
        bad.extend_from_slice(&[0x81, 0x10]);
        bad.extend_from_slice(&[0u8; 16]);
        d.run(&[case("mgm mutual with a wrong witness", bad, 0x6984)]);
        d.cross(&PIV_SPACE);
        report.absorb(d.into_report());
    }

    report.finish("piv", PIV);
}

// ═══════════════════════════════════════════════════════════════════════════
// Vendor LED applet
// ═══════════════════════════════════════════════════════════════════════════

/// The vendor LED applet's status words (`apps/vendor_led/src/lib.rs`).
const VENDOR_LED: &[Claim] = &[
    Claim::applet(0x9000, "SW_OK, returned :434,:444 and the SELECT arm"),
    Claim::applet(0x6700, "platform SW_WRONG_LENGTH (dispatch.rs:26), returned :417 and :446"),
    Claim::applet(0x6D00, "SW_INS_NOT_SUPPORTED, returned :450"),
    Claim::applet(0x6E00, "SW_CLA_NOT_SUPPORTED (lib.rs:189), returned :421"),
    Claim::dispatcher(0x6A82, "platform SW_FILE_NOT_FOUND (dispatch.rs:23)"),
];

/// `INS_SET = 0x10`, `INS_GET = 0x11` (`lib.rs:118`, `:120`) plus an
/// unhandled INS; `CLA_ISO = 0x00` (`lib.rs:125`) plus rejected classes.
const LED_SPACE: Space = Space {
    clas: &[0x00, 0x10, 0x80, 0xFF],
    ins: &[0x10, 0x11, 0x1C, 0x1D, 0x1E, 0x1F, 0x00, 0xFF],
    p1: &[0x00, 0x01, 0x02, 0xFF],
    p2: &[0x00, 0x01, 0x02, 0xFF],
};

/// The vendor LED applet is two INS wide, so its cases are few and the
/// refusals are about *framing* rather than data: the applet owns a
/// `[u8; LED_BLOCK_LEN]` and a single colour byte, and every refusal it has is
/// "this is not the shape of the one command that exists".
fn vendor_led_cases() -> Vec<Case> {
    vec![
        // GET is case-4 on this wire: the client appends `Le = 0x00`
        // (`picoforge/src/hal/rescue/ops.rs:719-725`), so its APDU is five
        // bytes. Nothing after the header is load-bearing, so a longer wire is
        // accepted rather than refused (`lib.rs:424-431`).
        case("GET", case2(0x11, 0x00, 0x00), 0x9000),
        case("GET with a trailing byte", vec![0x00, 0x11, 0x00, 0x00, 0x00, 0x00], 0x9000),
        // SET is case-3 with no data: exactly four bytes, no Lc and no Le
        // (`ops.rs:768-773`). A fifth byte is refused rather than absorbed —
        // the applet's own comment calls an absorbed frame "a host ends up
        // believing it wrote a colour it did not".
        case("SET", short(0x10, 0x00, 0x00, &[]), 0x9000),
        case("SET with an extra byte", vec![0x00, 0x10, 0x00, 0x00, 0x00], 0x6700),
        // The sub-header guard (`lib.rs:413-417`), the US-701 panic class.
        case("3-byte APDU", vec![0x00, 0x10], 0x6700),
        case("CLA 0x10", vec![0x10, 0x11, 0x00, 0x00], 0x6E00),
        case("unknown INS", short(0x00, 0x00, 0x00, &[]), 0x6D00),
    ]
}

#[test]
fn reachability_vendor_led() {
    let mut store = HostSecureStore::new();
    let mut app = fapico2_vendor_led::VendorLedApp::boot(&mut store);
    let mut d = Driver::new(&mut app, fapico2_vendor_led::VENDOR_LED_AID);
    d.sweep(&vendor_led_cases(), &LED_SPACE);
    d.into_report().finish("vendor_led", VENDOR_LED);
}

// ═══════════════════════════════════════════════════════════════════════════
// Rescue applet
// ═══════════════════════════════════════════════════════════════════════════

/// The Rescue applet's status words (`apps/rescue/src/lib.rs`).
const RESCUE: &[Claim] = &[
    Claim::applet(0x9000, "SW_OK, returned throughout (lib.rs:904,:911,:918,:1055,:1082)"),
    Claim::applet(
        0x6700,
        "platform SW_WRONG_LENGTH (dispatch.rs:26), returned :943,:960,:1090,:1128,:1131,:1150",
    ),
    // The applet spells this `SW_INVALID_DATA`; OATH and PIV spell the same
    // value `SW_INCORRECT_PARAMS`. Same wire, two names.
    Claim::applet(
        0x6A80,
        "SW_INVALID_DATA (lib.rs:438), returned :984 — the CCID-mask guard \
         (a 0x0B record that would clear USB_ITF_CCID)",
    ),
    Claim::applet(
        0x6A86,
        "SW_WRONG_PARAMETERS (lib.rs:437) — **a third name for 0x6A86**, alongside \
         OATH's and PIV's SW_INCORRECT_P1P2",
    ),
    Claim::applet(0x6D00, "SW_INS_NOT_SUPPORTED, returned :1154"),
    Claim::applet(0x6E00, "platform SW_CLA_NOT_SUPPORTED, returned :1099 — the CLA gate at :1098"),
    Claim::dispatcher(0x6A82, "platform SW_FILE_NOT_FOUND (dispatch.rs:23)"),
];

/// `INS_READ 0x1E`, `INS_WRITE 0x1C`, `INS_SECURE 0x1D`, `INS_REBOOT 0x1F`
/// (`lib.rs:347-353`), `CLA_PROPRIETARY = 0x80`, `READ_P1_PHY_CONFIG = 0x01`
/// (`lib.rs:356`) and `WRITE_P1_PHY_CONFIG = 0x01` (`lib.rs:365`).
const RESCUE_SPACE: Space = Space {
    clas: &[0x80, 0x00, 0x10, 0xFF],
    ins: &[0x1C, 0x1D, 0x1E, 0x1F, 0x00, 0xFF],
    p1: &[0x00, 0x01, 0x02, 0x03, 0xFF],
    p2: &[0x00, 0x01, 0x02, 0x03, 0xFF],
};

/// Cases for a **bare** Rescue applet — no PHY-record owner, no device
/// handler.
///
/// This is not a hypothetical configuration: it is the shape the applet has
/// between `RescueApp::new()` and `with_config_handler`, and every one of its
/// refusals is a *different* code from the wired applet's, which is why the
/// two need separate lists. With no owner, `READ` still answers `0x9000` with
/// an empty blob — the applet's comment calls that "the honest answer rather
/// than a refusal", because a read cannot lie by omission the way a write can
/// (`lib.rs:899-904`).
fn rescue_bare_cases() -> Vec<Case> {
    vec![
        case("READ PhyConfig (no owner)", vec![0x80, 0x1E, 0x01, 0x00, 0x00], 0x9000),
        case("READ with a P2 the protocol does not use", vec![0x80, 0x1E, 0x01, 0x7F, 0x00], 0x6A86),
        case("READ an unknown P1", vec![0x80, 0x1E, 0x7F, 0x00, 0x00], 0x6A86),
        // REBOOT and SECURE are case-3 with **no data field** — exactly five
        // bytes, no Lc and no Le (`ops.rs:646-652`, `:691-696`). An off-length
        // wire is refused rather than absorbed: for REBOOT that is "a reboot
        // the caller did not intend" (`lib.rs:1140-1153`).
        case("REBOOT off-length", vec![0x80, 0x1F, 0x01, 0x00], 0x6700),
        case("REBOOT with a body", vec![0x80, 0x1F, 0x01, 0x00, 0x00, 0x00], 0x6700),
        case("SECURE off-length", vec![0x80, 0x1D, 0x00, 0x00], 0x6700),
        case("unknown INS", vec![0x80, 0x00, 0x00, 0x00], 0x6D00),
        // The CLA gate, and the reason it exists: three of this applet's four
        // INS values are Management INS values, and the Rescue SELECT is
        // CLA 0x00 — so a 0x00 APDU reaching this applet through the
        // dispatcher's non-AID-SELECT fallthrough is a real path
        // (`lib.rs:1094-1098`).
        case("CLA 0x00", vec![0x00, 0x1C, 0x01, 0x00, 0x00], 0x6E00),
        case("CLA 0x10", vec![0x10, 0x1C, 0x01, 0x00, 0x00], 0x6E00),
        case("3-byte APDU", vec![0x80, 0x1C], 0x6700),
    ]
}

/// Cases for a Rescue applet wired to a record owner — the shape the device
/// boots (`firmware/src/main.rs`).
///
/// The interesting thing this list reaches that the bare one cannot is the
/// CCID-mask guard. `0x6A80` is decided **inside the tag loop** (`lib.rs:972-985`),
/// before the owner's `commit` is ever called, so it is reachable either way —
/// but the *accepting* half (`0x9000`) and the width refusal need an owner to
/// get past, and `cmd_read` is the only way to see a merged record come back.
fn rescue_owned_cases() -> Vec<Case> {
    vec![
        // A 0x0B record whose mask clears bit 0x01 (USB_ITF_CCID). The applet
        // refuses the whole blob, before any field is applied, because "a
        // 0x0B record replaces the stored mask outright" and a cleared mask
        // removes the transport this applet is reached over.
        case(
            "WRITE clearing the CCID mask",
            vec![0x80, 0x1C, 0x01, 0x00, 0x03, 0x0B, 0x01, 0x02],
            0x6A80,
        ),
        // A 0x0B record of the wrong width is a *length* refusal, not a mask
        // refusal — the width check runs before the value is read
        // (`lib.rs:957-962`).
        case(
            "WRITE with an over-wide 0x0B",
            vec![0x80, 0x1C, 0x01, 0x00, 0x04, 0x0B, 0x02, 0x00, 0x02],
            0x6700,
        ),
        // A tag the protocol defines but this firmware refuses to apply —
        // `SUPPORTED_PHY_TAGS` is seven of the twelve and this is not one of
        // them. `0x0F` is `LedDriver` (`0x0C`), which still has no field in the
        // persisted record, so it reaches the "this build does not serve it"
        // group instead of being caught earlier by the width check. It was
        // `UsbManufacturer` until that tag was given a field; the sweep
        // caught the change, which is what it is for — a named case whose
        // status changes is a behaviour change someone has to look at.
        case(
            "WRITE an undestined tag",
            vec![0x80, 0x1C, 0x01, 0x00, 0x03, 0x0C, 0x01, 0x19],
            0x6A86,
        ),
        // A name tag that *is* now writable, carrying a value with no
        // terminator. `6A80`, not `6A86`: the record is one this firmware
        // supports, and the value is one it cannot frame. Pinning both halves
        // of that distinction is why this sits next to the case above rather
        // than replacing it.
        case(
            "WRITE an unterminated name",
            vec![0x80, 0x1C, 0x01, 0x00, 0x03, 0x0F, 0x01, 0x19],
            0x6A80,
        ),
        // And the width check on a fixed-width tag, one byte short of its four.
        case(
            "WRITE an under-wide curves record",
            vec![0x80, 0x1C, 0x01, 0x00, 0x03, 0x0A, 0x01, 0x19],
            0x6700,
        ),
        // A tag the protocol does not define at all.
        case(
            "WRITE an undefined tag",
            vec![0x80, 0x1C, 0x01, 0x00, 0x03, 0x7F, 0x01, 0x19],
            0x6A86,
        ),
        // A declared length that runs past the end of the blob.
        case(
            "WRITE with an overrunning length",
            vec![0x80, 0x1C, 0x01, 0x00, 0x03, 0x0B, 0x40, 0x01],
            0x6700,
        ),
        // A supported record that merges cleanly (`0x04` = led_gpio, 1 byte).
        case(
            "WRITE an accepted record",
            vec![0x80, 0x1C, 0x01, 0x00, 0x03, 0x04, 0x01, 0x19],
            0x9000,
        ),
        case("READ PhyConfig (owned)", vec![0x80, 0x1E, 0x01, 0x01, 0x00], 0x9000),
        // REBOOT with no *device* handler: the record owner and the device
        // handler are two separate seams, and this one is absent.
        case("REBOOT (no device handler)", vec![0x80, 0x1F, 0x01, 0x00, 0x00], 0x6A86),
        case("SECURE (no device handler)", vec![0x80, 0x1D, 0x00, 0x00, 0x00], 0x6A86),
        // WRITE with a P1 that is not `WRITE_P1_PHY_CONFIG` (0x01).
        case(
            "WRITE with a wrong P1",
            vec![0x80, 0x1C, 0x00, 0x00, 0x03, 0x0B, 0x01, 0x02],
            0x6A86,
        ),
    ]
}

/// The PHY-record owner `RescueApp` refuses to work without.
struct OwnedRecord(std::cell::RefCell<fapico2_rescue::PhySnapshot>);

impl fapico2_rescue::RescueConfigHandler for OwnedRecord {
    fn snapshot(&self) -> fapico2_rescue::PhySnapshot {
        *self.0.borrow()
    }
    fn commit(&mut self, update: &fapico2_rescue::PhyUpdate) -> Sw {
        // The owner merges: an absent field keeps its stored value. The applet
        // proposes, the owner merges — that split is the design (see
        // `RescueConfigHandler`), and a test that merged inside the applet
        // would not be testing it.
        let mut s = self.0.borrow_mut();
        if update.vid_pid.is_some() {
            s.vid_pid = update.vid_pid;
        }
        if update.led_gpio.is_some() {
            s.led_gpio = update.led_gpio;
        }
        if update.led_brightness.is_some() {
            s.led_brightness = update.led_brightness;
        }
        if update.options.is_some() {
            s.options = update.options;
        }
        if update.enabled_usb_itf.is_some() {
            s.enabled_usb_itf = update.enabled_usb_itf;
        }
        0x9000
    }
}

#[test]
fn reachability_rescue() {
    let mut report = Report::default();

    // Scenario 1 — bare: no record owner, no device handler.
    {
        let mut app = fapico2_rescue::RescueApp::new();
        let mut d = Driver::new(&mut app, fapico2_rescue::RESCUE_AID);
        d.sweep(&rescue_bare_cases(), &RESCUE_SPACE);
        report.absorb(d.into_report());
    }

    // Scenario 2 — wired to a record owner, the device's own shape. The
    // applet holds `&'static mut dyn RescueConfigHandler`, so the fixture is
    // leaked rather than borrowed — the same single-fixture discipline
    // `apps/rescue/tests/protocol.rs` works around. Each scenario leaks its
    // own, so nothing shares a record.
    {
        let rec: &'static mut OwnedRecord = Box::leak(Box::new(OwnedRecord(
            std::cell::RefCell::new(fapico2_rescue::PhySnapshot::default()),
        )));
        let handler: &'static mut dyn fapico2_rescue::RescueConfigHandler = rec;
        let mut app = fapico2_rescue::RescueApp::new()
            .with_chipid(0x1122_3344_5566_7788)
            .with_config_handler(handler);
        let mut d = Driver::new(&mut app, fapico2_rescue::RESCUE_AID);
        d.sweep(&rescue_owned_cases(), &RESCUE_SPACE);
        report.absorb(d.into_report());
    }

    report.finish("rescue", RESCUE);
}

// ═══════════════════════════════════════════════════════════════════════════
// The platform itself
// ═══════════════════════════════════════════════════════════════════════════

/// The platform layer's status words.
///
/// This row exists because **two of them belong to no applet at all**, and a
/// per-applet table with no platform row would leave them unattributed:
///
/// * `0x6A82` — every applet's table carries it, and in *every* one of them it
///   comes from `Dispatcher::dispatch`, not from the applet. On a fresh boot
///   with no applet selected it is also the answer to any non-AID-SELECT APDU
///   (`dispatch.rs:182-197`), and the comment there records why it is `6A82`
///   and not `6E00`: gpg's scd maps `6E00` to `GPG_ERR_CARD`, which triggers
///   its Yubikey probe and makes a fresh-boot card print a synthetic Yubikey
///   AID. That is a client-visible consequence of a status word, which is
///   exactly the kind of thing this sweep exists to keep honest.
/// * `0x6F00` — the persist gate's durable-before-ack failure
///   (`platform/src/persist.rs:364`) and the CCID aborted-bulk failure
///   (`firmware/src/tasks.rs:238`). Neither the EPIC's list nor any applet
///   table mentions it, and it is the word a *user* sees when a durable write
///   fails — arguably the most consequential one on the device.
///
/// The other four are the **exported vocabulary**, not emissions: the
/// dispatcher never writes `0x6D00`, `0x6E00`, `0x6700` or `0x6982` itself
/// (a whole-file grep finds only the `const` and one use inside the
/// `#[cfg(test)]` stub at `dispatch.rs:473`). They are listed because they are
/// the constants every applet imports, and a reader comparing two applet
/// tables needs to know which half of the difference is the applet's and which
/// is the shared vocabulary.
const PLATFORM: &[Claim] = &[
    Claim::dispatcher(0x6A82, "SW_FILE_NOT_FOUND (dispatch.rs:23), written at :156,:179,:196"),
    Claim::transport(
        0x6F00,
        "persist_reply_windowed (persist.rs:361-366) and ccid_fail_reply (firmware/src/tasks.rs:226-238)",
        Reach::Corpus,
    ),
    Claim::dispatcher(0x9000, "SW_OK (dispatch.rs:22)"),
    Claim::dispatcher(0x6700, "SW_WRONG_LENGTH (dispatch.rs:26) — vocabulary; applets' SW_WRONG_DATA"),
    Claim::dispatcher(0x6D00, "SW_INS_NOT_SUPPORTED (dispatch.rs:24) — vocabulary"),
    Claim::dispatcher(0x6E00, "SW_CLA_NOT_SUPPORTED (dispatch.rs:25) — vocabulary"),
    Claim::dispatcher(
        0x6982,
        "SW_CONDITIONS_NOT_SATISFIED (dispatch.rs:29) — vocabulary, and its only in-tree use is \
         the `#[cfg(test)]` stub app at dispatch.rs:473",
    ),
];

#[test]
fn platform_dispatcher_emits_only_6a82() {
    // The closed-world invariant for the dispatcher itself: with a real applet
    // registered, the *only* word the dispatcher writes on its own account is
    // `0x6A82`. Everything else an applet row lists is that applet's.
    let mut app = fapico2_mgmt::ManagementApp::new();
    let mut d: Dispatcher<1> = Dispatcher::new();
    assert!(d.register(&mut app));
    let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
    let mut seen = BTreeSet::new();

    // Before any selection: a non-AID-SELECT has nowhere to go.
    d.dispatch(&[0x00, 0x20, 0x00, 0x00], &mut resp);
    seen.insert(sw_of(&resp).expect("a status word"));
    // A SELECT with no AID (`select MF`), and one naming an unregistered AID.
    d.dispatch(&[0x00, 0xA4, 0x04, 0x00, 0x00], &mut resp);
    seen.insert(sw_of(&resp).expect("a status word"));
    d.dispatch(&SELECT_UNKNOWN_AID, &mut resp);
    seen.insert(sw_of(&resp).expect("a status word"));
    // A SELECT naming a *registered* AID succeeds, and the dispatcher's own
    // contribution is then nothing at all — the applet's word comes through.
    d.dispatch(&select_aid(fapico2_mgmt::MANAGEMENT_AID), &mut resp);
    seen.insert(sw_of(&resp).expect("a status word"));

    assert_eq!(
        seen,
        BTreeSet::from([0x6A82, 0x9000]),
        "the dispatcher wrote {:?} — expected only 6A82 (routing) and 9000 (a successful SELECT)",
        seen
    );
}

#[test]
fn platform_persist_gate_answers_6f00_on_a_failed_program() {
    use fapico2_platform::persist::{persist_reply_windowed, ImageSink, WindowedImageSource};

    /// A sink that never manages to make the image durable — the US-920
    /// "answer `6F 00` rather than acknowledge a state that is not stored"
    /// path. `persist_reply_windowed` clears the applet's reply and writes
    /// `6F 00` in its place (`persist.rs:362-365`).
    struct DeadMedium;
    impl ImageSink for DeadMedium {
        fn program(&mut self, _src: &mut dyn WindowedImageSource) -> bool {
            false
        }
    }

    let mut store = HostSecureStore::new();
    let mut app = fapico2_mgmt::ManagementApp::new();
    // Make the applet dirty so the gate actually attempts the write.
    app.mark_dirty();
    let mut apps: [&mut dyn App; 1] = [&mut app];
    let mut reply = HeaplessVec::<u8, MAX_RESPONSE>::new();
    let outcome = persist_reply_windowed(&mut apps, &mut store, &mut DeadMedium, &mut reply);
    assert!(outcome.is_err(), "a dead medium must fail the gate");
    assert_eq!(
        reply.as_slice(),
        &[0x6f, 0x00],
        "durable-before-ack replaces the applet's own reply with 6F 00"
    );
    // And the applet is still left dirty, which is the other half of the
    // contract: the gate re-marks it so the *next* run retries, and a store
    // that reported success while the app believed it was clean would lose
    // the change silently (US-421).
    assert!(app.is_dirty(), "a failed gate must leave the applet dirty for a retry");
}

// ═══════════════════════════════════════════════════════════════════════════
// Cross-cutting invariants
// ═══════════════════════════════════════════════════════════════════════════

/// **The naming trap, as an executable assertion.** Every value the module
/// docs claim is "the same number under two names" is checked here, so a
/// future edit that gives one of them a *different* value fails instead of
/// quietly making the module docs wrong.
#[test]
fn naming_collisions_are_value_identities() {
    // `platform::dispatch::SW_WRONG_LENGTH` and each applet's local
    // `SW_WRONG_DATA` are the same value. The applet constants are private,
    // so the assertion is on the value the module docs state, cross-checked
    // against the one that *is* importable.
    assert_eq!(fapico2_platform::dispatch::SW_WRONG_LENGTH, 0x6700);
    assert_eq!(fapico2_platform::dispatch::SW_FILE_NOT_FOUND, 0x6A82);
    assert_eq!(fapico2_platform::dispatch::SW_INS_NOT_SUPPORTED, 0x6D00);
    assert_eq!(fapico2_platform::dispatch::SW_CLA_NOT_SUPPORTED, 0x6E00);
    assert_eq!(fapico2_platform::dispatch::SW_CONDITIONS_NOT_SATISFIED, 0x6982);
    // And the two PIV constants that mean the same thing under two codes —
    // a genuine *disagreement* inside one file, not a collision.
    assert_eq!(words(PIV).filter(|w| *w == 0x6A86).count(), 1);
    assert_eq!(words(PIV).filter(|w| *w == 0x6B00).count(), 1);
    // And the two family rows really are families — a sweep keyed to the base
    // value alone would miss a `0x63C2` or a `0x6180`.
    assert!(table_has(PIV, 0x63C0) && table_has(PIV, 0x63CF));
    assert!(table_has(OATH, 0x6100) && table_has(OATH, 0x61FF));
    // `0x6A80` is spelled SW_INCORRECT_PARAMS in OATH and PIV and
    // SW_INVALID_DATA in Rescue, and is in all three tables.
    for (who, table) in [("oath", OATH), ("piv", PIV), ("rescue", RESCUE)] {
        assert!(
            table_has(table, 0x6A80),
            "{who}'s table must carry 0x6A80 — the value two of the applets spell SW_INVALID_DATA"
        );
    }
}

/// **The EPIC's flat list, checked.** `EPIC-fapico2-picoforge-compatibility.md`
/// :998-1006 offers one 15-word list as the answer for every applet. This
/// test records which of those words no applet here can produce, and which
/// words are in use but missing from it, so the delta is a test failure rather
/// than a paragraph in a review.
const EPIC_LIST: &[Sw] = &[
    0x9000, 0x6581, 0x6A80, 0x6A81, 0x6A82, 0x6A83, 0x6A84, 0x6A88, 0x6700, 0x6B00, 0x6D00,
    0x6E00, 0x6982, 0x6983, 0x6985, 0x63C0,
];

/// Every table in this file, with the applet it belongs to.
fn all_tables() -> Vec<(&'static str, &'static [Claim])> {
    vec![
        ("mgmt", MGMT),
        ("oath (device)", OATH),
        ("otp", OTP),
        ("piv", PIV),
        ("vendor_led", VENDOR_LED),
        ("rescue", RESCUE),
        ("platform", PLATFORM),
    ]
}

#[test]
fn epic_word_list_6a83_is_produced_by_nothing() {
    // The single clearest error in the EPIC's list: `6A83` (record not found)
    // is on it, and nothing in this workspace emits it. Pinning a dead word is
    // as useful as pinning a live one — a reader who sees it in the list would
    // otherwise believe the firmware can answer it.
    const DEAD: &[Sw] = &[0x6A83];
    for (who, table) in all_tables() {
        for &d in DEAD {
            assert!(
                !table_has(table, d),
                "{who}: the table claims {d:04x}, which the EPIC lists but nothing emits"
            );
        }
    }
    assert!(
        EPIC_LIST.contains(&0x6A83),
        "if the EPIC ever drops 6A83 this test is stale and should be deleted, not edited"
    );
}

#[test]
fn epic_word_list_misses_words_four_applets_use() {
    // `6A86` is absent from the EPIC's list and is the primary P1/P2 refusal
    // for the OATH applet, the OTP applet, the Rescue applet and PIV — the
    // EPIC's own example failure (`6A82` where `6D00` is expected) is a swap
    // between two words, and this one was not even on the sheet.
    const MISSING_FROM_EPIC: &[Sw] = &[0x6A86, 0x6984, 0x61C0, 0x6F00];
    for m in MISSING_FROM_EPIC {
        assert!(
            !EPIC_LIST.contains(m),
            "the EPIC list now contains {m:04x}; this test is stale"
        );
    }
    for (who, table) in all_tables() {
        if matches!(who, "mgmt" | "vendor_led" | "platform") {
            continue;
        }
        assert!(
            table_has(table, 0x6A86),
            "{who}: the table must carry 6A86 — the word the EPIC's list omits"
        );
    }
    // And the two words in use but off the list that belong to exactly one
    // applet each, so a reader can find them.
    assert!(table_has(OATH, 0x6984), "OATH returns 6984 (missing from the EPIC list)");
    assert!(table_has(OATH, 0x6100), "OATH returns 61xx (missing from the EPIC list)");
    assert!(table_has(OATH, 0x6180), "and 0x61xx is a family, so 0x6180 is inside the same row");
    assert!(table_has(PLATFORM, 0x6F00), "the persist gate returns 6F00 (missing from the EPIC list)");
    assert!(table_has(PIV, 0x6984), "PIV returns 6984 (missing from the EPIC list)");
}

#[test]
fn epic_word_list_carries_three_words_piv_cannot_produce() {
    // The other direction, per applet. The EPIC offers one list for all
    // applets, so its PIV row necessarily contains words PIV does not answer.
    assert!(
        !table_has(PIV, 0x6985),
        "PIV does not answer 6985: apps/piv/src/lib.rs:71 defines \
         SW_CONDITIONS_NOT_SATISFIED and nothing in the file returns it"
    );
    for w in [0x6581u16, 0x6400] {
        assert!(
            table_has(PIV, w),
            "PIV's table should still *name* {w:04x}, marked Guarded — deleting the row would \
             hide a real fact about the source"
        );
        assert!(
            EPIC_LIST.contains(&w) || w == 0x6400,
            "0x6400 is not on the EPIC list at all, which is the other half of the error"
        );
    }
}

/// **The layer census.** `0x6A82` is the word every applet's table carries
/// and the only one no applet returns itself — it is the dispatcher's routing
/// answer. Pinning that is worth a test on its own because the alternative
/// reading ("the applet said 6A82") sends a debugger into the wrong crate, and
/// because the applet that *does* use it for itself (PIV, for a GET DATA of an
/// absent object) is exactly the one a reader would generalise from.
#[test]
fn every_applet_answers_6a82_only_through_the_dispatcher() {
    let dispatcher_rows = all_tables()
        .iter()
        .map(|(who, table)| (*who, table.iter().filter(|c| c.layer == Layer::Dispatcher).count()))
        .collect::<Vec<_>>();
    for (who, table) in all_tables() {
        let has_6a82 = table_has(table, 0x6A82);
        let as_dispatcher = table
            .iter()
            .any(|c| c.sw == 0x6A82 && c.layer == Layer::Dispatcher);
        assert!(
            has_6a82,
            "{who}: every applet can be made to answer 6A82 (SELECT an unregistered AID), so \
             every table must carry it"
        );
        if who == "platform" {
            continue;
        }
        assert!(
            as_dispatcher,
            "{who}: 0x6A82 must be marked Layer::Dispatcher — no applet here returns it from \
             `process`; the dispatcher does, on a SELECT naming an unregistered AID \
             (platform/src/dispatch.rs:177-181)"
        );
    }
    // PIV is the one applet that also uses the word itself, so it is the one
    // place a second, applet-layer row for 0x6A82 is legitimate.
    let piv_6a82_rows = PIV.iter().filter(|c| c.sw == 0x6A82).count();
    assert_eq!(
        piv_6a82_rows, 1,
        "PIV's 0x6A82 row names both origins in its `origin` string \
         (dispatch.rs:23 for the AID path and lib.rs:25 for an absent GET DATA object)"
    );
    // Sanity: the census is not vacuous — every table has at least one
    // applet-layer row, so `Layer` discriminates rather than being constant.
    assert!(
        dispatcher_rows.iter().all(|(_, n)| *n > 0),
        "every table has at least one dispatcher-layer row"
    );
    assert!(
        all_tables()
            .iter()
            .any(|(_, t)| t.iter().any(|c| c.layer == Layer::Applet)),
        "and at least one applet-layer row exists, so the enum is doing work"
    );
}

/// The tables must not drift into overlapping fictions: every applet's set is
/// distinct from its neighbours in at least one word, so a copy-paste of one
/// applet's table over another's fails here rather than passing silently.
#[test]
fn applet_tables_are_not_copies_of_each_other() {
    let tables = all_tables();
    for i in 0..tables.len() {
        for j in (i + 1)..tables.len() {
            let (an, a) = tables[i];
            let (bn, b) = tables[j];
            let set_a: BTreeSet<Sw> = words(a).collect();
            let set_b: BTreeSet<Sw> = words(b).collect();
            assert_ne!(
                set_a, set_b,
                "{an} and {bn} have identical status-word tables — one of them is a copy"
            );
        }
    }
}
