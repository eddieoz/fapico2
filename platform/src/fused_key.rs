//! US-1572 — **no root key outlives the operation that used it.**
//!
//! # The rule
//!
//! A root key that sits in a struct for the life of the process has an exposure
//! window equal to the process. RS-Key states the discipline in one sentence
//! (`../RS-Key/crates/rsk-crypto/src/kdf.rs:41-53`):
//!
//! ```c
//! /// How a holder obtains a fused device key at the moment it needs one: a read of
//! /// the OTP fuses, not a copy kept in RAM. Carried instead of the key itself so a
//! /// bug that discloses adjacent memory has nothing to disclose — the OTP window is
//! /// not RAM. `None` on an unprovisioned device.
//! pub type FusedKey = fn() -> Option<[u8; 32]>;
//! /// … Zeroized when the binding drops, so it must be a local of whoever builds the
//! /// `Device` that borrows it — that lifetime IS the exposure window.
//! pub type FusedRead = Option<Zeroizing<[u8; 32]>>;
//! ```
//!
//! Two failures it is aimed at are already in this tree, and they are worth
//! naming because only one of them is a "bug":
//!
//! * `drbg_seed.rs:197-256` — the DRBG seed is re-read and re-drawn per call
//!   into a `Zeroizing` local, with the comment "there is deliberately no named
//!   intermediate that would outlive it". That is the model, and this module is
//!   the same shape extended to the store key.
//! * pico-hsm, `sc_hsm.c:47-48, 249` — `session_pin` / `session_sopin` sit in
//!   static BSS for the whole power cycle and the *flags* around them are what
//!   get cleared. The value is never cleared, because nothing owns it. That is
//!   not a subtle bug: it is what "held a key, then unset a bool" looks like,
//!   and it is the outcome this module exists to make unavailable.
//!
//! # What a [`FusedKey`] is, and what it is not
//!
//! A [`FusedKey`] holds **where the key comes from** — an `fn` that re-reads
//! the inputs on every call — and never the key. [`FusedKey::read`] returns a
//! [`FusedRead`]: one operation's materialised copy, in a [`Zeroizing`], that is
//! cleared when the operation's binding drops. The exposure window is therefore
//! one operation, and not by discipline alone: there is no value in the struct to
//! outlive it. A memory-disclosure bug in the holder (the `static mut STORE`
//! the firmware keeps the secure store in is exactly such a holder) finds an
//! `&'static str` and a function pointer where the root used to be.
//!
//! The one deviation from RS-Key's spelling is deliberate and is in
//! [`FusedReader`]: the reader returns `Zeroizing<[u8; 32]>` rather than a plain
//! `[u8; 32]`, so no moment exists — not even a single `return` — at which a
//! plain copy of a root key is in RAM. The cost is one constructor call.
//!
//! # The cost, stated and measured
//!
//! Re-deriving per use is an HKDF-SHA256 over 40 bytes of input: one extract
//! (one HMAC) plus one expand block (one HMAC, one SHA-256 compression). On the
//! RP2350 that is a few microseconds, against a CTAP2 ceremony that also does an
//! ECDH and a user touch. **The OTP row read is the expensive part** — sixteen
//! ECC-corrected word reads (`read_ecc_word`), which is why this module makes
//! the read a *reader* rather than a cached value: the cost is paid once per
//! operation that needs the key, not once per boot. The store's own hot path
//! seals one partition image per persist, so the store pays it once per
//! persist, not once per credential write.
//!
//! It is still a real cost, and the honest way to have taken it is to name the
//! attack it stops: **a memory disclosure in anything holding the store —
//! the firmware's `static mut boot::STORE`, a debugger, a crash dump, a core
//! file — hands the attacker a key that decrypts every credential on the
//! board, for as long as the process lives.** Against that, one HKDF and
//! sixteen register reads per persist is not a close call. It is also why the
//! alternative — caching the root and clearing it on the way out — is not
//! offered: a static is never dropped, so a `Drop` on it never runs, which is
//! precisely pico-hsm's shape.
//!
//! # What is still resident, and is not this module's to fix
//!
//! * [`KeySource::Resident`] — the pre-US-1572 `set_store_key([u8; 32])` entry
//!   point, kept because callers outside this story's ownership still call it
//!   (`firmware/src/main.rs:595`, `firmware/src/bin/bridge.rs:132`, and four
//!   test files). It now at least *owns* a [`Zeroizing`] with a real `Drop`
//!   where the plain `[u8; 32]` field had none, so the key is cleared when the
//!   store is dropped or replaced rather than never. Switching the device path
//!   to [`KeySource::Fused`] is one line per call site.
//! * `SecureStore::store_key()` returns `Option<[u8; 32]>` **by copy**, and its
//!   callers (`platform/src/persist.rs:505`,
//!   `apps/fido/src/device_keystore.rs:1109,1618`) are outside this story's
//!   ownership. The store's own paths go through [`KeySource::read`] and hold a
//!   [`FusedRead`]; that trait method remains the by-copy seam.
//! * The OATH seal (`ckey::OathSeal`, held by `OathApp` in a `static mut` and
//!   derived once at boot by `boot::derive_oath_seal`) is the second instance
//!   of this story's anti-pattern, and **US-1572's BDD names it** — so the
//!   honest status is partial, not deferred. It is not "the same conversion",
//!   and the difference is structural:
//!
//!   [`FusedKey`] fuses **one** `[u8; KEY_LEN]`, re-read per operation through
//!   a closure. That works for the store key because the store *has a medium
//!   to read it back from* — its own encrypted image. `OathSeal` has no such
//!   medium and is not one value: it is a three-field derived struct
//!   (`ckey.rs:394-402`) — `kenc` and `nonce_key` from two different
//!   derivations over the same inputs, plus a 16-byte `aad` that is *not* key
//!   material at all.
//!
//!   So the conversion needs a container for a derived **struct** (or three
//!   fused sources), not a length-generic [`FusedKey`], and every use site in
//!   `apps/oath` changes from `self.seal.x` to a per-operation handle. That is
//!   a real piece of work across files this story does not own, and it is not
//!   taken here rather than taken badly.
//!
//!   **What it would buy, stated so the trade is legible:** today the seal
//!   sits in RAM for one session — 16 bytes plus a nonce root, cleared on drop
//!   (`ckey.rs:390-393`). The store key's residual is the larger one, and it
//!   is the one US-1572 closed. Naming the sizes is the point: this is a
//!   bounded, stated exposure, not an unbounded root key.
//!
//! # The zeroize assertion, and how it is made
//!
//! "The key is cleared when it goes out of scope" is a claim about bytes that
//! are, by then, in freed stack — there is no sound way for a test to read them
//! afterwards. So it is not asserted by reading them. [`FusedRead`]'s `Drop`
//! records, *after* its explicit zeroize, what the buffer held and whether it
//! had been non-zero at all; [`testing`] exposes that record. The `Drop` body
//! under test is the production one — the device build runs the same lines with
//! the recording call compiled out (`keyregion/crypto.rs` does this for the
//! region keys, and the argument is the same one).

use core::mem::size_of;
use zeroize::{Zeroize, Zeroizing};

/// AES-256 key width — the same value [`crate::ckey::KEY_LEN`] carries, named
/// here so the fused types and their tests do not restate it.
pub const KEY_LEN: usize = 32;

/// How a holder materialises a fused key **at the moment it needs one**.
///
/// A plain `fn`, not a closure and not a trait object: this is `no_std` with no
/// allocator, and a `fn` pointer is a code address, so the descriptor cannot
/// capture anything — there is no place for a key to hide in it even by
/// accident. The cost is that a reader can only reach `'static` inputs, which
/// is precisely the point: the inputs are the OTP row and the chip id, both of
/// which *are* `'static` hardware.
///
/// Returns [`Zeroizing`] rather than a plain array, unlike RS-Key's
/// `fn() -> Option<[u8; 32]>`: the plain variant has a window between the
/// reader's `return` and the caller's `Zeroizing::new` in which a root key is
/// in an ordinary stack slot, and the whole claim of this module is that no
/// such window exists.
pub type FusedReader = fn() -> Option<Zeroizing<[u8; KEY_LEN]>>;

/// Where a fused key comes from — never the key.
///
/// Deliberately neither `Copy`, nor `Clone`, nor `Debug`:
///
/// * not `Copy` / `Clone` — a duplicate of a key descriptor is one more
///   value to keep in step, and RS-Key's own argument (`kdf.rs:44-47`) is that
///   what is carried must contain nothing worth disclosing. Keeping this one
///   un-duplicable makes "how many holders of a root key exist" a question with
///   one answer;
/// * not `Debug` — an accidental `{:?}` on a key-bearing type is a disclosure.
///   The same rule `ckey::OathSeal` follows (`ckey.rs:390-397`).
///
/// **It cannot hold key material, and that is checked, not asserted.** The
/// [`const`] gate below pins its size to two pointers, so "this struct has no
/// 32-byte array in it" is a property of the type rather than a convention. A
/// future edit that adds a cached key to this struct fails to compile.
pub struct FusedKey {
    /// Provenance label — `"rp2350/otp/store"` and friends. Carried so the
    /// host witness can say *which* root a drop belonged to, and so a log line
    /// naming a key names its source rather than the key.
    origin: &'static str,
    read: FusedReader,
}

/// The size fence named in [`FusedKey`]'s docs: a `&'static str` and a `fn`
/// pointer are two words each on every target this firmware builds.
const _: () = assert!(
    size_of::<FusedKey>() <= 4 * size_of::<usize>(),
    "FusedKey must stay pointer-sized: a root key has no business being stored in it"
);

impl FusedKey {
    /// A fused source over a [`FusedReader`].
    ///
    /// `origin` is provenance, not a secret, and is deliberately a `&'static
    /// str` so it cannot be allocated per key or leak a caller-owned buffer.
    pub fn new(origin: &'static str, read: FusedReader) -> Self {
        Self { origin, read }
    }

    /// The provenance label this source reports — no key material.
    pub fn origin(&self) -> &'static str {
        self.origin
    }

    /// Materialise the key for **one** operation.
    ///
    /// `None` when the underlying inputs cannot be read (an unprovisioned or
    /// unreadable OTP row). Callers must treat `None` as a refusal, never as a
    /// reason to fall back to an unkeyed path — see the module docs on
    /// [`KeySource`] and the fail-closed note at the store's own call sites.
    pub fn read(&self) -> Option<FusedRead> {
        #[cfg(not(target_arch = "arm"))]
        testing::record_read();
        Some(FusedRead {
            origin: self.origin,
            key: (self.read)()?,
        })
    }

    /// Read, use, and drop in one expression.
    ///
    /// The preferred call shape: the [`FusedRead`] cannot outlive the body of
    /// `f`, so the exposure window is `f`'s own scope by construction rather
    /// than by the caller remembering to drop.
    pub fn with<R>(&self, f: impl FnOnce(&[u8; KEY_LEN]) -> R) -> Option<R> {
        self.read().map(|k| f(k.as_bytes()))
    }
}

/// One operation's materialised root key: the only copy in RAM, cleared when
/// the binding that holds it drops.
///
/// The type is the exposure window, which is why it is not `Copy`, not
/// `Clone`, carries no `Debug`, and hands its bytes out only as a borrow
/// (`as_bytes(&self) -> &[u8; KEY_LEN]`). A `Drop` body that records is the
/// same body the device build runs — see [`testing`].
pub struct FusedRead {
    origin: &'static str,
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl FusedRead {
    /// The key bytes, borrowed for the caller's use and bound to `&self`.
    ///
    /// Borrowed, never copied out: a method that returned `[u8; KEY_LEN]` would
    /// be a method whose result outlives the zeroize, which is the whole bug
    /// this module exists to remove.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.key
    }

    /// The provenance label of the source this read came from.
    pub fn origin(&self) -> &'static str {
        self.origin
    }
}

impl Drop for FusedRead {
    fn drop(&mut self) {
        // Whether the buffer was populated is recorded *before* the clear, so
        // "the witness saw zeroes" cannot be satisfied by a buffer that was
        // never written — the vacuity question a zeroize test always has to
        // answer, answered here rather than by a hopeful assertion in the test.
        // Host-only: on arm there is nobody left to read the result.
        #[cfg(not(target_arch = "arm"))]
        let was_nonzero = self.key.iter().any(|&b| b != 0);
        let bytes: &mut [u8; KEY_LEN] = &mut self.key;
        bytes.zeroize();
        #[cfg(not(target_arch = "arm"))]
        testing::record_dropped_key(self.origin, was_nonzero, *self.key);
    }
}

// ---------------------------------------------------------------------------
// KeySource — what a holder of the store key actually holds
// ---------------------------------------------------------------------------

/// What a holder of a root key holds: either a fused source, or — for the
/// pre-US-1572 entry point that callers outside this story still use — a key
/// that was handed over already derived.
///
/// **Why this is one enum and not two fields.** A holder with a fused source
/// *and* a cached key would have two answers to "what key does this store seal
/// with", and the cached one would win at every call site that forgot to read.
/// One slot, one accessor ([`KeySource::read`]), so the call site has exactly
/// one thing to get right.
pub enum KeySource {
    /// US-1572: re-read and re-derive per operation. Nothing is resident.
    Fused(FusedKey),
    /// The US-915 shape: one derived value handed over at boot and kept. It now
    /// owns a [`Zeroizing`] and a real [`Drop`], which the plain `[u8; 32]`
    /// field this replaced did not, so the key is cleared when the store is
    /// dropped instead of never.
    ///
    /// **Deprecated for new call sites**, and the only reason it exists is that
    /// `set_store_key([u8; 32])`'s signature is pinned by files this story
    /// does not own (`firmware/src/main.rs:595`, `firmware/src/bin/bridge.rs`,
    /// and four test files). On the device this variant's window is still the
    /// whole power cycle; switching a call site to
    /// [`KeySource::Fused`] is a one-line change.
    Resident(ResidentKey),
}

impl KeySource {
    /// A fused source — the US-1572 shape.
    pub fn fused(key: FusedKey) -> Self {
        Self::Fused(key)
    }

    /// A caller-supplied, already-derived key. Deprecated; see the variant.
    pub fn resident(key: [u8; KEY_LEN]) -> Self {
        Self::Resident(ResidentKey::new(key))
    }

    /// Materialise the key for **one** operation.
    ///
    /// The single accessor every holder path uses. `None` means "no key could
    /// be produced right now" — for a fused source, an unreadable OTP row; for
    /// a resident key, never.
    pub fn read(&self) -> Option<FusedRead> {
        match self {
            Self::Fused(f) => f.read(),
            Self::Resident(k) => Some(k.read()),
        }
    }

    /// Read, use, drop — the preferred call shape at a holder's call site.
    pub fn with<R>(&self, f: impl FnOnce(&[u8; KEY_LEN]) -> R) -> Option<R> {
        self.read().map(|k| f(k.as_bytes()))
    }
}

/// A key that was derived once and handed to a holder — the pre-US-1572 shape,
/// given a `Drop` and a `Zeroizing` it did not have.
///
/// Same non-`Copy`/non-`Clone`/no-`Debug` discipline as [`FusedRead`], for the
/// same reason, and the same host witness: when a store holding one is dropped
/// or replaced, the record proves the key was cleared.
pub struct ResidentKey(Zeroizing<[u8; KEY_LEN]>);

impl ResidentKey {
    /// Take ownership of an already-derived key. The key is zeroized on drop.
    pub fn new(key: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(key))
    }

    /// This operation's view of the resident key, in a [`FusedRead`] so that
    /// every holder path downstream is written against the same type — a
    /// resident key and a fused key are indistinguishable from the call site.
    pub fn read(&self) -> FusedRead {
        FusedRead {
            origin: "resident",
            key: Zeroizing::new(*self.0),
        }
    }
}

impl Drop for ResidentKey {
    fn drop(&mut self) {
        #[cfg(not(target_arch = "arm"))]
        let was_nonzero = self.0.iter().any(|&b| b != 0);
        let bytes: &mut [u8; KEY_LEN] = &mut self.0;
        bytes.zeroize();
        #[cfg(not(target_arch = "arm"))]
        testing::record_dropped_key("resident", was_nonzero, *self.0);
    }
}

// ---------------------------------------------------------------------------
// The store key's own source
// ---------------------------------------------------------------------------

/// The C firmware's OTP key row: 16 ECC words at `0xE90`.
///
/// The row the C firmware writes its key to (`firmware/src/boot.rs:1164-1172`
/// reads the same sixteen words through the same driver); it is *this* row
/// that `store_v3::derive_store_key` takes as its IKM.
#[cfg(all(feature = "device", target_arch = "arm"))]
const OTP_KEY_ROW: usize = 0xE90;

/// Re-read the OTP key row into a zeroized local. `None` when the controller
/// refuses a read — an unprovisioned part, or the SWD-debugger condition
/// AGENTS.md warns about, where `OTP_DATA_RAW` reads back `0xFFFFFFFF` and
/// `read_ecc_word` fails.
///
/// **Not fatal, and the difference matters.** `firmware/src/boot.rs:1191-1193`
/// fatals on this same failure, because a board that cannot derive its store
/// key cannot open its own sealed slots and there is nothing to fall back to.
/// A *per-operation* read must not inherit that: a transient refusal must fail
/// this one operation closed, not park the board. The callers of
/// [`KeySource::read`] are written to refuse rather than to degrade.
#[cfg(all(feature = "device", target_arch = "arm"))]
fn read_otp_key_row() -> Option<Zeroizing<[u8; KEY_LEN]>> {
    let mut row = Zeroizing::new([0u8; KEY_LEN]);
    for i in 0..KEY_LEN / 2 {
        let word = embassy_rp::otp::read_ecc_word(OTP_KEY_ROW + i).ok()?;
        row[i * 2..i * 2 + 2].copy_from_slice(&word.to_le_bytes());
    }
    Some(row)
}

/// The **device** store key, fused: every use re-reads the OTP row and the
/// chip id and re-derives `store_v3::derive_store_key` from them.
///
/// This is the replacement for `Rp2350SecureStore { key: Option<[u8; 32]> }`,
/// which held the derived root from boot to power-down. What is resident
/// instead is this descriptor: a label and a code address.
///
/// Install it with
/// `store.set_fused_store_key(fused_key::rp2350_store_key())` — a one-line
/// change at each of the two device call sites
/// (`firmware/src/main.rs:595`, `firmware/src/bin/bridge.rs:132`).
#[cfg(all(feature = "device", target_arch = "arm"))]
pub fn rp2350_store_key() -> FusedKey {
    FusedKey::new("rp2350/otp/store", || {
        let row = read_otp_key_row()?;
        let chipid = Zeroizing::new(embassy_rp::otp::get_chipid().ok()?.to_be_bytes());
        Some(Zeroizing::new(crate::store_v3::derive_store_key(
            &row,
            &chipid,
        )))
    })
}

/// A fused store key over a root the caller already holds — the host,
/// emulation and bridge shape, where "the hardware root" is public material
/// rather than sixteen register reads.
///
/// It still re-derives on every read: the [`FusedKey`] holds no key, and each
/// [`FusedRead`] is a fresh `Zeroizing` that is dropped at the end of the
/// operation that asked for it. The point of the emulation key is
/// reproducibility (`store_v3.rs:108-117`), not secrecy, so nothing is lost by
/// deriving it on demand rather than storing it.
///
/// A caller with its **own** root rather than the emulation one defines a
/// reader `fn` over its inputs and passes it to [`FusedKey::new`] — the shape
/// RS-Key's own tests use (`rsk-piv/src/tests.rs:455`,
/// `Some(test_mkek as FusedKey)`). The reason this is a `fn` pointer and not a
/// closure is in [`FusedReader`]: a closure could capture a key, and nothing
/// about this type would notice.
pub fn emulation_store_key() -> FusedKey {
    FusedKey::new("emulation/store", || {
        Some(Zeroizing::new(crate::store_v3::emulation_store_key()))
    })
}

// ---------------------------------------------------------------------------
// Host-only observation point for the zeroize assertion
// ---------------------------------------------------------------------------

/// What a dropped root key held, recorded by the key type's own `Drop` after
/// its explicit zeroize ran.
///
/// `was_nonzero` is the half that makes an all-zeroes assertion mean something:
/// without it, a buffer that was never populated would satisfy "cleared on
/// drop" just as well as one that was.
#[cfg(not(target_arch = "arm"))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DropWitness {
    /// Provenance of the key that was dropped.
    pub origin: &'static str,
    /// Whether the buffer held anything before its zeroize ran.
    pub was_nonzero: bool,
    /// The bytes the buffer held **after** the zeroize — expected all zeroes.
    pub bytes: [u8; KEY_LEN],
}

/// Host-only hooks the device build does not have.
///
/// **Why this exists, and why it is host-only.** "The key is zeroized on drop"
/// is a claim about bytes that are, by then, in freed stack — reading them from
/// a test is unsound. So the key's own `Drop` records what it holds, after
/// clearing it, into a thread-local, and the test asserts against that record.
/// The claim under test is exactly the production claim: the same `Drop` body
/// runs on arm, where the only difference is that nobody is left to read the
/// result. This is `keyregion::crypto`'s witness, with `was_nonzero` added so
/// the instrument cannot be vacuous.
#[cfg(not(target_arch = "arm"))]
pub mod testing {
    use super::{DropWitness, KEY_LEN};
    use core::cell::RefCell;

    std::thread_local! {
        /// Every root key dropped on this thread since the last [`clear`],
        /// oldest first. Thread-local so the parallel test harness gives each
        /// `#[test]` its own record.
        static DROPPED: RefCell<std::vec::Vec<DropWitness>> =
            const { RefCell::new(std::vec::Vec::new()) };
        /// How many times a fused source has been read on this thread. The
        /// proof that "per-operation" is per-operation: one read per use, never
        /// zero (a cache) and never two (a re-read that was not needed).
        static READS: RefCell<usize> = const { RefCell::new(0) };
    }

    /// Called from [`FusedKey::read`], on success only.
    pub(super) fn record_read() {
        READS.with(|r| *r.borrow_mut() += 1);
    }

    /// Called from the key types' `Drop`, after the buffer is cleared.
    pub(super) fn record_dropped_key(origin: &'static str, was_nonzero: bool, bytes: [u8; KEY_LEN]) {
        DROPPED.with(|d| {
            d.borrow_mut().push(DropWitness {
                origin,
                was_nonzero,
                bytes,
            })
        });
    }

    /// Every root key dropped on this thread since the last [`clear`].
    pub fn dropped_keys() -> std::vec::Vec<DropWitness> {
        DROPPED.with(|d| d.borrow().clone())
    }

    /// How many fused reads have happened on this thread since the last
    /// [`clear`].
    pub fn reads() -> usize {
        READS.with(|r| *r.borrow())
    }

    /// Forget both records, so one test cannot make the next one pass.
    pub fn clear() {
        DROPPED.with(|d| d.borrow_mut().clear());
        READS.with(|r| *r.borrow_mut() = 0);
    }
}