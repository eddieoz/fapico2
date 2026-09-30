//! US-106 (EPIC `PICOForge-COMPAT`) — the RS-Key `0x41` vendor channel
//! (PicoForge vendor framing **(C)**) and its clean `NOT_ALLOWED` stub set.
//!
//! # The protocol
//!
//! A `0x41` CTAP2 command opcode inside a standard `CTAPHID_CBOR` (`0x10`,
//! `0x90` on the wire) frame. The frame body is a CBOR request map:
//!
//! ```text
//! { 1: subCommand, 2: subCommandParams, 3: pinUvAuthProtocol, 4: pinUvAuthParam }
//! ```
//!
//! The response is a **status byte followed by a CBOR map** — and PicoForge
//! only attempts to parse the CBOR half when the status is `0`
//! (`picoforge/src/hal/fido/ops.rs:1600-1606`). So a non-zero status
//! correctly carries no body at all.
//!
//! This channel is what backs PicoForge's Offboard, Lock, Backup, Audit and
//! Attestation screens, all five of which became reachable when US-101..US-104
//! made the token advertise the RS-Key profile.
//!
//! # Why twelve of the fourteen sub-commands are still stubs
//!
//! `CONFIG_READ` (`0x0D`) became real in US-114 and `CONFIG_WRITE` (`0x0C`) in
//! US-115; the other twelve are not. Before this module a `0x41`
//! opcode fell into each `FidoApp`'s dispatch catch-all and answered
//! `CTAP2_ERR_INVALID_COMMAND` (`0x01`) — "I do not recognise this command" —
//! which is false. These sub-commands *are* part of the profile we advertise;
//! this firmware just does not permit them yet. That is
//! `CTAP2_ERR_NOT_ALLOWED` (`0x30`), and it is what the sibling vendor-vault
//! path already answers for its own recognised-but-unimplemented
//! sub-commands (see `crate::device_core` and
//! `app::FidoApp::process_vendor_vault`). A desktop app renders `0x30` as "not
//! supported"; it renders `0x01` as "broken token".
//!
//! This is the mitigation for EPIC risk R-1, and it is a **temporary** state.
//! (As of US-115, twelve stubs — the two that left are `CONFIG_READ` and
//! `CONFIG_WRITE`.)
//! [`config_read`] and [`config_write`] are the two arms that have left it, and
//! they left the way the module requires: a real arm in [`handle_subcommand`]
//! and no entry in [`PENDING`].
//!
//! # Shrink-to-empty — the discipline, and what actually enforces it
//!
//! There are two sets in play, and keeping them apart is the whole trick:
//!
//! * [`Subcommand`] is the **protocol** — every sub-command the RS-Key `0x41`
//!   channel defines. It is **permanent** and must never shrink, because it is
//!   what `from_byte` has to recognise in order to tell "pending" from
//!   "malformed" at all. Deleting a variant from here would make a real
//!   sub-command answer `INVALID_SUBCOMMAND`.
//! * [`PENDING`] is the **stub set** — the subset that currently answers
//!   `NOT_ALLOWED`. This is the set that shrinks, and shrinking it is the
//!   entire point of the story.
//!
//! ## What the compiler enforces, precisely
//!
//! Exhaustiveness in [`handle_subcommand`] is a **one-directional** check, and
//! it is worth being exact about which way it points. Adding a variant to
//! [`Subcommand`] fails the build until [`Subcommand::from_byte`],
//! [`Subcommand::byte`] and [`handle_subcommand`] each give it an arm. That
//! direction is genuinely compiler-enforced.
//!
//! The direction the story most cares about is **not**: nothing stops a Phase I
//! story from writing a real arm and leaving the variant in [`Subcommand`]
//! without touching [`PENDING`]. The compiler would be silent, because the
//! arm is present and exhaustive. "Is this still a stub?" was a matter of
//! reading the code, and the previous revision of this doc wrongly implied
//! otherwise.
//!
//! That is what [`PENDING`] is for. It makes the question answerable, and
//! `tests/vendor41.rs::vendor41_pending_set_is_exactly_the_stub_set` checks
//! the correspondence **in both directions**: every entry of [`PENDING`] must
//! answer `NOT_ALLOWED`, and every variant *not* in [`PENDING`] must not. So
//! implementing a sub-command and forgetting to drop it from [`PENDING`]
//! fails, and dropping it from [`PENDING`] without implementing it fails too.
//! Neither mistake is a review convention any more.
//!
//! ## How a Phase I story retires one stub
//!
//! Two edits, both in this file: write the real arm in
//! [`handle_subcommand`], and delete the entry from [`PENDING`]. Nothing else
//! needs to know. The tests iterate [`PENDING`], not the protocol table, so
//! this is a one-line move rather than a test rewrite — the permanent
//! protocol table in `tests/vendor41.rs` is cross-checked against
//! [`Subcommand`] and stays put.
//!
//! Two consequences, and both are deliberate:
//!
//! * **Do not "simplify" the exhaustive `match` in [`handle_subcommand`] into
//!   a `_ =>` arm.** That single edit would remove the compile-time forcing
//!   function and turn this module back into the permanent catch-all the EPIC
//!   forbids.
//! * **Adding a sub-command is not free.** The compile-time check above forces
//!   an arm; the *test-time* cross-check in
//!   `tests/vendor41.rs::vendor41_subcommand_set_matches_picoforge` walks
//!   [`Subcommand::ALL`] and asserts each variant round-trips through
//!   `from_byte`/`byte` and appears in a table of the sub-commands pinned from
//!   `picoforge/src/hal/fido/constants.rs`. That catches what the compiler
//!   cannot: a variant wired up consistently everywhere whose byte is still
//!   wrong relative to the protocol. Neither check substitutes for the other.
//!
//! [`handle`]'s `from_byte` lookup does have a fallback, and it is *not* a
//! silent swallow: a byte outside the enumerated set is a malformed request
//! rather than a pending one, and says so with
//! `CTAP2_ERR_INVALID_SUBCOMMAND` (`0x3E`). Answering `NOT_ALLOWED` there
//! would assert "you asked for something real and I declined", which would be
//! a lie about a byte the protocol does not define — and would let a future
//! extension (`0x0F`, or PicoForge's own `0xC1`) be absorbed into this
//! channel's `0x30` set by accident.
//!
//! # Phase I's state seam — [`VendorOps`]
//!
//! US-106..US-117 built the protocol: which sub-commands exist, which gate
//! each owes its caller, and two of the fourteen arms. US-176 added the thing
//! the remaining twelve need and cannot have without — durable state — as
//! [`VendorOps`], a trait [`handle`] takes and the two command paths
//! implement over their own keystores. Nothing consults it yet, and
//! [`PENDING`] still names all twelve: the Phase I stories (US-170 … US-175)
//! write the arms and delete their `PENDING` entry, and
//! `tests/vendor41.rs::vendor41_stub_never_touches_the_state` is what says
//! none of them has done so early. The reasoning for a trait rather than a
//! `&mut` state bundle, and for why the payloads could not ride on [`Outcome`]
//! instead, is on [`VendorOps`] itself.
//!
//! # Not the vendor vault
//!
//! `tests/vendor41.rs::vault_framing_does_not_alias_ctap2_vendor_0x41` for the
//! test that pins it. In short: the vault dispatches on the **CTAPHID frame
//! CMD byte**, a non-standard command handled in `firmware/src/tasks.rs`
//! (requiring `cmd == 0x41 && payload[0] == 0x05`); this module is the **first
//! payload byte of a standard `0x90` CBOR frame**. Disjoint fields of disjoint
//! frames. Their sub-command numbering even overlaps with *different* meanings
//! — `1` is `MSE` here and `STATUS` in the vault — which is why they must not
//! share a decoder. They do not share a **MAC** path either; see
//! [`verify_mac`].
//!
//! # The pinUvAuth MAC — [`verify_mac`]
//!
//! Most sub-commands on this channel are authenticated. PicoForge sends
//! `{3: pinUvAuthProtocol, 4: pinUvAuthParam}` alongside the sub-command, and
//! the param is
//!
//! ```text
//! HMAC-SHA256(pinToken, 0xFF*32 || 0x41 || subCommand || cbor(subCommandParams))[0..16]
//! ```
//!
//! (`picoforge/src/hal/fido/ops.rs:1581-1586` for the generic vendor call,
//! `:1526-1534` for `CONFIG_WRITE`, which builds the identical thing).
//! [`verify_mac`] recomputes exactly that, compares it, and on success hands
//! back the **authenticated params** as a span borrowed from the request, so
//! an arm never has to decide for itself which bytes were signed. That also
//! makes the "no params at all" shape first-class: `ops.rs:1560-1573` signs an
//! empty tail and omits key 2 entirely for `AUDIT_READ`, `EXPORT` and
//! `ATT_CLEAR`, and [`verify_mac`] returns an empty slice for those rather
//! than treating the omission as an error.
//!
//! ## What the MAC covers, and why each piece is load-bearing
//!
//! * **`0xFF × 32`** — the CTAP2 "null authenticator data" prefix. It is what
//!   makes this message distinguishable from a `pinUvAuthParam` over an
//!   authenticator command (`0x00`…), so a MAC harvested from one channel
//!   cannot be replayed on the other.
//! * **`0x41`** — the domain separator, and the reason the two `0x41`s in this
//!   firmware cannot borrow each other's authorisations. The sibling vault
//!   MACs `0xFF*32 || 0x0D || sub || params` (`device_core.rs`'s
//!   `vendor_vault_inner`). Same prefix, same shape, different domain byte and
//!   a different sub-command numbering: without the byte, a MAC the vault
//!   accepts would authorise a request here, and a MAC this channel emits
//!   would authorise a request there. `0x41` is the *vendor command* the
//!   authenticator is speaking, not a copy of the sub-command.
//! * **`subCommand`** — so one sub-command's authorisation cannot be replayed
//!   onto another. `CONFIG_WRITE`'s permission to change device config must not
//!   be spendable on `AUDIT_READ`.
//! * **`cbor(subCommandParams)`** — so the authorisation is bound to *what is
//!   being asked for*. This is the point of the whole construction: without it
//!   a valid MAC would be a bearer token for any sub-command, replayable with
//!   edited parameters. The bytes are the ones **as they arrived on the wire**
//!   ([`verify_mac`] captures the raw span), not a re-encoding, so no
//!   canonical-CBOR re-serialisation can drift between what the client signed
//!   and what the device verifies.
//!
//! ## `pinUvAuthProtocol` is 1, not 2
//!
//! PicoForge hard-codes `3: 1` (`ops.rs:1583`, `:1533`) — protocol 1, which is
//! HMAC-SHA256 truncated to 16 bytes — even though most CTAP2 helpers on that
//! side use protocol 2 (32 bytes). [`verify_mac`] accepts protocol 1 and
//! refuses any other declared protocol with
//! [`Ctap2Response::InvalidParameter`].
//!
//! The reason is interop and clarity, **not** security, and it is worth being
//! exact about that so nobody later "fixes" it: `crypto::pin_verify_auth`
//! length-checks, so a 32-byte param under a declared protocol 2 would be
//! compared against a 32-byte HMAC the caller cannot compute — strictly more
//! work for an attacker, not less. Refusing an undefined protocol with `0x02`
//! just says "this channel does not do that" instead of making an
//! unimplemented protocol look like a failed MAC.
//!
//! This is the **divergent** choice from the vault, which honours whatever the
//! request declares (`device_core.rs`'s `vendor_vault_inner`). A client that
//! sent protocol 2 would get `0x33` from the vault and `0x02` from here. Both
//! senders in this protocol hard-code `1`, so nothing in practice reaches it.
//!
//! ## The statuses, and the two places the EPIC gets them wrong
//!
//! * **No pinUvAuthParam, or no token to check it against** →
//!   [`Ctap2Response::PuatRequired`] (`0x36`).
//! * **A param that is present and does not verify** →
//!   [`Ctap2Response::PinAuthInvalid`] (`0x33`).
//!
//! The EPIC's US-111 bullet names these as "`0x36` (`PIN_REQUIRED`)" and
//! "`0x31` (`INVALID_COMMAND`)". The `0x36` *byte* is right and the *name* is
//! not — in this crate `0x36` is [`Ctap2Response::PuatRequired`], and
//! `INVALID_COMMAND` is `0x01`. `0x31` is not used at all: it is
//! [`Ctap2Response::PinInvalid`], which means "the PIN you entered was wrong"
//! and would send a desktop app round the PIN prompt for what is actually a
//! stale token or a MAC over the wrong bytes. `0x33` is what the sibling vault
//! already answers for a bad MAC (`device_core.rs`'s `vendor_vault_inner`),
//! so a client sees one coherent auth-error model across both channels.
//!
//! ## Which arms consult the MAC, and which do not
//!
//! [`verify_mac`] is public so a sub-command arm can call it, and as of US-115
//! exactly one does: [`config_write`], and only for the *identity* tier of its
//! field classifier. That is a narrower statement than "the gate is on", and
//! the difference is the story:
//!
//! * The **twelve stubs** must stay ungated, or they would answer `0x36`/`0x40`
//!   instead of the `0x30` the client needs to see. `CONFIG_WRITE` was one of
//!   them until US-115; the two "not yet wired" tests
//!   (`vendor41_mac_is_not_yet_wired_into_the_stubs` and
//!   `vendor41_permission_gate_is_not_yet_wired_into_the_stubs`) now iterate
//!   the twelve and say so in their names.
//! * **`CONFIG_READ`** is sent with no token and no MAC at all
//!   (`picoforge/src/hal/fido/ops.rs:1461-1479`), so a token demand reached
//!   from dispatch would reject a request the protocol deliberately sends
//!   ungated, and it doubles as the client's feature probe for whether this
//!   firmware supports `0x41` at all
//!   (`picoforge/src/hal/fido/mod.rs:1158-1166`).
//!   `tests/vendor41.rs::config_read_demands_no_token` checks it.
//! * **`CONFIG_WRITE`'s benign tier** is gated on a *presence grant*, not a
//!   token — see [`FieldTier`] — so a benign blob is not authenticated and a
//!   `pinUvAuthParam` riding along on one is not verified and therefore not
//!   charged. Two assertions make that a check rather than a comment:
//!   the last leg of
//!   `tests/vendor41.rs::vendor41_mac_is_not_yet_wired_into_the_stubs` (a
//!   *bogus* MAC on a benign blob, asserted to answer `0x3B` and to leave
//!   `pin_auth_failure` clear), and the `!refused.pin_auth_failure` leg of
//!   `tests/vendor41.rs::config_write_rejected_without_presence`.
//!
//! So the arrangement is still a test and not a promise; there are now three
//! of them instead of two, and each names the arm it is about.
//!
//! # US-112: the per-sub-command permission gate
//!
//! [`required_permission`] says what each sub-command demands of the caller,
//! and [`authorize`] turns a sub-command plus the caller's token permissions
//! into a decision, refusing with [`Ctap2Response::UnauthorizedPermission`]
//! (`0x40`). As of US-115 exactly one dispatch path consults them: `CONFIG_WRITE`,
//! and only once its field classifier has decided the blob is
//! [`FieldTier::Identity`]. The rest do not, for two different reasons that
//! are worth keeping apart:
//!
//! * For the **twelve stubs** it is because they owe the client `0x30`, and a
//!   gate reached from dispatch would answer `0x40` instead.
//! * For **`CONFIG_READ`** it is a property of the protocol rather than a
//!   placeholder: the row is [`Requirement::Ungated`], so consulting the table
//!   for it could only ever admit the request.
//!
//! `tests/vendor41.rs::vendor41_permission_gate_is_not_yet_wired_into_the_stubs`
//! enforces the first in the *permissive* direction too — a real `0x20` token
//! is presented and the twelve still answer `0x30`, so the test cannot be
//! passed by a gate that is switched on for the right tokens and off for the
//! rest. It no longer makes the `CONFIG_WRITE` leg, because `CONFIG_WRITE` is
//! no longer a stub; `config_write_identity_field_requires_pin_token` replaces
//! it, and the *permissive* direction it lost is now covered by
//! `config_write_identity_field_is_written_by_a_0x20_token`.
//!
//! ## Three requirements, not two
//!
//! [`Requirement`] has three variants, and the third one exists because the
//! client does not authenticate most of this channel over `0x41` at all.
//! [`authorize`] takes the caller's token as `Option<u8>`, so the table has to
//! say what happens when there is none — and the answer is **not** the same
//! for every row:
//!
//! * [`Requirement::Ungated`] — the protocol defines no authenticated form of
//!   this sub-command. The client never attaches a token, and a token that
//!   *is* attached is not consulted. One row: `CONFIG_READ`.
//! * [`Requirement::TokenOptional`] — a token carrying the bit *may*
//!   authorise the call, and its absence is a legitimate request the device
//!   is expected to satisfy another way. Twelve rows.
//! * [`Requirement::Permission`] — a token carrying the bit is *required*;
//!   no token is a refusal. One row: `CONFIG_WRITE`.
//!
//! The middle variant is the one an earlier revision of this story got wrong,
//! and getting it wrong is a latent interop break rather than a theoretical
//! one, so it is worth saying precisely what it is.
//!
//! ## Why `TokenOptional` exists: the client sends most of this channel bare
//!
//! `HidTransport::rs_key_vendor` (`picoforge/src/hal/fido/ops.rs:1556-1586`)
//! mints and attaches a `0x20` token **only when its `pin` argument is
//! `Some`**. With `None` it sends neither key 3 nor key 4, and says why in its
//! own comment: *"Without one, the firmware gates on a physical touch instead,
//! so no auth fields are sent."*
//!
//! Enumerating every `rs_key_vendor` call in `mod.rs`:
//!
//! | sub-command | call site | `pin` argument | token on the wire |
//! |---|---|---|---|
//! | `Mse` 1 | `mod.rs:1709` | `None` | never |
//! | `Export` 2 | `mod.rs:1771` | `pin.as_deref()` | only if `Some` |
//! | `Load` 3 | `mod.rs:1797` | `pin.as_deref()` | only if `Some` |
//! | `Finalize` 4 | `mod.rs:1757` | `None` | never |
//! | `State` 5 | `mod.rs:1741` | `None` | never |
//! | `Unlock` 6 | `mod.rs:1826`, `:1867` | `None` | never |
//! | `AuditRead` 7 | `mod.rs:1573` | `pin` | only if `Some` |
//! | `AuditCheckpoint` 8 | `mod.rs:1611` | `pin.as_deref()` | only if `Some` |
//! | `AuditConfig` 0x0E | `mod.rs:1653` | `None` | never |
//! | `AttImport` 9 | `mod.rs:1987` | `pin.as_deref()` | only if `Some` |
//! | `AttClear` 10 | `mod.rs:1916` | `pin.as_deref()` | only if `Some` |
//! | `AttState` 11 | `mod.rs:1895` | `None` | never |
//! | `ConfigWrite` 0x0C | `ops.rs:1514-1534` (via `mod.rs:1168` etc.) | always `Some` | always |
//! | `ConfigRead` 0x0D | `ops.rs:1461-1479` (via `mod.rs:1163-1166`) | n/a | never |
//!
//! The client's own function docs say the same thing in prose, which is a
//! useful second source: `backup_status` *"Read `{sealed, has_seed, locked,
//! unlocked}` (ungated)"* (`mod.rs:1738`), `lock_unlock` *"Ungated over the
//! `0x41` channel"* (`:1824`), `att_status` *"Read `{installed, chain_hash}`
//! (ungated)"* (`:1892`), `audit_status` *"(ungated status query, no touch)"*
//! (`:1659`), `backup_finalize` *"(touch-gated)"* (`:1754`), and the
//! `Option<String>`-taking entry points `backup_export`, `backup_restore`,
//! `audit_log`, `audit_verify`, `att_import` and `att_clear`, each documented
//! "PIN or touch gated" / "PIN/touch".
//!
//! So a table that demanded `0x20` from all thirteen non-ungated rows would
//! answer `0x40` to `backup_status`, `att_status`, `lock_unlock` and
//! `audit_status` — four calls the client documents as ungated, backing four
//! of the five screens US-106 made reachable. Nothing would fail loudly: the
//! stubs answer `0x30` today, the gate is not consulted, and the break would
//! surface only in Phase I, in the one story whose job is to implement a
//! handler. `tests/vendor41.rs::vendor41_permission_table_matches_the_picoforge_call_sites`
//! is the test that makes the table and the call sites agree, and it is
//! written to fail the day they stop.
//!
//! ## The table is per sub-command, not per channel
//!
//! PicoForge only ever mints `0x20` or `0x04`
//! (`picoforge/src/hal/fido/constants.rs:302-320`), so a single
//! "channel accepts either" rule would be observationally identical on the
//! wire. It is not identical in authority, though: `0x04`
//! (`CREDENTIAL_MANAGEMENT`) is what the desktop app requests for CTAP2
//! `credentialManagement` — enumerate and delete credentials
//! (`picoforge/src/hal/fido/ops.rs:1082`, `:1230`, `:1407`) — and that token
//! grants nothing over device configuration, firmware state or the seed.
//! Collapsing the two into one gate would let a credential-management token
//! rewrite the token's own configuration, which is precisely the boundary the
//! bit exists to draw. The table keeps it drawn, one row per sub-command.
//!
//! `0x04` is in fact **never** requested for any `0x41` sub-command, on any
//! call site: `rs_key_vendor` mints [`PERM_ACFG`] internally whenever it
//! authenticates at all (`ops.rs:1576-1580`), and every `mod.rs` caller that
//! builds the token itself does the same (`:1168`, `:1310`, `:1432`, `:1464`,
//! `:2057`, `:2093`).
//!
//! ## What each family requires
//!
//! | family | sub-commands | requirement |
//! |---|---|---|
//! | seed backup / restore | `MSE` 1, `EXPORT` 2, `LOAD` 3, `FINALIZE` 4 | `TokenOptional(0x20)` |
//! | soft lock | `STATE` 5, `UNLOCK` 6 | `TokenOptional(0x20)` |
//! | audit journal | `AUDIT_READ` 7, `AUDIT_CHECKPOINT` 8, `AUDIT_CONFIG` 0x0E | `TokenOptional(0x20)` |
//! | org attestation | `ATT_IMPORT` 9, `ATT_CLEAR` 10, `ATT_STATE` 11 | `TokenOptional(0x20)` |
//! | device config | `CONFIG_READ` 0x0D | `Ungated` |
//! | device config | `CONFIG_WRITE` 0x0C | `Permission(0x20)` |
//!
//! `CONFIG_WRITE` is the only strictly-gated row, and it is the one the
//! US-112 acceptance bullet names. Every caller that reaches it goes through
//! `HidTransport::rs_key_config_write` (`ops.rs:1514-1534`), which takes the
//! token as an argument rather than minting one, so there is no code path that
//! could reach it without a `0x20` token in hand.
//!
//! ## The soft-lock family is `TokenOptional`, and not because of the lock UI
//!
//! It is worth being explicit about one thing this table deliberately does
//! *not* cite. PicoForge's lock enable/disable pair — the functions that mint
//! a token at `mod.rs:1847` and `:1874` — is **not on this channel**. They call
//! `HidTransport::authconfig_vendor` (`ops.rs:1611-1656`), which is CTAP2
//! `CtapCommand::Config` with `ConfigSubCommand::VendorPrototype` and a 64-bit
//! vendor id: a standard `0x40` authenticatorConfig vendor prototype, reached
//! through a different opcode and a different MAC domain. Citing those two
//! lines as evidence about the `0x41` soft-lock rows would be citing a
//! different protocol. The `0x41` soft-lock evidence is `lock_unlock` and
//! `lock_disable` passing `None` to `rs_key_vendor` at `mod.rs:1826`/`:1867`,
//! plus `mod.rs:1738` ("ungated").
//!
//! ## `CONFIG_READ` is ungated, and what that exposes
//!
//! It has to be — and as of US-114 it is the one sub-command that really
//! answers, so this is a live exposure rather than a design note.
//! `picoforge/src/hal/fido/ops.rs:1461-1479` builds
//! `{1: 0x0D, 2: {1: target}}` with no key 3 and no key 4, and
//! `mod.rs:1163-1166` calls it as the *feature probe* for whether the
//! firmware supports `0x41` at all — before any token is minted. A gated
//! `CONFIG_READ` would answer `0x40` and the desktop app would report "this
//! RS-Key firmware does not support FIDO configuration" for a device that
//! does.
//!
//! Being exact about the exposure, because "ungated read" invites the question
//! and the answer is narrow. Re-verified against the client while writing
//! [`config_read`], and then re-re-verified in US-117 — the first pass
//! overstated it, so the list below is derived from
//! [`EMITTED_PHY_TAGS`] rather than from the protocol's tag set.
//!
//! The read paths target PHY (`0x01`) and LED (`0x02`), and those are the two
//! targets served. A `CONFIG_READ` at `0x01` emits exactly **four** records —
//! USB VID/PID, LED GPIO, LED brightness, and the power-cycle options word —
//! plus, since US-117, the 17-byte LED status block at `0x02`. Nothing else.
//! None of them contains key material, a PIN, a token, a credential or a seed.
//!
//! The useful shape of the claim is stronger than "discloses less than it
//! writes", and it is a property rather than a comparison:
//!
//! * **Every record the read emits is also writable**, so an unauthenticated
//!   reader learns nothing the token cannot be *asked* to change.
//! * The eight tags the read does *not* emit — the two USB strings, the
//!   presence timeout, the curve mask, the LED driver/order/count, and the
//!   enabled-interface mask — are refused by
//!   `apply_phy_record` with [`Ctap2Response::UnsupportedOption`] (seven of
//!   them) or, for the mask, deliberately withheld by
//!   [`EMITTED_PHY_TAGS`] for the security reason given there.
//!
//! US-114 served only PHY and said so; US-117 added `LED` and the claim needed
//! re-arguing rather than inheriting, because adding a served record to an
//! *ungated* read is exactly the move that could erode it. It does not: the
//! block is cosmetic, and the boundary below — the one target that is not
//! served — is unaffected by any amount of cosmetic disclosure.
//!
//! The boundary is what stops the ungated read from widening, and it is worth
//! stating outright: the `DEV_CONF` target (`0x00`) —
//! the USB application enabled-interface mask, written at `mod.rs:2086-2091` —
//! is **write-only over FIDO**. The client says so itself, and says it as a
//! fact about the firmware rather than a policy
//! (`picoforge/src/hal/fido/mod.rs:615-618`): *"Enabled-apps info is NOT
//! readable over the `0x41` CONFIG_READ path — the firmware exposes only
//! PHY/LED there and rejects DEV_CONF."* The read path targets PHY (`0x01`)
//! and LED (`0x02`); the only route to `DEV_CONF` is a `CONFIG_WRITE` carrying
//! a `0x20` token. An ungated read therefore cannot reach the one config blob
//! that changes what the token can do over USB, and the "strictly less than
//! the write permission" claim is bounded by that rather than assumed.
//!
//! ## The lockout seam
//!
//! US-111 established that [`verify_mac`] is a pure function answering
//! `0x33` with no counter of its own, and that is right: the three-strike
//! PIN-auth lockout is *session* state. On the host twin it is
//! `PinState::auth_failures` in `keystore.rs` — documented there as "volatile
//! … Not persisted" — and on the device it is `FidoApp::auth_failures` in
//! `device_app.rs`. Both are reached through a **private** method on the app
//! (`app::FidoApp::note_pin_auth_failure` and its device twin), and
//! deliberately not persisted, because a durable counter would outlive the
//! session that produced it.
//!
//! That rules out the obvious shortcut. The [`fapico2_platform::secure_store::SecureStore`] this module is
//! already handed is a key-value partition (`SecureStore::write`/`read`); it
//! *could* be given a `PIN_AUTH_FAILURES` slot, and doing so would be a
//! security regression — it would turn a session-scoped lockout into an
//! at-rest one, whose durable strikes would then interact with a
//! `needs_power_cycle` latch whose documented clearing condition is "a correct
//! PIN", outliving the session the spec scopes it to.
//!
//! The seam is [`Outcome`]. A sub-command arm returns the status **and** a
//! flag saying "I rejected a `pinUvAuthParam`"; the command path that owns the
//! app — `app::FidoApp::process_ctap2` and its device twin — turns that flag
//! into exactly one call to the private `note_pin_auth_failure` it already has,
//! and uses that method's return value (so the third strike still answers
//! `0x34`, not `0x33`). [`TokenAuth`] is the matching inbound half: the token
//! and its permission byte, assembled by the app and handed down, so an arm
//! can call [`verify_mac`] and [`authorize`] without re-deriving either.
//!
//! The trade-off is worth stating plainly: this costs a one-byte `bool` and two
//! changed signatures, and it deliberately does **not** introduce a callback
//! trait or a counter parameter into this module. A counter threaded in as
//! `&mut u8` would not have been enough — the latch (`needs_power_cycle`) and
//! its persistence live on the app too, so the app has to be the one deciding
//! — and a trait object would have put a `dyn` seam in a module that has no
//! reason to have one until an arm exists. What it buys is that the first real
//! arm can escalate by writing `Outcome::pin_auth_failure(status)` and
//! nothing else, with no second edit to either dispatch site and no way to
//! accidentally persist the counter.
//!
//! ## How a `TokenOptional` row is actually enforced
//!
//! When Phase I implements one, `authorize` admitting a tokenless request is
//! only half the story: the other half is whatever the device does instead —
//! a presence check, per the client's own comment at `ops.rs:1573-1575`. That
//! is a Phase I decision and it is **not** implemented here. Today every row,
//! optional or not, is a `0x30` stub reached without consulting this table at
//! all, so nothing here grants anything.

use crate::cbor::no_heap::{self, Item, Parser};
use crate::ctap2::Ctap2Response;
use crate::crypto;
use crate::device_core::PERM_ACFG;
use crate::CTAP2_MAX_MSG;
use fapico2_platform::phy_tlv::{self, PhyTag};
use heapless::Vec as HeaplessVec;

/// The CTAP2 command byte that selects this channel.
///
/// Used as the match pattern in **both** dispatch sites — the host
/// `app::FidoApp::process_ctap2` and the device `device_app::FidoApp` — so the
/// opcode is written down exactly once. Those are two independent `match`
/// statements over the same opcode space, so a literal `0x41` at each site
/// would let a later story arm one and forget the other, and the resulting bug
/// would only show up on whichever path that story happened to test.
pub const CMD: u8 = 0x41;

/// Every sub-command the RS-Key `0x41` protocol defines, in byte order.
///
/// Checked against `picoforge/src/hal/fido/constants.rs` (the `RSKEY_*`
/// block). The set is **closed and finite** — 14 entries, with no gap after
/// `0x0E`. Note that `0x0C`/`0x0D` are `CONFIG_WRITE`/`CONFIG_READ`; they are
/// not the 12th/13th members of the `1..=11` run, so the two are the same
/// bytes by design and there is no separate 12/13 to serve.
///
/// Removing a variant here is how a Phase I story retires its stub. See the
/// module docs for why the compiler then forces the rest of the change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subcommand {
    /// `RSKEY_VENDOR_MSE` (1) — ephemeral-ECDH channel for backup/unlock.
    Mse,
    /// `RSKEY_VENDOR_EXPORT` (2) — read the encrypted master seed.
    Export,
    /// `RSKEY_VENDOR_LOAD` (3) — restore a seed from a backup.
    Load,
    /// `RSKEY_VENDOR_FINALIZE` (4) — seal the one-time export window.
    Finalize,
    /// `RSKEY_VENDOR_STATE` (5) — `{1: sealed, 2: has_seed, 3: locked, 4: unlocked}`.
    State,
    /// `RSKEY_VENDOR_UNLOCK` (6) — load a soft-locked seed for this power cycle.
    Unlock,
    /// `RSKEY_VENDOR_AUDIT_READ` (7) — export the journal window.
    AuditRead,
    /// `RSKEY_VENDOR_AUDIT_CHECKPOINT` (8) — sign the chain head.
    AuditCheckpoint,
    /// `RSKEY_VENDOR_ATT_IMPORT` (9) — install an org attestation key + chain.
    AttImport,
    /// `RSKEY_VENDOR_ATT_CLEAR` (10) — remove the org attestation.
    AttClear,
    /// `RSKEY_VENDOR_ATT_STATE` (11) — `{1: installed, 2: chain_hash}`.
    AttState,
    /// `RSKEY_CONFIG_WRITE` (12) — write PHY / LED device config.
    ConfigWrite,
    /// `RSKEY_CONFIG_READ` (13) — read PHY / LED device config.
    ///
    /// Sent by PicoForge with **no MAC and no token**
    /// (`picoforge/src/hal/fido/ops.rs:1461-1479`), which makes it the most
    /// likely sub-command to be probed and therefore the most important one not
    /// to have left on `0x01`. It is stubbed with the rest, and the stub
    /// demands no token — a token-gated stub would reject a request the
    /// protocol sends ungated.
    ConfigRead,
    /// `RSKEY_VENDOR_AUDIT_CONFIG` (14) — turn the audit journal on/off.
    AuditConfig,
}

impl Subcommand {
    /// The whole enumerated set, in byte order.
    pub const ALL: [Subcommand; 14] = [
        Subcommand::Mse,
        Subcommand::Export,
        Subcommand::Load,
        Subcommand::Finalize,
        Subcommand::State,
        Subcommand::Unlock,
        Subcommand::AuditRead,
        Subcommand::AuditCheckpoint,
        Subcommand::AttImport,
        Subcommand::AttClear,
        Subcommand::AttState,
        Subcommand::ConfigWrite,
        Subcommand::ConfigRead,
        Subcommand::AuditConfig,
    ];

    /// The sub-command's wire byte.
    pub const fn byte(self) -> u8 {
        match self {
            Subcommand::Mse => 0x01,
            Subcommand::Export => 0x02,
            Subcommand::Load => 0x03,
            Subcommand::Finalize => 0x04,
            Subcommand::State => 0x05,
            Subcommand::Unlock => 0x06,
            Subcommand::AuditRead => 0x07,
            Subcommand::AuditCheckpoint => 0x08,
            Subcommand::AttImport => 0x09,
            Subcommand::AttClear => 0x0A,
            Subcommand::AttState => 0x0B,
            Subcommand::ConfigWrite => 0x0C,
            Subcommand::ConfigRead => 0x0D,
            Subcommand::AuditConfig => 0x0E,
        }
    }

    /// Map a wire byte to a sub-command, or `None` if the protocol does not
    /// define it.
    ///
    /// This is a **filter, not a catch-all**: `None` means "malformed", and the
    /// caller turns that into `INVALID_SUBCOMMAND` rather than
    /// `NOT_ALLOWED`. Adding a sub-command means adding a line here *and* a
    /// variant to [`Subcommand::byte`].
    pub const fn from_byte(byte: u8) -> Option<Subcommand> {
        match byte {
            0x01 => Some(Subcommand::Mse),
            0x02 => Some(Subcommand::Export),
            0x03 => Some(Subcommand::Load),
            0x04 => Some(Subcommand::Finalize),
            0x05 => Some(Subcommand::State),
            0x06 => Some(Subcommand::Unlock),
            0x07 => Some(Subcommand::AuditRead),
            0x08 => Some(Subcommand::AuditCheckpoint),
            0x09 => Some(Subcommand::AttImport),
            0x0A => Some(Subcommand::AttClear),
            0x0B => Some(Subcommand::AttState),
            0x0C => Some(Subcommand::ConfigWrite),
            0x0D => Some(Subcommand::ConfigRead),
            0x0E => Some(Subcommand::AuditConfig),
            // Not a fallback — the protocol genuinely stops at 0x0E. See the
            // module docs on why this must not widen to a catch-all.
            _ => None,
        }
    }
}

/// The **stub set**: the sub-commands that currently answer
/// [`Ctap2Response::NotAllowed`] because Phase I has not implemented them.
///
/// This is a strict subset of [`Subcommand::ALL`], and it is the list that
/// shrinks to empty. It is deliberately a *separate* list from the protocol
/// enumeration: the protocol table must stay complete forever, because
/// [`Subcommand::from_byte`] needs every real sub-command to tell "pending"
/// apart from "malformed". Keeping them apart is what makes retiring a stub a
/// one-line move here rather than an edit to a permanent table — and it is
/// what makes "is this still a stub?" a question a test can answer, which the
/// `match` in [`handle_subcommand`] on its own cannot.
///
/// Since US-114 it is the protocol minus `CONFIG_READ`, and since US-115 minus
/// that one too. To retire another, write the real arm in
/// [`handle_subcommand`] and delete the entry here.
/// `tests/vendor41.rs::vendor41_pending_set_is_exactly_the_stub_set` checks
/// the two against each other in both directions, so neither half of that
/// edit can be forgotten.
pub const PENDING: &[Subcommand] = &[];

/// Handle an RS-Key `0x41` request body (`data` is the CBOR map that followed
/// the `0x41` opcode byte) and return what the command path should do with it.
///
/// # There is no `store` parameter, and US-106's reason for adding one was wrong
///
/// US-106 threaded `store` here so the first real arm could commit through it.
/// US-115 shows that is not the shape. A durable `CONFIG_WRITE` has to commit
/// **transactionally against the whole keystore snapshot**, and the snapshot —
/// not the [`fapico2_platform::secure_store::SecureStore`] — is what [`crate::device_keystore::DeviceKeystore`]
/// owns. The store is what the snapshot is written *to*; a sub-command arm
/// handed the store but not the snapshot could write bytes with no way to roll
/// them back, which is the opposite of what SOAK-FINDING-1 asks for.
///
/// So the split is: this module **decides** and returns the [`crate::vendorff::PhyConfig`] it
/// wants committed on [`Outcome::phy`]; the dispatch arm that owns
/// `self.keystore` commits it through `grow_checked`. That is the same division
/// the `0xFF` legacy framing uses (`device_core.rs`'s `0xFF` arm), which is why
/// the commit there is transactional.
///
/// The parameter was then removed rather than left unread, because leaving it
/// forced both dispatch arms into a lifetime workaround: `handle` would have
/// had to borrow the store to hand it back, and the honest signature is the one
/// that does not take it. Four call sites, all of them here.
///
/// `auth` is the caller's pinUvAuth token and the permissions it was minted
/// with, assembled by the app that owns them. US-115 consults it — for the
/// identity tier only; see [`config_write`].
///
/// `presence` is the app's user-presence probe. US-115 consults it for the
/// benign tier only, and for the same reason: a token is a strictly stronger
/// authorisation than a touch, so a blob that needs the token does not also
/// need the button. See [`PresenceGate`].
///
/// `ops` is the Phase I state seam — see [`VendorOps`] for why it is a trait
/// and why it, rather than a proposal on [`Outcome`], is where a durable write
/// goes. **No arm consults it yet**: the twelve [`PENDING`] sub-commands still
/// answer [`Ctap2Response::NotAllowed`] and touch nothing, and
/// `tests/vendor41.rs::vendor41_stub_never_touches_the_state` is what keeps
/// that a check rather than a claim. It is threaded through
/// [`handle_subcommand`] on the same argument as `phy` and `auth` — the
/// parameters an arm has *when its story lands*, not ones it has today, so
/// adding a seventh is not a seventh edit to this signature.
///
/// The returned [`Outcome`] is a status, one flag, and the physical
/// configuration the command wants committed (US-115). As of US-115 the flag is
/// **not** always `false`: `identity_gate` sets it when [`verify_mac`]
/// refuses a `pinUvAuthParam` for the `CONFIG_WRITE` identity tier, which is
/// what lets an arm charge a rejected MAC against the app's own three-strike
/// counter without this module growing a counter of its own. It stays `false`
/// for the twelve stubs and for the two implemented arms' non-charging
/// answers — a benign-tier write authenticates nothing, and `CONFIG_READ` is
/// ungated by protocol. See the module docs on the lockout seam.
/// `phy` is the device's persisted physical-configuration record, read by the
/// app out of its own keystore and handed down by value ([`crate::vendorff::PhyConfig`] is a
/// `Copy` struct of four `Option`s). It is a parameter rather than something
/// read out of [`fapico2_platform::secure_store::SecureStore`] because that store is a key-value partition —
/// the record lives inside the keystore's `AuthState`, which is what the
/// `0xFF` framing writes and what a durable-before-ack flush has to cover, so
/// reading it from anywhere else would be reading a second copy of the state
/// that is actually authoritative. Only [`config_read`] consumes it.
///
/// `out` receives the response body, and is the reason this function is no
/// longer pure. The command path turns it into the reply **only** when the
/// status is [`Ctap2Response::Ok`] — the same rule the client applies in the
/// other direction, parsing the CBOR half only when the status byte is zero
/// (`HidTransport::read_cbor_response`). A body that outlived a non-zero
/// status would be the second, quieter half of that bug.
///
/// # `out` is emptied here, and that is not optional
///
/// [`handle`] clears `out` unconditionally on entry, and it is the **only**
/// writer of it on this channel, so this is the one place the contract can
/// live. It has to, because the device path hands in a *reused* buffer:
/// `firmware/src/tasks.rs` aliases `HID_RESP` — a `&'static mut` — out of the
/// static once and passes it to every CTAPHID command in turn, and never
/// clears it. An arm that forgot would otherwise write its body at the tail of
/// whatever the previous command left, and [`finish_reply`] would prepend the
/// status byte to *both*, shipping a reply of stale bytes followed by this
/// one's body.
///
/// One owner, not two, and that is a deliberate choice rather than an absence:
/// an earlier revision had the clear here *and* in the device dispatch arm,
/// and with two layers of defence the individual layers cannot be tested —
/// removing either one changes nothing observable, because the other covers
/// it. Putting the clear here makes the contract single, and
/// `tests/vendor41.rs::vendor41_reused_output_buffer_carries_no_stale_bytes`
/// able to pin it through the device path where the reuse actually happens.
///
/// The buffer is `CTAP2_MAX_MSG` on both paths, so the arm and the reply it
/// builds are bounded by the same constant the CTAPHID framing enforces.
pub fn handle(
    data: &[u8],
    auth: Option<TokenAuth<'_>>,
    phy: &crate::vendorff::PhyConfig,
    presence: PresenceGate,
    out: &mut HeaplessVec<u8, CTAP2_MAX_MSG>,
    ops: &mut dyn crate::vendor_backup::BackupOps,
) -> Outcome {
    // The buffer contract: empty on entry, whatever the caller passed. See
    // the note above — on the device path it is the previous command's reply.
    out.clear();
    match extract_subcommand(data) {
        Err(err) => Outcome::plain(err),
        Ok(sub) => handle_subcommand(sub, data, auth, phy, presence, out, ops),
    }
}

/// Pull `subCommand` (CBOR key 1) out of the request map with the no-alloc
/// `no_std` parser, so the same code serves the device and host paths.
///
/// A well-formed map that simply omits key 1 is a *missing parameter*
/// (`0x14`), which is distinct from a body that is not CBOR at all
/// (`0x12`) — collapsing the two would hide decoder regressions behind a
/// plausible status.
fn extract_subcommand(data: &[u8]) -> Result<Subcommand, Ctap2Response> {
    let mut p = Parser::new(data);
    let pairs = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => return Err(Ctap2Response::InvalidCbor),
    };
    let mut found: Option<Result<Subcommand, Ctap2Response>> = None;
    for _ in 0..pairs {
        let key = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
        if key == Item::U(1) {
            // A repeated key 1 is ambiguous — two different sub-commands in one
            // request — and CTAP2 canonical CBOR forbids it, so reject rather
            // than let last-write-wins silently pick one. This is not
            // redundant with the `found` check below; it is the only thing
            // making that check's "first one wins or error" rule explicit, and
            // it is the branch a reader is most likely to delete as noise.
            if found.is_some() {
                return Err(Ctap2Response::InvalidCbor);
            }
            found = Some(match p.next() {
                // Key 1 present but not an unsigned integer: the request is
                // not the shape this protocol defines. Note this is checked
                // before the range test, so a *string* sub-command is a CBOR
                // error rather than being silently coerced.
                Ok(Item::U(v)) => {
                    // `try_from`, not `as u8`: a truncation would turn 0x10E
                    // (270) into 0x0E and dispatch AUDIT_CONFIG for a request
                    // that never asked for it.
                    u8::try_from(v)
                        .ok()
                        .and_then(Subcommand::from_byte)
                        .ok_or(Ctap2Response::InvalidSubcommand)
                }
                _ => Err(Ctap2Response::InvalidCbor),
            });
        } else {
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
        }
    }
    found.unwrap_or(Err(Ctap2Response::MissingParameter))
}

/// Dispatch one enumerated sub-command.
///
/// # This `match` has no `_` arm on purpose
///
/// Every variant is listed, so adding one to [`Subcommand`] fails the build
/// until it is given an arm. That is the compile-time half of the discipline,
/// and it is worth restating its limit: it fires in the *add* direction only.
/// Writing a real arm and leaving the variant in [`Subcommand`] — or leaving
/// it in [`PENDING`] — compiles and passes every check here. The other half is
/// [`PENDING`] plus the two-way test that checks it against this function;
/// see the module docs.
///
/// `data`, `auth`, `phy`, `presence`, `out` and `ops` are passed through so an
/// arm has the request body, the caller's token, the physical configuration
/// record, the user-presence probe, somewhere to put a response, and the
/// durable-state seam, without another round of edits. The twelve stubs ignore
/// all six; [`config_read`] uses `data`, `phy` and `out`; [`config_write`] uses
/// `data`, `auth`, `phy` and `presence`.
///
/// `ops` is the one parameter with a lifetime-independent reason to be here
/// before it has a caller: a Phase I arm's state reads and writes all go
/// through it, and threading it now rather than when the first arm lands keeps
/// the "one more parameter" edit out of the two dispatch sites — which are
/// independent `match`es, and are exactly the place a half-done edit is
/// invisible.
fn handle_subcommand(
    sub: Subcommand,
    data: &[u8],
    auth: Option<TokenAuth<'_>>,
    phy: &crate::vendorff::PhyConfig,
    presence: PresenceGate,
    out: &mut HeaplessVec<u8, CTAP2_MAX_MSG>,
    ops: &mut dyn crate::vendor_backup::BackupOps,
) -> Outcome {
    // The escalation test seam, host builds only — see the section above.
    // It is checked before the `match` so that *no* arm is needed to set the
    // flag, and it answers for exactly the two armed sub-commands, so a test
    // that arms `ConfigWrite` still sees the others behave normally.
    //
    // Read through the thread-local, so a knob armed by one test is invisible
    // to every other test running concurrently. See the declaration for why
    // that is not a stylistic choice.
    #[cfg(feature = "host")]
    if ESCALATION_TEST_SUB.with(|c| {
        core::sync::atomic::AtomicU8::load(c, core::sync::atomic::Ordering::SeqCst)
    }) == sub.byte()
    {
        return Outcome::pin_auth_failure(Ctap2Response::PinAuthInvalid);
    }
    // US-176: no arm reads `ops` yet, and the twelve stubs must not start
    // reading it without also leaving `PENDING`. Naming the parameter `ops`
    // rather than `_ops` is deliberate — a Phase I arm's first line is then
    // the parameter itself — and this statement is what keeps the unused
    // warning from being the only thing recording the fact. The check that
    // actually enforces it is
    // `tests/vendor41.rs::vendor41_stub_never_touches_the_state`.
    let _ = ops;
    match sub {
        // --- seed backup / restore (Offboard, Backup) — US-171, US-172 ---
        // `MSE` is ungated *and* stateful: the channel it parks is the one
        // every later seal and open uses, so a stateless implementation would
        // derive a point and then decrypt nothing.
        Subcommand::Mse => crate::vendor_backup::mse(data, out, ops),
        Subcommand::Export => {
            crate::vendor_backup::export(data, auth, presence, out, ops)
        }
        Subcommand::Load => {
            crate::vendor_backup::load(data, auth, presence, ops)
        }
        // `FINALIZE` is the one arm that must NOT run `backup_auth`: the client
        // sends it as `rs_key_vendor(FINALIZE, None, None)` — no params *and*
        // no token (`picoforge/src/hal/fido/mod.rs:1755-1763`). Gating it
        // answers `0x36` to the only FINALIZE PicoForge ever sends, and
        // `0x36` renders to the user as "device requires a PIN — enter it".
        Subcommand::Finalize => crate::vendor_backup::finalize(presence, ops),
        // --- soft lock (Lock) — US-170 ---
        // `STATE` takes the sealed flag as an argument rather than reading it
        // here, so `vendor_lock` does not have to know that `handle`'s ops
        // parameter is a supertrait.
        Subcommand::State => {
            // Read the flag first: `state` takes `&mut dyn VendorOps`, so
            // passing `ops` and reading `ops.export_sealed()` in the same
            // expression is an immutable borrow captured by a later mutable
            // borrow. The flag is monotonic, so the read cannot go stale
            // between the two statements.
            let sealed = ops.export_sealed();
            crate::vendor_lock::state(ops, sealed, out)
        }
        Subcommand::Unlock => crate::vendor_lock::unlock(ops, data, auth),
        // --- audit journal (Audit) — US-173, US-174 ---
        Subcommand::AuditRead => {
            crate::vendor_audit::audit_read(data, auth, presence, ops, out).into()
        }
        Subcommand::AuditCheckpoint => {
            crate::vendor_audit::audit_checkpoint(data, auth, presence, ops, out).into()
        }
        Subcommand::AuditConfig => {
            crate::vendor_audit::audit_config(data, auth, presence, ops, out).into()
        }
        // --- org attestation (Attestation) — US-175 ---
        // `ATT_STATE` is ungated **by construction**: its signature takes no
        // request body and no token, so routing it through the shared gate is
        // not possible. That is deliberate — the client sends
        // `rs_key_vendor(ATT_STATE, None, None)` (`mod.rs:1895`), and the stock
        // gate checks for a `pinUvAuthParam` *before* it looks at the
        // sub-command (`vendor41.rs:2816-2819`), so an `ATT_STATE` sent the
        // client's exact way would answer `0x36`.
        Subcommand::AttState => crate::vendor_att::att_state(ops, out).into(),
        Subcommand::AttClear => {
            crate::vendor_att::att_clear(data, auth, presence, ops).into()
        }
        Subcommand::AttImport => {
            crate::vendor_att::att_import(data, auth, presence, ops).into()
        }
        // --- device config ---
        // US-115: the second real arm, and the only one that consults a
        // gate. Its gate is per-*field*, not per-request; see `config_write`.
        Subcommand::ConfigWrite => config_write(data, auth, phy, presence),
        // US-114: the first real arm on this channel. Ungated by protocol —
        // it must not reach `verify_mac` or `authorize`; see `config_read`.
        Subcommand::ConfigRead => config_read(data, phy, out),
    }
}

/// The refusal the stub arms used to return, **kept as the shape a refusal
/// takes** now that no arm calls it.
///
/// Phase I drained [`PENDING`], so every sub-command has a real arm and
/// `stub()` has no caller. It is deleted rather than kept as a convenience:
/// a live `fn stub() -> Outcome` is a function a later arm can reach for in a
/// hurry, and the whole point of the empty [`PENDING`] list is that "not
/// written yet" is no longer expressible on this channel.
///
/// The three properties it encoded are now obligations on the *real* arms, and
/// each has a test that would catch a violation:
///
/// * **Synchronous, ungated, no touch, no keepalive.** PicoForge allows 30 s
///   for `CONFIG_WRITE` (`ops.rs:1550`) and 32 s for the touch-gated vendor
///   calls (`ops.rs:1598`) because those handlers really can wait on a
///   button. An arm that opened a user-presence window on the *benign* tier
///   without saying so would read to the desktop app as a hang.
/// * **`Outcome::plain`, never `Outcome::pin_auth_failure`, unless the arm
///   rejected a `pinUvAuthParam`.** Charging a strike for a command that never
///   looked at a token is how a benign-tier command ends a PIN session.
///   `vendor_lock` and `vendor_audit` make this a *type* rather than a
///   convention — `ChargePinAuth::{Charge, NoCharge}` — so the distinction
///   cannot be forgotten at a call site.
#[cfg(any())]
const STUB_REMOVED: () = ();

// ---------------------------------------------------------------------------
// US-115: `CONFIG_WRITE` (sub-command `0x0C`) — field-tiered gating.
// ---------------------------------------------------------------------------

/// Which gate a PHY record's tag falls under.
///
/// # The decision this encodes, and why presence-only is not it
///
/// RS-Key's own `rsk-phy` accepts a `CONFIG_WRITE` with **no PIN and no
/// token** and writes `EF_PHY` / `EF_DEV_CONF` — while the *same records* are
/// PIN + `acfg`-token gated on the `authenticatorConfig` (`0x0D`) path. That
/// asymmetry, not the missing presence check, is the HIGH-1 finding in the
/// RS-Key adoption review (Appendix A of that epic), and it is the reason this
/// is an enum rather than a boolean.
///
/// The two tiers are not ordered by severity, they are ordered by *which
/// authority discharges them*, and only one of them is a real secret:
///
/// * [`FieldTier::Presence`] — a benign overlay. A physical touch authorises
///   it, because the thing being changed is a cosmetic property of the device
///   and the person in front of it is the only authority that matters. This is
///   what PicoForge expects: it says so in its own comment at
///   `picoforge/src/hal/fido/ops.rs:1573-1575` — *"Without one, the firmware
///   gates on a physical touch instead, so no auth fields are sent."*
/// * [`FieldTier::Identity`] — a record that changes how the device
///   identifies itself, or what it presents on the bus. A touch is the wrong
///   authority for this, because the threat is not a bystander pressing the
///   button: it is an unprivileged local process rewriting the USB identity of
///   a token somebody else is about to use. Only a `pinUvAuthToken` carrying
///   `AUTHENTICATOR_CONFIG` (`0x20`) separates those two.
///
/// The two are **not** cumulative. A blob is gated by the strongest tier it
/// touches, so an authenticated VID/PID write does not also demand a button
/// press: a token is a strictly stronger authorisation than a touch, and
/// making the holder of one prove it again by pressing a button would be a
/// requirement with no security content behind it — PicoForge sends no touch
/// for `CONFIG_WRITE` (`ops.rs:1514-1554`) and would simply time out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FieldTier {
    /// A benign overlay. Gate: one user-presence grant, no token.
    ///
    /// # The 30 000 ms collision, which is not a coincidence
    ///
    /// This tier requires a real physical press, and the device's window and
    /// the client's timeout are the **same number**:
    ///
    /// | | value | where |
    /// |---|---|---|
    /// | device consent window | `presence::CTAP_TOUCH_WINDOW_MS = 30_000` | `firmware/src/presence.rs` |
    /// | client `CONFIG_WRITE` timeout | `CONFIG_WRITE_TIMEOUT_MS = 30_000` | `picoforge/src/hal/fido/ops.rs:1551` |
    ///
    /// They are equal, and they are not the same clock. The client's deadline
    /// starts when it finishes *writing* the request; the device's window opens
    /// only after the device has *processed* it and answered
    /// [`Ctap2Response::UpRequired`]. So **the client's deadline always expires
    /// first**, by however long the device took to answer.
    ///
    /// ## What that means for a user today
    ///
    /// Determined by reading both loops, not assumed:
    ///
    /// * **Press before the client's deadline.** The device's retried arm
    ///   consumes the grant, commits through `grow_checked`, and replies
    ///   `0x00` in time. The Config screen reports success. This is the normal
    ///   case and it is the EPIC's row-1 requirement working.
    /// * **Press after the client's deadline but before the device's window
    ///   expires.** The device commits the write **durably** and puts `0x00` on
    ///   the wire into a client that has already returned
    ///   `PFError::Device("Timeout waiting for device response (Keepalive
    ///   limit exceeded)")`. **The change is applied and the desktop app
    ///   reports a failure.** The gap is the device's processing time, so it is
    ///   small — but it is real, and it is the one case where "the write did
    ///   not work" is simply untrue.
    /// * **No press.** The device's window expires, the loop breaks with the
    ///   `UpRequired` still in the buffer, and that `0x3B` goes to a client
    ///   that has already gone. Nothing is applied and nothing is persisted —
    ///   `grow_checked`'s commit never ran, because the arm never got past the
    ///   gate.
    ///
    /// So the property worth stating is: **a benign write is never lost after
    /// being applied.** It is either durably applied — possibly after the UI
    /// reported a timeout — or not applied at all. There is no third state in
    /// which the device has it and neither party knows.
    ///
    /// ## Why there is no desktop prompt
    ///
    /// There is none. The device flickers the activity LED
    /// (`presence::touch_prompt`, re-asserted on every keepalive) and streams a
    /// `CTAPHID_KEEPALIVE` every 100 ms, which the client's read loop
    /// deliberately tolerates (`picoforge/src/hal/transport/fido.rs:529-537`).
    /// The user therefore sees a device that looks busy and a UI that appears
    /// to be waiting, with nothing telling them a button is involved. That is
    /// the honest current behaviour of this tier, and it is a consequence of
    /// the EPIC's row 1 rather than a design choice made here: the row asks
    /// for Presence on the benign overlay, and Presence on this firmware means
    /// the board button.
    ///
    /// ## What would remove it
    ///
    /// Named, not done. The client already has the vocabulary — `rs_key_vendor`
    /// is the *touch-gated* call (`ops.rs:1556-1586`, "the firmware gates on a
    /// physical touch instead"), and the `backup_finalize` / `lock_*` family
    /// is documented as touch-gated. Routing the benign overlay through that
    /// call instead of `rs_key_config_write` would let the desktop app prompt
    /// for the press, and would give it a timeout that is not the same number
    /// as the device's. That is a client-side change in another repository; it
    /// is not this story's to make, and weakening the gate to suit the current
    /// client is exactly the RS-Key behaviour this story exists to avoid.
    Presence,
    /// Identity-destructive. Gate: `pinUvAuthToken` with `AUTHENTICATOR_CONFIG`.
    Identity,
}

/// The tier of a PHY record tag.
///
/// # No `_` arm, and that is the whole point
///
/// Adding a variant to [`PhyTag`] fails the build until this `match` gives it
/// a tier. A tag that arrives with no tier is not "a record we do not
/// recognise and therefore pass through" — it is a hole where a future
/// identity-bearing field would default to the weakest gate. The direction
/// that matters is the one the compiler does **not** check, and it is closed by
/// [`tier_of_wire`]: a *wire byte* outside [`PhyTag`] is a refusal, never a
/// [`FieldTier::Presence`].
///
/// Two rows are identity, and they are the two the EPIC names: the USB
/// VID/PID (`0x00`) and the enabled-USB-interface mask (`0x0B`). The other ten
/// are cosmetic or inert: LED geometry and colour, the product and
/// manufacturer strings, the presence timeout, the power-cycle options word
/// and the curve mask.
pub const fn tier_of(tag: PhyTag) -> FieldTier {
    match tag {
        // How the device identifies itself on the bus, and what it will
        // present once it does.
        PhyTag::VidPid | PhyTag::EnabledUsbItf => FieldTier::Identity,
        // LED geometry, colour, count and driver; USB strings; the
        // power-cycle/presence options; the curve mask. All operator intent
        // about how the device looks and behaves, none of which decides who it
        // is.
        PhyTag::LedGpio
        | PhyTag::LedBrightness
        | PhyTag::Options
        | PhyTag::PresenceTimeout
        | PhyTag::UsbProduct
        | PhyTag::Curves
        | PhyTag::LedDriver
        | PhyTag::LedOrder
        | PhyTag::LedNum
        | PhyTag::UsbManufacturer => FieldTier::Presence,
    }
}

/// The tier of a raw PHY **wire** tag, or `None` if the protocol's twelve tags
/// do not include it.
///
/// `None` is a refusal, not a default. `phy_tlv::Decoder` yields unknown tags
/// as a raw `u8` precisely so a *reader* can step over them the way
/// PicoForge's `_ => {}` arm does — and a reader that skips a record it does
/// not understand is correct, because it is reporting what is already stored. A
/// **writer** is different: a record it cannot classify is a record it cannot
/// gate, and admitting it as benign would be choosing the weakest gate for a
/// field nobody has looked at yet. So `config_write` turns `None` into
/// [`Ctap2Response::UnsupportedOption`].
///
/// The blob is attacker-controlled, which is the reason this is a hard rule
/// and not a style preference: the tag byte comes off the wire and has not
/// been authenticated at the point the classifier runs (see [`config_write`]
/// on why the classifier runs before the MAC).
pub const fn tier_of_wire(tag: u8) -> Option<FieldTier> {
    // A `match` rather than `PhyTag::from_byte(tag).map(tier_of)`: `Option::map`
    // is not `const`-callable on this toolchain, and a non-`const` helper would
    // be a worse trade than four lines that say what they say.
    match PhyTag::from_byte(tag) {
        Some(t) => Some(tier_of(t)),
        None => None,
    }
}

/// The user-presence probe a `CONFIG_WRITE` benign-tier write is gated on.
///
/// Two fields because this firmware has two presence paths and the app that
/// owns them already distinguishes them (`device_core`'s `FidoApp::user_present`):
/// the US-921 shared runtime's window grant takes a presence tag, and the
/// legacy synchronous button poll takes nothing. The resolution order below is
/// `user_present`'s, deliberately — a `CONFIG_WRITE` that gates presence
/// differently from `makeCredential` would be a second, drifting definition of
/// what a touch means.
///
/// [`Default`] is the host and emulation path, and it resolves through
/// `device_core`'s `default_user_present` — auto-ack on host, fail-closed on
/// device. (`pub(crate)`, so it is written as a path rather than a link: a
/// public item's docs linking a private one is its own warning, and the base
/// tree has none of them to add to.) That is the same default `user_present` uses, so a test that
/// drives a `CONFIG_WRITE` on the host twin without a probe is testing the
/// same "no probe means no gate" the rest of the host suite already assumes —
/// which is why the presence tier's RED test drives
/// [`config_write`] with an explicit probe rather than relying on it.
#[derive(Debug, Clone, Copy, Default)]
pub struct PresenceGate {
    /// The shared runtime's **join-only** window grant (device). Consumes a
    /// grant bound to `tag`; never opens a window itself — the HID task's
    /// `UpRequired` retry loop owns that lifecycle, which is the same
    /// arrangement `makeCredential` has.
    pub window_grant: Option<fn(u32) -> bool>,
    /// The legacy synchronous button poll, for hosts and tests.
    pub poll: Option<fn() -> bool>,
    /// The presence tag for the request's channel
    /// ([`crate::device_app::presence_tag_from_channel`]).
    pub tag: u32,
}

impl PresenceGate {
    /// Whether a presence grant is available for this request.
    ///
    /// The device path is **join-only** by design, so a first call returns
    /// `false` and the answer is [`Ctap2Response::UpRequired`]; the HID task
    /// then opens the window, streams keepalives and re-drives the command,
    /// and the second call consumes the press. That is the same two-step shape
    /// `makeCredential` uses, and it is why a `CONFIG_WRITE` on the device
    /// does not block: the blocking would be in the task, not the arm.
    pub fn granted(self) -> bool {
        if let Some(g) = self.window_grant {
            return g(self.tag);
        }
        match self.poll {
            Some(f) => f(),
            None => crate::device_core::default_user_present(),
        }
    }
}

/// # The `CONFIG_WRITE` targets this arm serves
///
/// Three, and the choice of three is the client's, read off
/// `RSKEY_CFG_TARGET_*` (`picoforge/src/hal/fido/constants.rs:771-775`):
///
/// | target | name | blob format | tier |
/// |---|---|---|---|
/// | [`TARGET_PHY`] `0x01` | PHY | a `TAG LEN VALUE` record stream | per-field ([`tier_of`]) |
/// | [`TARGET_DEV_CONF`] `0x00` | DEV_CONF | management TLV, one record | always [`FieldTier::Identity`] |
/// | [`TARGET_LED`] `0x02` | LED | a fixed 17-byte block | always [`FieldTier::Presence`] |
///
/// The other targets are refused with [`Ctap2Response::InvalidParameter`],
/// and that is a statement about the protocol rather than about support: the
/// three constants are the only ones the protocol defines, and a fourth byte
/// is not a record this firmware recognises.
///
/// # Why the two new targets do not share the PHY classifier
///
/// Because they do not share the PHY *format*, and running one dialect's
/// classifier over another's bytes is how a field gets written that means
/// something else. `DEV_CONF` carries a management-applet TLV whose only
/// record is `tag 0x03, len 2, enabled_be`
/// (`write_rskey_dev_config`, `picoforge/src/hal/fido/mod.rs:2086-2091`; the
/// tag constant `FIDO_MGMT_TAG_USB_ENABLED` is at `:2071`), and `LED` is not
/// a record stream at all but a fixed 17-byte block
/// (`RSKEY_LED_CONF_LEN`, `picoforge/src/hal/fido/mod.rs:2001`, written at
/// `:2043-2063`). Three functions, one per format, is what keeps the
/// `0x0B`-style "this record means what I say it means" property true of each.
///
/// The two tiers are worth stating separately, because they are not a
/// gradient — they are two different answers to "who is the authority".
///
/// * `DEV_CONF` is [`FieldTier::Identity`] **unconditionally**, and the reason
///   is that its one record *is* the USB enabled-interface mask: the same
///   operator intent the PHY record carries in tag `0x0B`, which
///   [`tier_of`] already classifies as identity. Routing a second carrier of
///   that value to a weaker gate would not be a new policy, it would be an
///   opening — the classification would describe every path but the one a
///   client actually uses. See `apply_dev_conf`.
/// * `LED` is [`FieldTier::Presence`] **unconditionally**, because every byte
///   of a 17-byte status block is a cosmetic property of a light. This is the
///   same answer [`tier_of`] gives `LedGpio` and `LedBrightness`, and for the
///   same reason: a touch is the authority for "make the LED blue".
///
/// The client degrades honestly on the refusal: `rs_key_config_write`
/// propagates the non-zero status (`picoforge/src/hal/fido/ops.rs:1552-1553`)
/// rather than answering a silent success.
///
/// # Handle `CONFIG_WRITE`: decode the target's record, classify every field,
/// gate on the strongest tier present, and return the
/// [`crate::vendorff::PhyConfig`] the dispatch arm should commit.
///
/// # The order of the four steps, and why each is where it is
///
/// ```text
/// 1. decode target + blob          (unauthenticated)
/// 2. classify + validate + zero-mask refusal   (unauthenticated)
/// 3. gate on the aggregate tier    (authenticated for Identity only)
/// 4. return the new record         (the dispatch arm makes it durable)
/// ```
///
/// Steps 1 and 2 run over **unauthenticated** bytes, before the MAC is checked,
/// and that is safe for two independent reasons. The first is that they can
/// only ever make the request *more* constrained: the worst an attacker does
/// is present a blob that classifies as [`FieldTier::Presence`] and therefore
/// reaches a presence gate instead of a token gate — and to do that they must
/// make the request pass a physical touch, at which point the touch is the
/// authority. The second is that the tag bytes are *inside* the params, so for
/// any request that gets as far as committing, the MAC has covered exactly
/// these bytes ([`verify_mac`] hands back the params span; the blob is
/// extracted from it).
///
/// The alternative ordering — authenticate, then classify — is not
/// implementable as a *tier* decision at all: it would mean demanding a token
/// from every `CONFIG_WRITE`, which is exactly the "presence, not token" row
/// the EPIC's table specifies, and it would break the benign tier outright.
/// PicoForge always sends a token for this sub-command
/// (`picoforge/src/hal/fido/ops.rs:1514-1554`), so nothing observable depends
/// on the benign tier being reachable without one — but the tier is what the
/// EPIC asked for, and a gate that cannot be told apart from a stricter one is
/// not a gate.
///
/// # The zero-mask refusal, and why it is unconditional
///
/// A USB enabled-interface mask of `0` is refused with
/// [`Ctap2Response::InvalidOption`] *before* step 3, in every authentication
/// state, on **both** carriers of the value. RS-Key's `rsk-phy` accepts
/// `(0x0B, 1)` — one byte, value 1 — with no non-zero floor, which means a
/// single unauthenticated packet makes the device re-enumerate with **no** USB
/// interfaces: gone from every attached host until BOOTSEL recovery. That is a
/// denial of service against the whole bus the token is on, it is reachable
/// with the weakest authority this tier admits, and it has no legitimate use —
/// there is no configuration in which "this authenticator presents nothing" is
/// what an operator meant. So it is unreachable in any configuration, which is
/// a stronger statement than "gated behind the token" and the reason it is
/// checked before the gate rather than inside the identity branch.
///
/// US-117 is where that stopped being a hypothetical. Until this story
/// `DEV_CONF` was refused outright, so the second carrier of the mask did not
/// exist; it now does, and a rule written only for PHY tag `0x0B` would leave
/// `03 02 00 00` — the same denial of service, spelled with the other
/// dialect's bytes — accepted behind a token. The rule is therefore stated
/// once, over the mask *value*, in `zero_mask_refusal_value`, and both
/// carriers call it.
///
/// # The non-zero floor, and why the other values do not get one
///
/// The EPIC asks whether this implementation should also floor the *other*
/// values. It should not, and the reason is that the zero mask is not
/// rejected for being zero — it is rejected for having a **total** effect on
/// every host on the bus. `LedGpio = 0` is a real pin. `LedBrightness = 0` is
/// "LED off" and is already bounded at `0..=100` by
/// [`crate::vendorff::validate`], the same authority the `0xFF` framing uses.
/// `Options` is a bitmask of three named bits. `VidPid` is a `u32` the client
/// packs as `(vid << 16) | pid`; `vendorff::validate` accepts `0x0000_0000`
/// and so does this arm, because on this firmware a zero VID/PID is **stored
/// and not applied** — the USB descriptors are a compile-time `CONFIG_DESC`
/// (`firmware/src/main.rs`, see `vendorff`'s "stored, not applied"). Refusing
/// it today would be a policy about a future that has not been built, and it
/// would make this framing disagree with `vendorff` about the same value, which
/// is the drift the shared-validator discipline exists to prevent. When
/// descriptors become runtime-configurable, a non-zero VID/PID floor belongs
/// with that story, for the same reason the interface mask belongs with it.
///
/// # What is committed, and what is not
///
/// Only **five** of the twelve tags have a field in
/// [`crate::vendorff::PhyConfig`]: VID/PID, LED GPIO, LED brightness, the
/// options word and the USB enabled-interface mask. The other **seven** are
/// **refused** with [`Ctap2Response::UnsupportedOption`] — the blob is rejected
/// whole, not partially applied.
///
/// US-117 moved one tag across that line, and this paragraph had not followed:
/// it still said four/eight, which stopped being true the moment
/// [`PhyTag::EnabledUsbItf`] gained a destination. It needed one, because
/// `DEV_CONF` (`0x00`) carries the same operator intent — the USB
/// enabled-interface mask — and a carrier with nowhere to put it is a carrier
/// that has to be refused. So it is two carriers and one field
/// ([`crate::vendorff::PhyConfig::enabled_usb_itf`]), held to one tier and one
/// zero-mask rule. The remaining seven are the USB product and manufacturer
/// strings, the presence timeout, the curve mask, and the LED driver, order
/// and count.
///
/// A partial apply is the one answer this arm cannot give. `CONFIG_WRITE`
/// carries a 30-second client timeout (`ops.rs:1550`) and the desktop app
/// renders a `0x00` as "Configuration updated successfully! The device is
/// re-enumerating" (`mod.rs:1180-1184`). Acking a request that persisted some
/// of the records it was asked for and refused the rest is a success that is
/// false, on a screen where the user has no way to tell. Refusing is loud, and
/// it is the same reason the unknown-tag case is a refusal.
///
/// The cost is named rather than hidden: a Config screen that touches the
/// product name, the manufacturer, the curve mask, the presence timeout or the
/// LED driver/order/count gets a clean `CTAP2_ERR_UNSUPPORTED_OPTION`, and the
/// fields it changes are not written. Lifting that is a change to `PhyConfig`
/// and therefore to the secure-snapshot codec (`device_keystore.rs`'s auth-map
/// key 6), which is a separate story with its own size budget — not something
/// to smuggle in behind a gate.
pub fn config_write(
    data: &[u8],
    auth: Option<TokenAuth<'_>>,
    phy: &crate::vendorff::PhyConfig,
    presence: PresenceGate,
) -> Outcome {
    // --- 1. the request shape: `{1: target, 2: <blob>}` ---
    let (target, blob) = match config_write_params(data) {
        Ok(p) => p,
        Err(e) => return Outcome::plain(e),
    };
    if target != TARGET_PHY && target != TARGET_DEV_CONF && target != TARGET_LED {
        // Only the three `RSKEY_CFG_TARGET_*` bytes are defined. A fourth is
        // not a record this firmware recognises, and answering it `0x00`
        // would be a `0x00` over bytes nobody has claimed mean anything.
        return Outcome::plain(Ctap2Response::InvalidParameter);
    }

    // --- 2. classify, validate, and refuse the zero mask ---
    let mut next = *phy;
    let tier = match target {
        TARGET_PHY => match classify_phy(blob, &mut next) {
            Ok(t) => t,
            Err(e) => return Outcome::plain(e),
        },
        TARGET_DEV_CONF => match apply_dev_conf(blob, &mut next) {
            Ok(t) => t,
            Err(e) => return Outcome::plain(e),
        },
        // The only remaining byte, and the first arm already excluded the
        // rest, so this is total.
        _ => match apply_led(blob, &mut next) {
            Ok(t) => t,
            Err(e) => return Outcome::plain(e),
        },
    };

    // --- 3. gate on the strongest tier the blob touches ---
    match tier {
        FieldTier::Identity => {
            if let Err(outcome) = identity_gate(data, auth) {
                return outcome;
            }
        }
        FieldTier::Presence => {
            if !presence.granted() {
                return Outcome::plain(Ctap2Response::UpRequired);
            }
        }
    }

    // --- 4. hand the record back for the dispatch arm to make durable ---
    //
    // An empty blob is a *benign-tier* blob (nothing in it is identity), so it
    // still needs a presence grant; once granted it changes nothing and
    // answers `0x00`. That is deliberate: refusing it would make a client that
    // sent a well-formed empty configuration look broken. The client does not
    // send one — `write_rskey_config` short-circuits an empty TLV before
    // getting here (`mod.rs:1145-1147`) — so this is a shape, not a case.
    //
    // "Not a case" is about the *client*, not about the medium: `next` equals
    // `*phy`, so the device arm still calls `grow_checked` and programs a
    // snapshot byte-identical to the stored one. To any caller who can supply a
    // touch that is a cheap flash-wear primitive, bounded only by the presence
    // window. Worth knowing before the shape is treated as inert; not worth
    // refusing, because "a well-formed empty configuration" is a legitimate
    // request and a `0x00` for it costs nothing but one slot write.
    Outcome::with_phy(Ctap2Response::Ok, next)
}

/// Decode a PHY record stream into `cfg` and report the strongest tier it
/// touches, or refuse it whole.
///
/// This is US-115's step 2, extracted from [`config_write`] verbatim so the
/// three targets have the same shape to be called in and so the ordering
/// property — classify and validate *before* the gate, never inside it — has
/// one place rather than three. The body did not change in US-117.
fn classify_phy(
    blob: &[u8],
    cfg: &mut crate::vendorff::PhyConfig,
) -> Result<FieldTier, Ctap2Response> {
    let mut tier = FieldTier::Presence;
    for record in phy_tlv::Decoder::new(blob) {
        let (raw, value) = match record {
            Ok(r) => r,
            // A blob that ends mid-record is not a short configuration, it is
            // a malformed one; `phy_tlv`'s own docs make that call and the
            // client's reader (`mod.rs:938`) is the leniency this deliberately
            // does not copy.
            Err(_) => return Err(Ctap2Response::InvalidCbor),
        };
        let (tag, this_tier) = match PhyTag::from_byte(raw) {
            Some(t) => (t, tier_of(t)),
            // Never a default tier. See `tier_of_wire`.
            None => return Err(Ctap2Response::UnsupportedOption),
        };
        // Checked before `apply`, and before the gate, and on its own: the
        // value is refused whether or not the caller holds a token, so no
        // authentication state reaches it.
        if let Some(err) = zero_mask_refusal(tag, value) {
            return Err(err);
        }
        apply_phy_record(cfg, tag, value)?;
        if this_tier > tier {
            tier = this_tier;
        }
    }
    Ok(tier)
}

/// The unconditional zero-interface-mask refusal, over the mask **value**.
///
/// # Why the rule is stated here and not on a tag
///
/// Because as of US-117 there are two carriers of the same value — the PHY
/// record's `0x0B` and the `DEV_CONF` record's `0x03` — and they carry it at
/// different widths (one byte and two). A rule written once per carrier would
/// be two rules, and two rules is one more than the property has. So the
/// property is stated over the number and each carrier is responsible only for
/// getting its own bytes to a number.
///
/// The property: a USB enabled-interface mask of `0` is refused with
/// [`Ctap2Response::InvalidOption`] in **every** authentication state, before
/// any gate runs. See [`config_write`] for why it is unconditional rather than
/// gated, and why US-117 made the question live rather than theoretical.
///
/// Split out of the carrier functions so the rule cannot drift into a tier
/// `match`. `config_write_rejects_zero_interface_mask_unconditionally` and
/// `dev_conf_rejects_the_zero_mask_unconditionally` pin both carriers, by
/// driving whole requests rather than by calling this, so the ordering being
/// asserted is the ordering that actually runs.
const fn zero_mask_refusal_value(mask: u16) -> Option<Ctap2Response> {
    if mask == 0 {
        Some(Ctap2Response::InvalidOption)
    } else {
        None
    }
}

/// The zero-mask refusal for the **PHY** carrier, or `None` for every other
/// `(tag, value)`.
fn zero_mask_refusal(tag: PhyTag, value: &[u8]) -> Option<Ctap2Response> {
    if tag != PhyTag::EnabledUsbItf {
        return None;
    }
    // The width is checked before the value, and it has to be: this tag's value
    // is one byte, so `value.first() == Some(&0)` alone would also fire on a
    // three-byte record that merely *starts* with zero — and `0x2B` means "an
    // invalid value for a real option", which is not what a wrong-width record
    // is. Falling through instead lets `apply_phy_record` give its own answer
    // (`0x2A`, this firmware has no field for the record), so each status keeps
    // meaning one thing. The client only ever writes one byte
    // (`tlv.push(RSKEY_PHY_TAG_ENABLED_USB_ITF); tlv.push(0x01)`,
    // `picoforge/src/hal/fido/mod.rs:1127-1128`), so this is defence in depth
    // against a hand-built request rather than a case in practice.
    if value.len() != 1 {
        return None;
    }
    zero_mask_refusal_value(u16::from(value[0]))
}

/// Apply a `DEV_CONF` blob, or refuse it whole. Always
/// [`FieldTier::Identity`].
///
/// # Why the tier is not derived from a tag
///
/// Because there is exactly one record this target carries, and it is the USB
/// enabled-interface mask. A classification that walked
/// [`PhyTag`] would not find it — `0x03` is a *management* tag, not a PHY one
/// — and the alternative, a one-entry table of DEV_CONF tags with a tier each,
/// would be a way to say "identity" once in a structure built to be extended.
/// If a second DEV_CONF record ever appears, this function grows an arm for it
/// and that arm's tier is the thing to argue about.
///
/// # Why identity, in one sentence
///
/// Because a mask of `0` is a denial of service against every host on the bus
/// and a non-zero mask changes what the token presents, so the authority for it
/// is the same `0x20` token that [`tier_of`] already demands of the PHY
/// record's own copy of the same value. Weakening it here would not be a new
/// policy for `DEV_CONF`; it would be the only path to that value that US-115's
/// classification did not cover.
///
/// # What is refused, and how
///
/// * An unknown tag, or a second record, whole — [`Ctap2Response::UnsupportedOption`].
///   A partial apply is not available for the same reason it is not on the PHY
///   path: see [`config_write`]'s "what is committed, and what is not".
/// * A mask of `0`, before the gate — [`Ctap2Response::InvalidOption`], from
///   `zero_mask_refusal_value`.
/// * A value that is not exactly two bytes — [`Ctap2Response::InvalidParameter`],
///   before the mask is computed, so a three-byte record is not read as a mask
///   with a stray byte attached.
fn apply_dev_conf(
    blob: &[u8],
    cfg: &mut crate::vendorff::PhyConfig,
) -> Result<FieldTier, Ctap2Response> {
    let mut mask: Option<u16> = None;
    for record in phy_tlv::Decoder::new(blob) {
        let (raw, value) = match record {
            Ok(r) => r,
            Err(_) => return Err(Ctap2Response::InvalidCbor),
        };
        if raw != DEV_CONF_TAG_USB_ENABLED {
            return Err(Ctap2Response::UnsupportedOption);
        }
        // A repeated record is refused rather than last-wins: a request whose
        // meaning depends on map order is a request this firmware will not
        // guess at, and "which mask was asked for" would be undecidable.
        if mask.is_some() {
            return Err(Ctap2Response::InvalidCbor);
        }
        let [hi, lo] = exact::<2>(value)?;
        mask = Some(u16::from_be_bytes([hi, lo]));
    }
    let mask = mask.ok_or(Ctap2Response::MissingParameter)?;
    if let Some(err) = zero_mask_refusal_value(mask) {
        return Err(err);
    }
    cfg.enabled_usb_itf = Some(mask);
    Ok(FieldTier::Identity)
}

/// Apply a `LED` block, or refuse it whole. Always [`FieldTier::Presence`].
///
/// # This stores 17 bytes; it does not interpret them
///
/// The block is `[steady(1), (effect, color, brightness, speed) × 4]`
/// (`RSKEY_LED_CONF_LEN`, `picoforge/src/hal/fido/mod.rs:2001`). Every byte of
/// it is a cosmetic property of a light, and the client is the only party that
/// defines what each one means — so the whole block is stored verbatim and the
/// tier is the presence tier, which is the same answer [`tier_of`] gives the
/// PHY record's own `LedGpio` and `LedBrightness`. See
/// [`crate::vendorff::LedConf`] for why no byte is range-checked here.
///
/// # Where the read-modify-write actually is
///
/// **Not here, and this is the load-bearing correction.** The EPIC text for
/// US-117 says the device must read the old block first, "or it will zero
/// effect and speed". The client does that, not the device:
/// `write_rskey_led_config` reads the current block with
/// `rs_key_config_read(RSKEY_CFG_TARGET_LED)`, copies it, and overwrites only
/// `block[0]`, `block[2 + 4i]` and `block[3 + 4i]`
/// (`picoforge/src/hal/fido/mod.rs:2043-2057`). The device receives a complete
/// 17-byte block and stores it whole.
///
/// So the zeroing the EPIC describes is real but its cause is the **read**,
/// not the write: if `CONFIG_READ` at target `0x02` fails or returns a short
/// blob, the client's `if let Ok(..) && current.len() >= RSKEY_LED_CONF_LEN`
/// falls through to an all-zero block, and *that* is what wipes effect and
/// speed. Which is why US-117 also makes `0x02` readable — see
/// [`config_read`]. A device that stored the block and then refused to read it
/// back would produce exactly the bug the EPIC predicted, by the other route.
///
/// # What is refused
///
/// A block that is not exactly [`crate::vendorff::LedConf::LEN`] bytes —
/// [`Ctap2Response::InvalidParameter`], before anything is stored. An empty
/// blob is included: it is not "leave the LED alone", it is a 17-byte block of
/// nothing, and accepting it would be indistinguishable on the wire from
/// accepting a block that turns every status dark.
fn apply_led(
    blob: &[u8],
    cfg: &mut crate::vendorff::PhyConfig,
) -> Result<FieldTier, Ctap2Response> {
    let block = exact::<{ crate::vendorff::LedConf::LEN }>(blob)?;
    cfg.led_conf = Some(crate::vendorff::LedConf(block));
    Ok(FieldTier::Presence)
}

/// The identity tier's gate: a `0x20` token, and a MAC that verifies.
///
/// `Ok(())` means the request is authorised; `Err` carries the outcome to
/// return. The order is CTAP2's own: *is there auth at all* (`0x36`), *does it
/// verify* (`0x33`, charged to the app's three-strike counter), *does it carry
/// the permission* (`0x40`) — the one order [`authorize`]'s docs tell an arm to
/// pick and not mix, and the order the reason a tokenless [`Requirement::Permission`]
/// request answers `0x36` rather than `0x40` follows from.
///
/// The latch is consulted before the MAC is looked at: once
/// `needs_power_cycle` is set, CTAP2.1 §6.5.7 requires pinUvAuth to be
/// refused outright, and answering `0x36` or `0x33` here would tell the client
/// its token was missing or wrong when in fact the device is refusing all
/// pinUvAuth. `0x34` is the right byte and it is not charged as a failure —
/// the app is already latched, and `note_pin_auth_failure` would only burn one
/// of the three strikes it already spent.
///
/// # Why a benign-tier request never reaches this
///
/// Because it is the *presence* tier, and a touch is the authority the EPIC
/// names for it. A `pinUvAuthParam` riding along on a benign blob is
/// deliberately **not** verified, so it is not charged either — the same
/// reasoning that keeps [`config_read`] from reaching [`verify_mac`]: refusing
/// to look at a param means refusing to charge a failure for it, and three
/// reads of a config screen must not latch a three-strike lockout against a
/// user who failed nothing.
fn identity_gate(data: &[u8], auth: Option<TokenAuth<'_>>) -> Result<(), Outcome> {
    // No token at all is `0x36`, not a fall-through to "authorised". This is
    // spelled out rather than folded into the `?` below because the function's
    // `Result` carries `Outcome` in its error arm, and a `?` on a `None`
    // `auth` would produce exactly the "no token means no gate" reading that
    // `Requirement::Permission` exists to prevent.
    let a = match auth {
        Some(a) => a,
        None => return Err(Outcome::plain(Ctap2Response::PuatRequired)),
    };
    if a.blocked {
        return Err(Outcome::plain(Ctap2Response::PinAuthBlocked));
    }
    match verify_mac(data, Some(a.token)) {
        Ok(_) => {}
        // Only a genuine authentication failure is charged. A request whose
        // CBOR is malformed, or which declares a protocol this channel does
        // not define, never reached a comparison against anything secret.
        Err(Ctap2Response::PinAuthInvalid) => {
            return Err(Outcome::pin_auth_failure(Ctap2Response::PinAuthInvalid))
        }
        Err(e) => return Err(Outcome::plain(e)),
    }
    // There is a token here, so this is `Some(perms)`: a legacy `getPinToken`
    // token arrives as `Some(0)` and is refused, which is the boundary
    // `authorize`'s docs draw.
    match authorize(Subcommand::ConfigWrite, Some(a.permissions)) {
        Ok(()) => Ok(()),
        Err(e) => Err(Outcome::plain(e)),
    }
}

/// Apply one already-classified PHY record to `cfg`, or refuse it.
///
/// The `match` has **no `_` arm**, for the same reason [`tier_of`] does: a
/// tag added to [`PhyTag`] cannot be applied here without being classified
/// there first, and the two are the same decision seen from opposite sides.
///
/// **Seven** of the twelve arms refuse, and they refuse **together**: see
/// [`config_write`] on why a partial apply is not available. `Vendorff`'s
/// range rules are the ones applied, so the two framings that reach the same
/// persisted record cannot disagree about what a valid value is.
///
/// US-117 took one of the eight out of the refusing set by giving
/// [`PhyTag::EnabledUsbItf`] a destination, leaving seven, and this count had
/// followed the `match` rather than the prose — the two are kept in step here
/// deliberately,
/// and `tests/vendor41.rs::config_write_refuses_records_with_no_destination_in_the_persisted_record`
/// is what holds them in step: it walks all twelve tags and asserts the
/// writable/refused split against this arm's behaviour rather than against
/// either list.
fn apply_phy_record(
    cfg: &mut crate::vendorff::PhyConfig,
    tag: PhyTag,
    value: &[u8],
) -> Result<(), Ctap2Response> {
    match tag {
        PhyTag::VidPid => {
            // Big-endian, because that is what the client writes
            // (`mod.rs:1026-1027`) and reads back (`:952`); see
            // `write_phy_record`'s note on why little-endian here would be
            // the identity-spoofing primitive rather than a bug.
            let v: [u8; 4] = exact(value)?;
            cfg.vid_pid = Some(crate::vendorff::pack_vidpid(
                u16::from_be_bytes([v[0], v[1]]),
                u16::from_be_bytes([v[2], v[3]]),
            ));
        }
        PhyTag::LedGpio => cfg.led_gpio = Some(exact::<1>(value)?[0]),
        PhyTag::LedBrightness => {
            let b = exact::<1>(value)?[0];
            // `0..=100`, the client's own bound
            // (`write_legacy_hardware_config`'s field validation) and
            // `vendorff::validate`'s. A brightness of 0 is "LED off", which is
            // a real setting — unlike the interface mask, which has no zero
            // that means anything except "disappear".
            if b > 100 {
                return Err(Ctap2Response::InvalidParameter);
            }
            cfg.led_brightness = Some(b);
        }
        PhyTag::Options => {
            let v: [u8; 2] = exact(value)?;
            let bits = u16::from_be_bytes(v);
            // The same three named bits `vendorff::OPT_*` defines, and the same
            // "no unnamed bits" rule `vendorff::validate` applies to the
            // options word on the `0xFF` path.
            if bits & !(crate::vendorff::OPT_DIMMABLE
                | crate::vendorff::OPT_DISABLE_POWER_RESET
                | crate::vendorff::OPT_LED_STEADY)
                != 0
            {
                return Err(Ctap2Response::InvalidParameter);
            }
            cfg.options = Some(bits);
        }
        // The two USB identity strings. Both are the same operation with a
        // different field, and both arrive **NUL-terminated** — the client's
        // writer appends the terminator inside the record
        // (`picoforge/src/hal/rescue/ops.rs:543-560`), so the stored value
        // drops it and the encoder puts it back.
        //
        // A name that will not fit is refused `InvalidParameter` rather than
        // truncated, because a silently shortened product name is one an
        // operator cannot see and a user reads as a typo.
        PhyTag::UsbProduct => {
            cfg.product = Some(identity_name(value)?);
        }
        PhyTag::UsbManufacturer => {
            cfg.manufacturer = Some(identity_name(value)?);
        }
        // Known tags with no field in `PhyConfig`. Refused as a group, with
        // the status that says "this firmware does not support this record"
        // rather than "you sent a value I cannot parse" — a distinction that
        // matters, because the client would skip the tag silently
        // (`mod.rs:1001-1003`) and would then be told the write succeeded.
        //
        // US-117 removed `EnabledUsbItf` from this list. It is not a "no
        // destination" case any more: `DEV_CONF` (`0x00`) gives the same
        // operator intent a field to land in, and the two carriers write the
        // same `PhyConfig::enabled_usb_itf`. One field, two paths, one
        // zero-mask rule — see `zero_mask_refusal_value`.
        PhyTag::Curves
        | PhyTag::PresenceTimeout
        | PhyTag::LedDriver
        | PhyTag::LedOrder
        | PhyTag::LedNum => return Err(Ctap2Response::UnsupportedOption),
        // Big-endian, for the same reason `VidPid` is: the one byte carries
        // eight interface bits, and the client writes it as a single byte
        // (`tlv.push(0x01)` — the value, not a big-endian word —
        // `picoforge/src/hal/fido/mod.rs:1127-1128`). The widths differ
        // between the two carriers and that is the client's, not this
        // firmware's, choice; the mask *value* is what both are refused on.
        PhyTag::EnabledUsbItf => {
            let v = exact::<1>(value)?[0];
            // Unreachable in practice: `zero_mask_refusal` has already refused
            // every width but one and refused `0` itself. Kept because the
            // function must not depend on a caller having checked, and because
            // routing it here is what makes the two carriers provably agree.
            if let Some(err) = zero_mask_refusal_value(u16::from(v)) {
                return Err(err);
            }
            cfg.enabled_usb_itf = Some(u16::from(v));
        }
    }
    Ok(())
}

/// A NUL-terminated wire name, as the stored value the encoder will re-frame.
///
/// The terminator is stripped rather than required: the client appends one
/// (`ops.rs:543-560`) but the codec's own `encode_nul_string` is what puts it
/// on the wire, so a caller that hand-rolled a record without it should be
/// stored faithfully rather than refused. An **interior** NUL is a different
/// matter and is refused — it is what `IdentityName::new` checks for, and a
/// name that splits in half at an invisible byte is not a name.
fn identity_name(value: &[u8]) -> Result<crate::vendorff::IdentityName, Ctap2Response> {
    let body = match value.split_last() {
        Some((0, rest)) => rest,
        _ => value,
    };
    // `IdentityName::new` takes a `&str`, and the client writes UTF-8
    // (`from_utf8` on the read side, `ops.rs:350`). Non-UTF-8 here is a
    // malformed record, not a name we can store.
    let text = core::str::from_utf8(body).map_err(|_| Ctap2Response::InvalidParameter)?;
    crate::vendorff::IdentityName::new(text).ok_or(Ctap2Response::InvalidParameter)
}

/// A record value of exactly `N` bytes, or refuse.
///
/// `try_into` on a slice, so a wrong width is a refusal rather than a
/// truncation: a truncated VID/PID or options word is a *different, valid*
/// record, and writing that one is precisely the identity-spoofing primitive.
fn exact<const N: usize>(value: &[u8]) -> Result<[u8; N], Ctap2Response> {
    <[u8; N]>::try_from(value).map_err(|_| Ctap2Response::InvalidParameter)
}

/// Pull `{1: target, 2: blob}` out of `subCommandParams` (CBOR key 2).
///
/// The inverse of what `rs_key_config_write` builds
/// (`picoforge/src/hal/fido/ops.rs:1519-1524`): a two-pair map whose second
/// value is a CBOR **byte string** carrying the TLV blob. The blob is
/// returned as a slice **borrowed from `data`**, not copied — it is bounded by
/// `CTAPHID_MAX_MSG`, and a 152-byte worst case on the RP2350's stack per
/// `CONFIG_WRITE` is not free.
///
/// The duplicate-key and trailing-byte refusals are the same two
/// [`crate::vendorff::PhyCommand::decode`] makes, and for the same reason: a
/// repeated `target` is a request whose meaning depends on map order, and a
/// repeated `blob` is a request where "which bytes were authorised" is
/// undecidable — the strongest possible reason to refuse rather than pick one.
fn config_write_params(data: &[u8]) -> Result<(u8, &[u8]), Ctap2Response> {
    use crate::cbor::no_heap::{Item, Parser};
    let mut p = Parser::new(data);
    let pairs = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => return Err(Ctap2Response::InvalidCbor),
    };
    let mut target: Option<u8> = None;
    let mut blob: Option<&[u8]> = None;
    for _ in 0..pairs {
        let key = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
        if key == Item::U(2) {
            let Ok(Item::Map(inner)) = p.next() else {
                return Err(Ctap2Response::InvalidCbor);
            };
            read_write_params(&mut p, inner, &mut target, &mut blob)?;
        } else {
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
        }
    }
    if p.remaining() != 0 {
        return Err(Ctap2Response::InvalidCbor);
    }
    match (target, blob) {
        (Some(t), Some(b)) => Ok((t, b)),
        _ => Err(Ctap2Response::MissingParameter),
    }
}

fn read_write_params<'a>(
    p: &mut Parser<'a>,
    pairs: u64,
    target: &mut Option<u8>,
    blob: &mut Option<&'a [u8]>,
) -> Result<(), Ctap2Response> {
    use crate::cbor::no_heap::Item;
    for _ in 0..pairs {
        let key = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
        match key {
            Item::U(1) => {
                if target.is_some() {
                    return Err(Ctap2Response::InvalidCbor);
                }
                // `try_from`, not `as u8`: a truncation would turn 0x101 into
                // `TARGET_PHY` and serve the whole PHY record to a
                // request that named some other target.
                *target = Some(match p.next() {
                    Ok(Item::U(v)) => {
                        u8::try_from(v).map_err(|_| Ctap2Response::InvalidParameter)?
                    }
                    _ => return Err(Ctap2Response::InvalidCbor),
                });
            }
            Item::U(2) => {
                if blob.is_some() {
                    return Err(Ctap2Response::InvalidCbor);
                }
                *blob = Some(match p.next() {
                    Ok(Item::B(b)) => b,
                    _ => return Err(Ctap2Response::InvalidCbor),
                });
            }
            _ => p.skip().map_err(|_| Ctap2Response::InvalidCbor)?,
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// US-114: `CONFIG_READ` (sub-command `0x0D`).
// ---------------------------------------------------------------------------

/// `RSKEY_CFG_TARGET_PHY` — the `target` byte in `CONFIG_READ`'s **and**
/// `CONFIG_WRITE`'s `subCommandParams` (`picoforge/src/hal/fido/constants.rs:773`).
///
/// One constant for both sub-commands, because it is one wire byte: PicoForge
/// sends the same `RSKEY_CFG_TARGET_PHY` to `rs_key_config_read` and to
/// `rs_key_config_write` (`picoforge/src/hal/fido/mod.rs:1161` and `:1177`).
/// Two constants for one value would be a second place for them to disagree,
/// and the disagreement would be invisible — the write would still answer
/// something, just about the wrong record.
pub const TARGET_PHY: u8 = 0x01;

/// `RSKEY_CFG_TARGET_DEV_CONF` — the `target` byte naming the `DEV_CONF`
/// record (`picoforge/src/hal/fido/constants.rs:771`).
///
/// The USB enabled-interface mask, and **write-only over `0x41`**. The client
/// says so as a fact about the firmware rather than as a policy
/// (`picoforge/src/hal/fido/mod.rs:615-618`): *"Enabled-apps info is NOT
/// readable over the `0x41` CONFIG_READ path — the firmware exposes only
/// PHY/LED there and rejects DEV_CONF."* So this constant appears in
/// [`config_write`] and in [`config_read`]'s refusal list, and nowhere else,
/// and that asymmetry is the protocol's rather than this firmware's.
pub const TARGET_DEV_CONF: u8 = 0x00;

/// `RSKEY_CFG_TARGET_LED` — the `target` byte naming the LED status block
/// (`picoforge/src/hal/fido/constants.rs:775`).
///
/// Readable as well as writable, and the read is not optional: see
/// [`config_read`].
pub const TARGET_LED: u8 = 0x02;

/// `FIDO_MGMT_TAG_USB_ENABLED` — the `DEV_CONF` record's only tag
/// (`picoforge/src/hal/fido/mod.rs:2071`).
///
/// `0x03`, and deliberately **not** a [`PhyTag`]: it is a management-applet
/// tag, in a dialect of its own, and giving it a [`PhyTag`] variant would put
/// it in reach of the PHY record's twelve-tag classifier and its tier table.
/// It is the same *value* as [`PhyTag::EnabledUsbItf`] (`0x0B`), and both
/// carriers of that value are held to the same gate and the same zero-mask
/// refusal — see `apply_dev_conf`.
pub const DEV_CONF_TAG_USB_ENABLED: u8 = 0x03;

/// The **boot-resolved** configuration the `2` map carries, or nothing.
///
/// # Why every field is `None` today
///
/// The `2` map is not "the configuration again" — the `1` map already is
/// that. It is specifically the *firmware defaults*, and PicoForge's UI says
/// so where it consumes them: `config.effective_led_gpio` becomes the
/// placeholder `format!("Firmware default (GPIO {g})")`
/// (`picoforge/src/ui/screens/config/view_model.rs:364-370`). It is what the
/// config form shows while the user's own field is empty, so putting a
/// *stored* value there would make the desktop app print a claim about this
/// firmware's build-time defaults that is simply false.
///
/// And there is no boot-resolved value to report, because nothing in this
/// firmware reads [`crate::vendorff::PhyConfig`] to drive hardware: the USB descriptors are a
/// compile-time `CONFIG_DESC` and the activity LED is the build-time pin
/// (see `vendorff`'s "stored, not applied"). So the honest `CONFIG_READ` omits
/// key 2 entirely — the client handles its absence explicitly
/// (`if let Some(Value::Map(e)) = m.get(&Value::Integer(2))`,
/// `picoforge/src/hal/fido/ops.rs:1490`) and its own docs call it optional.
///
/// The seam stays, because the moment something *does* resolve these at boot
/// the map has to be emitted rather than newly invented, and the two
/// directions (emit when populated, omit when empty) are worth having pinned
/// before then rather than after.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EffectiveConfig {
    /// Key 4 — the boot-resolved activity-LED GPIO.
    pub led_gpio: Option<u8>,
    /// Key 8 — the boot-resolved presence timeout, in seconds.
    pub touch_timeout: Option<u8>,
    /// Key 0x0C — the boot-resolved LED driver type.
    pub led_driver: Option<u8>,
}

impl EffectiveConfig {
    /// Whether any of the three is known.
    pub fn is_empty(&self) -> bool {
        self.led_gpio.is_none() && self.touch_timeout.is_none() && self.led_driver.is_none()
    }
}

/// What the device can report as *effective* right now.
///
/// Deliberately takes [`crate::vendorff::PhyConfig`] and returns nothing: the
/// stored record is operator intent, not a resolved configuration, and a
/// future boot-time resolver replaces this body rather than the field it is
/// derived from. See [`EffectiveConfig`] for why the answer is empty on this
/// firmware.
///
/// The `const` is a signal about what this is: a function that cannot be
/// anything other than "no effective configuration", kept in the shape a real
/// resolver would take.
pub const fn effective_config(_phy: &crate::vendorff::PhyConfig) -> EffectiveConfig {
    EffectiveConfig {
        led_gpio: None,
        touch_timeout: None,
        led_driver: None,
    }
}

/// How many bytes the PHY record for `phy` will occupy.
///
/// A separate function from the encoder because a CBOR byte-string header
/// needs the length *before* the content, and writing that content through a
/// 3 KB scratch buffer just to learn its size afterwards would put a
/// worst-case-sized allocation on the RP2350 stack for every read. Four
/// fields, four fixed widths, so this is exact rather than an estimate.
///
/// The result is a subset of [`phy_tlv::MAX_BLOB_LEN`], which is the bound a
/// *response buffer* is sized against: at most
/// `(2+4) + (2+1) + (2+1) + (2+2)` = **16** bytes today, against a
/// `CTAP2_MAX_MSG` (7609) reply buffer — three orders of magnitude of room,
/// and the 16 is asserted as an upper bound in
/// `tests/vendor41.rs::config_read_blob_fits_the_reply_buffer`.
///
/// # The widths come from [`PhyTag::declared_width`], not from literals
///
/// US-116 introduced that table and left this function spelling its four
/// widths out as `record_len(4)` / `(1)` / `(1)` / `(2)`, on the grounds that
/// the migration belongs to whichever story owns the write path. US-117 is that
/// story, and the reason to do it here rather than leave it is that this story
/// **added a fifth hard-coded width** — `PhyTag::EnabledUsbItf`'s `exact::<1>`
/// in `apply_phy_record` — so the count of places a width is written down
/// went up rather than down.
///
/// Both halves of the read now read the same table, which is the property that
/// matters: a width that appeared in [`phy_record_len`] but not
/// `write_phy_record` would make the CBOR byte-string header disagree with
/// its content, and the reply would be a `0x00` carrying a malformed record.
/// `tests/vendor41.rs::phy_read_widths_come_from_the_codec_table` is what makes
/// that correspondence a check rather than a claim.
pub fn phy_record_len(phy: &crate::vendorff::PhyConfig) -> usize {
    let mut len = 0;
    if phy.vid_pid.is_some() {
        len += phy_tlv::record_len(EMITTED_WIDTHS[0]);
    }
    if phy.led_gpio.is_some() {
        len += phy_tlv::record_len(EMITTED_WIDTHS[1]);
    }
    if phy.led_brightness.is_some() {
        len += phy_tlv::record_len(EMITTED_WIDTHS[2]);
    }
    if phy.options.is_some() {
        len += phy_tlv::record_len(EMITTED_WIDTHS[3]);
    }
    len
}

/// The four tags `CONFIG_READ` at target `0x01` emits, in ascending order.
///
/// A `const` array rather than a `match` so that the length calculation and
/// the encoder index the **same** element: `write_phy_record` walks this array,
/// and `phy_record_len` reads the widths out of it. Two separate lists would
/// be two chances for the header and the content to disagree.
///
/// # This list is a security boundary, and it is a new one
///
/// **The USB enabled-interface mask is kept out of the unauthenticated read by
/// this array, and by nothing else.** That is worth stating at the point of
/// enforcement rather than only in [`config_read`]'s prose, because the
/// exclusion is not a technical consequence of anything:
///
/// * [`PhyTag::EnabledUsbItf`] is a *legitimate* fixed-width tag —
///   `declared_width` says `Some(1)`, and `apply_phy_record` writes it.
/// * Until US-117 it had no field in [`crate::vendorff::PhyConfig`] and was
///   refused, so its absence from the read was an accident of which tags had
///   fields rather than a decision anyone made.
/// * US-117 gave it a field, because `DEV_CONF` (`0x00`) needed somewhere to
///   land the same operator intent. That is the moment the exclusion stopped
///   being accidental and became load-bearing.
///
/// So a maintainer who adds `EnabledUsbItf` here, seeing a valid width and a
/// working apply arm, would be making a security change without being told so.
/// The reason it is out is the one `config_read` gives for refusing the
/// `DEV_CONF` target: the mask is the one configuration value that changes what
/// the token can do on the USB bus, and `CONFIG_READ` is the one `0x41`
/// sub-command the client sends with **no token and no MAC** at all
/// (`picoforge/src/hal/fido/ops.rs:1461-1479`). Reading it ungated would hand
/// an unprivileged local process the bus configuration, and the write-side
/// tiering exists precisely to keep that behind a `0x20` token.
///
/// Note the asymmetry this creates, because it is the point: the mask is
/// **writable but deliberately not readable**, where every other tag here is
/// both. `config_write` reaches it through the identity tier;
/// `phy_record_len` and `write_phy_record` do not.
pub const EMITTED_PHY_TAGS: [PhyTag; 4] = [
    PhyTag::VidPid,
    PhyTag::LedGpio,
    PhyTag::LedBrightness,
    PhyTag::Options,
];

/// The width each of [`EMITTED_PHY_TAGS`] is emitted at, taken from
/// [`PhyTag::declared_width`].
///
/// `None` — the two USB string tags — maps to `0` rather than panicking.
/// An `expect` here would be a panic inside a CTAP2 command handler, which
/// owns no recovery, and neither of those tags is in
/// [`EMITTED_PHY_TAGS`] today. If one ever were, a `0` width would under-count
/// the CBOR byte-string header.
///
/// What would then happen is worth being precise about, because it is
/// **not** a clean refusal: `write_config_read_response` pushes the byte-string
/// head and then streams the content, and `encode_record` only checks
/// capacity — so a `0`-width tag would emit a record whose length byte
/// disagrees with the bytes after it, and the client would misparse it. In a
/// **debug** build [`encode_at`]'s `debug_assert_eq!` stops the run first; in
/// a **release** build it compiles out and the malformed record would ship.
/// That is the reason the table test below fails on a fifth tag rather than
/// relying on anything at runtime.
///
/// The `0` is therefore a "cannot represent this" marker, not a safe default,
/// and
/// `tests/vendor41.rs::phy_read_widths_come_from_the_codec_table` is what turns
/// it into a check. Note its limit: it compares the *aggregate* reply length,
/// so a per-tag width swap inside `phy_record_len` that preserved the total
/// would pass it.
const EMITTED_WIDTHS: [usize; 4] = [
    fixed_width(EMITTED_PHY_TAGS[0]),
    fixed_width(EMITTED_PHY_TAGS[1]),
    fixed_width(EMITTED_PHY_TAGS[2]),
    fixed_width(EMITTED_PHY_TAGS[3]),
];

const fn fixed_width(tag: PhyTag) -> usize {
    match tag.declared_width() {
        Some(w) => w,
        None => 0,
    }
}

/// Write `phy` as a PHY record, in ascending tag order.
///
/// Ascending is a canonical choice here, **not** a claim about the client.
/// `build_rskey_phy_tlv` (`picoforge/src/hal/fido/mod.rs:1015`) is not itself
/// ascending — it emits `0x0F` manufacturer before `0x0A` curves — but
/// `read_rskey_physical_config` (`picoforge/src/hal/fido/mod.rs:923`) is a
/// flat `while offset < data.len()` walk with no ordering rule, so any order
/// reads back the same. Ascending is chosen because a canonical order is what
/// makes the output byte-comparable against a literal, which is the only way
/// to check a wire format against anything but itself. See
/// [`fapico2_platform::phy_tlv::PhyTag::ALL`], which states the same ordering
/// and the same reasoning.
///
/// The `u16`/`u32` fields go out **big-endian**, because that is what the
/// client writes (`tlv.extend_from_slice(&vid.to_be_bytes())`,
/// `picoforge/src/hal/fido/mod.rs:1026-1027`) and what it reads back
/// (`u16::from_be_bytes`, `:952`). A little-endian encoder would produce a
/// record the client silently misparses into a different VID/PID — which is
/// the identity-spoofing primitive this whole record is about.
///
/// # Each value is written at [`EMITTED_WIDTHS`]' width, not at its own
///
/// The four values are assembled into a fixed-width buffer and handed to
/// [`encode`] sized by the same table [`phy_record_len`] reads. That is what
/// keeps the CBOR byte-string header and its content from disagreeing: both
/// come from one array, so a width cannot be changed in the length calculation
/// and missed in the encoder. The literal widths this used to carry —
/// `[0u8; 4]`, `&[v]`, `&v.to_be_bytes()` — each restated the same fact a third
/// time, in a form nothing could check.
fn write_phy_record<const N: usize>(
    phy: &crate::vendorff::PhyConfig,
    out: &mut HeaplessVec<u8, N>,
) -> Result<(), Ctap2Response> {
    if let Some(packed) = phy.vid_pid {
        let (vid, pid) = crate::vendorff::unpack_vidpid(packed);
        let mut value = [0u8; 4];
        value[..2].copy_from_slice(&vid.to_be_bytes());
        value[2..].copy_from_slice(&pid.to_be_bytes());
        encode_at(EMITTED_PHY_TAGS[0], &value, out)?;
    }
    if let Some(v) = phy.led_gpio {
        encode_at(EMITTED_PHY_TAGS[1], &[v], out)?;
    }
    if let Some(v) = phy.led_brightness {
        encode_at(EMITTED_PHY_TAGS[2], &[v], out)?;
    }
    if let Some(v) = phy.options {
        encode_at(EMITTED_PHY_TAGS[3], &v.to_be_bytes(), out)?;
    }
    Ok(())
}

/// One `TAG LEN VALUE` record at the width [`EMITTED_WIDTHS`] declares for
/// `tag`, with the codec's errors mapped onto CTAP2.
///
/// A thin wrapper over [`encode`] that supplies the width, so the two cannot
/// come apart: `phy_record_len` sizes the CBOR byte-string header from
/// [`EMITTED_WIDTHS`] and this sizes each record's length byte from the same
/// place. An encoder that took its own width would be a second source for the
/// same number, which is the drift this table exists to remove.
fn encode_at<const N: usize>(
    tag: PhyTag,
    value: &[u8],
    out: &mut HeaplessVec<u8, N>,
) -> Result<(), Ctap2Response> {
    debug_assert_eq!(
        value.len(),
        fixed_width(tag),
        "the PHY read emitted {} bytes for a tag declared {} wide; the CBOR \
         byte-string header is sized from the same table, so a mismatch here \
         would put a length in front of content that does not match it",
        value.len(),
        fixed_width(tag)
    );
    encode(tag, value, out)
}

/// One `TAG LEN VALUE` record, with the codec's errors mapped onto CTAP2.
///
/// [`Ctap2Response::RequestTooLarge`] for a value the one-byte length cannot
/// express and [`Ctap2Response::LimitExceeded`] for a full buffer: both are
/// "I will not send you a record I cannot represent", which is the property
/// that matters. Truncating the value to fit, or wrapping the length, would
/// instead produce a record the client reads as a *different* field.
fn encode<const N: usize>(
    tag: PhyTag,
    value: &[u8],
    out: &mut HeaplessVec<u8, N>,
) -> Result<(), Ctap2Response> {
    phy_tlv::encode_record(tag, value, out).map_err(|e| match e {
        phy_tlv::TlvError::ValueTooLong { .. } => Ctap2Response::RequestTooLarge,
        // `Truncated` is a decode-side variant and `encode_record` never
        // produces it. It is folded into the same status rather than given
        // one of its own, because a distinct status would claim this path can
        // detect something it cannot.
        //
        // The two string-refusal variants land here too, and for the same
        // reason: `encode_record` can only return `BufferFull` beyond the arm
        // above, and `LimitExceeded` is the honest "I will not build this
        // record" for all of them. `StringTooLong` and `EmbeddedNul` are not
        // reachable through *this* function, which is handed a finished value
        // slice; they are reachable through `phy_tlv::encode_nul_string`, and
        // the caller that uses that maps them itself.
        _ => Ctap2Response::LimitExceeded,
    })
}

/// The response body for `CONFIG_READ` with `target == PHY`: `{1: <record>}`.
///
/// Key 1 is the PHY record as a CBOR byte string. Key 2 — the effective /
/// firmware-default map — is appended **only** when `eff` has something to
/// say; see [`EffectiveConfig`] for why
/// [`effective_config`] produces nothing today.
///
/// # Why `eff` is a parameter rather than computed here
///
/// An earlier revision called [`effective_config`] internally, which left ~20
/// lines of emission behind a condition that could never be true and that no
/// test could reach: there was no way to hand a populated value in, so the
/// "emit when populated" half of the rule was unexercised code shipped on the
/// strength of a comment. Taking [`EffectiveConfig`] by reference makes both
/// directions testable — `config_read_omits_the_effective_config_map` for the
/// empty case, `write_config_read_response_emits_the_effective_map_when_populated`
/// for the populated one — without a resolver existing yet.
///
/// The map header and the pair count are derived from the same value by
/// [`EffectiveConfig::is_empty`] and [`eff_field_count`], which is the only
/// way that a fourth field added to one and not the other could stay
/// invisible: both now read the struct, and the populated test asserts the
/// exact byte length.
///
/// The record is written straight into the reply buffer after its CBOR
/// byte-string head rather than into an intermediate blob, so a
/// [`CTAP2_MAX_MSG`]-sized output and a header-only scratch are the only
/// buffers involved.
pub fn write_config_read_response<const N: usize>(
    out: &mut HeaplessVec<u8, N>,
    phy: &crate::vendorff::PhyConfig,
    eff: &EffectiveConfig,
) -> Result<(), Ctap2Response> {
    let pairs = if eff.is_empty() { 1 } else { 2 };
    no_heap::push_map_header(out, pairs).map_err(cbor_err)?;
    no_heap::push_uint(out, 1).map_err(cbor_err)?;
    // Major type 2 (byte string), length known up front from the fixed field
    // widths. `push_bstr` is not usable here precisely because it takes the
    // content it is describing.
    no_heap::push_head(out, 2, phy_record_len(phy) as u64).map_err(cbor_err)?;
    write_phy_record(phy, out)?;
    if !eff.is_empty() {
        no_heap::push_uint(out, 2).map_err(cbor_err)?;
        no_heap::push_map_header(out, eff_field_count(eff)).map_err(cbor_err)?;
        if let Some(v) = eff.led_gpio {
            no_heap::push_uint(out, 4).map_err(cbor_err)?;
            no_heap::push_uint(out, v as u64).map_err(cbor_err)?;
        }
        if let Some(v) = eff.touch_timeout {
            no_heap::push_uint(out, 8).map_err(cbor_err)?;
            no_heap::push_uint(out, v as u64).map_err(cbor_err)?;
        }
        if let Some(v) = eff.led_driver {
            no_heap::push_uint(out, 0x0C).map_err(cbor_err)?;
            no_heap::push_uint(out, v as u64).map_err(cbor_err)?;
        }
    }
    Ok(())
}

fn eff_field_count(eff: &EffectiveConfig) -> usize {
    usize::from(eff.led_gpio.is_some())
        + usize::from(eff.touch_timeout.is_some())
        + usize::from(eff.led_driver.is_some())
}

fn cbor_err(_e: no_heap::CborError) -> Ctap2Response {
    // A CTAP2 reply buffer is sized at `CTAP2_MAX_MSG`, and the largest
    // response this function can produce is `CTAP2_MAX_MSG`-well-below by
    // construction (see `phy_record_len`), so a full buffer here is a bug
    // rather than a runtime condition. It still needs a status rather than a
    // panic: the command path owns no recovery.
    Ctap2Response::LimitExceeded
}

/// Turn an arm's body buffer into the wire reply: `status || body`.
///
/// Both command paths call this rather than splicing the status byte in
/// themselves, so the two cannot disagree about what a reply looks like —
/// they are independent `match`es over the same opcode space, and a rule
/// written twice is a rule that eventually is written twice differently.
///
/// `body` holds the CBOR half, as cleared and written by whichever arm ran.
/// Anything left in it is dropped unless `status` is
/// [`Ctap2Response::Ok`]: a non-zero status must carry no body at all, because
/// the client parses the CBOR half only when the status byte is zero
/// (`HidTransport::read_cbor_response`,
/// `picoforge/src/hal/transport/fido.rs:453-480`). A body behind a non-zero
/// status is at best ignored and at worst mis-parsed as the next reply's
/// status.
///
/// The clearing is done *here* rather than left to each call site. It was
/// duplicated in both dispatch arms first, and a rule written twice is a rule
/// that eventually is written twice differently — and a forgotten clear is
/// invisible on the wire, because the client ignores the bytes anyway.
///
/// # The full-buffer case, and why it is not a `.ok()`
///
/// Prepending costs one slot, so a body that exactly filled the reply buffer
/// leaves nowhere to put the status byte. That is unreachable at present —
/// the largest body this channel produces is a 16-byte PHY record in a
/// `CTAP2_MAX_MSG` (7609) buffer — but it is reachable in principle once
/// US-115 adds a `CONFIG_WRITE` body, and discarding the failure with `.ok()`
/// would leave a reply whose **first byte is body content**: the client would
/// read a CTAP2 success body as a status byte and report a plausible-looking
/// error for a request that succeeded.
///
/// So the failure is made *visible* rather than ignored: the buffer is cleared
/// and a non-zero status is put in its place, which is a clean, correctly
/// framed refusal. `CTAP2_ERR_LIMIT_EXCEEDED` (`0x15`) is the byte for "the
/// authenticator produced a response it could not deliver", and the push that
/// follows the clear cannot itself fail.
///
/// The prepend is an O(n) memmove of the whole body. Irrelevant at 16 bytes;
/// worth knowing at the ~7 KB a future `CONFIG_WRITE` body could reach, where
/// it is a few microseconds of stack copying per call rather than a
/// correctness problem. US-115 should size its body against the buffer before
/// this becomes worth avoiding.
///
/// Both properties are pinned by
/// `tests/vendor41.rs::finish_reply_refuses_rather_than_emitting_a_body_without_a_status`.
pub fn finish_reply<const N: usize>(out: &mut HeaplessVec<u8, N>, status: u8) {
    if status != Ctap2Response::Ok.code() {
        out.clear();
    }
    if out.insert(0, status).is_err() {
        out.clear();
        // Cannot fail for any `N` this is called with: the buffer was just
        // cleared, so it has room for at least one byte. **Not** true of
        // `N == 0`, where the `push` below also fails and the reply comes
        // back empty — the very shape this function exists to prevent. No
        // caller uses a zero-capacity buffer (`CTAP2_MAX_MSG` on both paths,
        // and the test's 4- and 8-byte ones), and handling `N == 0` would mean
        // inventing a status byte with nowhere to put it, so the honest thing
        // is to say so rather than to imply the case cannot arise.
        // `.ok()` rather than `unwrap` only because heapless has no
        // infallible push.
        out.push(Ctap2Response::LimitExceeded.code()).ok();
    }
}

/// Handle `CONFIG_READ`: the PHY record for `target == PHY`.
///
/// # Unauthenticated, and what that exposes
///
/// This is the only `0x41` sub-command the client sends with **no token and
/// no MAC** (`picoforge/src/hal/fido/ops.rs:1461-1479`), and it is the call
/// it uses to decide whether this firmware supports `0x41` at all — before
/// any token exists (`picoforge/src/hal/fido/mod.rs:1158-1166`). So this arm
/// must not call [`verify_mac`] or [`authorize`]; a gate here would answer
/// `0x40` to the request the protocol deliberately sends bare, and the
/// desktop app would report the device as not supporting FIDO
/// configuration.
///
/// What an unauthenticated local process learns is a **four-record PHY blob** —
/// USB VID/PID, LED GPIO, LED brightness, and the power-cycle options word —
/// and, since US-117, the 17-byte **LED status block**: a steady flag and four
/// `(effect, colour, brightness, speed)` records. Those are the only records
/// this read can emit; see [`EMITTED_PHY_TAGS`]. No key material, no PIN, no
/// token, no credential, no seed, and nothing about a credential.
///
/// # Why the list is this short, and why that is a better argument
///
/// An earlier revision of this paragraph listed eleven items — the product and
/// manufacturer strings, the LED driver, order and count, the presence
/// timeout, the curve mask among them — none of which `write_phy_record` emits
/// and all of which `apply_phy_record` refuses with
/// [`Ctap2Response::UnsupportedOption`]. US-114's list was inherited and
/// US-117 amended it without re-deriving it, which is the second time in this
/// EPIC that a story extended a list instead of rebuilding it from the code.
///
/// The corrected claim is not merely smaller, it is a *property* rather than a
/// comparison: **every record this read emits is also writable**, so an
/// unauthenticated reader learns nothing the token cannot be asked to change.
/// The eight tags it does not emit are the two USB strings, the presence
/// timeout, the curve mask, the LED driver/order/count — refused as
/// unsupported — and the USB enabled-interface mask, withheld for the security
/// reason documented on [`EMITTED_PHY_TAGS`] and which is the only record here
/// that would change what the token can do on the bus.
///
/// The LED block needs one sentence of its own, since it is the record US-117
/// added to an *ungated* read: 17 bytes describing how a light should look,
/// and a process that can read it could already read the PHY record's LED GPIO,
/// brightness, driver, order and count. See [`crate::vendorff::LedConf`].
///
/// The one thing the ungated read must not reach is the `DEV_CONF` record
/// (`0x00`) — the USB enabled-interface mask, which changes what the token
/// can do on the bus — and it still does not: `DEV_CONF` is refused with
/// [`Ctap2Response::InvalidParameter`], which is PicoForge's own statement
/// about the protocol rather than a policy invented here ("the firmware
/// exposes only PHY/LED there and rejects DEV_CONF",
/// `picoforge/src/hal/fido/mod.rs:615-618`). The client agrees and routes
/// around it: it reads enabled-apps over the `0xC2` Management path
/// (`read_management_info`, `picoforge/src/hal/fido/mod.rs:615-623`).
///
/// # Why `LED` (`0x02`) is served, and why that is not optional
///
/// US-114 refused it, on a correct-sounding but wrong reason: a 17-byte block
/// is not a TLV record, so answering it with a PHY record would be a `0x00`
/// the client misparses. True — and US-117 answers it with a *block* instead,
/// which is the whole fix.
///
/// What makes serving it necessary rather than merely nice is the client's
/// write path. `write_rskey_led_config` is read-modify-write
/// (`picoforge/src/hal/fido/mod.rs:2043-2057`):
///
/// ```text
/// let mut block = [0u8; RSKEY_LED_CONF_LEN];
/// if let Ok((current, _)) = transport.rs_key_config_read(RSKEY_CFG_TARGET_LED)
///     && current.len() >= RSKEY_LED_CONF_LEN
/// {
///     block.copy_from_slice(&current[..RSKEY_LED_CONF_LEN]);
/// }
/// block[0] = if config.steady { 0x01 } else { 0x00 };
/// for (i, &(color, brightness)) in config.statuses.iter().enumerate() {
///     block[2 + 4 * i] = color & 0x07;   // effect (1+4i) and speed (4+4i) untouched
///     block[3 + 4 * i] = brightness;
/// }
/// ```
///
/// A device that **stores** the block but **refuses to read it** is therefore
/// the exact failure the EPIC warned about, arriving by the other road: the
/// `if let` falls through, `block` stays all-zero, and a colour change wipes
/// every WS2812 effect and speed the operator set out of band. The read and
/// the write are one operation, and only the write half was ever going to
/// exist here.
///
/// # Why an unconfigured device serves 17 zero bytes and not an empty blob
///
/// **Because the read has a second consumer, and an empty answer fails it.**
///
/// `read_rskey_led_config` (`picoforge/src/hal/fido/mod.rs:2010-2019`) does
/// not do the read-modify-write — it reads the block to *show* it, propagating
/// the transport with `?` and then `parse_led_block(&data).ok_or_else(..)`.
/// And `parse_led_block` returns `None` on an empty input
/// (`picoforge/src/hal/common/led.rs:21-22`). So an empty blob turns a
/// straightforward "what is this token's LED set to?" into
/// `PFError::Device("LED config response too short: 0 bytes")` — an error
/// surfaced by `hal::io::read_led_config` (`picoforge/src/hal/io.rs:179`),
/// which is what the Rescue LED UI calls. Seventeen zeros returns a
/// well-defined answer instead: `steady = false` and four `(colour 0,
/// brightness 0)` statuses, i.e. an LED that is not steady and dark in every
/// state.
///
/// That is a *differentiated* answer where an empty blob is a failure, and it
/// is the reason the shape is 17 bytes rather than "whatever is stored".
/// A device that had never been configured has a real LED setting — the
/// default one — and the default is what it should report.
///
/// ## The read-modify-write also does not distinguish them, and that is
/// deliberately the weaker argument
///
/// `write_rskey_led_config` guards on `current.len() >= RSKEY_LED_CONF_LEN`
/// (`picoforge/src/hal/fido/mod.rs:2045-2047`), so an empty blob would take
/// its all-zero fall-through exactly as an error does, and the write that
/// follows would be byte-identical. For *that* consumer the two answers are
/// interchangeable, and it would be a coincidence dressed as a reason to lead
/// with it.
///
/// Two different consumers, two different reasons, and they should not be
/// conflated: **serving target `0x02` at all** is what protects the
/// read-modify-write (see the arm docs above), while **the 17-byte shape** is
/// what protects the explicit read. Doing the first without the second would
/// still wipe effects and speeds on a client's first write; doing the second
/// without the first would leave the Rescue LED UI unable to read a default.
pub fn config_read(
    data: &[u8],
    phy: &crate::vendorff::PhyConfig,
    out: &mut HeaplessVec<u8, CTAP2_MAX_MSG>,
) -> Outcome {
    let target = match config_read_target(data) {
        Ok(t) => t,
        Err(e) => return Outcome::plain(e),
    };
    // The device has no boot-resolved configuration to report, so the `2` map
    // is empty and key 2 is omitted. See [`EffectiveConfig`].
    let eff = effective_config(phy);
    let written = match target {
        TARGET_PHY => write_config_read_response(out, phy, &eff),
        TARGET_LED => write_led_read_response(out, phy),
        // `DEV_CONF` and every unassigned byte. `DEV_CONF` is the client's own
        // statement about the protocol; the rest is a target the protocol does
        // not define. Neither gets a `0x00`, because a `0x00` here would carry
        // a body keyed to a record the caller did not ask for.
        _ => Err(Ctap2Response::InvalidParameter),
    };
    match written {
        Ok(()) => Outcome::plain(Ctap2Response::Ok),
        // A failed body is not a `0x00` with a partial map: the buffer is
        // cleared so nothing partial can ride along behind a non-zero status,
        // which the client would not parse anyway. The entry clear is
        // [`handle`]'s; this is the exit one.
        Err(e) => {
            out.clear();
            Outcome::plain(e)
        }
    }
}

/// The response body for `CONFIG_READ` with `target == LED`: `{1: <block>}`.
///
/// The same outer shape as the PHY response and deliberately so: the client's
/// `rs_key_config_read` unwraps key 1 and treats key 2 as optional
/// (`picoforge/src/hal/fido/ops.rs:1480-1487`), so a `{1: <block>}` map is read
/// correctly by both targets' callers. Key 2 is omitted, which for `LED` is
/// not merely "nothing to report": the effective map is PHY-shaped
/// ([`EffectiveConfig`]) and its keys would be read by the client as
/// `led_gpio`/`touch_timeout`/`led_driver` on a record that has no such
/// fields.
fn write_led_read_response<const N: usize>(
    out: &mut HeaplessVec<u8, N>,
    phy: &crate::vendorff::PhyConfig,
) -> Result<(), Ctap2Response> {
    let block = phy
        .led_conf
        .unwrap_or(crate::vendorff::LedConf::UNCONFIGURED);
    no_heap::push_map_header(out, 1).map_err(cbor_err)?;
    no_heap::push_uint(out, 1).map_err(cbor_err)?;
    no_heap::push_head(out, 2, crate::vendorff::LedConf::LEN as u64).map_err(cbor_err)?;
    out.extend_from_slice(&block.0)
        .map_err(|_| Ctap2Response::LimitExceeded)
}

/// Pull `target` (CBOR key 1 inside `subCommandParams`, CBOR key 2) out of the
/// request.
///
/// Strict rather than defaulting, for the same reason [`extract_subcommand`]
/// is: a request that does not say which record it wants has not asked for
/// anything, and answering with the PHY record anyway would be guessing.
/// [`Ctap2Response::MissingParameter`] is what a well-formed map without the
/// key earns — distinct from [`Ctap2Response::InvalidCbor`], which is a body
/// that is not CBOR at all.
fn config_read_target(data: &[u8]) -> Result<u8, Ctap2Response> {
    let mut p = Parser::new(data);
    let pairs = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => return Err(Ctap2Response::InvalidCbor),
    };
    let mut target: Option<Result<u8, Ctap2Response>> = None;
    for _ in 0..pairs {
        let key = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
        if key == Item::U(2) {
            if target.is_some() {
                return Err(Ctap2Response::InvalidCbor);
            }
            target = Some(match p.next() {
                Ok(Item::Map(n)) => read_target_from_params(&mut p, n),
                // Key 2 present but not a map: not the shape this sub-command
                // defines.
                _ => Err(Ctap2Response::InvalidCbor),
            });
        } else {
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
        }
    }
    target.unwrap_or(Err(Ctap2Response::MissingParameter))
}

fn read_target_from_params(p: &mut Parser<'_>, pairs: u64) -> Result<u8, Ctap2Response> {
    let mut found: Option<Result<u8, Ctap2Response>> = None;
    for _ in 0..pairs {
        let key = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
        if key == Item::U(1) {
            if found.is_some() {
                return Err(Ctap2Response::InvalidCbor);
            }
            found = Some(match p.next() {
                // `try_from`, not `as u8`: 0x100 would truncate to 0 and turn
                // "the whole of DEV_CONF" into "the PHY record".
                Ok(Item::U(v)) => u8::try_from(v).map_err(|_| Ctap2Response::InvalidParameter),
                _ => Err(Ctap2Response::InvalidCbor),
            });
        } else {
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
        }
    }
    found.unwrap_or(Err(Ctap2Response::MissingParameter))
}

// ---------------------------------------------------------------------------
// US-111: the pinUvAuth MAC.
// ---------------------------------------------------------------------------

/// The RS-Key pinUvAuth MAC length — protocol 1 truncates HMAC-SHA256 to 16.
///
/// `tests/vendor41.rs` defines its **own** constant of the same name rather
/// than importing this one, and pins both against an out-of-band vector. A
/// test that read the width from the implementation would only prove the
/// implementation agrees with itself; this one proves the implementation
/// agrees with the protocol.
pub const MAC_LEN: usize = 16;

/// Verify the RS-Key `0x41` pinUvAuth MAC on a request body, returning the
/// **authenticated params** on success.
///
/// The message is exactly what PicoForge signs
/// (`picoforge/src/hal/fido/ops.rs:1581-1586`):
///
/// ```text
/// HMAC-SHA256(token, 0xFF*32 || 0x41 || subCommand || cbor(subCommandParams))[0..16]
/// ```
///
/// `token` is the caller's current pinUvAuth token. It is a parameter and not
/// something read out of `store` because a pinUvAuth token is **session
/// state**, not at-rest state: it is minted by `clientPin`
/// (`getPinUvAuthToken`, or `getPinToken`) into a field of the command
/// handler, is dropped on `reset`, and is not something a
/// [`fapico2_platform::secure_store::SecureStore`] can be asked for. The token therefore has to come from
/// whichever app owns the session, which is the only thing that differs
/// between the host and device paths here.
///
/// `data` is the same CBOR request body [`handle`] receives, and this function
/// re-derives everything it needs from it: the sub-command (key 1), the raw
/// bytes of the params (key 2), the protocol (key 3) and the param (key 4).
/// Re-parsing rather than threading a parsed struct keeps a future arm from
/// having to widen [`handle`]'s signature before it can authenticate anything.
///
/// ## What it returns, and why an arm should not re-find them
///
/// On success the return is the params' raw CBOR bytes, **borrowed from
/// `data`** — no copy, no `no_std` problem — and an empty slice when the
/// request carried no key 2 at all.
///
/// That empty case is the real client's, not a theoretical one:
/// `picoforge/src/hal/fido/ops.rs:1560-1573` signs an empty params tail and
/// then omits key 2 from the map entirely, and `mod.rs:1573` calls
/// `rs_key_vendor(RSKEY_VENDOR_AUDIT_READ, None, pin)`. `AUDIT_READ`,
/// `EXPORT` and `ATT_CLEAR` all take that path. It is a first-class outcome
/// here, not a malformed request.
///
/// The borrow is the point. `CONFIG_READ` and `CONFIG_WRITE` need the params
/// *decoded* — a target and a blob — so an arm has to walk them. If the arm
/// walked `data` itself it would be parsing the request a second time, and
/// the duplicate-key-2 rejection below would no longer be the only decider of
/// which pair is "the params": `verify_mac` could refuse a duplicate while the
/// arm's own helper walked straight past it. Handing back the span that was
/// actually verified makes [`verify_mac`] the single place that decides, and
/// gives the arm bytes that are by construction the bytes that were signed.
///
/// ## Statuses
///
/// * [`Ctap2Response::PuatRequired`] (`0x36`) — no `pinUvAuthParam` was
///   supplied, or there is no token to check one against. Both are "you sent
///   no usable auth", and they are kept together deliberately: answering
///   `0x33` for the no-token case would tell the client its MAC was wrong and
///   send the user back to the PIN prompt for a token the app never obtained.
/// * [`Ctap2Response::PinAuthInvalid`] (`0x33`) — a param *was* supplied and
///   did not verify.
/// * [`Ctap2Response::InvalidCbor`] (`0x12`) — the body is not a well-formed
///   map, or a key is of the wrong CBOR type for its slot.
/// * [`Ctap2Response::InvalidSubcommand`] (`0x3E`) — key 1 is a well-formed
///   integer outside [`Subcommand`]. There is nothing to bind a MAC to.
/// * [`Ctap2Response::InvalidParameter`] (`0x02`) — `pinUvAuthProtocol` is a
///   well-formed integer that is not `1`. It names a value the profile does
///   not define, rather than a malformed request, so it is not
///   [`Ctap2Response::InvalidCbor`].
/// * [`Ctap2Response::InvalidLength`] (`0x03`) — the param, or the assembled
///   message, exceeded the fixed buffers below. In practice this is a params
///   **value** over 158 bytes: the message buffer is 192 and the message is a
///   fixed 34-byte head (`0xFF`×32 ‖ `0x41` ‖ subCommand) plus the params. A
///   `CONFIG_WRITE` params value spends 6 of those on its own head
///   (`A2 01 01 02 58 LL`), so a config blob of up to 152 bytes fits and a
///   larger one is refused outright. It is a refusal, never a truncation — a
///   truncated message would verify against the wrong thing.
///
/// ## The comparison is constant-time, and where that comes from
///
/// The check itself is [`crypto::pin_verify_auth`], the same helper the
/// sibling vault MAC-verifies with (`device_core.rs`'s
/// `vendor_vault_inner`) — so this channel and the vault share one audited
/// comparison path rather than two. It computes the HMAC into a fixed 32-byte
/// buffer and compares with [`crypto::ct_eq`], which XOR-accumulates the byte
/// differences so neither the time nor the branch pattern depends on where the
/// inputs differ. `subtle`'s `ConstantTimeEq` is not used: the crate already
/// has this helper and it is the one every other MAC check in this firmware
/// goes through. (`ct_eq` does return early on a length mismatch, which is
/// sound here — the expected length is fixed by the protocol and the observed
/// one is chosen by the attacker, so it carries no secret.)
///
/// ## The token type
///
/// `&[u8; 32]` is the token width this channel uses, and CTAP2 can also return
/// a 16-byte per-credential token. Nothing here depends on 32: the array is
/// only a compile-time statement of the width this client actually obtains,
/// and `crypto::pin_verify_auth` takes the key as a slice internally. It is
/// deliberately not widened to a slice, because widening it would mean
/// re-deciding what this channel accepts about tokens.
///
/// ## Who calls it, and who does not
///
/// **One arm calls it: `identity_gate`, for the `CONFIG_WRITE` identity tier**
/// (reached from the `ConfigWrite` arm of [`handle_subcommand`]). That is the whole of the dispatch-side reach today, and it is
/// narrower than it looks, so the two exclusions are worth naming:
///
/// * The **benign tier** does not reach it. A benign blob is gated on a
///   physical touch, not on a MAC, so a `pinUvAuthParam` riding along on one
///   is not verified — and is therefore not charged either.
/// * **`CONFIG_READ`** does not reach it. PicoForge sends that sub-command
///   with no token and no MAC at all (`picoforge/src/hal/fido/ops.rs:1461-1479`),
///   and uses it as the feature probe for whether this firmware supports `0x41`
///   at all.
///
/// The twelve stubs must stay ungated, or they would answer `0x36`/`0x40`
/// instead of the `0x30` the client needs to see;
/// `tests/vendor41.rs::vendor41_mac_is_not_yet_wired_into_the_stubs` drives all
/// twelve with a correct and a bogus MAC and pins it.
pub fn verify_mac<'a>(
    data: &'a [u8],
    token: Option<&[u8; 32]>,
) -> Result<&'a [u8], Ctap2Response> {
    // The params are never copied: only their span in `data` is recorded, and
    // the span is handed back. The two fixed buffers left are the param (the
    // vault uses 64 for the same thing in `vendor_vault_inner`) and the
    // assembled message, which must be contiguous for the HMAC. The vault's
    // 192-byte message budget is kept so the two channels overflow alike, which
    // caps a params value at 158 bytes — see the `InvalidLength` note above.
    let mut params_span: Option<(usize, usize)> = None;
    let mut mac: HeaplessVec<u8, 64> = HeaplessVec::new();
    let mut sub: Option<Subcommand> = None;
    let mut protocol: u64 = 1;
    let mut have_mac = false;

    let mut p = Parser::new(data);
    let pairs = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => return Err(Ctap2Response::InvalidCbor),
    };
    for _ in 0..pairs {
        let key = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
        if key == Item::U(1) {
            // Repeated key 1 is the same ambiguity `extract_subcommand`
            // rejects, and for a stronger reason here: the sub-command is
            // inside the signed message, so two of them means the MAC could
            // only match one of them and which one is unverifiable.
            if sub.is_some() {
                return Err(Ctap2Response::InvalidCbor);
            }
            sub = Some(match p.next() {
                Ok(Item::U(v)) => u8::try_from(v)
                    .ok()
                    .and_then(Subcommand::from_byte)
                    .ok_or(Ctap2Response::InvalidSubcommand)?,
                _ => return Err(Ctap2Response::InvalidCbor),
            });
        } else if key == Item::U(2) {
            // Rejected on repetition for the same reason key 1 and key 4 are,
            // and it is the strongest of the three: the params are *inside*
            // the signed message, so a repeated key 2 makes "which params was
            // signed" undecidable, and last-wins would decide it silently.
            // It also keeps this function the only place that choice is made —
            // a later arm that re-parsed the params with its own helper could
            // otherwise land on the other pair from the same bytes.
            if params_span.is_some() {
                return Err(Ctap2Response::InvalidCbor);
            }
            // The params are captured as the **raw bytes that arrived**, not
            // decoded and re-encoded. PicoForge MACs `to_vec(&params)` — the
            // canonical encoding of the value — so on a canonical request the
            // two are the same bytes; taking the wire bytes means this
            // firmware never has to agree with a serialiser about canonical
            // form, and a request that is not canonical still gets verified
            // against exactly what the client signed.
            let start = p.pos();
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
            let end = p.pos();
            // A repeated key 2 is refused above, so there is never a second
            // span to weigh against the first.
            params_span = Some((start, end));
        } else if key == Item::U(3) {
            // Last-wins on repetition, deliberately, and unlike keys 1, 2 and
            // 4. Key 3 is *outside* the signed message, so a repeated protocol
            // cannot change what was authorised — the MAC is unaffected either
            // way, and the value that survives still has to be `1`. Refusing it
            // would buy no safety and would make this the one key whose
            // repetition is a different kind of error from the rest.
            //
            // Kept as a `u64` rather than narrowed: a value too wide for a
            // `u8` is not a different error, it is simply "not 1", and the
            // check below rejects both the same way.
            protocol = match p.next() {
                Ok(Item::U(v)) => v,
                _ => return Err(Ctap2Response::InvalidCbor),
            };
        } else if key == Item::U(4) {
            // Rejected for the same reason a repeated key 1 is: two params
            // means the one that was signed is ambiguous.
            if have_mac {
                return Err(Ctap2Response::InvalidCbor);
            }
            have_mac = true;
            mac.clear();
            match p.next() {
                Ok(Item::B(b)) => mac
                    .extend_from_slice(b)
                    .map_err(|_| Ctap2Response::InvalidLength)?,
                _ => return Err(Ctap2Response::InvalidCbor),
            }
        } else {
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
        }
    }

    // Protocol 1 is the only one this channel defines: PicoForge hard-codes
    // `3: 1` and a 16-byte param (`ops.rs:1583`, `:1533`). The reason to
    // refuse any other declared protocol is interop and clarity, **not**
    // security: `crypto::pin_verify_auth` already length-checks, so a
    // 32-byte param under a declared protocol 2 would be compared against a
    // 32-byte HMAC the caller cannot compute — strictly *more* work for an
    // attacker, not less. Refusing an undefined protocol with `0x02` simply
    // says "this channel does not do that" instead of making an
    // unimplemented protocol look like a failed MAC.
    //
    // This is the **divergent** choice from the vault, which honours whatever
    // the request declares (`vendor_vault_inner`,
    // `crypto::pin_verify_auth(protocol, …)`). A client that sent protocol 2
    // would therefore get `0x33` from the vault and `0x02` from here. Both
    // senders in this protocol hard-code `1`, so nothing in practice hits it.
    // (A request with no key 3 at all is protocol 1, which is what an
    // unauthenticated request from this client looks like anyway.)
    if protocol != 1 {
        return Err(Ctap2Response::InvalidParameter);
    }

    // The rest of the order is deliberate too. The protocol check above runs
    // first, so a request that both omits the param and declares a protocol
    // this channel does not define answers `0x02` — the request is
    // describing something unimplemented either way.
    //
    // "No param" is then decided before the sub-command is looked up, because
    // `CONFIG_READ` is legitimately sent this way (no token, no MAC,
    // `picoforge/src/hal/fido/ops.rs:1461-1479`) and must not be answered with
    // a complaint about its own sub-command.
    if !have_mac {
        return Err(Ctap2Response::PuatRequired);
    }
    let token = token.ok_or(Ctap2Response::PuatRequired)?;
    let sub = sub.ok_or(Ctap2Response::MissingParameter)?;

    let params: &[u8] = match params_span {
        Some((start, end)) => &data[start..end],
        // No key 2 at all: the client signs an empty params tail in this case
        // (`picoforge/src/hal/fido/ops.rs:1560-1573`), so the message tail is
        // empty too. See the return-value note above.
        None => &[],
    };
    // The buffer is sized for the **largest legal 0x41 request**, not a typical
    // one. It was 192 — 34 bytes of fixed headroom plus ~158 for params — which
    // silently made `ATT_IMPORT` (US-175) unauthenticatable: the client sends
    // `{1: wrapped scalar (60 B), 2: DER chain (1..=2048 B)}`, over 2,100
    // bytes of params, so every real request overflowed here and answered
    // `InvalidLength` before a single MAC byte was compared. The client would
    // have reported a device failure where the real fault was capacity.
    // See `docs/tasks/phase-gj-decision-validation-laya.md` D-GJ-4.
    //
    // 2200 = 34 (head) + 2116 (the worst-case params, measured) + 50 (slack).
    // The cost is stack in *this* function, transient and not on the async
    // main frame: measured at +2008 B of reservation, with `check_async_frame`
    // unchanged at 9216 B.
    let mut msg: HeaplessVec<u8, 2200> = HeaplessVec::new();
    for _ in 0..32 {
        msg.push(0xFF).map_err(|_| Ctap2Response::InvalidLength)?;
    }
    msg.extend_from_slice(&[CMD, sub.byte()])
        .map_err(|_| Ctap2Response::InvalidLength)?;
    msg.extend_from_slice(params)
        .map_err(|_| Ctap2Response::InvalidLength)?;

    if !crypto::pin_verify_auth(1, token, &msg, &mac) {
        return Err(Ctap2Response::PinAuthInvalid);
    }

    // Only now are these bytes released as *the* params: whatever an arm does
    // with them, it is acting on the span the MAC was just checked over. A
    // request that never carried key 2 gets an empty slice rather than an
    // error, because omitting the params is how this client sends the
    // sub-commands that take none.
    Ok(match params_span {
        Some((start, end)) => &data[start..end],
        None => &[],
    })
}

// ---------------------------------------------------------------------------
// US-112: the per-sub-command permission gate, and the lockout seam.
// ---------------------------------------------------------------------------

/// What a sub-command demands of its caller before its arm may run.
///
/// Three variants, not two, because the client does not authenticate most of
/// this channel over `0x41`. The module docs enumerate the call sites; the
/// short version is that `rs_key_vendor` attaches a token only when its `pin`
/// argument is `Some`, and most callers pass `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// The protocol defines no authenticated form of this sub-command.
    ///
    /// A token is never attached by the client, and one that *is* attached is
    /// not consulted — this row has no authorising bit at all, only a refusal
    /// of the concept. One row today: [`Subcommand::ConfigRead`], sent as the
    /// client's ungated feature probe for `0x41` support.
    Ungated,
    /// A token carrying this bit **may** authorise the call, and its absence is
    /// a legitimate request the device is expected to satisfy another way.
    ///
    /// Twelve rows. This is not leniency for its own sake: the client's own
    /// comment at `picoforge/src/hal/fido/ops.rs:1573-1575` says that without a
    /// PIN "the firmware gates on a physical touch instead, so no auth fields
    /// are sent", and `backup_status`, `lock_unlock`, `att_status` and
    /// `audit_status` are documented as ungated outright. A token that *is*
    /// supplied must still carry the bit, so a `CREDENTIAL_MANAGEMENT`-only
    /// token is refused here exactly as it is on a [`Requirement::Permission`]
    /// row.
    TokenOptional(u8),
    /// The caller's pinUvAuth token must carry this bit; no token is a
    /// refusal.
    ///
    /// One row: [`Subcommand::ConfigWrite`], which is the only sub-command
    /// this channel reaches exclusively through a caller that already holds a
    /// `0x20` token (`picoforge/src/hal/fido/ops.rs:1514-1534`).
    Permission(u8),
}

/// The permission a sub-command requires — one row per [`Subcommand`].
///
/// # No `_` arm, same discipline as [`handle_subcommand`]
///
/// Adding a variant to [`Subcommand`] fails the build until this `match` gives
/// it a row, so "a new sub-command has no declared permission" is a compile
/// error rather than a runtime accident. The converse is deliberately *not*
/// enforced the way [`PENDING`] enforces the stub set: a row here says what
/// the sub-command demands, not whether it is implemented, so there is nothing
/// to cross-check in the other direction.
///
/// # Each row is derived from a call site, not from a guess about the family
///
/// `tests/vendor41.rs::vendor41_permission_table_matches_the_picoforge_call_sites`
/// holds the client facts as a literal table with a `picoforge` line number per
/// row and asserts this function agrees with it. That test is the reason to
/// trust this table: an earlier revision of this story derived all thirteen
/// non-ungated rows from "the client mints `0x20`" and got twelve of them
/// wrong — the six the client sends bare (`None`) and the six it sends
/// PIN-or-touch (`pin.as_deref()`) are all `TokenOptional`, not `Permission`.
/// That would have answered `0x40` to four calls the client documents as
/// ungated (`backup_status`, `lock_unlock`, `att_status`, `audit_status`) the
/// moment a Phase I story wired the gate, and nothing would have failed
/// before then.
pub const fn required_permission(sub: Subcommand) -> Requirement {
    match sub {
        // --- device config: read is a probe the client sends bare ---
        // `picoforge/src/hal/fido/ops.rs:1461-1479` builds it with no key 3
        // and no key 4, and `mod.rs:1163-1166` uses it to decide whether this
        // firmware supports `0x41` at all — before any token exists.
        Subcommand::ConfigRead => Requirement::Ungated,
        // --- device config: write is the only strictly-gated row ---
        // Reached only via `rs_key_config_write` (`ops.rs:1514-1534`), which
        // takes the token as an argument, so every path to it already holds a
        // `0x20` token. This is the US-112 acceptance bullet.
        Subcommand::ConfigWrite => Requirement::Permission(PERM_ACFG),
        // --- seed backup / restore (Offboard, Backup) ---
        // Moves the master seed in and out of the device. `MSE` and
        // `FINALIZE` pass `None` (`mod.rs:1709`, `:1757`); `EXPORT` and
        // `LOAD` pass `pin.as_deref()` (`:1771`, `:1797`).
        Subcommand::Mse => Requirement::TokenOptional(PERM_ACFG),
        Subcommand::Export => Requirement::TokenOptional(PERM_ACFG),
        Subcommand::Load => Requirement::TokenOptional(PERM_ACFG),
        Subcommand::Finalize => Requirement::TokenOptional(PERM_ACFG),
        // --- soft lock (Lock) ---
        // `backup_status` is documented "Read {sealed, has_seed, locked,
        // unlocked} (ungated)" (`mod.rs:1738`) and passes `None` (`:1741`);
        // `lock_unlock` is "Ungated over the 0x41 channel" (`:1824`) and
        // passes `None` (`:1826`), as does `lock_disable` (`:1867`).
        //
        // Note that the lock *enable/disable* pair is NOT this channel: those
        // call `authconfig_vendor` (`ops.rs:1611-1656`), a CTAP2
        // `authenticatorConfig` vendor prototype on opcode `0x40` with its own
        // MAC domain. See the module docs.
        Subcommand::State => Requirement::TokenOptional(PERM_ACFG),
        Subcommand::Unlock => Requirement::TokenOptional(PERM_ACFG),
        // --- audit journal (Audit) ---
        // `audit_status` is "ungated status query, no touch" (`mod.rs:1659`)
        // and passes `None` (`:1653`); `AUDIT_READ` (`:1573`) and
        // `AUDIT_CHECKPOINT` (`:1611`) pass `pin.as_deref()`.
        Subcommand::AuditRead => Requirement::TokenOptional(PERM_ACFG),
        Subcommand::AuditCheckpoint => Requirement::TokenOptional(PERM_ACFG),
        Subcommand::AuditConfig => Requirement::TokenOptional(PERM_ACFG),
        // --- org attestation (Attestation) ---
        // `att_status` is "Read {installed, chain_hash} (ungated)"
        // (`mod.rs:1892`) and passes `None` (`:1895`); `ATT_IMPORT` (`:1987`)
        // and `ATT_CLEAR` (`:1916`) pass `pin.as_deref()`.
        Subcommand::AttImport => Requirement::TokenOptional(PERM_ACFG),
        Subcommand::AttClear => Requirement::TokenOptional(PERM_ACFG),
        Subcommand::AttState => Requirement::TokenOptional(PERM_ACFG),
    }
}

/// # The unimplemented half: [`requires_presence_when_tokenless`]
///
/// A `TokenOptional` row is a *deferral*, not a grant, and the thing it
/// defers to is not built. The client sends those twelve sub-commands
/// bare precisely because the firmware is supposed to gate them on a physical
/// touch instead (`picoforge/src/hal/fido/ops.rs:1573-1575`), and **no presence
/// check exists on this channel today** — every one of them is a `0x30` stub
/// that consults nothing, so nothing is unguarded in the deployed sense.
///
/// The hazard is not today's behaviour; it is what a Phase I implementer can
/// read out of this commit. `token_optional_rows_admit_a_tokenless_request`
/// (in `apps/fido/tests/pin_perms.rs`) asserts, as a **passing test**, that a
/// tokenless request clears [`authorize`] for all twelve of these rows — and
/// two of them are `Export` ("read the encrypted master seed") and `State`
/// (`has_seed` / `locked`). An implementer who takes that test as a green
/// light, implements `Export`, and wires the gate has shipped an unguarded
/// seed read with no touch requirement either, and the suite is still green.
///
/// So the obligation gets a **name** rather than a paragraph:
/// [`requires_presence_when_tokenless`] is the function a Phase I arm calls to
/// find out whether admitting a tokenless request commits it to a presence
/// check, it is asserted against the table, and the twelve sub-commands it
/// returns `true` for are greppable. It reports the obligation; it does not
/// discharge it. Nothing calls it yet, and
/// `pin_perms::todo_us1xx_presence_gate_covers_every_tokenless_row` is
/// `#[ignore]`d with the twelve sub-commands listed, so the debt is also
/// discoverable as a failing-if-enabled test rather than only as prose.
///
/// # Which rows it covers, and why the other two are excluded
///
/// `true` for every [`Requirement::TokenOptional`] row — the ones that can
/// reach an arm without a token. Deliberately `false` for the other two
/// variants, and the distinction is the point rather than a detail:
///
/// * [`Requirement::Permission`] — a tokenless request is **refused**
///   ([`authorize`] returns `0x40`), so there is no request left to gate. Had
///   this returned `true` for `CONFIG_WRITE` it would assert a touch fallback
///   exists for the one sub-command that must never have one.
/// * [`Requirement::Ungated`] — the protocol defines no authenticated form
///   (`CONFIG_READ`), and the module docs argue separately that the data it
///   returns discloses less than the write permission paired with it. Whether
///   that is acceptable is a protocol question, not one this predicate should
///   blur by answering `true` for it.
pub const fn requires_presence_when_tokenless(sub: Subcommand) -> bool {
    matches!(required_permission(sub), Requirement::TokenOptional(_))
}

/// Decide whether a caller holding `token_permissions` may invoke `sub`.
///
/// `token_permissions` is `None` when no pinUvAuth token is held. What that
/// means depends on the row, and that is the whole reason
/// [`Requirement`] has three variants:
///
/// * [`Requirement::Ungated`] — always `Ok`. There is no authenticated form of
///   this sub-command, so there is nothing to check.
/// * [`Requirement::TokenOptional`] — `Ok` with no token. The client sends
///   this sub-command bare in the ordinary case
///   (`picoforge/src/hal/fido/ops.rs:1573-1575`) and expects the device to gate
///   it another way; refusing here would break a call the client documents as
///   ungated. If a token *is* presented it must still carry the bit.
/// * [`Requirement::Permission`] — `Err` with no token. This is
///   [`Subcommand::ConfigWrite`], and "no token" means the caller did not
///   authorise a device-configuration write.
///
/// `Some(0)` is the **legacy** `getPinToken` (`0x05`) token: both `FidoApp`
/// twins read a zero permission byte as "MC or GA only"
/// (`app::FidoApp::token_allows` and its device twin), so it authorises
/// nothing on this channel and is refused by both gated variants. Treating
/// `Some(0)` as "unrestricted" would be the exact legacy special case the
/// CTAP2 spec reserves for `makeCredential`/`getAssertion`.
///
/// `Ok(())` means the *permission* is present; it says nothing about the MAC,
/// which [`verify_mac`] checks separately and in this order deliberately —
/// a caller with the right bit and a bad MAC gets `0x33`, and a caller with no
/// token at all gets `0x36` from [`verify_mac`] before this function is ever
/// consulted. An arm that gates first will therefore answer `0x40` to a
/// tokenless [`Requirement::Permission`] request that [`verify_mac`] would
/// have answered `0x36`; both are refusals and neither is more informative,
/// but the arm must pick one order and not mix them.
///
/// Reached from dispatch by exactly one path: `identity_gate`, after
/// [`verify_mac`], for the `CONFIG_WRITE` identity tier. The other thirteen
/// sub-commands do not reach it — twelve because they owe the client `0x30`,
/// and `CONFIG_READ` because its row is [`Requirement::Ungated`] and
/// consulting the table for it could only ever admit the request.
/// `tests/vendor41.rs::vendor41_permission_gate_is_not_yet_wired_into_the_stubs`
/// pins the twelve.
pub fn authorize(
    sub: Subcommand,
    token_permissions: Option<u8>,
) -> Result<(), Ctap2Response> {
    let bit = match required_permission(sub) {
        Requirement::Ungated => return Ok(()),
        // Deliberately before the token is examined: the *absence* of a token
        // is the expected shape of this request, so it is not a refusal. What
        // a token that is present must carry is the same question as on a
        // `Permission` row, and it is asked by the same line below.
        Requirement::TokenOptional(_) if token_permissions.is_none() => return Ok(()),
        Requirement::TokenOptional(bit) | Requirement::Permission(bit) => bit,
    };
    match token_permissions {
        Some(perms) if perms & bit != 0 => Ok(()),
        _ => Err(Ctap2Response::UnauthorizedPermission),
    }
}

/// The caller's pinUvAuth token and the permissions it was minted with.
///
/// Assembled by the app that owns the session state and handed down, so a
/// sub-command arm can reach [`verify_mac`] and [`authorize`] without
/// re-deriving either. It is not read out of the [`fapico2_platform::secure_store::SecureStore`] for the same
/// reason [`verify_mac`] takes its token as a parameter: a pinUvAuth token is
/// session state, minted by `clientPin` into a field of the app and dropped on
/// `reset`, and a store is not something one can be asked for it.
///
/// # `blocked` is the latch, and holding a token does **not** mean it was
/// consulted
///
/// CTAP2.1 §6.5.7 requires an authenticator to refuse pinUvAuth entirely once
/// the three-strike latch is set, and that check lives in each app's
/// `verify_token` — `device_core.rs`'s for the device path, the host twin's
/// equivalent for `makeCredential`/`getAssertion`. The `0x41` seam does not go
/// through `verify_token`, so an app assembling a `TokenAuth` **must** carry
/// the latch across too; carrying it as a field rather than as a paragraph is
/// what makes the omission visible at the arm rather than in a module header
/// nobody re-reads.
///
/// As of US-115 **one place consults it: `identity_gate`**, which refuses a
/// `CONFIG_WRITE` identity-tier request with
/// [`Ctap2Response::PinAuthBlocked`] (`0x34`) when this is set, *before* it
/// looks at the `pinUvAuthParam` at all.
///
/// The order is the substantive part, and it is why `identity_gate` returns
/// `Outcome::plain` rather than `Outcome::pin_auth_failure` for this case. Once
/// the latch is set the app is **already** latched and has already spent its
/// three strikes, so charging another would burn one of strikes that have been
/// taken and would move the status from the app's `0x34` to the arm's `0x33` —
/// telling the client its token was wrong when in fact the device is refusing
/// all pinUvAuth, and sending the user back to the PIN prompt for a token that
/// is perfectly good. CTAP2.1 §6.5.7 is about refusing pinUvAuth outright;
/// "outright" is what `0x34` says and `0x33` does not.
///
/// The benign tier must stay **unaffected**, and that asymmetry is a claim
/// rather than an omission: the latch is a pinUvAuth latch, and a benign write
/// presents no pinUvAuth, so letting the latch refuse it would turn a PIN typo
/// into a Config screen that needs a power cycle.
/// `tests/vendor41.rs::vendor41_token_auth_reports_the_latch_and_only_the_identity_tier_reads_it`
/// pins both directions on both command paths.
#[derive(Debug, Clone, Copy)]
pub struct TokenAuth<'a> {
    /// The current pinUvAuth token — the HMAC key for [`verify_mac`].
    pub token: &'a [u8; 32],
    /// The `pinUvAuthPermission` byte that token was minted with; `0` for a
    /// legacy `getPinToken` token. See [`authorize`].
    pub permissions: u8,
    /// Whether the app's PIN-auth lockout latch is currently set
    /// (`needs_power_cycle`). An arm that authenticates with `token` must
    /// refuse with [`Ctap2Response::PinAuthBlocked`] when this is `true`.
    pub blocked: bool,
}

// ---------------------------------------------------------------------------
// Phase I foundation: the state the twelve stubs need, and the seam that reaches
// it.
//
// # Why this is a trait and not a `&mut VendorState` bundle
//
// [`handle`] already returns an [`Outcome`] rather than reaching a keystore, for
// the reason its own doc comment argues at length: a durable commit has to be
// transactional against the **whole snapshot**, and the snapshot — not the
// [`fapico2_platform::secure_store::SecureStore`] — is what
// [`crate::device_keystore::DeviceKeystore`] owns. This module decides; the
// dispatch arm that owns the keystore commits.
//
// Three ways to give the twelve arms durable state were weighed
// (`docs/tasks/phase-gj-decision-validation-laya.md`, D-GJ-2; a Laya
// `choice` call over the three came back 0.52/0.29/0.19 at `confidence`
// 0.078, i.e. no signal, so the decision was made on engineering grounds and
// the null result is recorded rather than dressed up):
//
// 1. A `&mut VendorState` bundle. **Rejected**: it inverts the rule above for
//    the four kinds of hot-path security material the state holds (master
//    seed, soft-lock key, org attestation scalar, audit checkpoint key). An
//    arm holding `&mut` to those bytes could publish them with no rollback, and
//    the US-106 → US-115 correction exists precisely because that shape was
//    wrong.
// 2. A second entry point. **Rejected**: two dispatch sites over one protocol.
//    The two `FidoApp` types already have independent `match`es over the same
//    opcode space, and [`handle_subcommand`] exists so the sub-command set is
//    written down exactly once; a second dispatcher would be a third.
// 3. `&mut dyn VendorOps`, which is this. It keeps **one** dispatch site and
//    **one** trust boundary, and it makes the commit point the implementation's
//    to define — which is the whole requirement, since
//    [`crate::device_keystore::DeviceKeystore::grow_checked`] is the only thing
//    in this firmware that can make a keystore write durable-or-reverted.
//
// # Why the payloads cannot ride on `Outcome` instead
//
// [`Outcome`] is `Copy` and its one payload is a
// [`crate::vendorff::PhyConfig`] — four `Option`s of scalars. An org
// attestation certificate chain is **1..=2048 bytes**
// (`picoforge/src/hal/fido/mod.rs:1990`), so no proposal value can carry it,
// and a `0x41` response buffer is `CTAP2_MAX_MSG` rather than an arbitrary
// size. Writes therefore *have* to go through the trait. That is the argument
// for the trait being the commit point, not against it: an implementation
// stages, persists and only then reports success, so a caller that gets
// `Ok(())` knows the bytes are durable.
//
// [`PhyConfig`]: crate::vendorff::PhyConfig
//
// # What is deliberately *not* on the trait
//
// The trait declares **operations**, not storage. There is no
// `read_state() -> &VendorState`, and no `set_state(VendorState)`:
// [`SoftLock`], [`AuditRecord`], [`OrgAttestation`] and [`MseChannel`] are
// per-operation shapes an arm reasons about, not a snapshot an arm can be
// handed and edited. That is what keeps an arm from being able to construct a
// state that no single operation would have produced — a lock engaged with no
// key, a journal with a gap in its sequence numbers, a chain whose hash no
// longer matches its bytes.
// ---------------------------------------------------------------------------

/// The master seed's width (`backup.rs`'s `HKDF`/AEAD plaintext, and the
/// 24-word BIP-39 entropy `seed_to_mnemonic` renders).
pub const MASTER_SEED_LEN: usize = 32;

/// Largest stored soft-lock key blob, in the **sealed** form it arrives in.
///
/// PicoForge seals a 32-byte lock key with ChaCha20-Poly1305
/// (`backup.rs::chacha_seal`) and the blob is `nonce(12) ‖ ct(32) ‖ tag(16)` =
/// **60** bytes. The bound is 64 so the shape has one round number of headroom
/// over the client's actual output, and so a client that adds a 3-byte nonce
/// version prefix is not refused for a reason the protocol does not state. The
/// plaintext is 32; the stored form is not, and an arm that bounds this at 32
/// would refuse every lock enable PicoForge performs.
pub const LOCK_BLOB_MAX: usize = 64;

/// One journal record on the wire (`audit.rs::ENTRY_LEN`).
pub const AUDIT_ENTRY_LEN: usize = 20;

/// Live records the journal ring keeps before the oldest is folded into
/// [`VendorState::audit_epoch`].
///
/// The client has no window parameters — `read_journal` sends `AUDIT_READ` with
/// **no** `subCommandParams` at all (`mod.rs:1573`) and then requires the
/// returned byte count to be exactly `20 × (seq_next - start)`
/// (`audit.rs::175-178`). So the device chooses the window and this is the
/// window's size: 640 bytes, which fits the no-alloc snapshot codec with room
/// to spare, and is deep enough that a token which is used rather than
/// administered never evicts anything.
pub const AUDIT_RING_MAX: usize = 32;

/// Largest org-attestation DER chain (`mod.rs:1990`: `1..=2048`).
pub const ORG_CHAIN_MAX: usize = 2048;

/// ASN.1 DER ECDSA P-256 signature bound (`SEQUENCE { INTEGER r, INTEGER s }`
/// with two minimal-length integers of at most 33 bytes each: 72).
pub const SIG_DER_MAX: usize = 72;

/// SEC1 uncompressed P-256 point: `0x04 ‖ x ‖ y`.
pub const P256_POINT_LEN: usize = 65;

/// The domain separator prefixed to a signed audit checkpoint, byte-exact and
/// with **no** NUL terminator (`audit.rs::CKPT_TAG`, checked at
/// `audit.rs:154`).
///
/// **17 bytes, not 18.** The EPIC's US-174 bullet says *"18 ASCII bytes, no
/// NUL"*, and the count is off by one: `R S K - A U D I T - C K P T - v 1` is
/// 3 + 1 + 5 + 1 + 4 + 1 + 2 = 17. The constant is taken from the client,
/// which is the only side that verifies against it — `ring`'s verifier hashes
/// the bytes this names, so a firmware that appended a NUL to reach 18 would
/// produce a signature no host accepts. US-174 must transcribe 17.
pub const AUDIT_CHECKPOINT_TAG: &[u8] = b"RSK-AUDIT-CKPT-v1";

/// The soft-lock state: engaged, and the sealed lock key that engages it.
///
/// # `engaged` is a method, not a field, and that is the point
///
/// "Is the lock on?" has exactly one answer, and it is whether a lock key
/// exists. A stored `engaged: bool` beside `key: Option<..>` is a second source
/// of truth for the same fact, and the two can disagree after any sequence of
/// partial writes — a device that answers `locked = true` and then cannot
/// decrypt anything is the failure mode, and it is exactly what a torn write
/// to two fields would produce. Deriving it makes that state unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SoftLock {
    /// The lock key, as `wrap_secret` sealed it
    /// (`mod.rs::wrap_secret`): `nonce(12) ‖ ct ‖ tag(16)`, at most
    /// [`LOCK_BLOB_MAX`] bytes. The device never unwraps this at rest — the
    /// soft-lock is a *wrap* of the seed, and the key that opens it is the one
    /// the holder recorded as a BIP-39 phrase.
    pub key: Option<[u8; LOCK_BLOB_MAX]>,
    /// How many bytes of `key` are real. `0` when `key` is `None`.
    pub key_len: u8,
}

impl SoftLock {
    /// Whether the soft lock is engaged.
    pub const fn engaged(&self) -> bool {
        self.key.is_some()
    }

    /// The sealed key's real bytes, or `None` when the lock is off.
    pub fn key_bytes(&self) -> Option<&[u8]> {
        self.key.as_ref().map(|k| &k[..self.key_len as usize])
    }

    /// Build a [`SoftLock`] from a sealed blob, or refuse it.
    ///
    /// The one constructor, so a lock can never be built with a `key_len`
    /// that disagrees with the key it is paired with — the second way the
    /// "engaged but unopenable" state could be built by hand.
    pub fn new(key: &[u8]) -> Result<Self, Ctap2Response> {
        if key.is_empty() {
            // Disengaging is a real operation, and it is the only way to
            // produce "no key"; it is spelled as an empty blob rather than as
            // a separate flag for that reason.
            return Ok(Self::default());
        }
        // **Copied and zero-padded**, not `try_from`'d. The wire form is 60
        // bytes and the slot is `LOCK_BLOB_MAX`, so a `try_from` here would
        // refuse every lock PicoForge actually enables — the check is a length
        // bound, not an equality, and `key_len` is what keeps the padding from
        // being read back.
        if key.len() > LOCK_BLOB_MAX {
            return Err(Ctap2Response::InvalidLength);
        }
        let mut k = [0u8; LOCK_BLOB_MAX];
        k[..key.len()].copy_from_slice(key);
        Ok(Self { key: Some(k), key_len: key.len() as u8 })
    }
}

/// One audit journal record, as the arm describes the event.
///
/// `seq` is deliberately absent: the state owns the sequence, and a record that
/// carried one would be a way to write a gap into the journal. `uptime_ms` is
/// the caller's because the state has no clock; see the field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuditRecord {
    /// Milliseconds since boot, little-endian in the stored record
    /// (`audit.rs:120`).
    ///
    /// There is no monotonic clock reachable from a CTAP2 command on this
    /// path today, so a Phase I arm that has nothing better passes `0`, and
    /// `0` is a legal value that no client rejects. The field is on the trait
    /// rather than invented by the state because inventing it would put a
    /// fabricated timestamp in a tamper-evident log, which is worse than an
    /// honest zero.
    pub uptime_ms: u32,
    /// RS-Key event id (`audit.rs::event_name`: `0x04` reset, `0x0A`
    /// `LOCK_ENGAGE`, `0x0C` `BACKUP_EXPORT`, `0x11` `CHECKPOINT`, …). Values
    /// the table does not name are legal — `event_label` renders them as hex.
    pub event: u8,
    /// The event's auxiliary byte; meaning is per-event.
    pub aux: u8,
    /// Eight opaque detail bytes.
    pub detail: [u8; 8],
}

impl AuditRecord {
    /// The 20 wire bytes: `seq` ‖ `uptime_ms` ‖ `event` ‖ `aux` ‖ `detail`.
    ///
    /// The field order and both endiannesses are the client's
    /// (`audit.rs::parse_entries`), and the two trailing bytes the host never
    /// reads are emitted as `0` rather than omitted — a record is 20 bytes on
    /// the wire whatever the payload holds, and the client computes its
    /// expected length from `seq_next - start` alone.
    pub fn encode(&self, seq: u32) -> [u8; AUDIT_ENTRY_LEN] {
        let mut out = [0u8; AUDIT_ENTRY_LEN];
        out[0..4].copy_from_slice(&seq.to_le_bytes());
        out[4..8].copy_from_slice(&self.uptime_ms.to_le_bytes());
        out[8] = self.event;
        out[9] = self.aux;
        out[10..18].copy_from_slice(&self.detail);
        out
    }
}

/// The window [`VendorOps::audit_window`] chose, for the `AUDIT_READ` response
/// `{1: start, 2: seq_next, 3: epoch, 4: entries}`.
///
/// Returned **beside** the record bytes rather than letting the arm read the
/// epoch and the sequence separately: the client checks
/// `entries.len() == 20 × (seq_next - start)` and folds `head` from `epoch` and
/// the entries, so a response whose three numbers came from three different
/// reads of a journal an append is concurrently extending is a response that
/// fails its own host check. One call, one consistent view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuditWindow {
    /// First live sequence number; everything below is folded into `epoch`.
    pub start: u32,
    /// One past the last sequence number — the next [`VendorOps::audit_append`]
    /// will use it.
    pub seq_next: u32,
    /// `h₀`, the accumulator evicted history has been folded into.
    pub epoch: [u8; 32],
}

/// The device's MSE public point, for the `MSE` response's COSE key
/// `{1: 2, 3: -25, -1: 1, -2: x, -3: y}`.
///
/// # The response key order is the client's, and is non-canonical
///
/// PicoForge builds the map through a `BTreeMap<Value, Value>`, so the device's
/// own key comes back in signed-key order `-3, -2, -1, 1, 3`. CTAP2 canonical
/// CBOR would sort unsigned before negative, so this is **not** canonical, and
/// an arm that re-serialised the map in canonical order would produce bytes the
/// host's `Value` map decodes identically but whose signature coverage (there
/// is none here — `MSE` is sent ungated) and byte-comparison do not. The arms
/// emit the map; this struct only carries the two coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MsePoint {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// The derived backup-channel material one MSE session produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MseChannel {
    /// `HKDF-SHA256(salt = b"", ikm = z, info = aad, L = 32)`
    /// (`backup.rs::derive_channel_key`).
    pub key: [u8; 32],
    /// The AAD: the device's own uncompressed point, `0x04 ‖ x ‖ y`
    /// (`mod.rs:1716-1721`). The same value travels to the host in the `MSE`
    /// response, so the two sides bind the same bytes.
    pub aad: [u8; P256_POINT_LEN],
}

/// A signed audit checkpoint: the `AUDIT_CHECKPOINT` response
/// `{1: head, 2: seq, 3: sig, 4: pubkey}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    /// The chain head that was signed.
    pub head: [u8; 32],
    /// `seq_next` at the moment of signing — one past the last record the head
    /// covers.
    pub seq: u32,
    /// ASN.1 DER ECDSA P-256 signature over
    /// [`AUDIT_CHECKPOINT_TAG`] ‖ `head` ‖ `seq.to_le_bytes()` ‖ `challenge`.
    pub sig: [u8; SIG_DER_MAX],
    /// How many bytes of `sig` are real (70..=72).
    pub sig_len: u8,
    /// SEC1 uncompressed P-256 public key, so the host can verify and pin it by
    /// full hex or by the 16-hex `sha256(pubkey)[..8]` fingerprint
    /// (`audit.rs::fingerprint`).
    pub pubkey: [u8; P256_POINT_LEN],
}

/// The organisation attestation credential **as an import carries it**: a
/// P-256 scalar and the DER chain that vouches for it, both owned.
///
/// This is the *write* payload ([`VendorOps::set_org_attestation`]). The
/// *read* side is [`OrgAttestationView`], which borrows, because the chain is
/// up to [`ORG_CHAIN_MAX`] bytes and an `ATT_STATE` — which wants two booleans
/// and a hash — must not copy 2 KB to get them.
///
/// # It is not the per-device attestation identity
///
/// `ATT_IMPORT` writes here and nowhere else. The per-device attestation
/// (`crate::attestation`, minted at boot from the TRNG) continues to serve the
/// **FIDO2** path and is never read, replaced or cleared by anything on this
/// channel — see US-175's layering rule. A device with no org cert imported
/// still mints normal FIDO2 attestations, and that is the regression test.
///
/// # The scalar is stored **unwrapped**
///
/// The client sends it sealed under the MSE channel (`mod.rs::att_import` calls
/// `wrap_secret`), so an arm opens that wrap with [`VendorOps::mse_channel`]
/// and hands the state the raw 32-byte scalar. What is stored is what a later
/// `0x41` attestation surface would sign with; a stored wrap would have to be
/// re-opened under a session that no longer exists.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OrgAttestation {
    /// The P-256 private scalar, 32 bytes. `None` ⇒ not installed.
    pub scalar: Option<[u8; 32]>,
    /// The concatenated DER of every certificate in the chain, `1..=`
    /// [`ORG_CHAIN_MAX`] bytes. `None` ⇒ not installed.
    pub chain: Option<HeaplessVec<u8, ORG_CHAIN_MAX>>,
}

/// A borrowed view of the stored org attestation — what
/// [`VendorOps::org_attestation`] hands an arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OrgAttestationView<'a> {
    /// The P-256 private scalar, if one is installed.
    pub scalar: Option<[u8; 32]>,
    /// The stored DER chain, borrowed. Empty when none is installed.
    pub chain: &'a [u8],
}

impl OrgAttestationView<'_> {
    /// Whether an org attestation is installed.
    ///
    /// Derived from the scalar rather than carried as a flag, for the same
    /// reason [`SoftLock::engaged`] is derived: the write is all-or-nothing
    /// (see [`VendorOps::set_org_attestation`]), so the two fields cannot
    /// legally disagree, and one question asked one way means a partial write
    /// cannot make them disagree either.
    pub const fn installed(&self) -> bool {
        self.scalar.is_some()
    }

    /// `SHA-256` over the stored DER chain, or `None` when not installed.
    ///
    /// Derived rather than stored, because a stored hash is a second copy of
    /// the chain that a future edit to the chain would silently desynchronise —
    /// and `ATT_STATE`'s `chain_hash` is what a host pins an org identity
    /// against, so a stale one would be a silent identity failure.
    pub fn chain_hash(&self) -> Option<[u8; 32]> {
        if self.installed() {
            Some(crate::crypto::sha256(self.chain))
        } else {
            None
        }
    }
}
///
/// Object-safe, and passed as `&mut dyn VendorOps`. Every mutating method is
/// **all-or-nothing**: on `Err` the durable state is byte-for-byte what it was
/// before the call. That is not a convention the implementations are asked to
/// honour — it is the shape of the only commit they have
/// ([`crate::device_keystore::DeviceKeystore::grow_checked`], which applies,
/// persists, and runs an undo closure if the persist fails), and the methods
/// validate before they mutate so a refusal never reaches the apply step at
/// all.
pub trait VendorOps {
    /// Fill `out` with cryptographically-secure random bytes.
    ///
    /// On the trait rather than reached for directly because this is the one
    /// input the two command paths genuinely disagree about: the device serve
    /// loop holds no [`fapico2_platform::trng::Trng`] handle and draws from a
    /// boot-filled pool (`device_app`'s `rng_pool`/`rng_cursor`), while the host
    /// has OS entropy. An MSE ephemeral scalar, a ChaCha20-Poly1305 nonce and
    /// the one-time audit checkpoint key all need it, and a state module with
    /// a `Trng` lifetime parameter would not be constructible from either
    /// dispatch arm.
    fn random_bytes(&mut self, out: &mut [u8]);

    // ---- seed backup / restore (US-171 `MSE`, US-172 `EXPORT`/`LOAD`) ----

    /// The 32-byte master seed, or `None` on a device that has none.
    ///
    /// `STATE`'s `has_seed` is exactly `master_seed().is_some()`, so a soft-lock
    /// engaged over a device with no seed is representable and truthful.
    /// Whether the one-time seed-export window is permanently closed.
    ///
    /// `STATE`'s key 1, and the same durable bit `FINALIZE`
    /// (`RSKEY_VENDOR_FINALIZE`, `0x04`) sets. It is **monotonic**: no
    /// protocol path clears it, and a "may this token ever export again"
    /// answer that can return to yes is not an answer.
    ///
    /// Read-only on the trait; the writer is
    /// [`crate::vendor_backup::BackupWindow::seal_backup`], which
    /// `FINALIZE` is the only caller of. Splitting read from write is what
    /// let the `STATE` arm and the `FINALIZE` arm be written against
    /// disjoint files without either reconciling the other's choice.
    fn export_sealed(&self) -> bool;

    fn master_seed(&self) -> Option<[u8; 32]>;

    /// Install a master seed, durably, or leave the state untouched.
    fn set_master_seed(&mut self, seed: [u8; 32]) -> Result<(), Ctap2Response>;

    // ---- soft lock (US-170 `STATE`, `UNLOCK`) ----

    /// The at-rest soft-lock record.
    fn soft_lock(&self) -> SoftLock;

    /// Replace the soft-lock record wholesale, durably.
    ///
    /// One method rather than `set_engaged` plus `set_key` because engaging the
    /// lock *is* storing its key: a two-method split would let an arm engage
    /// without a key (or replace the key without re-wrapping the seed) through
    /// two individually-successful calls, and `ATT_CLEAR`-style partial
    /// application is exactly what this channel refuses elsewhere
    /// ([`config_write`]'s "what is committed, and what is not").
    fn set_soft_lock(&mut self, lock: SoftLock) -> Result<(), Ctap2Response>;

    /// Whether the soft-locked seed has been loaded for **this power cycle**.
    ///
    /// Session state, not at-rest state: it is `false` after every reset, which
    /// is what makes the flag a real second factor rather than a latch. It is
    /// deliberately absent from the snapshot for the same reason
    /// `auth_failures` is (`device_app`'s "volatile, never persisted"): a
    /// durable "unlocked" would survive the power cycle it is defined against.
    fn unlocked_this_power_cycle(&self) -> bool;

    /// Set — or clear — the unlocked flag. Volatile; returns nothing, because
    /// there is nothing to make durable and therefore nothing that can fail.
    fn set_unlocked_this_power_cycle(&mut self, unlocked: bool);

    // ---- the MSE backup channel (US-171 `MSE`; used by `EXPORT`/`LOAD`,
    //      `UNLOCK`, `ATT_CLEAR`, `ATT_IMPORT`) ----

    /// Run one ephemeral ECDH against the host's point and keep the derived
    /// channel for this power cycle, reporting the device's own point in
    /// `out`.
    ///
    /// The host key arrives as a COSE `{1: 2, 3: -25, -1: 1, -2: x, -3: y}` and
    /// only `x`/`y` reach this method: the arm parses the map (its key order is
    /// the client's non-canonical one, see [`MsePoint`]) and the curve and kdf
    /// ids are this channel's constants, not the caller's to choose.
    fn mse_establish(
        &mut self,
        host_x: [u8; 32],
        host_y: [u8; 32],
        out: &mut MsePoint,
    ) -> Result<(), Ctap2Response>;

    /// The channel material the last [`VendorOps::mse_establish`] derived, or
    /// [`Ctap2Response::InvalidParameter`] when no session is established.
    ///
    /// "No session" is a refusal rather than a zero key: an arm that reaches
    /// this without an `MSE` has skipped a step, and handing it a zero key
    /// would turn that into a decryption against `HKDF(0, 0)`.
    fn mse_channel(&self, out: &mut MseChannel) -> Result<(), Ctap2Response>;

    // ---- the audit journal (US-173 `AUDIT_READ`, US-174 `CHECKPOINT` /
    //      `AUDIT_CONFIG`) ----

    /// Whether the journal is recording. Opt-in (`mod.rs::audit_set_enabled`:
    /// *"nothing is written to flash until it is enabled"*).
    fn audit_enabled(&self) -> bool;

    /// Turn the journal on or off, durably.
    fn set_audit_enabled(&mut self, enabled: bool) -> Result<(), Ctap2Response>;

    /// Append one record and make it durable, or leave the journal untouched.
    ///
    /// A **no-op returning `Ok(())` while the journal is disabled** — not an
    /// error, and not a write. The opt-in is the client's stated contract, and
    /// an arm that appended anyway would burn a flash write per event on a
    /// device whose owner never asked for a journal. The state enforces it so
    /// that no arm has to remember to.
    fn audit_append(&mut self, record: AuditRecord) -> Result<(), Ctap2Response>;

    /// Write the chosen window's record bytes into `out` and report the three
    /// numbers the `AUDIT_READ` response needs.
    ///
    /// The records are streamed **into the reply buffer**, after the CBOR
    /// byte-string head, exactly as [`write_phy_record`] does for the PHY
    /// record: the largest window is
    /// [`AUDIT_RING_MAX`] × [`AUDIT_ENTRY_LEN`] = 640 bytes, and a second
    /// buffer that size on the RP2350 stack per `AUDIT_READ` would be a cost
    /// for a copy the reply already has room for.
    fn audit_window(
        &self,
        out: &mut HeaplessVec<u8, CTAP2_MAX_MSG>,
    ) -> Result<AuditWindow, Ctap2Response>;

    /// Sign a fresh checkpoint over the journal's current head and the host's
    /// 16-byte challenge, filling every field of the response.
    ///
    /// # Why the arm does not assemble the signed message
    ///
    /// The layout is byte-exact
    /// ([`AUDIT_CHECKPOINT_TAG`] ‖ `head` ‖ `seq.to_le_bytes()` ‖ `challenge`,
    /// `audit.rs:154-160`), and the host verifies it against the `head` and
    /// `seq` the **response** carried (`audit_verify`'s `head_matches`). If the
    /// arm read the head, then a `makeCredential` appended a record, then asked
    /// for a signature, the response's `head` would not be the head that was
    /// signed and the host would report the journal as unauthentic — a race
    /// the device can close and the arm cannot. So the state takes the
    /// challenge, reads its own head and sequence **once**, signs, and returns
    /// both.
    ///
    /// # Why this is `&mut self` for a signature
    ///
    /// The device's checkpoint key is minted from the TRNG the first time one
    /// is needed and then lives in the sealed snapshot, so a token whose
    /// journal has never been signed has no key yet. Minting is a durable
    /// write, and a durable write cannot happen through `&self`.
    ///
    /// The key is a **dedicated slot**, not something derived from existing
    /// state. `device_random` is the obvious candidate and is wrong: it is
    /// transmitted in `getInfo`'s `encState` (`device_core.rs:1873-1875`),
    /// so anything derived from it is public to anyone who has spoken to the
    /// token, and a checkpoint key that is public authenticates nothing. It is
    /// not derived from the store key either — that key is a documented
    /// constant on the host and the file store, so the checkpoint fingerprint
    /// a host pins would be the same on every host that ever ran this firmware.
    fn audit_sign_checkpoint(
        &mut self,
        challenge: &[u8; 16],
        out: &mut Checkpoint,
    ) -> Result<(), Ctap2Response>;

    // ---- org attestation (US-175 `ATT_STATE`, `ATT_IMPORT`, `ATT_CLEAR`) ----

    /// A borrowed view of the org attestation credential.
    ///
    /// Borrowed rather than returned by value because the chain is up to
    /// [`ORG_CHAIN_MAX`] bytes and `ATT_STATE` — the only sub-command that
    /// reads it — wants two booleans and a hash. See
    /// [`OrgAttestationView`] for why the hash is derived rather than stored.
    fn org_attestation(&self) -> OrgAttestationView<'_>;

    /// Install or clear the org attestation, durably and all-or-nothing.
    ///
    /// `OrgAttestation::default()` clears. An import that arrives with a scalar
    /// and no chain, or a chain and no scalar, is refused rather than half
    /// stored: a `chain_hash` with no key, or a key no host can check against a
    /// chain, is the state `ATT_STATE` would then report as installed.
    fn set_org_attestation(&mut self, att: OrgAttestation) -> Result<(), Ctap2Response>;
}

// ---------------------------------------------------------------------------
// The two byte-exact constructions the implementations share.
//
// Both are here, in the protocol module, rather than in
// `crate::vendor_state`, and both are here for the same reason: the host and
// device [`VendorOps`] implementations must produce **identical** bytes from
// identical state, and the one way to guarantee that is for the construction to
// exist once. A `derive_channel_key` in one implementation and a
// `checkpoint_message` in the other would be two chances to be written twice
// differently — and both are checked on the host against a fixture the host
// suite cannot derive from the firmware, so a divergence would be a
// cross-implementation bug that passes every device test.
// ---------------------------------------------------------------------------

/// The signed audit-checkpoint message, byte-exact:
/// [`AUDIT_CHECKPOINT_TAG`] ‖ `head` ‖ `seq.to_le_bytes()` ‖ `challenge`.
///
/// 17 + 32 + 4 + 16 = **69** bytes, and the buffer is 1024 rather than 69 for
/// the same reason every other fixed buffer here has headroom: a future field
/// must be a one-line change, not a resize that has to survive a stack audit.
///
/// The two things a reader gets wrong, and why they are the two things pinned
/// here: the tag is 17 ASCII bytes with **no** NUL terminator
/// (`audit.rs:154` does `msg.extend_from_slice(CKPT_TAG)` on a `&[u8]`, not a
/// C string — and the EPIC's "18" is an off-by-one; see
/// [`AUDIT_CHECKPOINT_TAG`]), and `seq` is **little-endian** while the
/// journal's own `seq` field is also little-endian but the *response* carries
/// it as an integer. `ring`'s verifier is byte-exact, so either mistake
/// produces a signature that fails to verify and an audit screen that says the
/// journal is unauthentic.
pub fn checkpoint_message<const N: usize>(
    head: &[u8; 32],
    seq: u32,
    challenge: &[u8; 16],
    out: &mut HeaplessVec<u8, N>,
) -> Result<(), Ctap2Response> {
    out.clear();
    out.extend_from_slice(AUDIT_CHECKPOINT_TAG).map_err(|_| Ctap2Response::LimitExceeded)?;
    out.extend_from_slice(head).map_err(|_| Ctap2Response::LimitExceeded)?;
    out.extend_from_slice(&seq.to_le_bytes()).map_err(|_| Ctap2Response::LimitExceeded)?;
    out.extend_from_slice(challenge).map_err(|_| Ctap2Response::LimitExceeded)?;
    Ok(())
}

/// The backup-channel key: `HKDF-SHA256(salt = b"", ikm = z, info = aad,
/// L = 32)`, with `aad` the device's own uncompressed point
/// (`backup.rs::derive_channel_key`).
///
/// The salt is **empty**, which is also what "no salt" means here. An earlier
/// revision of this comment claimed `Salt::new(HKDF_SHA256, b"")` differs from
/// `Salt::new(HKDF_SHA256, &[])` and that the client's spelling was the one
/// that mattered. It does not differ: `hkdf` 0.12 resolves `None` to
/// `Output::<H>::default()` (32 zero bytes) and HMAC-SHA256 zero-pads its key
/// to the block size, so the empty slice, the 32 zero bytes and a 64-byte zero
/// slice all produce a byte-identical PRK. The behaviour was right and the
/// stated reason was wrong, which is worse than being wrong outright — a
/// reader who believed it could "correct" the code into something still correct
/// for a reason that is also false. The client derives it as
/// `hkdf::Salt::new(HKDF_SHA256, b"")` (`backup.rs:34`); so does this. The AAD is bound into `info`
/// *and* travels to the host as the `MSE` response's own point, so a channel
/// key cannot be replayed against a different device point.
pub fn derive_mse_channel(z: &[u8; 32], device_point: &[u8; P256_POINT_LEN]) -> [u8; 32] {
    let mut key = [0u8; 32];
    crate::crypto::hkdf_sha256(None, z, device_point, &mut key);
    key
}

// ---------------------------------------------------------------------------
// The escalation test seam (US-112 review, finding 2).
//
// `Outcome::pin_auth_failure` is the whole of the lockout seam, and until this
// knob existed **no test on either command path ever set it** — the only test
// that touched the flag asserted it was `false`. That left the commit's central
// claim ("a Phase I arm gets `0x34` and the durable latch for free") true by
// reading and unobserved, which this series does not accept.
//
// The knob is compiled under `#[cfg(feature = "host")]` and therefore does not
// exist in the RP2350 firmware at all: the device build takes
// `fapico2-fido` with `default-features = false` and enables only `device`
// (`firmware/Cargo.toml`'s dependency block, and the crate's own
// `default = ["host"]`), so nothing below reaches a shipped binary. What it
// does reach is the host stack and the emulation binary, and there it is
// inert unless a test sets it.
// ---------------------------------------------------------------------------

// **Host builds only.** The sub-command that `handle_subcommand` should answer
// as a `pinUvAuthParam` failure, or `None` for none.
//
// A [`Subcommand`] cannot be stored in an `AtomicU8` without losing its
// identity, so this holds the wire byte and is compared against
// [`Subcommand::byte`]. Inert when `0`, which is not a sub-command.
//
// **It is thread-local, and that is load-bearing rather than tidy.** It was a
// plain `static`, which made it a process-wide knob: the two tests that arm it
// set a flag that *every other test running concurrently on another thread*
// then saw, so any parallel run had a window in which a `CONFIG_WRITE` was
// answered `0x33` instead of `0x00`. That surfaced as a ~3 % flake spread
// across four unrelated tests, always failing at whichever precondition ran
// first — a symptom with no visible connection to the knob that caused it.
// libtest spawns a fresh thread per test and never reuses one, so a
// thread-local is exactly as isolated as a test needs and no more.
//
// [`AtomicU8`]: core::sync::atomic::AtomicU8
#[cfg(feature = "host")]
thread_local! {
    static ESCALATION_TEST_SUB: core::sync::atomic::AtomicU8 =
        const { core::sync::atomic::AtomicU8::new(0) };
}

/// **Host builds only.** Point [`ESCALATION_TEST_SUB`] at `sub`, so the next
/// [`handle_subcommand`] for that sub-command answers
/// [`Ctap2Response::PinAuthInvalid`] *and* asks the app to charge its
/// PIN-auth failure counter — which is what a real arm does when
/// [`verify_mac`] refuses a `pinUvAuthParam`.
///
/// `None` disarms it. The returned [`EscalationTestGuard`] disarms on **drop**,
/// and a test must bind it, so a failing assertion cannot leave the emulation
/// binary answering `0x33` to every `0x41` request for the rest of the
/// *test's own* execution. Re-arming mid-test is drop-then-set. The guard
/// remains necessary even though the knob is now thread-local: it is what
/// stops a re-armed test from leaking into the test that runs next *on the
/// same thread*, which under `--test-threads=1` is every test.
///
/// This exists because nothing else can produce the flag: no sub-command is
/// implemented, so nothing reaches [`verify_mac`]. It is a test instrument,
/// not a debug feature, and it is absent from the device build.
#[cfg(feature = "host")]
pub fn set_escalation_test_sub(sub: Option<Subcommand>) -> EscalationTestGuard {
    ESCALATION_TEST_SUB.with(|c| {
        c.store(sub.map_or(0, |s| s.byte()), core::sync::atomic::Ordering::SeqCst)
    });
    EscalationTestGuard
}

/// Disarms [`ESCALATION_TEST_SUB`] on drop. `#[must_use]` because ignoring the
/// return value of [`set_escalation_test_sub`] is exactly the bug it prevents:
/// the knob would outlive the test that set it.
#[cfg(feature = "host")]
#[must_use = "bind the guard, or the knob outlives the test that set it"]
pub struct EscalationTestGuard;

#[cfg(feature = "host")]
impl Drop for EscalationTestGuard {
    fn drop(&mut self) {
        ESCALATION_TEST_SUB.with(|c| c.store(0, core::sync::atomic::Ordering::SeqCst));
    }
}

/// What a sub-command reports back to the command path that owns the PIN state
/// and the keystore.
///
/// The status is what goes on the wire. `pin_auth_failure` is the whole of the
/// lockout seam: an arm that rejected a `pinUvAuthParam` sets it, and the app
/// — which owns the volatile three-strike counter
/// (`app::FidoApp::note_pin_auth_failure` and its device twin) — turns it into
/// exactly one increment and substitutes that method's status, so the third
/// strike still answers `0x34` rather than `0x33`.
///
/// The flag is `false` for every stub. That is asserted, not assumed:
/// `tests/vendor41.rs::vendor41_stub_never_charges_pin_auth_failure`.
///
/// # `phy`, and why the commit is not here
///
/// `Some(record)` on a `0x00` is this sub-command's *proposal*: the physical
/// configuration the dispatch arm should make durable. It is a proposal rather
/// than a mutation because this module has no keystore — see [`handle`] on
/// why `store` is the wrong thing to hand a sub-command arm. The dispatch arm
/// commits it through `grow_checked`, which is the same transactional shape the
/// `0xFF` legacy framing uses, and a commit that cannot be made durable is
/// reported as a failure rather than as a `0x00`.
///
/// `None` for every refusal, which is what makes "did anything get written?"
/// answerable from the return value alone.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Outcome {
    /// The CTAP2 status byte to put on the wire.
    pub status: Ctap2Response,
    /// `true` when the arm rejected a `pinUvAuthParam` and the app should
    /// charge its PIN-auth failure counter.
    pub pin_auth_failure: bool,
    /// The physical configuration to commit, on a `0x00` that changes one.
    pub phy: Option<crate::vendorff::PhyConfig>,
}

impl Outcome {
    /// A status with nothing to charge and nothing to commit — the correct
    /// answer for anything that did not look at a `pinUvAuthParam`.
    pub const fn plain(status: Ctap2Response) -> Self {
        Self { status, pin_auth_failure: false, phy: None }
    }

    /// A `0x00` that wants `phy` made durable before the reply goes out.
    pub const fn with_phy(status: Ctap2Response, phy: crate::vendorff::PhyConfig) -> Self {
        Self { status, pin_auth_failure: false, phy: Some(phy) }
    }

    /// A status from an arm that rejected a `pinUvAuthParam`, asking the app
    /// to charge its PIN-auth failure counter.
    ///
    /// `status` is normally [`Ctap2Response::PinAuthInvalid`], which is what
    /// [`verify_mac`] returns; it is a parameter rather than hard-wired so an
    /// arm that has already learned something more specific (a blocked PIN,
    /// say) is not forced to lie about it. Nothing is proposed for commit: a
    /// request that failed authentication has not earned a configuration
    /// change, and carrying the field at all would be a way to forget that.
    pub const fn pin_auth_failure(status: Ctap2Response) -> Self {
        Self { status, pin_auth_failure: true, phy: None }
    }
}
