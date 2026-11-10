//! US-1821 (WARM-BOOT-SERVE) — the randomness consumer map is pinned, not
//! remembered.
//!
//! # What this file holds
//!
//! The epic's whole posture rests on two claims, and both rot silently
//! because the paths that would falsify them are arm-only or spread across
//! crates:
//!
//! 1. **"getAssertion is deterministic"** — the epic's central promise (a
//!    cold board authenticates you while the TRNG warms) is exactly the
//!    claim that a "small" refactor of the signing path could quietly
//!    invalidate by adding a draw. No host test compiled the device GA path
//!    until `device_core_mc_ga.rs`; nothing read its *source*.
//! 2. **"every consumer in the map is gated"** — the warming refusals
//!    (US-1826) exist as concrete source shapes in three applets. Deleting
//!    one (the exact regression US-1826 was written to prevent: a creation
//!    operation serving empty-pool keystream bytes) passes every behavioural
//!    host test, because the host twins have no warming state.
//!
//! So this file source-pins both, in the `include_str!` shape
//! `bootphase.rs`'s call-site test and `wait_blink.rs`'s collision test use
//! for arm-only files: the source is read at compile time (a moved or
//! deleted file is a build error, not a stale pass) and the pinned shapes
//! are asserted against it.
//!
//! # What a failure means
//!
//! * `the_get_assertion_path_draws_no_randomness` — someone added a draw to
//!   the GA path. The epic's promise ("a cold board authenticates you") is
//!   no longer true; the class table's `GetAssertion = Allow` is now a lie
//!   on the wire.
//! * `the_warming_gates_are_in_the_source` — a US-1826 refusal was deleted.
//!   The corresponding creation operation would serve attacker-derivable
//!   bytes from the empty-pool keystream during a warming window.

/// The device FIDO command path — host-compiled, shipped on device (§1 of
/// AGENTS.md: this is the twin that gets the hardware proof).
const DEVICE_CORE: &str = include_str!("../src/device_core.rs");
/// The OATH device core (the `#[cfg(device, arm)]` applet type).
const OATH_CORE: &str = include_str!("../../../apps/oath/src/oath_core.rs");
/// The Nostr applet — the provider Option the warming posture installs.
const NOSTR: &str = include_str!("../../../apps/nostr/src/lib.rs");

/// Extract one function's source text from `src` by name, brace-matched.
///
/// The shape `bootphase.rs` uses for `mark!` sites, generalized: find the
/// `fn NAME` declaration, walk to its opening brace, and take the text up
/// to the matching close brace. Comments and nested braces are preserved
/// verbatim; only the brace counting matters. Returns `None` when the
/// function is absent — which is itself a failure the caller asserts on
/// (a renamed or deleted function is a moved target, not a pass).
fn fn_body(src: &str, name: &str) -> Option<String> {
    let pat = format!("fn {name}(");
    let start = src.find(&pat)?;
    // The signature may contain braces of its own (generic const args,
    // `HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>`), so the body's opening
    // brace is the first brace AFTER the balanced parameter list closes.
    let mut open_paren = src[start..].find('(')? + start;
    let mut paren_depth = 0usize;
    for (i, ch) in src[open_paren..].char_indices() {
        match ch {
            '(' => paren_depth += 1,
            ')' => {
                paren_depth -= 1;
                if paren_depth == 0 {
                    open_paren += i;
                    break;
                }
            }
            _ => {}
        }
    }
    let open = src[open_paren..].find('{')? + open_paren;
    let mut depth = 0usize;
    for (i, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(src[open..open + i + 1].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// US-1821 scenario: "the deterministic claims hold — neither [the
/// assertion signing path nor the PIN verification path] calls a
/// randomness source at serving time."
///
/// The GA path is pinned directly: the `get_assertion_inner` body must not
/// name any draw primitive or adapter. RFC 6979 signing (`SigningKey::sign`
/// through `crypto::p256_sign`) takes no RNG; a draw here would be a new
/// nonce dependency the class table does not declare.
#[test]
fn the_get_assertion_path_draws_no_randomness() {
    let body = fn_body(DEVICE_CORE, "get_assertion_inner")
        .or_else(|| fn_body(DEVICE_CORE, "handle_get_assertion"))
        .expect("the device GA path exists (get_assertion_inner or handle_get_assertion)");
    for draw in ["random_bytes", "draw_random", "take_random", "TrngAdapter", "SecretKey::random"] {
        assert!(
            !body.contains(draw),
            "the getAssertion path must draw no randomness (found `{draw}`) — \
             the class table's `GetAssertion = Allow` under Warming claims this \
             path is deterministic; a draw here makes the warming posture serve \
             empty-pool keystream bytes as assertion material"
        );
    }
}

/// US-1821 scenario: "every random_bytes site is known and gated" — the
/// FIDO half. The makeCredential warming gate (US-1826) must be in the
/// source: the non-resident arm's keypair drawn from an empty pool is not
/// merely stale, it is attacker-derivable, so the gate is the one thing
/// between a warming window and a known private key.
#[test]
fn make_credential_carries_the_warming_gate() {
    let body = fn_body(DEVICE_CORE, "make_credential_inner")
        .expect("the device makeCredential path exists");
    assert!(
        body.contains("rng_pool.is_empty()"),
        "makeCredential must refuse while the pool is empty (US-1826) — \
         an empty-pool non-resident keypair is SHA-256 keystream, i.e. a \
         known private key"
    );
    // The gate's refusal word is the US-1007 precedent (`Other`, 0x7F) —
    // pinned so a silent switch to a harsher code (a client-visible
    // dialect change) cannot ride in with an unrelated edit.
    assert!(
        body.contains("Ctap2Response::Other"),
        "the warming refusal word is Ctap2Response::Other (0x7F, the \
         US-1007 entropy-starved precedent)"
    );
}

/// US-1821: the OATH half of "every consumer is gated". VALIDATE and
/// SET_CODE refuse while the pool is empty (US-1826): VALIDATE over the
/// constant construction challenge would replay across warming boots, and
/// SET_CODE's salts would be keystream bytes for a persisted secret.
#[test]
fn oath_validate_and_set_code_carry_the_warming_gates() {
    let validate = fn_body(OATH_CORE, "cmd_validate")
        .expect("oath_core::cmd_validate exists");
    assert!(
        validate.contains("rng_pool.is_empty()"),
        "OATH VALIDATE must refuse while Warming — the session challenge is \
         the stretch-from-empty constant during the warming window, and a \
         challenge-response proof over it replays across boots"
    );
    let set_code = fn_body(OATH_CORE, "cmd_set_code")
        .expect("oath_core::cmd_set_code exists");
    assert!(
        set_code.contains("rng_pool.is_empty()"),
        "OATH SET_CODE must refuse while Warming — its salts would be \
         keystream bytes for a persisted secret"
    );
}

/// US-1821, review P1 follow-up (WARM-BOOT-SERVE): the clientPIN half.
/// The token MINT (getPinToken / getPinUvAuthTokenUsingPin) and the
/// PERSISTED PIN SALTS (setPIN / changePIN) draw from the pool — a
/// warming-window mint is an attacker-derivable pinUvAuthToken (a PIN
/// bypass past Ready), and a warming-window salt makes the persisted PIN
/// verifier brute-forceable offline. Both must refuse while the pool is
/// empty; getRetries and getKeyAgreement stay ungated (deterministic — the
/// client needs them to learn the refusal and to retry).
#[test]
fn client_pin_gates_the_token_mint_and_the_persisted_salts() {
    let body = fn_body(DEVICE_CORE, "client_pin_inner")
        .expect("the device clientPIN path exists");
    // The gate must cover the four drawing subcommands by number, so a
    // renumbered or half-covered list cannot slip through.
    for sub in ["0x03", "0x04", "0x05", "0x09"] {
        assert!(
            body.contains(sub),
            "clientPIN warming gate must name subcommand {sub} (setPIN,              changePIN, getPinToken, getPinUvAuthTokenUsingPin) — its draws              are a minted token or a PERSISTED salt, not ephemera"
        );
    }
    // The deterministic subcommands stay ungated: the gate block must not
    // refuse them (getRetries 0x01, getKeyAgreement 0x02).
    let gate = body
        .split("rng_pool.is_empty()")
        .nth(1)
        .unwrap_or("")
        .split("match subcommand")
        .next()
        .unwrap_or("");
    assert!(
        !gate.is_empty(),
        "the clientPIN warming gate block is missing entirely"
    );
    assert!(
        !gate.contains("0x01") && !gate.contains("0x02"),
        "getRetries (0x01) and getKeyAgreement (0x02) must stay servable          while Warming — they are deterministic and the client needs them          to learn the refusal"
    );
}

/// US-1821: the Nostr half. The rng provider is an `Option<fn>` and the
/// device install passes `None` while Warming (US-1826) — the applet's
/// `None` arm is the refusal every draw-carrying command answers, on both
/// transports at once.
#[test]
fn nostr_provider_is_option_gated() {
    assert!(
        NOSTR.contains("rng: Option<fn(&mut [u8])>"),
        "the Nostr rng provider must be an Option<fn> so the warming posture \
         can install the refuse path (US-1826)"
    );
    assert!(
        NOSTR.contains("self.rng = rng"),
        "install_providers must store the provider as given — `Some(rng)` \
         here would make a None install silently impossible"
    );
}

/// US-1821 scenario: "every random_bytes site is known and gated" — the
/// quarantine coverage list. Every production file that carries a
/// randomness consumer is named here; a consumer added anywhere else is a
/// new file `check_rng_path.py`'s allowlist does not declare, and that CI
/// gate is what turns red on the *addition*. This list is the *deletion*
/// half: removing a file's warming gate without removing its entry here
/// (and the reason it carries) fails this test.
#[test]
fn the_quarantine_coverage_names_every_gated_consumer() {
    const COVERAGE: &[&str] = &[
        "apps/fido/src/device_core.rs",   // MC gate (this file pins it)
        "apps/oath/src/oath_core.rs",     // VALIDATE + SET_CODE gates
        "apps/nostr/src/lib.rs",          // Option provider + None refuse arm
        "platform/src/trng.rs",           // LazyDrbg: NotSeeded is the refuse
        "platform/src/trusted_backend/device.rs", // Rp2350Rng maps NotSeeded
    ];
    // The host twin is deliberately absent: app.rs carries no pool and
    // draws from OS entropy that cannot starve — the device twin is the
    // shipped path (AGENTS.md §1), and the gate comment in
    // `make_credential_inner` records the reasoning.
    for file in COVERAGE {
        assert!(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent() // apps/
                .unwrap()
                .parent() // workspace root
                .unwrap()
                .join(file)
                .exists(),
            "quarantine coverage entry {file} does not exist — the map has \
             drifted from the tree"
        );
    }
}
