# US-1678 — red, then green: `an_argument_above_the_wire_cap_is_refused_in_band`

## The red (against the pre-fix tip, `feat/nostr` @ `c0fffec`)

The test drives `process_vendor_through` with a 3,000-byte CBOR argument
through every vendor command byte `0x40–0x7F`. On the pre-fix tip it panics
at the `build_apdu` `extend_from_slice(arg).unwrap()` — the USB-reachable
reboot the review's P0 named (`panic = "abort"` makes the panic a device
reboot; here it is the test harness catching the same overflow):

```
$ cargo test -p fapico2-firmware --lib --features device,emulation \
    --target x86_64-unknown-linux-gnu an_argument_above_the_wire_cap -- --test-threads=1

running 1 test
test nostr_wire::tests::an_argument_above_the_wire_cap_is_refused_in_band ... FAILED

---- nostr_wire::tests::an_argument_above_the_wire_cap_is_refused_in_band stdout ----

thread 'nostr_wire::tests::an_argument_above_the_wire_cap_is_refused_in_band' panicked at firmware/src/nostr_wire.rs:289:32:
called `Result::unwrap()` on an `Err` value: ()
```

(`nostr_wire.rs:289` on that tip is the `out.extend_from_slice(arg).unwrap()`
in `build_apdu`; full transcript in `red-pre-fix.txt`. A note for the
record: the first cut of the fix carried a `debug_assert!` beside the
reachability proof; US-1679's over-capacity row probes `build_apdu`'s own
bound directly, so the assert was dropped in favour of the explicit
overflow arm alone — the proof stays written, and the tests carry it.)

## The green

After the fix — the §2.2.1 wire cap enforced in `decode_request`
(`NOSTR_REQ_ARG_MAX = fapico2_nostr::MAX_REQUEST_ARG`, derived from
`MAX_PLAINTEXT`, never restated) and `build_apdu` made infallible by
construction (`Option` return, explicit overflow arm, `debug_assert!` with
the written reachability proof, `process_vendor_through` mapping `None` to
the in-band `SW_WRONG_DATA`) — every vendor command byte answers the
`6A80` envelope and the suite does not panic:

```
test result: ok. 124 passed; 0 failed; ... (fapico2-firmware --lib --features device,emulation)
```

## Acceptance checks

- the red-first test is green at the story's tip;
- `grep -n "unwrap" firmware/src/nostr_wire.rs` returns no
  `extend_from_slice`-overflow `unwrap` — the remaining hits are the tests'
  `decode_response(..).unwrap()`, `decode_request`'s `sw?`/`unwrap_or`
  (not capacity-bearing), and `encode_request`'s host-side `Option` unwraps
  in test callers;
- the parser cap's constant is `fapico2_nostr::MAX_REQUEST_ARG` — derived
  from `MAX_PLAINTEXT` through `nip44::calc_padded_len_const` (the lockstep
  of the const mirror with the runtime form is pinned by
  `nip44::tests::calc_padded_len_const_matches_runtime`), not restated in
  the firmware crate.
