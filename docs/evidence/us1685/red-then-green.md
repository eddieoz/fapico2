# US-1685 — red, then green: `a_truncated_extended_lc_form_is_refused`

## The red (against the pre-fix tip, `feat/nostr` @ `5221fe9`)

`00 10 00 00 00 FF FF` — an extended-Lc APDU declaring 65,535 bytes of data
and carrying none — answered `0x9000` (36864) with `GET_INFO`'s success
shape: `parse_data` treated the truncation as an empty data field, so
`refuse_payload` passed and the command executed.

```
$ cargo test -p fapico2-nostr --target x86_64-unknown-linux-gnu --test wire a_truncated_extended

assertion `left != right` failed: a declared length the frame does not carry must not succeed
  left: 36864
 right: 36864
test result: FAILED. 0 passed; 1 failed
```

## The green

`parse_data` returns `Result<&[u8], Sw>`: a truncated extended form is
`SW_WRONG_LENGTH` (0x6A87-class vocabulary named at the site), a short-form
command with bytes past its `Lc` window is `SW_WRONG_DATA` (0x6A80), and the
empty and well-formed cases behave exactly as before — the change is
observable only to a malformed APDU.

```
$ cargo test -p fapico2-nostr --target x86_64-unknown-linux-gnu
keymgmt 18, wire 14, presence 5, nostr_shared 13, store suites 9+9 — 0 failed.
```

## The behavioural net (the emulator Python suites)

The suites drive `parse_data` through every command over the CCID harness
with well-formed frames — the proof that the strictness changed no
well-formed behaviour:

```
$ ./run_tests.sh --suites-only
311 passed, 6 skipped   (pico-fido core)
 13 passed, 17 xfailed
  4 passed, 1089 skipped
 62 passed, 5 skipped, 1 xfailed   (Nostr suites among them)
0 failures.
```
