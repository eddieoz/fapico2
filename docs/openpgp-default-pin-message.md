# Why "Card error" is what GnuPG prints for the factory-PIN case

**Status: investigated, and the requested fix is not achievable.** Deferred
2026-10-04. This file is the analysis, so the question is not re-derived from
scratch next time.

## The symptom

A card that still has its factory PINs (PW1 `123456`, PW3 `12345678`) refuses
`gpg --card-generate` with:

    gpg: key generation failed: Card error

Same under Kleopatra, which drives the same agent.

## The card's half: it is already saying the right thing

Our applet refuses, at `vendor/opcard/src/command.rs:498-503`:

```rust
// US-912: key generation is refused while the factory-default PINs are
// still in force (after the CRT/template read above, which is public).
if context.state.persistent.factory_defaults_in_force() {
    warn!("GENKEY refused: factory-default PINs still in force");
    return Err(Status::ConditionsOfUseNotSatisfied);
}
```

`factory_defaults_in_force()` (`vendor/opcard/src/state.rs:1417`) is
`pw1_changed != Some(true) || pw3_changed != Some(true)` — it fails closed, so
an unparsed snapshot is treated as "defaults in force".

`Status::ConditionsOfUseNotSatisfied` is ISO 7816-4 **`0x6985`**. That is the
most semantically apt status word the card can return for "you have not
personalised this card", and it is already being returned.

## The client's half: it throws the status word away

GnuPG 2.4.4, `scd/iso7816.c`, maps status words to errors in `map_sw()`:

| SW | GnuPG error | `gpg_strerror` |
|---|---|---|
| `0x6985` `SW_USE_CONDITIONS` | `GPG_ERR_USE_CONDITIONS` | `Conditions of use not satisfied` |
| `0x63Cx` `SW_CHV_WRONG` | `GPG_ERR_BAD_PIN` | `Bad PIN` |
| `0x6982` | *not in the table* → default | `Card error` |

So `0x6985` **does** map to a distinct string — and then it is discarded,
in `scd/app-openpgp.c:5059-5067`:

```c
  err = iso7816_generate_keypair (app_get_slot (app), exmode, 0x80, 0, ...);
  if (err)
    {
      log_error (_("generating key failed\n"));
      return gpg_error (GPG_ERR_CARD);      /* <-- `err` is dropped here */
    }
```

`do_generate_keypair` did the right thing two frames up
(`iso7816.c:924` — `return map_sw (sw)`); the caller replaces the result with
`GPG_ERR_CARD`, which renders as `Card error`. Every status word collapses to
the same string.

**That is the root cause of the message.** It is in the client, not the card.

## Why no status-word change can fix it

Because the caller discards all of them. The card could return `0x6985`,
`0x6982`, `0x6A81` or anything else and the user would see `Card error`
identically.

Refusing *earlier*, at a step GnuPG does map, was considered and rejected:

* **VERIFY PW3 (`0x20 00 83`)** — refusing a *correct* PW3 is a wire lie
  (AGENTS.md §4), and it would break every client that legitimately verifies
  the admin PIN on a factory card.
* **PUT DATA (`0xDA 00 00`, the algorithm attribute)** — GnuPG maps this one,
  so the user would get `Conditions of use not satisfied`. Two reasons it is
  not worth doing: it still does not say "change the PINs", and GnuPG only
  sends it `if the requested algorithm differs from the card's`
  (`app-openpgp.c:5017`), so for the common case it would never fire. It would
  also refuse an operation the spec does not ask us to refuse.

**The most a status-word change can buy is `Card error` →
`Conditions of use not satisfied`.** That names neither the PIN nor the remedy,
so it does not meet the goal.

## What would actually help, and why it is not ours

GnuPG already carries a default-PIN hint, in `g10/card-util.c` — but it is
gated on the card having **no name** set:

```c
  /* If no displayed name has been set, we assume that this is a fresh
     card and print a hint about the default PINs.  */
  if (!info.disp_name || !*info.disp_name)
    { ... "You should change them using the command --change-pin" ... }
```

A card that has been personalised in any other way — including the
`gpg --card-edit` → name flow, which sets DO `0x65` without touching the PINs —
gets no hint at all, and then the generic `Card error`. **That is the exact
case reported here.**

Three routes, none of which is a firmware change:

1. **Patch GnuPG** to drop the `!info.disp_name` condition. A client change.
2. **Have the applet refuse earlier** with `0x6985` at PUT DATA, for the
   marginal `Conditions of use not satisfied`. Rejected above: unreliable
   coverage, no PIN in the message, and it refuses an operation the spec does
   not require refusing.
3. **Document it.** `gpg --edit-pin` is the remedy, and the user has to already
   know that. This is what the rest of the firmware can do, and it is what
   should be done instead of chasing the message.

## A side finding: is the gate even required?

The OpenPGP Card 3.4.1 specification (§4.3.1) states the factory PINs and then:

> **It is highly recommended that the cardholder changes these default values!**

A recommendation, not a requirement — and §7.2.14's status-word list for
key generation does not include a mandatory-refusal row. The sibling reference
`pico-openpgp` has `pw1_and_pw3_are_factory_default()` but uses it only to seed
an adminless-mode byte; it does **not** refuse key operations.

So US-912 is **stricter than both the spec and the reference**. That is a
defensible security choice for an authenticator, and this document does not
propose changing it — but it is a policy decision, and it is worth knowing that
nothing requires it.
