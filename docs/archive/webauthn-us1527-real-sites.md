# US-1527 — real-site passkey registration (human-run evidence)

**Board:** ours, `EddieOz` / `Fapico2`, serial `94746395`, running the epic build
(`capFlags 0x05`, `makeCredUvNotRqd False`). Firmware version 5.4.0.
**Human operator, real browser, real login.** No credentials were ever handled by
an agent; the agent neither used nor requested any.

## 1 — https://www.token2.com/tools/fido2-demo — **PASS**

> Register → PIN prompt → PIN `123123` → "touch the security key" → button
> pressed → **authenticated**

## 2 — https://webauthn.io/ — **PASS**

> Register → PIN prompt → PIN `123123` → "touch the security key" → button
> pressed → **authenticated**

## 3 — https://x.com/settings/account/login_verification/security_keys — **FAIL**

> Add Another Key → security code validated by email → "unlocked, get started"
> window → **Add security key** → a popup opens showing a **QR code** (not the
> PIN prompt) → the board starts flashing, armed, waiting for a touch → button
> pressed → **nothing happens; the QR-code window stays**.

And the operator's own observation, which is the most diagnostic line in this
whole epic:

> "During our tests, x.com was asking the PIN, but now it stays with the qr-code
> instead of asking the pin, and the board is flashing fast asking for a touch."

## What the failure is

**The QR code is a transport choice, not a device failure.** A QR code in a
passkey prompt is the signature of **hybrid / cross-device** transport: X is
offering to complete the ceremony on a phone, scanning the code, with the desktop
browser acting as the authenticator. In that path **the desktop browser is not
driving the USB key at all**, so a desktop security key is not what the ceremony
is waiting for.

The board flashing is a **separate, stale thing**: a consent window left open by
the *previous* attempt, which X had already abandoned. The operator described the
sequence exactly — the first attempt **did** ask for the PIN (the direct USB
path), and a later attempt presented the QR code instead.

## Device state after the failure — it is NOT wedged

Measured immediately after the operator reported the failure:

```
GetInfo  answered in 166.1 ms
ping     16.1 ms / 15.9 ms / 16.0 ms
```

The board is fully responsive. The stale consent window drained on its own
**inside its 30 s bound** — which is the US-1509/US-1510 slot behaving exactly
as designed (single-occupancy, deadline-bounded, refuse-don't-queue). This is
the opposite of the pre-fix behaviour, where the same condition held the serve
loop blind for 30 s and could wedge it permanently.

## What this closes and what it does not

**Closes:** the epic's reported symptom is **reproduced on a real site**, and it
is **not** a discovery failure, **not** a transport failure, **not** a PIN
failure, and **not** a blackout. The device is offered, enumerated, reachable and
responsive. Two of three real sites register a passkey correctly with PIN +
touch.

**Does not close:** DoD item 1. We know the failure is real and where it
happens (X's Add-security-key step presents hybrid instead of the direct USB
path), but **why X chooses hybrid on a retry and not on a first attempt** is a
site-side and browser-side behaviour this repo cannot observe. The plausible
mechanism — an abandoned window from a previous attempt causing the retry to
fall to hybrid — is a **hypothesis, not a finding**, and is stated as one below.

## Hypothesis to be tested by the next run (operator)

The QR path appeared **only after** an earlier attempt had been abandoned
mid-flight. If the stale window is the trigger, then:

- **wait ≥ 35 s after any abandoned attempt, before retrying**, and
- **start from a cold boot**, and

X should again ask for the **PIN** (the direct USB path) rather than presenting a
QR code. If it still presents the QR code, the stale window is exonerated and the
cause is X's own retry/transport selection.

Either outcome is a real result. Record which.