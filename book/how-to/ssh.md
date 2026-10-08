# SSH keys on fapico2

OpenSSH supports FIDO2 (`sk`) keys: the private key is generated on the device and never leaves it — the server holds only the public half, and every connection needs the PIN and a touch. A stolen laptop with the key-handle file opens nothing.

## What you need

- A fapico2 board, flashed and working, with a **FIDO2 PIN set** (see [Getting Started](../getting-started/index.md)).
- OpenSSH 8.2 or newer on your machine (`ssh-keygen -t ...sk` support).

## Create the key

```bash
ssh-keygen -t ecdsa-sk -O verify-required -C "Fapico2-SSH" -O resident -O application=ssh:swarm
```

Touch the device when it blinks and enter your PIN. Two files land in your working directory:

- `fapico2_sk` — the key handle. This is *not* the secret; it is a pointer the device resolves. Keep it anywhere.
- `fapico2_sk.pub` — the public key. This is what the server gets.

What the flags do:

- `-O verify-required` — every use asks for the PIN and a touch. Without it, a stolen handle plus a touch is enough.
- `-O resident` — the credential is stored on the device, so any machine can re-download the handle with `ssh-keygen -K`. Losing the handle file costs nothing.
- `-O application=ssh:swarm` — namespaces the key away from the default `ssh:` application, so this credential enumerates separately from any other `sk` key on the device.

## Authorize it on the server

Add the public key to the destination's `authorized_keys`:

```bash
cat fapico2_sk.pub | ssh user@192.168.0.130 'cat >> ~/.ssh/authorized_keys'
```

or by hand — same content, one line.

## Connect

```bash
ssh -i ./fapico2_sk 192.168.0.130
```

The device blinks — touch it, enter your PIN, and you are in. No key file on the client machine is ever sufficient alone.

## Recover on a new machine

The credential is resident. On a fresh machine with the device plugged in:

```bash
ssh-keygen -K
```

writes every resident `sk` key back into the current directory. Your accounts travel with the device, not with the laptop.

## Troubleshooting

- **`invalid format` on a sign or connect attempt** — the device is waiting for a touch; OpenSSH maps the keepalive cancel to that same string. Touch the device.
- **`invalid format` on `ssh-keygen -K` with an empty board** — a wiped board answers `NO_CREDENTIALS`, which older libfido2 (1.14.x, Ubuntu's) treats as a hard failure. Register a credential first, or use a newer libfido2.
- **`Operation timed out`** — another client (Yubico Authenticator, a browser) may be holding the device. Close it and retry.
