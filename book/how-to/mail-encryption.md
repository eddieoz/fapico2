# Encrypting to the recipient: mail and files

Instead of writing a note, screenshotting it and trusting a channel to keep it safe — encrypt it directly to the recipient's key. The message is unreadable to everyone but the holder of the other key: not the mail provider, not the channel, not a subpoena target. The card makes the private half of *your* key unusable anywhere but in your hand.

## Your card key becomes your identity

After [generating the keys on the card](../using/index.md#the-openpgp-card), publish the public half:

```bash
gpg --armor --export <fingerprint>
```

Give it to the people who will write to you — attach it, keyserver it, put it in your profile. Verification is the whole point: a public key fingerprint compared out-of-band is what makes "encrypt to the recipient" mean something.

## Encrypt a file or a message

```bash
gpg --encrypt --recipient friend@example.com note.txt     # -> note.txt.gpg
gpg --decrypt note.txt.gpg                                # card asks PIN, then touch
```

The decryption private operation runs on the chip; the laptop receives only the plaintext you asked for. Same command for backups, notes, anything at rest — an encrypted archive is worthless to whoever copies the disk, and that is the point.

## Mail clients

Any client that uses GnuPG inherits the card automatically. In current Thunderbird, external GnuPG keys are enabled in the Config Editor (`mail.openpgp.allow_external_gnupg_key = true`); associate the card key with the account and every encrypted mail is a PIN and a touch away. With `pcscd` in the picture, give scdaemon the [room it needs](../interop/index.md#the-quirks-worth-knowing) — the two readers otherwise fight over one device.

## The honest cost

The card's encryption key is generated there and is not exportable — if the board dies, mail encrypted to that key is gone with it. Keep your correspondents current when you rotate, and treat the board like the single copy of a key it is: [back up what can be backed up](./index.md), and plan recovery for what cannot.
