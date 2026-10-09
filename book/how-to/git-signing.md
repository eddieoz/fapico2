# Signing git commits with the OpenPGP card

A commit's author line is a claim; a signature is the evidence behind it. With the card, the signing key is generated on the chip and never leaves it — your workstation holds only the public half, so a compromised laptop can verify your history but cannot forge it.

## One-time: put a signing key on the card

Follow the [card setup](../using/index.md#the-openpgp-card) if you haven't: `gpg --card-status`, then `gpg --card-edit` and `generate` to create the three key slots on the chip. Note the signature key's fingerprint from `gpg --card-status`, then:

```bash
git config --global user.signingkey <signature-key-fingerprint>
git config --global commit.gpgsign true
```

## Sign

```bash
git commit              # every commit is signed from now on
git tag -s v1.0         # signed tags, same path
```

pinentry asks for the card's PIN, the LED waits for the touch, and the signature is produced inside the chip. Anyone can check it:

```bash
git log --show-signature
```

## Publish the public half

Keys born on the card cannot be exported — publish the *public* key so the world can verify you: `gpg --armor --export <fingerprint>`, then upload it wherever your collaborators and forges look (a keyserver, or your forge's account settings). The private half exists only on the board; that is the property, not a limitation to engineer around.

## Rotation and loss

Re-running `generate` on the card creates a fresh identity in the slots; old signatures verify against the old published key for as long as you keep it published. If the board dies, your signing identity dies with it — plan for that the same way you plan for a lost resident passkey: publish the new key, sign a statement that the identity moved.
