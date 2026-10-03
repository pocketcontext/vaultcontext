# Implementation brief

VaultContext stores arbitrary files as encrypted, immutable versions. A CLI and portable skill serve humans and coding agents. Clipperz is architectural inspiration only; no source or legacy compatibility is included.

One deployment serves one Google Workspace. Default `users` identities have no implicit cross-user access. Each user initializes a private encryption/signing identity; encrypted private bundles persist only on the server. Unlocking downloads and decrypts in memory. No recovery keys. Lost passphrases cannot be bypassed through Google sign-in. Application tokens and public-key pins may persist locally; private-key bundles may not.

Personal vaults and explicitly shared project vaults have one owner and optional editors/readers. New members receive retained history. Membership removal blocks server retrieval immediately and requires rotation before subsequent writes. Old plaintext and downloaded keys cannot be recalled. Underlying credentials in files require independent provider rotation.

Files are opaque binary input, initially limited to 8 MiB each. Encrypted chunks live in protected file storage; filtered SQL exports metadata only. Complete backups include a consistent database snapshot and every referenced ciphertext file. Metadata names and labels are encrypted. Counts, membership, timing and ciphertext sizes remain server-visible. No automatic execution, synchronization, external-user admission, browser UI or unattended permanent unlock.

Exports encrypt file content under an independently supplied archive passphrase, excluding identity private keys. This is a portable data backup, not an identity recovery mechanism. Deployment backups remain private and include encrypted identity bundles as server state.

## Local implementation choices

- Repository: `vaultcontext`; environment prefix: `VAULTCONTEXT`.
- Proposed production origin: `https://vault.pocketcontext.com` (not provisioned).
- Proposed image: `ghcr.io/pocketcontext/vaultcontext` (not published).
- Dedicated Google Web client, private R2 bucket `vaultcontext-backup`, replica prefix `once-pocketcontext/vaultcontext` required before deployment.
- Donors: RaiseContext `40a1fdb69478758e92470a12216358763ea4077a`, AccountContext `b9b81840597c4299263a27bd79f8bde2dbf2e270`.
- Initial server pin: `a92b0de5e1b66b6d3b6135b90092d2d6da5f7cc8`, matching existing active-app infrastructure; validate intentionally.
- User authorization: local implementation and subagent collaboration; no cloud provisioning or production deployment.
- Real records/credentials: none. All automated fixtures synthetic.

## Release requirements

Validate binary fidelity, malformed crypto inputs, cross-user SQL/REST/realtime isolation, invitations and role limits, fingerprints, revocation/rotation atomicity, stale writes, client session expiry and lock, no local private-key artifacts, safe paths/permissions, independent archive decryption, populated database restore, deployment startup/failure behavior and copied-skill portability. Report unperformed browser, provider, container and independent security review honestly.
