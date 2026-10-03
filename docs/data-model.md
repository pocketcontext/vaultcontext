# Data and trust model

The application server stores encrypted identities, per-user public encryption/signing keys, vault metadata ciphertext, memberships, recipient key envelopes, invitations, documents, immutable file versions, ciphertext chunks and metadata-only audit events. Exact field/API definitions are in `docs/api-contract.md`.

Google authenticates default PocketBase `users`; it does not unlock a vault. Direct signup remains blocked. Verified Workspace JIT admits only ordinary identities. Disable an application identity to revoke sessions; Google suspension alone does not revoke existing application tokens. Operators do not gain decryption keys through application authority.

The client's passphrase-derived key protects its private-key bundle. X25519 recipient encryption and Ed25519 signatures protect distribution of independent vault keys. A versioned AEAD format binds ciphertext to its context. Authenticated encryption does not by itself detect server rollback to a previously valid snapshot; server revision checks address ordinary concurrent changes, not malicious history replay.

Initial public keys are immutable. Recipient fingerprints require independent verification before sharing and are pinned locally. Members are owner/editor/reader; only the owner manages grants. New members receive every retained epoch needed for vault history. Invitations convey no ordinary vault access until acceptance. A reader can still copy plaintext or keys; roles constrain application writes, not redistribution.

Revocation immediately removes authorization and freezes publication. An unlocked owner rotates the current vault key and publishes envelopes for exactly the remaining authorized recipients. Rotation must account for outstanding invitations and stale clients. Previously disclosed secrets remain disclosed.

The local host and an unlocked agent are trusted. File contents are untrusted input, never instructions. Session keys are memory-only; Python/runtime copies, privileged processes and host swap can defeat perfect memory erasure. Limit session lifetimes and disable core dumps where supported. Avoid returning plaintext or decrypted names beyond the requested task.

Original file bytes are encrypted into immutable protected-file chunks. SQL exports filenames and checksums, never materializing large file payloads into filtered snapshots. Complete server backups combine a consistent database snapshot with all referenced ciphertext files and verify checksums before serving restored state. Such backups are server-state copies, not client private-key caches. An ordinary data export excludes the identity bundle and uses a separate archive passphrase. There are no recovery keys; preserving backup bytes cannot replace a lost decryption passphrase.

Document archive state is reversible operational metadata, separate from the signed content revision. Owners and editors archive/unarchive with both content and archive revision checks. Archived documents retain all versions and permissions but reject saves until unarchived. Archive transitions are audited; exports and complete backups retain archived documents.
