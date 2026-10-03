# Schema and protocol

Metadata reads use authenticated `/api/context/schema` and `/api/context/query`; ciphertext blobs use the independently authorized protected-file download API. Requester-filtered snapshots control every row. Standard auth collections and system tables are not queryable. All domain writes use `POST /api/collections/vault_actions/records` with `{op,payload}` and return `{result}`; action payloads are not persisted. Direct collection mutation is blocked.

- `user_directory`: registered user IDs, display names, emails.
- `identities`: registered public encryption/signing keys and fingerprints.
- `identity_secrets`: only the requester's encrypted private-key bundle and revision.
- `vaults`, `memberships`: accessible vaults, roles, current encryption epoch, revision and frozen state.
- `key_envelopes`: only the requester's encrypted vault keys; pending invitees can obtain their invitation envelopes.
- `documents`, `versions`, `version_chunks`: current document pointers, reversible `archived` state and its `archive_revision` concurrency marker, immutable signed manifests and protected encrypted file chunks. Chunk SQL records expose filenames and hashes, not ciphertext bytes. Names and sizes are inside encrypted metadata.
- `invitations`: explicit owner invitations, recipient acceptance and status.
- `audit_log`: accessible metadata-only action history; never plaintext file contents.

Ciphertext/signatures are versioned crypto-helper formats. Envelope signatures bind sender, recipient, vault and epoch. Version signatures bind author, vault/document/version IDs, epoch, revision, encrypted metadata and ciphertext hash. The client reconstructs identity context and verifies fingerprints before decrypting. This detects tampering/substitution, not all malicious server rollback; a compromised server can deny access or replay previously valid state.

Files are encrypted as a complete authenticated message, split into protected file chunks for transport, then published transactionally. Ciphertext file downloads require a short-lived user file token. The 8 MiB raw file limit corresponds to a server limit of 12,000,000 encoded ciphertext characters. Encrypted size and operational metadata remain observable to the server.

`archive`/`unarchive` actions require owner/editor membership, an unfrozen vault, and matching `expected_revision` and `expected_archive_revision`. Only an actual state change increments the archive marker and creates an audit event. Content revisions and signed manifests remain unchanged. Saves reject archived documents and stale archive markers. Archived files retain independent read/download permissions and are included in exports and backups.
