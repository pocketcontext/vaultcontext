# VaultContext API contract

Ordinary identities are PocketBase `users`. Read through authenticated
`POST /api/context/query` with `{ "sql": "..." }`. Results contain `columns`
and positional `rows`; every table uses requester-filtered snapshots. The
allowlisted columns are in `pocketcontext.json`. Direct ordinary REST record reads,
updates and deletes on internal domain collections are closed. Ciphertext bytes
are the exception to SQL reads: `version_chunks.ciphertext` is a protected file
name, with server-computed `sha256`. Obtain a short-lived token from authenticated
`POST /api/files/token`, then download `/api/files/version_chunks/{id}/{ciphertext}?token=...`.
Each download rechecks active membership and account status. Decode the downloaded
UTF-8 bytes to obtain the original encrypted chunk string. Database and storage
files must be backed up and restored together. Batch is disabled.

Writes use `POST /api/collections/vault_actions/records` with
`{"op":"operation","payload":{...}}`. Success is HTTP 200 with `{"result":{...}}`.
The action payload is never saved. Each action, including audit events, runs in
one transaction. IDs supplied by clients contain exactly 15 lowercase ASCII
letters/digits. Encrypted structures are JSON serialized into opaque strings.

| Operation | Payload |
| --- | --- |
| `identity_init` | `public_key`, `signing_key`, `fingerprint`, `key_bundle` |
| `identity_rewrap` | `key_bundle`, `expected_revision` |
| `vault_create` | `id`, encrypted `metadata`, own `envelope` |
| `save` | `vault`, `document`, `version`, `expected_revision`, `epoch`, encrypted `metadata`, `manifest`, `signature`, `chunks` |
| `share` | `vault`, `account`, `role` (`reader` or `editor`), `expected_revision`, `envelopes:[{epoch,envelope}]` |
| `accept` | `invitation` |
| `revoke` | `vault`, `account`, `expected_revision` |
| `rotate` | `vault`, `expected_revision`, new `epoch`, `envelopes:[{account,envelope}]` |

Identity initialization is one-time. Public keys are immutable; rewrap replaces
only the user's encrypted bundle and increments its revision. There is no recovery
or identity-reset operation. Key bundles are visible only to their owner.

Vault creation begins at epoch/revision 1. Its name metadata remains encrypted
under epoch 1. `save` compares the document revision (0 for a new document), checks
the current vault epoch, and creates an immutable version and chunks. Result has
`id`, `version`, `revision`. A reader cannot save. Chunk strings are at most 262144
characters; at most 64 chunks and 12000000 encoded characters per save. The client
limits plaintext to 8 MiB. Empty files still have nonempty authenticated ciphertext.

Sharing is owner-only and supplies exactly one envelope for every epoch. A pending
recipient can inspect the invitation and their own envelopes, but cannot read vault
contents until acceptance. Accept increments the vault revision and activates the
membership. All retained history becomes readable. Share returns the invitation
`id` and new vault `revision`; accept returns vault `id` and `revision`.

Revoke is owner-only, removes recipient envelopes and active membership, cancels
all pending invitations, increments the revision and freezes writes. Canceled
invitees cannot read retained envelopes. Rotate requires exactly the remaining
active members and epoch+1; it atomically publishes their envelopes and unfreezes
writes. Frozen vaults remain readable to active members. The single owner cannot
be revoked. Role edits, ownership transfer and document/vault deletion are not
implemented; changing a role requires revoke, rotate and a fresh invitation.

Revision conflicts return HTTP 409. Clients must reread and reassess; do not blindly
retry. On uncertain network results inspect the supplied document/version/vault IDs
before another write. Membership state is enforced independently of client claims.
The server treats ciphertext as opaque; clients verify fingerprints, envelope
signatures and file manifests. Server metadata audits contain IDs and action names.
