# Local validation

Validated on 2026-10-03 using synthetic users/files and temporary isolated databases on Linux ARM64. No production application, provider resource, real credential or user file was used.

Server pin: `a92b0de5e1b66b6d3b6135b90092d2d6da5f7cc8`, built in a separate checkout with Go 1.27.1 and CGO. Its `make build` and race-enabled `make test` passed. Generic PocketContext source was not modified. Client dependency: PyNaCl 1.6.2.

## Passed application checks

- 39 unit tests covering contextual encryption/signatures, KDF limits, tampering, binary/empty files, safe atomic writes, archive validation, token/session handling, backup checksums and startup configuration.
- 12 OAuth client tests and 12 locked-deployment-wrapper tests.
- Backend integration: filtered SQL privacy, own-only private bundles, locked REST collections, reader/editor/owner authority, pending invitations, full-history access, concurrent stale saves, transactional audit rollback, revocation and frozen rotation, independent protected downloads and disabled accounts.
- Account lifecycle and synthetic Google OAuth provider integration: default `users`, verified Workspace admission, blocked direct signup, identity preservation, token expiry/refresh and disable/re-enable revocation.
- Real SSE test with a positive delivery control: ordinary domain realtime remains closed.
- Copied portable skill: full 8 MiB binary round trip, metadata search/history, sharing, reader rejection, revocation/rotation, old-epoch reads, independent encrypted archive restoration, passphrase changes, memory-session lock/expiry and no persisted identity bundle.
- Independent CLI forward test: copied skill, two ordinary accounts, actual terminal init/unlock prompts without passphrase echo, binary save/share/accept/restore and 0600 output.
- Size boundary: six 8 MiB versions exceed 64 MiB of protected ciphertext without exhausting SQL snapshots; historical/current data restore exactly; 8 MiB plus one byte is rejected before mutation.
- Live complete backup: consistent database snapshot and referenced ciphertext files restored into a separate server; same identity unlocks and decrypts exact original bytes; foreign access fails and missing originals fail verification.
- Deployment settings and invalid provider configuration tests.
- Skill metadata validator.

## Container checks

The local ARM64 image builds from the pinned server, Go/Debian digests and Litestream checksums. Container configuration and smoke tests passed, including missing configuration, unreachable replica refusal, restricted origins, paired provider settings, persistence across restart, no secrets in output and clean shutdown.

The complete object-storage restore drill is recorded below when finished. No image has been published.

## Scope and remaining verification

This is a local implementation with automated tests and targeted subagent review, not an independent security audit. No live Google browser sign-in, production R2/DNS/TLS, registry publication, production deployment or AMD64 image execution was performed. Deployment and provider configuration remain preparation only.

Initial limitations: Linux client, 8 MiB per file, 64 MiB plaintext export container including encoding overhead, explicit fingerprint verification, whole-vault retained-history sharing, no owner transfer, no identity-key reset, no document deletion, no recovery keys, no browser UI or automatic synchronization. Metadata snapshot row/byte budgets still bound very large record histories. The client does not provide comprehensive malicious-server rollback detection or isolation from its unlocked execution host.
