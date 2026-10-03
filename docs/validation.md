# Local validation

This records the initial local validation. Subsequent CI and production checks are
recorded in [deployment evidence](../DEPLOYMENT.md).

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

The populated object-storage restore drill passed: upload a complete database/ciphertext snapshot to an isolated pinned-source MinIO fixture, destroy the original volume, restore into an empty volume, authenticate as the retained ordinary user and decrypt exact original bytes. A later write survived the final shutdown backup. Removing a referenced ciphertext file caused startup refusal. Configuration, smoke and restore checks also passed on the final revision-labelled image. All drill containers, volumes and networks were removed.

- Implementation source: `c46121cf5ba1899ecd83d9cca4d2338606054e3f` (subsequent changes document verification and allow explicit reuse of the built test fixture).
- Local ARM64 image: `vaultcontext:check`, image ID `sha256:d6aefa61967019f2381d642fc882579af7784e4e25d89fed77edf5c7140a0f2c`.
- Image revision label: `c46121cf5ba1899ecd83d9cca4d2338606054e3f`; container application/configuration/backup source hashes match the committed runtime files.
- Pinned-source test fixture image: `sha256:3292c5909c24410511302bb815fe741787bab6d45a13bbd7a4b9baa573a744d8`.
- No image or VaultContext repository has been published.

Go 1.27.1 was downloaded with the upstream SHA-256 verified. Docker was installed locally to execute container gates. The local portable skill is linked at `.agents/skills/vaultcontext`; its dependency environment is `~/.local/share/vaultcontext-venv`. Shared instructions were committed/pushed separately in `workspace` (`14aca44`); the pre-existing `skills-lock.json` changes were preserved.

## Scope and remaining verification

This is a local implementation with automated tests and targeted subagent review, not an independent security audit. No live Google browser sign-in, production R2/DNS/TLS, registry publication, production deployment or AMD64 image execution was performed. Deployment and provider configuration remain preparation only.

Initial limitations: Linux client, 8 MiB per file, 64 MiB plaintext export container including encoding overhead, explicit fingerprint verification, whole-vault retained-history sharing, no owner transfer, no identity-key reset, no document deletion, no recovery keys, no browser UI or automatic synchronization. Metadata snapshot row/byte budgets still bound very large record histories. The client does not provide comprehensive malicious-server rollback detection or isolation from its unlocked execution host.

## Packaged client validation — 2026-10-03

The client moved into `vaultcontext_client`, with a packaged schema, console entry point and root `uv.lock`. Cryptographic implementation bytes are unchanged. The standalone skill launcher is released separately with an immutable client commit pin and no script lockfile.

Validated the wheel installed into a fresh environment from outside the repository, including its console entry point and bundled schema. All 39 unit tests passed on Python 3.11 and 3.14; all 12 OAuth client tests passed. Integration, realtime, limits, complete-backup integration, auth, OAuth integration, portable package, deployment settings and deployment workflow tests passed against a rebuilt server at `a92b0de5e1b66b6d3b6135b90092d2d6da5f7cc8` with Go 1.27.1 and CGO. The ARM64 container build, configuration, smoke and populated complete-restore checks passed. No production deployment was performed for this client change.

The single-file `vc` launcher pins client commit `d0c7d4923b563b4797997e0ba026761a78a47162`. A cold-cache run fetched and built that GitHub revision successfully without neighboring files or a script lockfile. Both copied-launcher skill and terminal CLI tests passed outside the repository, including schema access, synthetic login, no-echo passphrase prompts, save/share/restore, daemon survival, explicit locking and real session expiry. CI now runs both copied-launcher checks in addition to the current package tests.
