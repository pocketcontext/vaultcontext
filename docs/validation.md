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

## CLI help release — 2026-10-03

Client `b7845ac443f64a1e9b513a04e90545cc7fe3b06d` adds grouped help, first-use
configuration, command examples, argument meanings and prerequisites. Launcher
`30b4ded` pins that published client. No command or server behavior changed.

Independent review checked all 26 commands, 52 old/new argument parsing cases,
all 27 help screens without configuration, and every subcommand example. All
README validation commands passed against the clean pinned server using isolated
synthetic records. The final parser passed the 39-unit suite, packaged skill and
terminal CLI forward checks. Both copied-launcher release checks passed against
the published client. The local PATH launcher was replaced and its help verified.

## Cat release — 2026-10-03

Client `81559e944ceb01896ca0fe76e311c33bcb5ff296` adds
`vc cat DOCUMENT_ID [--version VERSION_ID]` with fully verified exact-byte stdout.
Launcher release `91ac202` pins this client. No server or schema changes were
needed. Existing unlocked sessions must be restarted with `vc lock` and
`vc unlock` after the client upgrade.

All README checks passed locally against the clean pinned server, using isolated
synthetic records: 39 unit tests, integration, realtime, file limits, populated
backup recovery, authentication/OAuth, portable skill, terminal CLI forward,
deployment settings and deployment wrapper checks. Independent review found no
blocking issues. Both copied-launcher release suites passed, explicitly including
cat coverage.

New checks cover 8 MiB binary and empty files, current/historical versions, exact
output without an added newline, locked/unauthorized/revoked/unverified reads,
version/document mismatch and corrupted final ciphertext with zero stdout. Small
and large closed stdout pipes produce no traceback; disconnected and stalled
socket readers do not terminate the memory session.

Initial copied-launcher CI exposed a test false positive: uv's public source
cache contains the schema field name `key_bundle`. The corrected test checks all
cached JSON for actual synthetic private keys, and every regular application
cache file for private keys or persisted key bundles. Both copied-launcher
suites passed again after this correction. The local PATH launcher and installed
skill documentation were updated; no active user session was locked.

## Path labels and document archive release — 2026-10-03

Client/application `7619d0c8e69a2cec5b414063bc63388d5f551f70` preserves the literal source argument as the
default encrypted file name and adds reversible document archive state. Launcher
`6a9fa4b` pins that package. Existing names and signed content versions remain
unchanged. Archive transitions use their own concurrency marker; stale saves
conflict even after an archive/unarchive cycle. Encrypted export v2 includes
archive status; the client still reads strict v1 exports.

All README validation passed locally against the clean pinned server using
isolated synthetic fixtures: 41 unit tests, integration, populated schema
migration, realtime, limits, populated complete backup recovery, auth/OAuth,
portable skill, terminal CLI forward, deployment settings and wrapper checks.
Both copied-launcher release suites passed against the published package,
including explicit path-label/archive CLI assertions. Independent review found
no blocking issues.

Tests cover absolute/relative path arguments, explicit name overrides and version
updates; owner/editor actions, reader/outsider denial, idempotent no-op auditing,
stale/concurrent saves, frozen vaults, audit rollback and unchanged historical
reads. Default/archived/all filtering retains pagination; archived documents
remain accessible by ID and to newly accepted members. Saves fail while archived.
Populated recovery retains archive state, audit events, versions and exact bytes.

The local ARM64 image build, container configuration, smoke and populated restore
drill passed. The container drill now archives its encrypted multi-chunk fixture
and verifies archive state and audit recovery alongside exact-byte decryption
after both disaster restoration and graceful-shutdown replication.

## Management-only agent skill — 2026-10-03

Skill instructions, workflows and README now prohibit agent inspection of vault
file contents, including indirect reading, redaction and source/restored files.
Metadata operations and opaque file management remain available. The CLI retains
user-operated private viewing; this policy is not cryptographic isolation.

Skill metadata validation, diff checks, all 41 unit tests and every README
application validation command passed against the rebuilt pinned server using
isolated synthetic fixtures. Both copied-launcher release suites passed with
client pin `5e2562624d9302d77eb2d9a01b8c7cf462fefb19`. Release `33b9324` passed
application CI and container configuration, smoke and populated restore gates
before image publication and verified production deployment. See
[release evidence](../DEPLOYMENT.md#management-only-agent-skill-release).


## Confidential-dotfile onboarding release — 2026-10-03

All 41 unit tests and all twelve README application validation scripts passed
against isolated fixtures using pinned server `a92b0de`. Copied standalone skill
and terminal/session tests passed with the launcher pinned to `8f09fd8`. Final
ARM64 container build, configuration, smoke and populated complete restore checks
passed. Release `ceba562` passed both GitHub workflows, including AMD64/ARM64
publication; links and the exact deployed manifest are in `DEPLOYMENT.md`.

Static routing checks verified exact assets, CSP, nosniff, no-referrer, source-file
denial, missing-path 404s and unaffected API health. Local and live Chromium checks
covered desktop, 390/320-pixel layouts, keyboard navigation, installation method
switching, clipboard success/fallback and native disclosures without JavaScript.
Public asset verification accounted only for Cloudflare's Rocket Loader HTML
transformation; all three origin asset hashes matched the checked-in source.
The production schema endpoint continued to reject anonymous requests.

## Bare-command help release — 2026-10-03

Bare `vc` prints the same full help as `vc --help` and exits 0 before loading
configuration. Invalid commands and incomplete `save` still exit 2. Checked both
the development entry point and an isolated copied launcher installed from the
pushed implementation commit `cd7020f72c7240845b2716405eb9e10d15c238f9`.

All 41 unit tests, 12 OAuth tests, 12 deployment-workflow tests and the README's
pinned-server integration, archive migration, realtime, size-limit, populated
backup recovery, auth, OAuth integration, skill, CLI-forward and deployment
checks passed locally using synthetic fixtures and isolated temporary databases.
Both remotely installed copied-launcher release checks (`skill.py` and\n`cli_forward.py`) also passed before the launcher release commit.
## macOS memory-session compatibility (2026-10-03)

The source client now checks Unix socket peers with Darwin `getpeereid` on macOS
and retains Linux `SO_PEERCRED`. Credential lookup errors and foreign UIDs reject
the connection without ending the session. Unsupported platforms fail before
prompting for an unlock passphrase.

All README validation commands passed on macOS against rebuilt pinned server
`a92b0de5e1b66b6d3b6135b90092d2d6da5f7cc8`, using isolated synthetic fixtures and
`TMPDIR=/private/tmp`: 46 unit tests, integration, archive migration, realtime,
size limits, populated backup recovery, auth, OAuth integration/client, portable
package, terminal CLI forward exercise, deployment and deployment workflow.
New regression tests cover native peer credentials, Linux decoding, Darwin
lookup failure, unsupported platforms and session survival after rejected peers.

The launcher now pins `e51d92bee5c257acd43fdc7ddd5cd6b0f8fb9ce7`. Both copied
remote-launcher checks passed locally on macOS. CI runs source-package and copied
launcher validation on Linux and macOS, with uv installed in an isolated bootstrap
venv to accommodate the macOS runner's managed Python installation.
Container checks were not run locally: the configured Docker SSH host could not
resolve. No package was published and no deployment changed.

## Optional macOS Keychain source implementation (2026-10-03)

All 67 unit tests passed on macOS with `TMPDIR=/private/tmp`, including 14 new
bridge/lifecycle checks and seven native helper rejection checks. The native
tests compile Swift with warnings treated as errors for macOS 12 and never call
Keychain with a valid request. Bridge checks cover private-pipe transport,
sanitized errors, origin scoping, platform and installation rejection, enrollment
verification, cancellation/stale credentials, explicit opt-in and session behavior.
An initial run with macOS's default symlinked temporary path failed four existing
file-safety fixtures; the non-symlink temporary directory resolved those failures.

All twelve README application validation scripts passed against rebuilt pinned
server `a92b0de5e1b66b6d3b6135b90092d2d6da5f7cc8` using isolated synthetic data.
Portable source-package and terminal/session suites were rerun after client
integration and passed. The native build script passed Python syntax validation.

No real Keychain item, production vault or signing credential was accessed.
Actual profile-authorized signing, installation, enrollment, Touch ID/device
credential fallback, ACL updates and signed upgrade behavior remain unverified;
follow the on-device checklist in [macOS setup](macos-keychain.md). Container
checks were not run for this client-only change. No commit, launcher pin update,
package publication or deployment was performed.

The subsequent client release pins the portable launcher to implementation
`58e94a3381f4fc8c25a5ed236142f8490ea5867f`. Both copied remote-launcher checks
(`skill.py` and `cli_forward.py`) passed on macOS against the pinned server before
publishing the launcher update. These changes do not enter the server image;
production deployment is unnecessary. The native helper still requires separate
Apple signing/provisioning and on-device verification.

## macOS and Keychain onboarding page (2026-10-03)

The public manual now covers Linux and macOS, optional separately signed Keychain
setup, and retained enrollment after lock/logout. Its sample resolves the
temporary directory to a physical path before saving, avoiding macOS's `/var`
symlink. A synthetic sample read and exact-byte restore passed.

Local Chromium checks passed for desktop, 390- and 320-pixel layouts, keyboard
disclosures, installation switches, and the new copy buttons. Command text keeps
literal `&&` after HTML decoding; narrow layouts have no page overflow. The
clipboard-denial fallback selected commands and announced manual copying in an
isolated JavaScript check. Pinned-server checks with an isolated database verified
exact public assets, CSP/security headers, private-source 404s and anonymous API
rejection. The page does not install or authenticate the native helper.
