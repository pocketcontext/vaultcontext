# Demo implementation validation — 9 October 2026

This records local synthetic validation of the `vaultcontext-demo` worktree. It is not evidence of a public deployment or a completed provider migration. The source repository remains private. Public client artifacts are generated during the image build; generated wheels and bundles are not committed. Repeat builds with the tested tooling produced identical artifacts. The build backend is pinned, but its transitive build-tool dependencies are not fully locked; content-addressed paths prevent changed bytes from silently replacing a prior release.

Final local regression: 176 unit checks ran successfully (169 passed, 7 platform-specific skips). This includes the real pinned-server and Litestream cases enabled through their test environment variables. The 43 production entrypoint checks and 10 deployment-workflow checks also passed, as did demo backend, signed identity, deployment/object-storage settings, browser onboarding, and the two public-launcher integration suites.

## Recovery and isolation

- Exact pinned PocketContext server revision `976ddf71a4734530adefe4a56633658a0894b449`, built with CGO and the declared SQLite tags.
- Exact image-pinned Litestream 0.5.17 Linux ARM64 binary, verified against the Dockerfile SHA-256 before execution.
- Actual Litestream file-replica round trips for populated main and auxiliary databases; original local files removed before entrypoint recovery.
- Actual paired handoff uses a forced snapshot, independently restores both databases, compares logical digests, and adopts them into another isolated directory. The original UTC generation is preserved.
- Actual contact-service enrollment, security event, withdrawal, write draining, final synchronization, replica restoration and handoff digest checks. Unverified disaster recovery disables restored marketing permissions.
- Synthetic reset tests use isolated databases, mocked provider operations and a real pinned-server local lifecycle. Contacts survive the full disposable runtime purge.
- Docker lifecycle, credential separation, source/target fencing and failure handling have command/metadata tests. These are not a substitute for running the containers.

## Client and application

- Public wheel and standalone launcher served from an isolated loopback HTTP origin. Artifact sizes and SHA-256 hashes checked before installation. `uv tool install` and copied launcher execution use no private GitHub dependency; GitHub credential environment variables were excluded from the installation check.
- Full portable client and copied CLI exercises pass against the downloaded public-wheel launcher: exact original bytes, immutable versions, comparison privacy, protected-file authorization, revocation, literal paths, archive handling, request limits and independent memory-session operation.
- Demo backend validation covers verified synthetic Google admission, required terms, optional separate purpose preferences, private directory/metadata reads, quotas, disabled alternative authentication and daily-generation expiry.
- Signed identity replacement rejects token-only, wrong-signature, tampered and stale requests, while preserving the encrypted bundle and actor-private audit behavior.
- Existing deployment settings, object-storage configuration and production entrypoint checks run alongside the demo checks. Browser tests cover desktop/mobile preview, onboarding, consent conflicts, expiry and unsubscribe behavior.

## Remaining release checks

A Docker daemon is unavailable on this local host. Image configuration, smoke and provider-backed populated restore/migration checks must pass in container CI and a dedicated staging environment. CI invokes the real replication tests using the Litestream binary extracted from the built image.

Before public enrollment, finalize legal identity/contact details, confirm the disclosed backup-expiry policy with actual provider cleanup behavior, configure the separate Google OAuth client, validate live personal/Workspace login, provision the isolated storage and stable HTTPS origin, and exercise the complete daily reset and host cutover. Verify source-host timers/deployment controllers remain fenced and old disposable local copies are removed before midnight. No production deployment, provider resource creation, external commercial message or newsletter subscription was performed by these local checks.
