# Matching client and backend releases

VaultContext supports exactly one client release per backend release. The canonical
`pb_hooks/release.json` contains `release_id` and the public installation URL. The
Python package carries the same file. Use a new release ID for each feature or
application-contract release; do not derive it from Git HEAD, because publishing
package code and updating the launcher require separate commits. Documentation-only
and launcher-pin commits for the same release retain its ID.

Ordinary API requests carry `X-VaultContext-Release`. Missing or different IDs receive
HTTP 403 with `data.code = client_upgrade_required`. This is a compatibility gate,
not authentication or proof of installed software: every request still needs its
normal permissions, and identity replacement always requires a valid signature.
There are no ranges, feature flags or legacy API handlers.

`GET /api/vaultcontext/compatibility` is public and uncached. It reports the required
release and installation URL without account data. Health, public pages, operator
APIs and the OAuth callback remain available. Anonymous realtime setup and the exact
OAuth subscription remain available for browser sign-in; data subscriptions require
a matching client and normal authorization.

The client checks compatibility before online commands and before each unlocked
worker operation. Its API and protected-download requests carry the release ID, so
a backend change between discovery and a request fails closed. Upgrade errors do
not retry writes or trigger authentication fallback. Local lock/logout and offline
archive restoration remain available. Older clients may show generic errors because
they cannot interpret the new response. Previously downloaded files or keys cannot
be revoked by a release gate.

## User upgrade

Read the installation instructions at the configured server's public page. Run the
old client's `vaultcontext lock` for each configured account before replacing it.
Install the matching pinned launcher or package, then run `vaultcontext unlock`
privately. Do not initialize a new identity. No automatic package installation or
unlocking occurs. An existing worker runs its original code until stopped; updating
a launcher alone does not update that worker. Keep ordinary session reuse guidance
outside explicit upgrades.

## Release procedure

1. Assign the release ID in `pb_hooks/release.json`. Keep existing persisted data
   readable or supply tested migrations; client equality does not migrate data.
2. Run source validation, including `tests/release_gate.py`,
   `tests/identity_rewrap.py`, the full README suite and container recovery gates.
3. Publish the tested package implementation first, without deploying its backend.
   Use the repository's established `[skip ci]` staging convention for this package
   commit, or explicitly pause deployment before publishing. A package-only push
   must not activate backend enforcement with the previous launcher.
4. Pin `skills/vaultcontext/vaultcontext` to that full published package commit.
   Run both copied-launcher checks from the README against the new backend. These
   checks must pass with the remote package before the final release is published.
5. Publish the launcher/release commit through the normal image validation gates,
   then deploy its backend through the maintained dispatcher. Old clients stop
   online operations until users upgrade. There is no coordinated fleet update.
6. Verify the public compatibility response and matching client operation after
   deployment. Rollback requires the backend's matching client; never enable an
   unsigned identity-replacement fallback or weaken the release gate.

Each backend release has one installation target. Mirror base images and verify
availability before updating Dockerfile consumers, as described in
[CI and deployment](ci-and-deployment.md). Keep image and client pins separate from
the shared release ID. A forged release ID never substitutes for authorization.

## Backport provenance

Selected changes came from the separate VaultContext demo repository:

- `eadfcf601d522690cee1d68b616294ce27c390de`: signed replacement requests and
  fingerprint directory/file ownership, permissions and integrity checks.
- `1164339cdb233106225c7e8e3e374a649e362d32`: server signature verification,
  vendored verifier, identity-replacement auditing and synthetic regression tests.
- `8b8b1771eb31219702b0534646b14715362fb15d`: identity initialization preflight and
  duplicate-initialization guidance.
- `8b59e84`, `02be786`, `a4c4329`, `f9f1455`: digest-preserving base mirrors.
- `b4a656d`: explicit malformed image-digest rejection.

Demo enrollment, consent, resets, retained contacts, browser authentication,
restricted sharing and deployment ownership were excluded. Google-only CLI login
was deferred; password and Google authentication retain their existing semantics.
Core and demo keep their own release IDs, package pins and validation.
