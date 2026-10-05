# VaultContext

Encrypted personal and shared file vaults for humans and coding agents, built on PocketContext. Any file type is accepted as exact opaque bytes, initially up to 8 MiB per file. Names and descriptive metadata are encrypted too. A CLI and portable skill provide the file interface. A public single-page website provides product information and a guided onboarding manual; it does not authenticate, unlock vaults or access application data. Clipperz inspired the architecture; no Clipperz code or compatibility is included.

## Access and keys

Google Workspace login authenticates PocketBase's default `users` identity. It does not unlock encrypted data. Each account initializes an encryption/signing identity protected by a separate passphrase. The encrypted private-key bundle persists only on the server; unlocking downloads and decrypts it in process memory. Application tokens and verified public fingerprints may be cached locally, never the private-key bundle. There are no recovery keys. A lost passphrase without a usable unlocked session or enrolled macOS Keychain credential means lost access; Google account recovery cannot decrypt the vault. Optional macOS Keychain enrollment stores the passphrase locally, never the private-key bundle.

Personal vaults are private. Shared project vaults have one owner and explicit editor/reader members, initially within the configured Workspace. Verify recipient and writer public fingerprints through an independent trusted channel. New members receive retained history. Revoking a member blocks retrieval immediately and freezes writes until key rotation completes. Downloaded plaintext or keys cannot be recalled, and credentials contained in files may need separate provider rotation. Owners cannot remove themselves; owner transfer and identity-key replacement are not implemented.

The execution host and unlocked agent are trusted. The client retains keys in a same-OS-user Unix socket session, with a 15-minute default lifetime and explicit `lock`. Linux and macOS are supported client platforms. Python cannot promise perfect memory erasure or protect against a privileged host, swap or an agent already authorized to read local files. No stored content authorizes execution or sharing.

See [implementation brief](docs/implementation-brief.md), [data and trust model](docs/data-model.md), [API contract](docs/api-contract.md) and [deployment preparation](docs/deployment.md).

## Onboarding page

The hand-maintained static page lives in `pb_public/` and is served at `/` by the application-owned `pb_hooks/frontend.pb.js` hook. The container includes these assets. No frontend build is required. Optional production-only analytics are described below. Open Graph and Twitter large-image metadata reference the public `pb_public/og-card.png` (1730 × 909); its URL and the canonical page URL use the production origin. The built-in image generator created the card; its prompt is recorded in `docs/social-card-prompt.txt`.

For a page-only local preview, run `python3 -m http.server 8769 --bind 127.0.0.1 --directory pb_public`. Expose only this public directory when sharing a temporary preview.

Keep onboarding commands aligned with the portable client and `skills/vaultcontext/references/workflows.md`. After edits, check desktop/mobile layout, keyboard disclosures, installation method switching and clipboard success/failure. Validate routing and security headers with the pinned server in an isolated temporary database before release. The “Bring your files to another computer” guide demonstrates explicit prefix mapping, comparison reports, selected version-pinned restores and verification with synthetic examples. Company-specific onboarding stays in WikiContext.

## Public website analytics

Tracking runs only on the exact origin `https://vault.pocketcontext.com` and root
page `/`, after the visitor chooses **Allow analytics**. Localhost, forks,
previews, alternate ports and self-hosted deployments load no analytics services,
even with a remembered choice. **Analytics settings** in the footer lets visitors
withdraw; the browser stores only the choice until analytics is accepted.

The page reuses PocketContext's public GA4 measurement ID `G-1X0FZLTWGE` and
Rybbit site ID `d8b36ba4a63f`. These are public routing identifiers, not credentials.
Rybbit receives explicit `/api/track` requests, without loading its script or
session recorder. GA4 loads in an empty same-origin frame only after acceptance;
its automatic capture operates on a blank document instead of the guide. Ads storage,
ad personalization and Google signals are disabled. Google analytics cookies use
a VaultContext-specific prefix and host. Withdrawal removes the frame and those
cookies, and stops new application events; it cannot recall already sent events.

Explicit events are `page_view`, `onboarding_open`, `onboarding_method` and
`onboarding_copy`. The shared GA4 property can also emit automatic scroll or
engagement events for the empty frame; filter to the explicit event names when
measuring guide use. The frame isolates automatic capture, not untrusted scripts. Custom events contain only an allowlisted `target` such as
`compare_prompt` or `restore_commands`. Copy events mean a successful clipboard
write, not a completed CLI operation. Requests use a fixed root page URL/title
and omit query strings, fragments and referrers. No contents, local paths,
clipboard text, identities or vault operations enter analytics. Providers still
receive ordinary network metadata; browser blocking can reduce reported counts.

Filter both dashboards by **Hostname equals `vault.pocketcontext.com`**.
In Rybbit, use the site dashboard filter and save a segment where supported.
In GA4, create a Free form exploration, import Hostname, then apply the exact
hostname filter. These are reporting filters; the origin guard controls collection.
Existing marketing-site tracking settings are not changed by this integration.

Public JS/CSS references include a `v` query containing the first 12 characters
of that asset's SHA-256. Update the HTML reference whenever its asset changes;
the browser check verifies these versions. The container smoke gate verifies
all public assets, including both analytics-frame files, match source exactly.

Run the offline browser checks (all provider traffic is intercepted):

```sh
uv run --with playwright==1.60.0 python -m playwright install chromium
uv run --with playwright==1.60.0 python tests/website_analytics.py
# With an installed Chrome instead: PLAYWRIGHT_CHANNEL=chrome uv run --with playwright==1.60.0 python tests/website_analytics.py
```

## Local server

Build the exact commit in `POCKETCONTEXT_VERSION` with its `go.mod` toolchain, CGO and a C compiler. Keep it in a separate checkout if your existing server revision differs:

```sh
# In the pinned PocketContext checkout:
make build
# In this repository, with a disposable database for evaluation:
/absolute/path/to/pocketcontext serve --dir /absolute/private/test/pb_data --http 127.0.0.1:8090
```

The application directory supplies migrations, hooks and SQL configuration. No users or real records are seeded. Operators provision test identities through ordinary maintenance APIs; the CLI never uses superuser credentials.

Production Google settings use a separate Web OAuth client, paired `VAULTCONTEXT_GOOGLE_CLIENT_ID` / `VAULTCONTEXT_GOOGLE_CLIENT_SECRET`, and `VAULTCONTEXT_GOOGLE_WORKSPACE_DOMAIN`. Server-side verified claims enforce the exact Workspace domain. Direct public signup is blocked. Without a configured domain, Google login requires preprovisioned identities. Disable the application account to revoke its tokens; Google suspension alone does not invalidate existing app sessions.

## Portable client

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) and copy the executable launcher onto your PATH:

```sh
install -Dm755 skills/vaultcontext/vaultcontext ~/.local/bin/vaultcontext
export PATH="$HOME/.local/bin:$PATH"
export VAULTCONTEXT_URL=https://vault.example.com
export VAULTCONTEXT_USER_EMAIL=you@example.com
vaultcontext login --google
```

The launcher declares its Python requirements and pins the client package to a full Git commit. It can run from any directory without neighboring source files. The first run needs network access to download the package, Python if needed, and dependencies; later runs reuse uv's cache. Updating the copied launcher adopts its new client revision. Before replacing an installed client, run its `lock` command for each configured server/account with an unlocked session. After updating, have the user run `vaultcontext unlock` explicitly in their private terminal so the session uses the new client; installation never unlocks automatically. The skill has no script lockfile: transitive dependencies may resolve differently on fresh installations. The repository's `uv.lock` governs development and tests, not launcher execution.

To migrate from the old `vc` launcher, run `vc lock` before installing `vaultcontext`, then remove only the old VaultContext launcher you installed (for example, `~/.local/bin/vc`). The package and skill provide no `vc` alias or compatibility wrapper. Update scripts to call `vaultcontext`. Existing authentication configuration and macOS Keychain enrollment remain valid.

The memory session runs in a fresh Python process using the launcher's own interpreter and installed package environment. Unlock waits for worker readiness; verified keys cross only a private inherited socket, never arguments, environment variables or files. Lock sessions before clearing uv's cache. `unlock`, `lock` and `logout` recover an abandoned socket only after checking ownership, permissions and connection refusal; ambiguous or unsafe endpoints remain errors. Repeating `lock` on an already locked account succeeds.

Alternatively, install the package from a trusted checkout into an external Python 3.11+ virtual environment. This provides the same `vaultcontext` command without requiring uv at runtime:

```sh
python3 -m venv ~/.local/share/vaultcontext-venv
~/.local/share/vaultcontext-venv/bin/pip install /absolute/path/to/vaultcontext
~/.local/share/vaultcontext-venv/bin/vaultcontext login --google
```

Run `vaultcontext` or `vaultcontext --help` for grouped commands and a first-use example, or `vaultcontext COMMAND --help`
for arguments, prerequisites and examples. Commands return JSON except `cat`,
which writes exact file bytes to stdout. Help does not require configuration or sign-in.

Use the chosen `vaultcontext` command for `whoami`, `check`, `init`, `unlock`, and subsequent operations. `init` and ordinary `unlock` prompt in an interactive terminal. On macOS, opt in with `vaultcontext keychain-enroll`, then use `vaultcontext unlock --keychain` to retrieve the saved passphrase after Touch ID or macOS credential authentication. This requires the signed native helper; see [macOS Keychain setup and trust model](docs/macos-keychain.md). Never pass unlock secrets through chat, arguments, environment variables or pipes. Over SSH, forward Google callback port 8765 as described in the [skill workflows](skills/vaultcontext/references/workflows.md); decryption still occurs on the machine running the CLI. Configuration must be available wherever the command runs; a workspace `.envrc` may not be loaded outside that workspace.

The [skill](skills/vaultcontext/SKILL.md) includes the launcher and operation references. It supports vault creation, arbitrary-file saves, local name search, version history, private equality checks, exact restores, invitations, memberships, revocation/rotation, encrypted export and independent archive restore. Agents manage files and metadata but never inspect file contents, including source or restored files. The dedicated `compare` command may answer a requested equality check without exposing contents or hashes. Content viewing with `cat` is for users in their own private terminals. This skill rule does not remove the CLI or unlocked session's decryption capability. Saving again with `--document` creates a new immutable version. The default encrypted display name preserves the exact source-path argument (after shell expansion), including relative or absolute directories; `--name` overrides it. Names are labels, not unique identifiers or restore destinations. Existing versions keep their names. No format-specific parsing, automatic synchronization or shell activation occurs.

`vaultcontext archive DOCUMENT_ID` hides a document and all its versions from default `list` and `search`; `--archived` selects archived documents and `--all` selects both. Owners and editors can archive or `unarchive`; readers cannot. Repeating either action is harmless. Archived documents retain `history`, `cat` and `restore` access by ID, but reject new versions until unarchived. Archiving changes neither access nor retention: exports, complete backups and whole-vault sharing include archived documents. Archive state is document metadata, distinct from an encrypted export archive.

Listings and name searches fetch selected version metadata in batches and reuse verified
keys only for the current command. Every version's signature and document binding
are still checked; subsequent commands recheck access and fingerprints. SQL reads
that receive HTTP 429 retry at most twice, waiting 10 seconds each time. Writes
are never automatically replayed after rate limiting.

`vaultcontext compare DOCUMENT_ID LOCAL_PATH` compares a local file with the current saved version; add `--version VERSION_ID` to select history. It requires login and an unlocked session and returns document/version IDs, a `same` boolean and a comparison `method`, never contents or hashes. New saves include a SHA-256 checksum of the plaintext inside encrypted, signed version metadata. For those versions, comparison downloads metadata only (`encrypted-sha256`); it reads local bytes internally to compute their checksum. Older versions use `legacy-download`, downloading and verifying the stored bytes in memory without plaintext temporary files. No existing version is rewritten. Hash equality has negligible collision risk, but does not prove that stored ciphertext remains downloadable or recoverable. Use backup/restore validation for recovery assurance.

`vaultcontext cat DOCUMENT_ID` outputs the current file; add `--version VERSION_ID` for a historical version. It verifies the entire file before output, creates no plaintext temporary files, and adds no formatting or newline. Binary data and terminal control characters pass through unchanged. Output can expose secrets to the terminal, pipes or captured logs. Shell redirection uses ordinary shell permissions and overwrite behavior; use `restore` for protected disk writes. Neither command executes file contents.

Restores require explicit paths and existing parent directories, reject symlinks and preserve byte contents with mode 0600. Existing destinations require `--overwrite`. Original executable bits, permissions, ownership and source absolute paths are not restored. An `.envrc.private` restored into a direnv-enabled directory can execute later when the user's shell loads it; the client never activates it.

## Storage and backups

Metadata reads use authenticated requester-filtered SQL. Writes use the standard REST `vault_actions` collection and transactional hooks; action payloads are not persisted. Encrypted file chunks use protected file storage and authenticated downloads so file bytes do not exhaust SQL snapshot budgets. Independent rules cover file downloads, REST and realtime. There is no implicit operator decryption access.

Complete deployment backups cover the database and every referenced ciphertext file with checksums. A database-only backup is insufficient. Startup must refuse missing/corrupt originals. An ordinary data export instead decrypts accessible file versions in memory and encrypts an archive under a separately entered archive passphrase; it includes no identity private keys or live vault-key envelopes. Exports restore without the server, but cannot recover a forgotten live-vault passphrase. Export plaintext is capped at 64 MiB including base64 overhead and metadata. New exports use format v2 to retain document archive status and require an updated CLI to inspect or restore. The updated CLI also reads existing v1 exports.

## Validation

Use synthetic fixtures and isolated temporary databases only. From this repository, install the locked development environment and run:

On macOS, first run `export TMPDIR=/private/tmp` in the test shell. The default
temporary path traverses the `/var` symlink, which the client's safe file handling
intentionally rejects. The unit suite compiles the native Keychain helper with
Apple's Swift command-line tools on macOS; its rejection tests never access Keychain.

```sh
uv sync --locked
uv run --locked python -m unittest discover -s tests -p 'test_*.py'
uv run --locked python tests/integration.py --binary /absolute/path/to/pinned/pocketcontext
uv run --locked python tests/archive_migration.py --binary /absolute/path/to/pinned/pocketcontext
uv run --locked python tests/realtime.py --binary /absolute/path/to/pinned/pocketcontext
uv run --locked python tests/limits.py --binary /absolute/path/to/pinned/pocketcontext
uv run --locked python tests/backup_integration.py --binary /absolute/path/to/pinned/pocketcontext
uv run --locked python tests/auth.py --binary /absolute/path/to/pinned/pocketcontext
uv run --locked python tests/oauth_integration.py --binary /absolute/path/to/pinned/pocketcontext
uv run --locked python tests/oauth.py
uv run --locked python tests/skill.py --binary /absolute/path/to/pinned/pocketcontext
uv run --locked python tests/cli_forward.py --binary /absolute/path/to/pinned/pocketcontext
uv run --locked python tests/deploy.py --binary /absolute/path/to/pinned/pocketcontext
uv run --locked python tests/deploy_workflow.py
```

Container configuration, smoke and populated complete-restore checks gate image publication; see deployment documentation for commands. Real Google browser/provider configuration and independent security review are separate from synthetic tests. Actual verification results and remaining limitations are recorded in `docs/validation.md`.

VaultContext is deployed at `https://vault.pocketcontext.com`; see [release evidence](DEPLOYMENT.md). The repository and container image are public. Image publication is enabled, but automatic production deployment is not.

Identity, OAuth and deployment patterns are adapted from RaiseContext; filtered access and complete-original backup patterns follow AccountContext. Their domain schemas and readers are not copied.

## Client launcher releases

Commit and push the tested package implementation first. Update `skills/vaultcontext/vaultcontext` to that full commit SHA, then validate the remotely installed client before committing and pushing the launcher:

```sh
uv run --locked python tests/skill.py --binary /absolute/path/to/pinned/pocketcontext --client skills/vaultcontext/vaultcontext
uv run --locked python tests/cli_forward.py --binary /absolute/path/to/pinned/pocketcontext --client skills/vaultcontext/vaultcontext
```

These checks copy only the executable into a temporary directory. The launcher intentionally has no adjacent lockfile; keep the root development lockfile separate. A copied launcher must be replaced to adopt a later client revision.

## Runtime maintenance freeze

Superusers use `GET /api/context/maintenance` and generation-checked
`PUT /api/context/maintenance` with `{"readOnly":true,"expectedGeneration":N}`
to drain and block writes without restarting. Existing authorized reads and
protected original downloads remain available. Authentication that creates or
updates records is blocked; preserve an existing operator token for thaw.
Set `readOnly:false` with the returned generation to resume writes explicitly.

The private durable `pb_data/maintenance.json` marker survives restart. Frozen
startup requires the existing database, skips restore and superuser/settings
provisioning, verifies original files, and refuses pending migrations. Malformed
markers fail closed. Backup/Litestream supervision remains active; this is a
managed database/API freeze, not cross-host writer fencing or byte-immutable disk.
Keep the marker with migration snapshots and fence the source before cutover.

Validate with `python3 tests/maintenance_entrypoint.py` and
`python3 tests/maintenance.py --binary /absolute/path/to/pinned/pocketcontext`.

Replicated startup waits for a private Litestream IPC synchronization before
serving, including fresh Google-only databases. A failed initial sync refuses
traffic; clean early shutdown therefore uses an initialized replica.
