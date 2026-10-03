# VaultContext

Encrypted personal and shared file vaults for humans and coding agents, built on PocketContext. Any file type is accepted as exact opaque bytes, initially up to 8 MiB per file. Names and descriptive metadata are encrypted too. A CLI and portable skill provide the interface; there is no browser frontend. Clipperz inspired the architecture; no Clipperz code or compatibility is included.

## Access and keys

Google Workspace login authenticates PocketBase's default `users` identity. It does not unlock encrypted data. Each account initializes an encryption/signing identity protected by a separate passphrase. The encrypted private-key bundle persists only on the server; unlocking downloads and decrypts it in process memory. Application tokens and verified public fingerprints may be cached locally, never the private-key bundle. There are no recovery keys. A lost passphrase without a usable unlocked session means lost access; Google account recovery cannot decrypt the vault.

Personal vaults are private. Shared project vaults have one owner and explicit editor/reader members, initially within the configured Workspace. Verify recipient and writer public fingerprints through an independent trusted channel. New members receive retained history. Revoking a member blocks retrieval immediately and freezes writes until key rotation completes. Downloaded plaintext or keys cannot be recalled, and credentials contained in files may need separate provider rotation. Owners cannot remove themselves; owner transfer and identity-key replacement are not implemented.

The execution host and unlocked agent are trusted. The client retains keys in a same-OS-user Unix socket session, with a 15-minute default lifetime and explicit `lock`. Linux is the initial client platform. Python cannot promise perfect memory erasure or protect against a privileged host, swap or an agent already authorized to read local files. No stored content authorizes execution or sharing.

See [implementation brief](docs/implementation-brief.md), [data and trust model](docs/data-model.md), [API contract](docs/api-contract.md) and [deployment preparation](docs/deployment.md).

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
install -Dm755 skills/vaultcontext/vc ~/.local/bin/vc
export PATH="$HOME/.local/bin:$PATH"
export VAULTCONTEXT_URL=https://vault.example.com
export VAULTCONTEXT_USER_EMAIL=you@example.com
vc login --google
```

The launcher declares its Python requirements and pins the client package to a full Git commit. It can run from any directory without neighboring source files. The first run needs network access to download the package, Python if needed, and dependencies; later runs reuse uv's cache. Updating the copied launcher adopts its new client revision. The skill has no script lockfile: transitive dependencies may resolve differently on fresh installations. The repository's `uv.lock` governs development and tests, not launcher execution.

Alternatively, install the package from a trusted checkout into an external Python 3.11+ virtual environment. This provides the same `vc` command without requiring uv at runtime:

```sh
python3 -m venv ~/.local/share/vaultcontext-venv
~/.local/share/vaultcontext-venv/bin/pip install /absolute/path/to/vaultcontext
~/.local/share/vaultcontext-venv/bin/vc login --google
```

Use the chosen `vc` command for `whoami`, `check`, `init`, `unlock`, and subsequent operations. `init` and `unlock` prompt in an interactive terminal. Never pass unlock secrets through chat, arguments, environment variables or pipes. Over SSH, forward Google callback port 8765 as described in the [skill workflows](skills/vaultcontext/references/workflows.md); decryption still occurs on the machine running the CLI. Configuration must be available wherever the command runs; a workspace `.envrc` may not be loaded outside that workspace.

The [skill](skills/vaultcontext/SKILL.md) includes the launcher and operation references. It supports vault creation, arbitrary-file saves, local name search, version history, exact restores, invitations, memberships, revocation/rotation, encrypted export and independent archive restore. Saving again with `--document` creates a new immutable version. No format-specific parsing, automatic synchronization or shell activation occurs.

Restores require explicit paths and existing parent directories, reject symlinks and preserve byte contents with mode 0600. Existing destinations require `--overwrite`. Original executable bits, permissions, ownership and source absolute paths are not restored. An `.envrc.private` restored into a direnv-enabled directory can execute later when the user's shell loads it; the client never activates it.

## Storage and backups

Metadata reads use authenticated requester-filtered SQL. Writes use the standard REST `vault_actions` collection and transactional hooks; action payloads are not persisted. Encrypted file chunks use protected file storage and authenticated downloads so file bytes do not exhaust SQL snapshot budgets. Independent rules cover file downloads, REST and realtime. There is no implicit operator decryption access.

Complete deployment backups cover the database and every referenced ciphertext file with checksums. A database-only backup is insufficient. Startup must refuse missing/corrupt originals. An ordinary data export instead decrypts accessible file versions in memory and encrypts an archive under a separately entered archive passphrase; it includes no identity private keys or live vault-key envelopes. Exports restore without the server, but cannot recover a forgotten live-vault passphrase. Export plaintext is capped at 64 MiB including base64 overhead and metadata.

## Validation

Use synthetic fixtures and isolated temporary databases only. From this repository, install the locked development environment and run:

```sh
uv sync --locked
uv run --locked python -m unittest discover -s tests -p 'test_*.py'
uv run --locked python tests/integration.py --binary /absolute/path/to/pinned/pocketcontext
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

Commit and push the tested package implementation first. Update `skills/vaultcontext/vc` to that full commit SHA, then validate the remotely installed client before committing and pushing the launcher:

```sh
uv run --locked python tests/skill.py --binary /absolute/path/to/pinned/pocketcontext --client skills/vaultcontext/vc
uv run --locked python tests/cli_forward.py --binary /absolute/path/to/pinned/pocketcontext --client skills/vaultcontext/vc
```

These checks copy only the executable into a temporary directory. The launcher intentionally has no adjacent lockfile; keep the root development lockfile separate. A copied launcher must be replaced to adopt a later client revision.
