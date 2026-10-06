# Container deployment and recovery

The container runs one PocketContext/SQLite writer and Litestream publisher, serves
port 80 and `/up`, and stores SQLite under `/storage/pb_data`. Primary files are
private S3 objects. `docker/entrypoint.py` is the sole startup program; tini and
Litestream own normal signal forwarding and shutdown. No archive scheduler runs.
The server remains pinned by `POCKETCONTEXT_VERSION`; no schema or ciphertext-format
change accompanies this runtime refactor. The public onboarding assets remain included.

## Configuration

Require all of `VAULTCONTEXT_S3_BUCKET`, `VAULTCONTEXT_S3_ENDPOINT`,
`VAULTCONTEXT_S3_REGION`, `VAULTCONTEXT_S3_ACCESS_KEY_ID` and
`VAULTCONTEXT_S3_SECRET_ACCESS_KEY`. `VAULTCONTEXT_S3_FORCE_PATH_STYLE` defaults to
`true` and accepts only `true` or `false`. Use private primary-file storage with
credentials scoped to that bucket. Configure separate `LITESTREAM_BUCKET`,
`LITESTREAM_PATH`, `LITESTREAM_ACCESS_KEY_ID` and `LITESTREAM_SECRET_ACCESS_KEY`.
The file bucket and access key must differ from the replica bucket and access key.
Set `LITESTREAM_REGION=auto` and the verified S3 endpoint for R2. The default sync
interval is 10 seconds. `LITESTREAM_DISABLED` is unsupported.

Keep paired `VAULTCONTEXT_GOOGLE_CLIENT_ID`/`VAULTCONTEXT_GOOGLE_CLIENT_SECRET`,
`VAULTCONTEXT_GOOGLE_WORKSPACE_DOMAIN`, optional paired operator email/password,
`BASE_URL`, trusted proxy and SMTP configuration unchanged for an existing deployment.
Secrets remain in the deployment scaffold's ignored private configuration. The
server child retains primary-storage credentials but drops replica/AWS credentials
and the bootstrap password. Errors suppress subprocess and SDK details.

The WikiContext migration record dated 6 October 2026 records production on the
`once-pocketcontext-v2` scaffold with `vaultcontext-files` and `vaultcontext-replica`,
prefix `once-v2/vaultcontext-production`, separate bucket-scoped keys and manual
stop-first deployment. This refactor does not attest the current live configuration.
Older `DEPLOYMENT.md` entries remain historical evidence.

## Start, initialize and recover

Ordinary startup preserves an existing database. When absent, it strictly restores
Litestream into a temporary sibling directory, checks SQLite and every referenced
remote file, fsyncs the database, then installs it and fsyncs the directory. Missing
replicas and partial local state fail closed. A failed verification installs no
database. Ciphertext is streamed and compared with stored SHA-256; avatars and any
other file fields are streamed for readability/completeness, without a hash guarantee.

For a genuinely new installation only, provide a private environment file and a
new volume (these example paths/names are placeholders):

```sh
docker run --rm --env-file /absolute/private/vaultcontext.env \
  -v new-vaultcontext:/storage ghcr.io/pocketcontext/vaultcontext:REVIEWED_TAG init
docker run -d --env-file /absolute/private/vaultcontext.env \
  -v new-vaultcontext:/storage -p 127.0.0.1:8090:80 ghcr.io/pocketcontext/vaultcontext:REVIEWED_TAG
```

`init` requires an empty directory and no existing replica, applies migrations and
optional operator provisioning, verifies objects, and exits. Normal startup then
establishes replication before HTTP. Never run `init` for upgrades, production
restarts or recovery. Interrupted initialization leaves a durable
`initialization.pending`; preserve the failed volume rather than deleting the marker.

Frozen startup requires existing main and auxiliary databases and the private
`maintenance.json` marker. It skips restore and provisioning, checks stored S3
settings against configuration and verifies remote files. Pending migrations remain
rejected by the pinned server. Litestream does not recover `maintenance.json` or
`auxiliary.db`: carry consistent snapshots separately for a frozen host migration.
A writable recovery can recreate auxiliary state, not its prior history.

## Single-writer updates and rollback

Use the maintained `once-pocketcontext-v2` stop-first policy and its restricted
shared deployment dispatcher. Preserve the volume and exact configuration, fence the
old publisher and writer, and keep ONCE automatic updates disabled. Host-local
locks and maintenance state do not provide cross-host fencing. Never run a recovery
copy against the active replica.

The image workflow deploys only after the tested multi-architecture manifest is
published. Set `COLORS_PROFILE=once-pocketcontext-v2` to select the GitHub environment
holding the app-specific `SSH_PRIVATE_KEY` secret and `SERVER_IP`, `SERVER_USER`,
`SSH_KNOWN_HOSTS` variables. The job requires pinned SSH host keys and sends no remote
command: the restricted key invokes the maintained dispatcher for VaultContext only.
Preserve its stop-first locking, one-writer checks, graceful shutdown and guarded
rollback. Keep ONCE's own automatic updates disabled; GitHub handles deployment.
Deployment jobs serialize without cancelling a running update, then check
`https://vault.pocketcontext.com/up`. That health check verifies availability, not
the deployed image revision; verify the running revision separately when needed.

Set `CONTEXT_DEPLOY_PAUSED=true` to pause deployment while CI and publication continue.
Keep the profile intact. Resume only when deployment is intended by setting it to
`false` or removing it. The guard affects newly evaluated jobs; finish or cancel an
already running deployment before treating the host as fenced. The existing
`VAULTCONTEXT_PUBLISH=true` publication gate remains required.

The app-local `deploy/install.py` and `deploy/deploy-vaultcontext.py` are retired
fail-closed stubs. Do not use them to overwrite once-v2 SSH commands, sudo rules or
shared dispatcher policy. Provision or change those through the maintained private
`once-pocketcontext-v2` scaffold; keep its app key scoped to VaultContext.

For code rollback, first record the actual previous immutable image and verify its
schema/startup compatibility; stop the new process and run the previous S3-capable
image on the current volume. Do not restore an older database merely to roll back
code. Historical pre-S3 archives remain recoverable through the old archive-capable
image, for example the retained migration image
`ghcr.io/pocketcontext/vaultcontext@sha256:e408d0149ef3dc5f1b17fc7116098a19a61c9498097aeb2969f7d787967d7909`,
in an isolated environment with reviewed configuration. This refactor deletes no
archives, remote objects, volumes or replica history.

Litestream replication is asynchronous: clean exit alone does not prove final
remote durability. Verify synchronization and an independent restore. File retention
is independent of replica retention; a database cannot restore deleted objects.
Full ciphertext verification can increase readiness time. No recovery key exists;
the user's unlock passphrase is still required to decrypt files.

## Validation and release gates

```sh
uv sync --locked
python3 tests/entrypoint.py
python3 tests/object_storage_settings.py
uv run --locked python -m unittest discover -s tests -p 'test_*.py'
uv run --locked python tests/deploy_workflow.py
# Run all pinned-server checks listed in README.md.
docker build -t vaultcontext:check .
uv run --locked python docker/smoke.py config --image vaultcontext:check
uv run --locked python docker/smoke.py smoke --image vaultcontext:check
uv run --locked python docker/smoke.py restore --image vaultcontext:check
```

The smoke and populated recovery checks use synthetic MinIO with separate scoped
file/replica identities. `restore` invokes `docker/object_storage_smoke.py`, comparing
all main database rows before destroying the stopped source volume, retaining a
frozen snapshot, and exercising actual empty-volume recovery and late writes.
Unit tests exercise failed staged restores, initialization interruption, signals,
credential stripping, all-file inventory and corruption. Legacy archive helpers
remain test-only under `tests/legacy_backup.py` and are excluded from the image.
To reuse a trusted local MinIO fixture, `VAULTCONTEXT_TEST_MINIO_IMAGE` selects its
full `sha256:` image ID; otherwise tests build the pinned fixture.

Image CI gates publication on application and container checks; publication still
requires `VAULTCONTEXT_PUBLISH=true`. The guarded deployment job follows successful
publication. New
release evidence belongs in `docs/validation.md`; historical results do not prove
this changed runtime or a live deployment.
