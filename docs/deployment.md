# Deployment preparation

No resources have been provisioned and no image has been published or deployed.
The proposed application origin is `https://vault.pocketcontext.com`, with image
`ghcr.io/pocketcontext/vaultcontext`. These names must be confirmed against actual
infrastructure before release. The prepared container serves port 80 and `/up`,
uses `/storage/pb_data`, and runs one SQLite/Litestream writer.

The image pins the PocketContext commit, Go and Debian base image digests, and
Litestream release checksums. It contains no browser frontend or CLI private-key
cache. Ciphertext chunks are immutable protected files. Complete backups include a
consistent database snapshot plus every referenced ciphertext file, with checksums.
A database-only replica cannot restore file contents.
The user's unlock passphrase is still required. There is no recovery key.

## Required separate resources

During separately authorized provisioning, create a dedicated private R2 bucket
and replica prefix `once-pocketcontext/vaultcontext`, a Google OAuth Web client,
and the application hostname. Never reuse a sibling application's bucket, client
or credentials. For Google, use an Internal audience, `openid email profile`, and
exact redirects `http://127.0.0.1:8765/callback` and
`https://vault.pocketcontext.com/api/oauth2-redirect`. Real Google browser login
must be verified separately from synthetic provider tests.

Configure paired `VAULTCONTEXT_GOOGLE_CLIENT_ID` and
`VAULTCONTEXT_GOOGLE_CLIENT_SECRET`, plus `VAULTCONTEXT_GOOGLE_WORKSPACE_DOMAIN`.
Optional initial maintenance provisioning uses paired
`VAULTCONTEXT_SUPERUSER_EMAIL` and `VAULTCONTEXT_SUPERUSER_PASSWORD`.
Use `VAULTCONTEXT_TRUSTED_PROXY_HEADER=X-Forwarded-For` on the existing ONCE path.
ONCE provides `BASE_URL` and SMTP settings. The image enables rate limits.

Replication requires `LITESTREAM_BUCKET`, `LITESTREAM_PATH`,
`LITESTREAM_ACCESS_KEY_ID`, and `LITESTREAM_SECRET_ACCESS_KEY`. Set
`LITESTREAM_REGION=auto` and the bucket's verified `LITESTREAM_ENDPOINT` for R2.
The default database sync interval is 10 seconds. Complete file snapshots run
after startup, every `VAULTCONTEXT_BACKUP_INTERVAL` seconds (default 3600, maximum
3600), and after graceful shutdown. The interval begins after upload completes;
the recovery point is the latest successfully uploaded complete snapshot, even
if a newer database-only replica exists. This is not a zero-data-loss guarantee. `LITESTREAM_DISABLED=true` is for disposable tests only.
Keep all app-specific credentials in the deployment scaffold's ignored
`.envrc.private` under `COLORS_PAR_APP_VAULTCONTEXT_*`.

The local `once-pocketcontext` scaffold was prepared on 3 October 2026 with one
VaultContext entry (one CPU, 512 MiB RAM), all 13 environment mappings and private
configuration placeholders. Proposed bucket name: `vaultcontext-backup`.
Google credentials, operator credentials and the verified R2 endpoint/object
credentials remain blank. Existing private values were preserved and the file
restricted to mode 0600. Sequential scaffold build and create dry-run passed;
sibling configuration and compute guards are unchanged. This does not establish
provider access or deployability. See the scaffold's README for the remaining
targeted rollout steps. No cloud mutation or publication was performed.

## Validation and publication gates

```sh
python3 -m pip install -r skills/vaultcontext/scripts/requirements.txt
python3 tests/deploy_workflow.py
python3 -m unittest discover -s tests -p test_backup.py
python3 -m unittest discover -s tests -p test_packaging.py
python3 tests/deploy.py --binary /absolute/path/to/pinned/pocketcontext
python3 tests/backup_integration.py --binary /absolute/path/to/pinned/pocketcontext
docker build -t vaultcontext:check .
python3 docker/smoke.py config --image vaultcontext:check
python3 docker/smoke.py smoke --image vaultcontext:check
python3 docker/smoke.py restore --image vaultcontext:check
```

The populated restore drill uses isolated volumes and a pinned-source MinIO
fixture. To reuse an already built trusted local fixture, set
`VAULTCONTEXT_TEST_MINIO_IMAGE` to its full `sha256:` image ID; the runner verifies
that exact local digest. Without it, the runner builds the pinned fixture. It writes real encrypted multi-chunk binary files and encrypted identity
keys, destroys the original volume, restores into an empty volume, logs in as the
same ordinary user, decrypts and compares exact bytes. It also tests a late write
replicated during graceful shutdown. An unreachable replica must prevent startup.
No drill may use production credentials or the live replica.

Image CI gates publication on application tests and container configuration,
smoke and populated restore checks. Publication additionally requires repository
variable `VAULTCONTEXT_PUBLISH=true`; it is not enabled by these files. The workflow
contains no deployment job. Package visibility and anonymous pull access must be
verified after an authorized publication; no visibility is assumed here.

## Single-writer updates

`deploy/deploy-vaultcontext.py` targets only the proposed hostname and image. It
accepts no arguments, acquires `/run/lock/deploy-vaultcontext.lock`, requires one
matching container, pulls the image, gracefully stops the old writer, rejects an
unclean exit, and updates ONCE with automatic updates disabled. Recovery starts
the old container only if it remains the sole matching container. Never use ONCE
rolling or automatic updates for this application.

After an authorized first deployment, install the root-owned wrapper using
`deploy/install.py` from a trusted checkout. It requires a dedicated existing
application deployment key and preserves unrelated keys. Verify restricted SSH
access, no-argument sudo permission, known host keys, and the wrapper before
adding any CI deployment integration. Environment changes use the same lock and
graceful-stop discipline; do not run full scaffold convergence for routine app
changes.

## Recovery and outstanding verification

Existing databases remain authoritative and referenced ciphertext is verified
before serving. A missing database first restores the latest complete snapshot.
Only when no complete snapshot exists does Litestream attempt database restore;
startup then refuses any missing or corrupt ciphertext. An empty replica permits
initialization; inaccessible or damaged replicas fail closed. Tini and Litestream forward shutdown and complete a
final database sync and complete snapshot. Backups contain sensitive auth settings and ciphertext even though
file plaintext is encrypted, so the replica remains private.

Stop every production writer before rollback. A prior image is safe only with a
compatible schema; otherwise restore a selected verified backup under a deliberate
replica strategy. Never launch a restored copy against the live replica while
production is running. Measure actual recovery time and backup age in an isolated
drill before release. Retention configuration is an operator decision, not implied
by version retention inside the vault.

Local ARM64 container config/smoke/populated-restore checks passed; see [validation evidence](validation.md).
Outstanding release checks include independent security review, R2 access/restore, DNS/TLS, registry visibility, real
Google login, and verification of exactly one writer with automatic updates off.
Record actual source/image digests and provider evidence in a sanitized release
record when those checks have been performed.
