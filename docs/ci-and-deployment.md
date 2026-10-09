# Common validation and deployment contract

`image.yml` owns push, pull-request and manual validation. It calls `test.yml`
once per run; the test workflow has no independent push/PR trigger. Each app's
backend, authentication, client and frontend checks remain application-specific.
Both application tests and container configuration/smoke/populated recovery run
on native AMD64 and ARM64 Linux. VaultContext additionally tests its client and
memory-session behavior on macOS. Tests use isolated synthetic data only.

Publication on main requires all application and container checks to pass. Each
architecture is built on its native runner and published by digest; the manifest
uses exactly those two digests. All external actions are pinned to full commits.
VaultContext and NotifyContext retain their separate publication-enable variables.

The dedicated `vaultcontext-demo` branch may publish after the same application
and native container gates when `VAULTCONTEXT_DEMO_PUBLISH=true`. Its manifest job
checks the current demo branch revision and publishes only `demo` and
`demo-sha-<full commit>` tags. It records the immutable multi-platform index digest
in the job output, summary and `demo-image-metadata` artifact. Demo deployment must
use that digest; neither tag is itself immutable. This path never updates `latest`
or production commit tags and cannot enter the main-only production deploy job.
Pull requests and other branches cannot publish through either path. The existing
`VAULTCONTEXT_PUBLISH` variable continues to control main publication independently.

Demo CD is a separate `demo_deploy` job after `demo_manifest`. Enable it with
repository variable `VAULTCONTEXT_DEMO_DEPLOY_ENABLED=true`; set
`VAULTCONTEXT_DEMO_DEPLOY_PAUSED=true` to pause deployment while keeping validation
and publication available. The fixed GitHub environment is `vaultcontext-demo`.
It needs variables `SERVER_IP`, `SERVER_USER=deploy`, `SSH_KNOWN_HOSTS` and a
`SSH_PRIVATE_KEY` secret for its dedicated forced-command key. Restrict that
environment to the `vaultcontext-demo` branch. No production deployment key is
reused. Both workflow-level and demo deployment concurrency prohibit automatic
cancellation of an active release; the host also serializes lifecycle changes.

Immediately before SSH, the workflow verifies that its commit remains the current
demo branch revision. The key accepts no remote command. Standard input contains
exactly one bounded JSON object with `revision` (40 lowercase hexadecimal digits)
and `image` (`ghcr.io/pocketcontext/vaultcontext@sha256:` plus 64 lowercase
hexadecimal digits). The digest comes directly from the successful
`demo_manifest` output, never from a mutable tag. No registry credentials, shell
scripts, archives or application secrets are transferred. The host dispatcher validates the request and uses the ONCE CLI for the fixed
`vault-demo.pocketcontext.com` application. It prepares the running supervisor
through `once exec`, updates to the exact digest with both `--auto-update=false`
and `--auto-backup=false`, then validates and commits the candidate through
`once exec`. The supervisor holds the volume writer lock and checks its baked
revision, current generation and preservation of all three databases before
opening public ingress. The dispatcher returns exactly
`{"image":"<requested image>","revision":"<requested revision>","ready":true}`.
A failed or mismatched receipt fails the workflow. The workflow sends no Docker command. Host operator helpers are reviewed and
installed separately; this protocol does not upgrade them. ONCE owns the
application, route and named volume. `/up` proves exclusive control readiness;
public application traffic stays closed until configuration/adoption or release
commit succeeds. Whole-volume automatic backups stay disabled because they
would retain disposable vault data alongside durable contacts.

The final public check requires today's UTC generation and the exact public skill
installation contract, including the client pin from the packaged launcher. It
compares root HTML, JavaScript, CSS, legal pages and the vendored SDK with the
workflow checkout and requires retired demo/download routes to return 404. Together with the host's digest/revision receipt, this attests the
requested image and public assets. It does not perform Google sign-in or prove
backup durability. No automatic rollback occurs after deployment or attestation
failure; investigate the host's durable state before retrying.

Before promoting `latest`, the workflow queries the current main revision and
refuses stale, malformed or failed lookups. A second check runs before deployment.
The image receives full and short commit tags alongside `latest`. These checks
reject old reruns; they do not lock Git refs, and main can advance after a check.
Concurrency serializes running releases but does not guarantee commit ordering
or execution of every pending run. Do not cancel a deployment in progress.

The active deployment uses the main-only `once-v2` GitHub environment and its
existing app-specific restricted SSH key. `CONTEXT_DEPLOY_PAUSED=true` disables
deployment without disabling validation or image publication.

Deployment sends no caller-selected remote command or registry credentials.
Strict host-key checking and a dedicated forced-command key select the permitted
application. The shared `once-pocketcontext-v2` dispatcher resolves the configured
image to an immutable digest, takes the host/application deployment lock, refuses
pending recovery state, disables the old writer's restart policy, and requires a
clean stop before replacement. The maintained policy uses a 300-second grace
period and disables ONCE's independent automatic image updates. It preserves
named volumes and verifies the replacement. It does not automatically roll back.

Production workflow health checks prove HTTP/database availability, not the exact deployed
source revision, data equivalence, or backup durability. The shared dispatcher
resolves `latest` when it runs; the commandless SSH contract does not carry the
workflow's digest. Record independent runtime revision evidence when releasing.
Host-local locks are not distributed fencing, and Litestream remains asynchronous.

Old `deploy/install.py`, app-local deployment wrappers and any old bootstrap
commands fail closed. They must not overwrite shared authorized keys or restart
retained source state. New deployment provisioning, storage creation and DNS
changes require a separate explicitly authorized operation. Container `init` is
only for a genuinely fresh installation, never an existing volume or replica.

After source changes, run the repository's README validation and the isolated
workflow checks:

```sh
python3 tests/deploy_workflow.py
```

Validate workflow YAML with actionlint. Actual native CI and image recovery gates
remain required before release; local validation does not replace either platform.

The native image checks also run `docker/once_smoke.py` in isolated CI containers:
control-only bootstrap returns `/up` 200, public routes remain 503, invalid
configuration is rejected, a second supervisor cannot take the same volume, and
shutdown completes cleanly. These Docker calls are image tests, not deployment
operations. Deployment operations use ONCE.

`tests/test_demo_once_runtime.py` exercises state transitions and failure paths
with real SQLite fixtures. With `VAULTCONTEXT_TEST_BINARY` and
`VAULTCONTEXT_TEST_LITESTREAM`, it also runs the pinned server, contact service and
three local replicas through a process adapter, restores each replica, verifies
ciphertext equality/decryption and preserves withdrawn marketing preferences
across a validated release. This process test does not claim to exercise the
shipped container paths; the separate native image bootstrap check covers those
paths. End-to-end ONCE adoption and live provider behavior remain separate checks.

## Mirrored build bases

The application and MinIO recovery-test Dockerfiles pull their pinned Go and
Debian bases from public `ghcr.io/pocketcontext/vaultcontext:base-*` tags, always
with the original upstream index digest. These tags are base images, not releases
of the VaultContext application. Both indexes retain every upstream platform.

`.github/workflows/mirror-bases.yml` copies the fixed upstream indexes using
Skopeo `--all --preserve-digests`, then verifies the destination index digest and
AMD64/ARM64 platform entries. It uses Docker's official ECR Public distribution,
with Docker Hub as an alternate source on retry, and the repository's temporary
`GITHUB_TOKEN` for publication. No new long-lived registry credential is needed.
The workflow runs only on the demo branch, on changes to that workflow or manual
dispatch, and never updates application release tags.

When updating a base, first update and run the mirror workflow, verify anonymous
GHCR access and the exact upstream digest, then update both Dockerfiles. Container
smoke and populated recovery checks remain required before publication. Mirroring
does not upgrade or rebuild the upstream images. Build tooling and other external
package downloads have their own upstream availability requirements.
