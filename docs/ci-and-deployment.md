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
scripts, archives or application secrets are transferred. The host dispatcher
validates the request, verifies the immutable image's revision and operator ABI,
and performs the locked release before returning exactly
`{"image":"<requested image>","revision":"<requested revision>","ready":true}`.
A failed or mismatched receipt fails the workflow. Host operator helpers are
reviewed and installed separately; this protocol does not upgrade them.

The final public check requires today's UTC generation and available downloads,
verifies all three downloadable artifacts against their manifest sizes and SHA-256
hashes, and compares the served HTML, JavaScript and CSS with the workflow's checked
out revision. Together with the host's digest/revision receipt, this attests the
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
