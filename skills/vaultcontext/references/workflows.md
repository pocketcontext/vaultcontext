# Workflows

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) and run the installed skill's launcher directly, or copy it onto your PATH:

```sh
install -Dm755 /absolute/path/to/skill/vc ~/.local/bin/vc
export PATH="$HOME/.local/bin:$PATH"
vc --help
```

Both `uv` and `~/.local/bin` must be on PATH. The launcher is self-contained and pins the client package to a full Git commit. uv supplies a compatible Python and installs dependencies into its managed environment. Initial downloads require network access; offline use requires a prepared cache. Replace the launcher to adopt a new client revision. If a session is already unlocked, run `vc lock` then `vc unlock` after updating so new commands are available in the session. No adjacent lockfile is required; transitive dependency versions may vary on fresh installations.

For an existing Python 3.11+ setup, install the package from a trusted checkout into an external environment instead:

```sh
python3 -m venv ~/.local/share/vaultcontext-venv
~/.local/share/vaultcontext-venv/bin/pip install /absolute/path/to/vaultcontext
~/.local/share/vaultcontext-venv/bin/vc --help
```

This console entry point does not require uv at runtime. In the examples below, use your chosen `vc` executable. Configuration must be exported in the invoking environment; a workspace `.envrc` is not necessarily loaded when working elsewhere.

## Sign in and initialize

```sh
export VAULTCONTEXT_URL=https://vault.example.com
export VAULTCONTEXT_USER_EMAIL=you@example.com
vc login --google
vc whoami
vc check
vc init
vc unlock --timeout 900
vc create 'Personal'
```

`init` runs once per account and prompts for a passphrase twice. Keep its public fingerprint for independent verification. There is no recovery key. Google callback uses port 8765; on SSH forward it with `ssh -L 8765:127.0.0.1:8765 user@host` and open the provided URL on the browser machine. This does not move vault decryption from the execution host to the browser machine. `VAULTCONTEXT_USER_PASSWORD` supports ordinary provisioned test/password accounts; it is not the vault passphrase.

Application tokens and public fingerprint pins are local, privately permissioned, and scoped by server/user. Only encrypted private keys persist on the server. `change-passphrase` prompts for a new passphrase while unlocked and updates the server bundle. `lock` terminates the memory session; expiration rejects new requests, while an operation already running may finish. `logout` locks and deletes the local application token, but does not revoke copied tokens.

## Optional macOS Keychain unlock

Install the signed native helper using the repository's `docs/macos-keychain.md` instructions. Keychain enrollment is optional and specific to the Mac, server origin and immutable account ID. It stores a non-synchronizing copy of the vault passphrase, never the identity bundle. Have the user perform enrollment in their private interactive terminal:

```sh
vc keychain-enroll
vc unlock --keychain --timeout 900
vc lock
# Remove this server/account's saved credential while logged in:
vc keychain-forget
```

Enrollment checks the entered passphrase against the current server bundle before storing it. Retrieval uses Touch ID or macOS credential authentication, so macOS may still request a password. Once unlocked, the session trusts same-user agents as before; authentication does not approve individual reads. Never retrieve the credential using other tools or expose it in agent output.

`unlock --keychain` does not silently fall back on cancellation or failure. Run ordinary `vc unlock` explicitly to use a terminal passphrase, including on Linux or remote hosts. Google callback forwarding does not forward Keychain or Touch ID to an SSH host.

`lock`, expiration and `logout` retain the enrolled credential. `keychain-forget` deletes the credential for the logged-in account; separately run `lock` to end an active session. After `change-passphrase`, run `keychain-enroll` with the new passphrase or `keychain-forget` to remove the stale credential. Retaining enrollment can preserve access if the vault passphrase is forgotten; Google account recovery still cannot decrypt a vault.

## Save and restore without inspection

```sh
vc vaults
vc save VAULT_ID /absolute/path/to/file --name 'Optional display name'
vc save VAULT_ID /absolute/path/to/replacement --document DOCUMENT_ID
vc list VAULT_ID
vc search VAULT_ID 'display-name fragment'
vc history DOCUMENT_ID
vc restore DOCUMENT_ID --to /absolute/path/to/destination
vc restore DOCUMENT_ID --version VERSION_ID --to /absolute/path/to/destination --overwrite
```

The encrypted display name defaults to the exact source-path argument, after any shell expansion. For example, `/projects/one/.envrc` and `/projects/two/.envrc` keep their distinct full names; `projects/one/.envrc` keeps that relative spelling. `--name` overrides the default, including when adding a version with `--document`. Existing versions retain their names. Saving the same path again without `--document` still creates another document: names are labels, not unique IDs, and never determine restore destinations.

Files may be binary or text, up to 8 MiB. Parent directories must already exist. Symlink sources, destinations and ancestor directories are rejected. Restored files have mode 0600. Permissions, ownership, original absolute paths and executable bits are not restored. Empty files work. `list`, `search` and `history` authenticate file versions; they do not print file content. No filename extensions receive special treatment.

Agents must not inspect source or restored file contents, including through previews, scripts, content searches or redaction. Verify operations using returned metadata/status and `history`, without opening the file. For content changes, have the user edit privately and provide the replacement path for `save --document`.

### Compare without exposing contents

For a requested equality check, agents may use the dedicated command:

```sh
vc compare DOCUMENT_ID /absolute/path/to/local-file
vc compare DOCUMENT_ID /absolute/path/to/local-file --version VERSION_ID
```

Login and unlock first. After upgrading an already unlocked client, run `vc lock` and have the user unlock again so the session uses the updated code. Comparison works for active and archived documents accessible to the account. It rejects symlinks and oversized local files using the same source-file rules as `save`.

The JSON result contains `document`, `version`, `same` (a boolean), and `method`. `encrypted-sha256` means the saved version carries a plaintext SHA-256 checksum inside encrypted, signed metadata: the client verifies and decrypts metadata, hashes the local bytes internally, and avoids downloading file chunks. `legacy-download` means an older version lacks the checksum: the client downloads and verifies saved bytes in memory, without plaintext temporary files. Neither method prints file contents or hashes. Existing immutable versions remain unchanged.

Use only this command for agent equality checks; do not read files, invoke `cat`, run manual hashing/diffs or build alternative comparison scripts. Hash equality has negligible collision risk. In particular, `encrypted-sha256` does not prove ciphertext availability or successful recovery; use the separate backup and restore validation workflow for that assurance.

### Private viewing by the user only

If the user requests content inspection, explain the skill's management-only boundary and offer this command for their own private terminal. Never execute it through agent tools or ask for its output:

```sh
vc cat DOCUMENT_ID | less
# For a historical version:
vc cat DOCUMENT_ID --version VERSION_ID | less
```

`cat` requires login and an unlocked session and verifies the entire file before writing exact bytes to stdout. It creates no plaintext temporary file and does not execute the contents. Binary bytes and terminal control characters pass through unchanged; terminal recording or logging can expose the output. Shell redirection does not provide `restore`'s protected file creation. The agent must not use `cat`, even with redirection or a filtering pipeline.

## Archive and unarchive documents

```sh
vc archive DOCUMENT_ID
vc list VAULT_ID --archived
vc search VAULT_ID '.envrc' --all
vc unarchive DOCUMENT_ID
```

Owners and editors can archive a whole document and its versions; readers cannot. Default `list` and `search` show active documents. `--archived` selects only archived documents; `--all` selects both, and these flags cannot be combined. Results include an `archived` boolean.

Archived documents remain accessible through `history`, `compare` and `restore` by ID; user-operated private viewing with `cat` also remains available. Unarchive before saving another version. Repeated archive/unarchive requests are harmless. Concurrent changes can return revision conflicts; reread state before retrying. Archiving does not delete ciphertext, reclaim storage or revoke access. Complete backups, encrypted exports and whole-vault sharing retain archived documents and history. An archived document is distinct from an encrypted export archive.

## Shared project vaults

```sh
vc directory
vc share VAULT_ID RECIPIENT_ACCOUNT_ID --role editor --fingerprint VERIFIED_RECIPIENT_FINGERPRINT
vc invitations
vc accept INVITATION_ID --fingerprint VERIFIED_OWNER_FINGERPRINT
vc verify-user WRITER_ACCOUNT_ID --fingerprint VERIFIED_WRITER_FINGERPRINT
vc members VAULT_ID
vc revoke VAULT_ID RECIPIENT_ACCOUNT_ID
```

`directory` returns registered user names/emails and public keys, not proof those keys belong to the intended person. Verify separately. Sharing grants the whole vault and all retained history. For a single-file request, use a dedicated vault containing only the authorized file; do not expose unrelated personal files. Owners alone invite/revoke; owners/editors save; readers restore. Active members cannot be reinvited to change roles: revoke/rotate then invite with the new role. Owners cannot remove themselves.

`revoke` cancels pending invitations and freezes writes before rotating keys for remaining active members. If rotation fails, verify remaining member fingerprints and run `vc rotate VAULT_ID`. Reissue canceled invitations afterward. Old versions remain decryptable by their original recipients; rotation applies to future versions.

## Encrypted export

```sh
vc export VAULT_ID --to /absolute/path/to/project.vault-export
vc inspect-export /absolute/path/to/project.vault-export
vc restore-export /absolute/path/to/project.vault-export --document DOCUMENT_ID --version VERSION_ID --to /absolute/path/to/destination
```

These archive commands prompt for an archive passphrase; have the user run them in their own interactive terminal, without agent capture of the passphrase or file contents. Agents may prepare commands and use metadata to identify the requested document/version, but must not inspect restored files.

Export includes all accessible retained file versions, including archived documents and their archive status, encrypted under a separately prompted archive passphrase. Use inspect-export or history to choose document/version IDs on restore. Restore-export works without a server or Google session. The decrypted archive exists only in memory; only the selected file is written. The archive contains no user private keys or live vault-key envelopes. The plaintext archive is limited to 64 MiB (including base64 encoding and metadata), so a large vault may exceed this first-release limit. Lost archive passphrases cannot be recovered. New exports use format v2 to retain document archive status and require an updated CLI to inspect or restore. The updated CLI also reads existing v1 exports.
