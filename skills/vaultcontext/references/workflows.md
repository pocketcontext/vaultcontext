# Workflows

Install the dependency in an external virtual environment:

```sh
python3 -m venv ~/.local/share/vaultcontext-venv
~/.local/share/vaultcontext-venv/bin/pip install -r /absolute/path/to/skill/scripts/requirements.txt
```

In these examples, `vc` means running that environment's Python with the installed skill's `scripts/vc.py` path. No shell alias is installed automatically.

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

## Save and restore

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

Files may be binary or text, up to 8 MiB. Parent directories must already exist. Symlink sources, destinations and ancestor directories are rejected. Restored files have mode 0600. Permissions, ownership, original absolute paths and executable bits are not restored. Empty files work. `list`, `search` and `history` authenticate file versions; they do not print file content. No filename extensions receive special treatment.

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

Export includes all accessible retained file versions, encrypted under a separately prompted archive passphrase. Use inspect-export or history to choose document/version IDs on restore. Restore-export works without a server or Google session. The decrypted archive exists only in memory; only the selected file is written. The archive contains no user private keys or live vault-key envelopes. The plaintext archive is limited to 64 MiB (including base64 encoding and metadata), so a large vault may exceed this first-release limit. Lost archive passphrases cannot be recovered.
