# macOS Keychain unlock

Keychain unlock is opt-in. It saves the vault passphrase on this Mac so opening a new VaultContext session can use Touch ID or macOS credential authentication. Apple's `userPresence` policy permits a device credential fallback; this feature does not guarantee a password-free macOS prompt.

The encrypted identity bundle still lives only on the server. The client downloads it after ordinary application authentication and decrypts it in memory. The Keychain item is non-synchronizing, device-local and scoped to the server origin plus immutable account ID. It is not a portable backup or a recovery key. An enrolled Mac can retain access after the user forgets the vault passphrase; Google account recovery alone cannot decrypt a vault.

## Build and install the native helper

The portable Python launcher does not install a native helper. Build one from a trusted checkout on macOS 12 or later, using Apple's Swift command-line tools, a Developer ID Application signing identity and a matching macOS provisioning profile. The profile must authorize the exact application ID `TEAMID.com.pocketcontext.vaultcontext.keychain` and its Keychain access group. These signing prerequisites are separate from Google Workspace login. An unsigned or ad-hoc-signed helper is not supported.

From the repository root, with your own signing identity and ten-character team ID:

```sh
python3 native/macos/build.py \
  --identity 'Developer ID Application: YOUR NAME (TEAMID)' \
  --team-id TEAMID \
  --profile /absolute/path/to/helper.provisionprofile \
  --output "$HOME/Library/Application Support/VaultContext/KeychainHelper.app"
```

The output path must not already exist; build upgrades at a new path, then replace the installed signed bundle. The build creates a private, signed helper bundle for the current Mac's architecture and verifies its signature. It never accesses a vault credential. The client uses this fixed location; do not invoke the helper directly or substitute a helper through PATH. Keep the same signing team, application ID and Keychain group when upgrading. Changing them may make an existing credential inaccessible. Keep your vault passphrase available as the portable fallback.

This build step does not notarize or publish the helper. Distributing it to other Macs requires a reviewed signed distribution, appropriate architecture builds and Apple's applicable distribution checks. No signing credentials or provisioning profiles belong in the repository.

## Enroll and unlock

Install the signed native helper before enrollment. Run enrollment in your own interactive terminal:

```sh
vaultcontext login
vaultcontext keychain-enroll
vaultcontext unlock --keychain --timeout 900
```

Enrollment prompts for the existing vault passphrase and validates it against the server bundle before saving it. It does not create a new identity. Running enrollment again updates the saved passphrase and reapplies the required user-presence and device-only access policy; macOS may request authentication. `unlock --keychain` retrieves the secret through the helper and starts the ordinary memory session. Cancellation, a missing item, an unavailable helper or authentication failure stops the command; there is no silent fallback. Ordinary `vaultcontext unlock` continues to prompt for the passphrase.

The authentication request applies to opening a session, not each vault operation. Same-user agents are trusted for the session's lifetime, which defaults to 15 minutes. `vaultcontext lock`, expiration and `vaultcontext logout` retain enrollment. Remove it explicitly while logged into the enrolled account:

```sh
vaultcontext keychain-forget
vaultcontext lock
```

Forgetting the credential does not end an already unlocked session. Changing the vault passphrase does not update Keychain. After `vaultcontext change-passphrase`, run `vaultcontext keychain-enroll` with the new passphrase, or remove the stale credential with `vaultcontext keychain-forget`.

## Trust and remote use

The native helper uses the Data Protection Keychain with user-presence access control on secret retrieval itself. The installed helper and its signing identity are trusted, alongside the local host and client. Secret transfer uses private process pipes; never invoke the helper to display, capture or inspect its protocol output. Never put a vault passphrase in arguments, environment variables, shell scripts or files.

This does not protect against an already authorized same-user agent or a compromised execution host. Runtime copies and host swap prevent a guarantee of perfect memory erasure. Ending a session or deleting enrollment cannot recall secrets already disclosed.

Use terminal passphrase unlock on Linux or remote hosts. SSH and Google callback forwarding do not forward the local Mac's Keychain or Touch ID to a remote client. Noninteractive or locked-screen authentication can fail; unlock from an available local macOS login session instead.

## On-device validation

Automated tests cover synthetic client/helper boundaries; they cannot establish real Touch ID behavior. Before adopting a signed build, validate enrollment and retrieval with a synthetic account, cancellation, macOS credential fallback, screen lock, absent enrollment, wrong account/origin, helper replacement using the same signing identity, passphrase changes, forget, session expiry and logout. Confirm a canceled retrieval starts no new session and that the helper cannot retrieve the credential under an unrelated signing identity. Do not use production vault passphrases in test fixtures or captured output.
