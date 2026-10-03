// Identity claims come from PocketBase's server-to-server Google userinfo request.
// Neither createData nor the authorization URL's hd hint is trusted.
function domain() {
  const value = $os.getenv("VAULTCONTEXT_GOOGLE_WORKSPACE_DOMAIN");
  if (!value) return "";
  if (value.length > 253 || value !== value.toLowerCase() ||
      !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(value)) {
    throw new Error("VAULTCONTEXT_GOOGLE_WORKSPACE_DOMAIN must be a lowercase DNS domain");
  }
  return value;
}

function authenticate(e) {
  const workspace = domain();
  if (e.record && e.record.getBool("disabled")) {
    throw new ForbiddenError("This VaultContext account is disabled.");
  }

  const user = e.oAuth2User;
  const raw = user && user.rawUser;
  const email = user && user.email;
  if (e.providerName !== "google" || !raw || raw.email_verified !== true ||
      typeof email !== "string" || !email || raw.email !== email ||
      email.split("@").length !== 2 ||
      (workspace && (raw.hd !== workspace || email.split("@")[1].toLowerCase() !== workspace))) {
    throw new ForbiddenError("A verified Google Workspace account in the configured domain is required.");
  }
  // PocketBase's initial email lookup is case-sensitive. Resolve case variants
  // before provisioning so an existing identity (including a disabled one)
  // cannot be bypassed by Google's email casing.
  const matches = e.app.findRecordsByFilter("users", "email:lower = {:email}", "", 2, 0,
    {email: email.toLowerCase()});
  if (matches.length > 1 || (e.record && matches.length && matches[0].id !== e.record.id)) {
    throw new ForbiddenError("Google identity matches conflicting VaultContext accounts; contact an operator.");
  }
  if (!e.record && matches.length === 1) {
    e.record = matches[0];
    e.isNewRecord = false;
  }
  if (e.record && e.record.getBool("disabled")) {
    throw new ForbiddenError("This VaultContext account is disabled.");
  }
  // PocketBase can otherwise fall back to the currently authenticated user when
  // linking an OAuth provider. Never attach another person's Google identity.
  if (e.record && e.record.getString("email").toLowerCase() !== email.toLowerCase()) {
    throw new ForbiddenError("Google identity does not match the VaultContext account.");
  }
  // Keep the stored spelling while allowing PocketBase's exact comparison to
  // verify the existing account using the validated, equivalent Google email.
  if (e.record) user.email = e.record.getString("email");

  // Domain configuration explicitly enables Google Workspace onboarding. Without
  // it, only an existing provisioned identity may authenticate.
  if (!workspace && !e.record) throw new ForbiddenError("VaultContext account provisioning is disabled.");
  // Never trust client-selected IDs, passwords, verification, access flags or
  // names. Google supplies identity, PocketBase generates the account password.
  const name = typeof user.name === "string" ? user.name.trim().slice(0, 200) : "";
  e.createData = {email: email, name: name || email.split("@")[0].slice(0, 200)};
  return e.next();
}

module.exports = {domain, authenticate};
