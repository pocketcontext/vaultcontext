migrate((app) => {
  const users = app.findCollectionByNameOrId("users");
  users.fields.add(new TextField({name: "workspace_google_email", max: 320, hidden: true}));
  users.fields.add(new TextField({name: "workspace_google_domain", max: 253, hidden: true}));
  app.save(users);
  const directory = app.findCollectionByNameOrId("user_directory");
  directory.fields.add(new BoolField({name: "sharing_eligible"}));
  app.save(directory);
  // Existing OAuth mappings do not retain the verified hosted-domain claim.
  // A fresh Google login establishes eligibility; never infer it from an email suffix.
}, () => {
  throw new Error("Sharing identity rollback requires a deliberate backup restore.");
});
