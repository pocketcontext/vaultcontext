migrate((app) => {
  // PocketBase sets this context internally during OAuth record creation.
  // google_auth.js validates trusted Google claims before permitting creation.
  // Update the existing built-in collection without changing any user records.
  const users = app.findCollectionByNameOrId("users");
  users.createRule = "@request.context = 'oauth2'";
  app.save(users);
}, (app) => {
  const users = app.findCollectionByNameOrId("users");
  users.createRule = null;
  app.save(users);
});
