migrate((app) => {
  // Configure PocketBase's built-in collection; never create another auth table.
  const users = app.findCollectionByNameOrId("users");
  users.fields.add(new BoolField({name: "disabled"}));
  users.fields.add(new TextField({name: "name", required: true, max: 200}));
  users.listRule = null;
  users.viewRule = "id = @request.auth.id && @request.auth.collectionName = 'users' && @request.auth.disabled = false";
  users.createRule = null;
  users.updateRule = null;
  users.deleteRule = null;
  users.manageRule = null;
  users.authRule = "disabled = false";
  users.passwordAuth = {enabled: true, identityFields: ["email"]};
  users.authToken.duration = 604800;
  users.authAlert.enabled = false;
  app.save(users);
}, () => {
  throw new Error("Account policy rollback requires a deliberate backup restore.");
});
