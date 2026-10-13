onBootstrap((e) => {
  require(`${__hooks}/google_auth.js`).domain();
  e.next();
  require(`${__hooks}/user_directory.js`).refresh(e.app);
});

onRecordAuthWithOAuth2Request((e) => require(`${__hooks}/google_auth.js`).authenticate(e), "users");
