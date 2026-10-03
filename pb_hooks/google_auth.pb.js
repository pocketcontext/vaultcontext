onBootstrap((e) => {
  require(`${__hooks}/google_auth.js`).domain();
  e.next();
});

onRecordAuthWithOAuth2Request((e) => require(`${__hooks}/google_auth.js`).authenticate(e), "users");
