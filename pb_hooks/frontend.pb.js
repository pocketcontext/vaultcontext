/// <reference path="../pb_data/types.d.ts" />
// Public demo onboarding. Vault cryptography and file operations stay in the CLI.
// Run from the application directory; API routes remain more specific.
routerAdd('GET', '/{path...}', (e) => {
  if(require(`${__hooks}/demo.js`).enabled()) {
    if(/^\/(demo|downloads)(\/|$)/.test(e.request.url.path))throw new NotFoundError('Page not found.');
  }
  return $apis.static('pb_public',false)(e);
}, (e) => {
  e.response.header().set('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  e.response.header().set('X-Content-Type-Options', 'nosniff');
  e.response.header().set('Referrer-Policy', 'no-referrer');
  return e.next();
});
