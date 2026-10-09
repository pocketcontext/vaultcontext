/// <reference path="../pb_data/types.d.ts" />
// Public product onboarding only. Authentication and vault operations stay in the CLI.
// Run from the application directory; API routes remain more specific.
routerAdd('GET', '/{path...}', (e) => {
  if(require(`${__hooks}/demo.js`).enabled()) {
    if(e.request.url.path==='/')return e.redirect(303,'/demo/');
    if(['/terms','/privacy'].includes(e.request.url.path))return e.redirect(303,'/demo'+e.request.url.path+'/');
  }
  return $apis.static('pb_public',false)(e);
}, (e) => {
  const frameAncestors = e.request.url.path === '/analytics-frame.html' ? "'self'" : "'none'";
  e.response.header().set('Content-Security-Policy', "default-src 'self'; script-src 'self' https://www.googletagmanager.com/gtag/js; style-src 'self'; img-src 'self' data:; connect-src 'self' https://rybbit.getcolors.ai/api/track https://www.google-analytics.com/g/collect https://region1.google-analytics.com/g/collect; frame-ancestors " + frameAncestors + "; base-uri 'none'; form-action 'self'");
  e.response.header().set('X-Content-Type-Options', 'nosniff');
  e.response.header().set('Referrer-Policy', 'no-referrer');
  return e.next();
});
