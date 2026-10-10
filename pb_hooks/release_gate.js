// One supported application release. This is a compatibility check, not auth.
function release() {
  const value = require(`${__hooks}/release.json`);
  if (!value.release_id || !value.installation_url) throw new Error('Invalid application release configuration.');
  return value;
}

function compatibility(e) {
  e.response.header().set('Cache-Control', 'no-store');
  return e.json(200, release());
}

function request(e) {
  const path = e.request.url.path;
  const method = e.request.method;
  if (!path.startsWith('/api/') || method === 'OPTIONS') return e.next();
  // Operator maintenance retains PocketBase's authentication and IP restrictions.
  if (e.auth && e.auth.isSuperuser()) return e.next();
  if (path.startsWith('/api/collections/_superusers/')) return e.next();
  if ((method === 'GET' && (path === '/api/health' || path === '/api/vaultcontext/compatibility')) ||
      ((method === 'GET' || method === 'POST') && path === '/api/oauth2-redirect')) return e.next();
  // PocketBase's browser OAuth flow opens an anonymous SSE stream. It grants no
  // record access; only the exact OAuth subscription is exempt from the gate.
  if (path === '/api/realtime' && !e.auth) {
    if (method === 'GET') return e.next();
    if (method === 'POST') {
      const body = e.requestInfo().body;
      if (body && typeof body.clientId === 'string' && body.clientId &&
          Array.isArray(body.subscriptions) && body.subscriptions.length === 1 &&
          body.subscriptions[0] === '@oauth2') return e.next();
    }
  }
  const required = release();
  if (e.request.header.get('X-VaultContext-Release') !== required.release_id) {
    e.response.header().set('Cache-Control', 'no-store');
    return e.json(403, {
      status: 403,
      message: 'Install the matching VaultContext client and restart your unlocked session.',
      data: {code: 'client_upgrade_required', release_id: required.release_id,
        installation_url: required.installation_url},
    });
  }
  return e.next();
}

module.exports = {request, compatibility};
