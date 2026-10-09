"""Synthetic OAuth ordering checks; no browser, Google account or live service."""
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class OAuthPopup(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node required for UI runtime checks')
    def test_callback_cancellation_and_cleanup(self):
        program = r"""
const vm = require('node:vm'), fs = require('node:fs'), assert = require('node:assert/strict');
const source = fs.readFileSync('pb_public/demo/app.js', 'utf8');
const login = source.slice(source.indexOf('function googleLogin('), source.indexOf('function showOnboarding('));
const tick = () => new Promise(resolve => setImmediate(resolve));
async function fixture() {
  const timers = new Set(), intervals = new Set(), requests = [], streams = [];
  let exchange;
  const popup = {closed: true, closes: 0, close() { this.closes++; }, location: {href: ''}};
  const context = {
    URL, Error, JSON, location: {origin: 'https://demo.example'},
    cancelGoogleButton: {hidden: true}, cancelGoogleLogin: null,
    setTimeout: fn => {timers.add(fn); return fn;}, clearTimeout: fn => timers.delete(fn),
    setInterval: fn => {intervals.add(fn); return fn;}, clearInterval: fn => intervals.delete(fn),
    EventSource: class {
      constructor() {this.listeners = {}; this.closed = false; streams.push(this);}
      addEventListener(name, fn) {this.listeners[name] = fn;}
      close() {this.closed = true;}
    },
    api: async (path, body) => {
      requests.push({path, body});
      if (path.endsWith('auth-methods')) return {oauth2: {providers: [{name: 'google',
        authURL: 'https://accounts.google.com/o/oauth2/auth?client_id=synthetic', codeVerifier: 'verifier'}]}};
      if (path === '/api/realtime') return {};
      return new Promise(resolve => {exchange = resolve;});
    },
  };
  vm.createContext(context); vm.runInContext(login, context);
  let outcome;
  context.googleLogin(popup).then(value => outcome = {value}, error => outcome = {error});
  await tick();
  const stream = streams[0];
  await stream.listeners.PB_CONNECT({data: JSON.stringify({clientId: 'synthetic-state'})});
  const callback = (state = 'synthetic-state', error = '') => stream.listeners['@oauth2']({
    data: JSON.stringify({state, code: 'synthetic-code', error})});
  const result = {token: 'synthetic-token', record: {id: 'synthetic', collectionName: 'users', email: 'demo@example.com'}};
  return {context, popup, timers, intervals, requests, stream, callback, result,
    outcome: () => outcome, complete: () => exchange(result)};
}
(async () => {
  // COOP-severed handles and successful redirects can both appear closed before SSE.
  let f = await fixture();
  for (const poll of f.intervals) poll();
  await tick();
  assert.equal(f.outcome(), undefined, 'A closed popup handle must not cancel OAuth');
  assert.equal(f.context.cancelGoogleButton.hidden, false);
  assert.equal(new URL(f.popup.location.href).searchParams.get('state'), 'synthetic-state');
  const pending = f.callback();
  await f.callback(); // duplicate callback must not exchange the code again
  f.complete(); await pending; await tick();
  assert.equal(f.outcome().value.token, 'synthetic-token');
  assert.equal(f.requests.filter(r => r.path.endsWith('auth-with-oauth2')).length, 1);
  assert.equal(f.stream.closed, true); assert.equal(f.timers.size, 0);
  assert.equal(f.context.cancelGoogleButton.hidden, true);
  assert.equal(f.context.cancelGoogleLogin, null);

  f = await fixture(); f.context.cancelGoogleLogin(); await f.callback(); await tick();
  assert.match(f.outcome().error.message, /cancelled/);
  assert.equal(f.requests.filter(r => r.path.endsWith('auth-with-oauth2')).length, 0);
  assert.equal(f.stream.closed, true);

  f = await fixture(); const cancelledExchange = f.callback();
  f.context.cancelGoogleLogin(); f.complete(); await cancelledExchange; await tick();
  assert.match(f.outcome().error.message, /cancelled/);

  f = await fixture(); for (const timeout of f.timers) timeout(); await tick();
  assert.match(f.outcome().error.message, /timed out/); assert.equal(f.stream.closed, true);

  for (const [state, error] of [['wrong-state', ''], ['synthetic-state', 'access_denied']]) {
    f = await fixture(); await f.callback(state, error); await tick();
    assert.match(f.outcome().error.message, /not completed/);
    assert.equal(f.requests.filter(r => r.path.endsWith('auth-with-oauth2')).length, 0);
  }
  f = await fixture(); f.stream.onerror(); await tick();
  assert.match(f.outcome().error.message, /interrupted/); assert.equal(f.stream.closed, true);
})().catch(error => {console.error(error); process.exitCode = 1;});
"""
        subprocess.run(['node', '-e', program], cwd=ROOT, check=True)


if __name__ == '__main__':
    unittest.main()
