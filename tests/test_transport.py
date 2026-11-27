"""Keep-alive connection reuse, read-only replay and never-replayed writes."""
import http.server
import json
import os
import threading
import time
import unittest
from unittest.mock import patch

from vaultcontext_client import auth, cli


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        server = self.server
        with server.lock:
            server.connections += 1
            self.connection_number = server.connections
        self.handled = 0

    def respond(self, status, body, headers=()):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)

    def handle_request(self):
        server = self.server
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length) if length else b''
        self.handled += 1
        server.requests.append((self.command, self.path, self.connection_number, self.headers.get('X-VaultContext-Release'), body))
        # Simulate a keep-alive connection closed by the server just as the next
        # request arrives: no response bytes are ever written.
        if server.drop_second and self.handled == 2:
            self.close_connection = True
            return
        if self.path == '/redirect':
            return self.respond(302, {}, [('Location', 'https://elsewhere.invalid/')])
        if self.path == '/big':
            raw = b'x' * 300000
            self.send_response(200)
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        self.respond(200, {'path': self.path})
        if server.close_after:
            self.close_connection = True  # Without announcing it, like an idle timeout.

    do_GET = do_POST = do_PATCH = do_DELETE = handle_request


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # Expected resets from deliberately dropped connections.

    def __init__(self):
        super().__init__(('127.0.0.1', 0), Handler)
        self.lock = threading.Lock()
        self.connections = 0
        self.requests = []
        self.drop_second = False
        self.close_after = False


class TransportTests(unittest.TestCase):
    def setUp(self):
        for name in ('http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY'):
            os.environ.pop(name, None)
        env = patch.dict(os.environ, {'no_proxy': '*', 'NO_PROXY': '*'})
        env.start()
        self.addCleanup(env.stop)
        auth.close_connections()
        auth._proxied_hosts.clear()
        self.addCleanup(auth.close_connections)
        self.server = Server()
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.cfg = {'url': f'http://127.0.0.1:{self.server.server_address[1]}'}

    def test_sequential_requests_share_one_connection(self):
        for index in range(5):
            status, data = auth.send(self.cfg, 'POST', '/api/context/query', {'sql': f'SELECT {index}'}, 'token')
            self.assertEqual((status, data), (200, {'path': '/api/context/query'}))
        auth.send(self.cfg, 'GET', '/api/vaultcontext/compatibility')
        self.assertEqual(self.server.connections, 1)
        self.assertEqual({request[3] for request in self.server.requests}, {auth.RELEASE_ID})

    def test_reused_connection_failure_replays_reads_once(self):
        auth.send(self.cfg, 'GET', '/first')
        self.server.drop_second = True
        for method, path, body in (('GET', '/api/context/schema', None), ('POST', '/api/context/query', {'sql': 'SELECT 1'})):
            with self.subTest(method=method):
                before = len(self.server.requests)
                self.assertEqual(auth.send(self.cfg, method, path, body)[0], 200)
                attempts = self.server.requests[before:]
                self.assertEqual([r[1] for r in attempts], [path, path])
                self.assertNotEqual(attempts[0][2], attempts[1][2])

    def test_writes_are_never_replayed(self):
        for method, path in (('POST', '/api/collections/vault_actions/records'), ('PATCH', '/api/collections/x/records/y'),
                             ('DELETE', '/api/collections/x/records/y'), ('POST', '/api/files/token'),
                             ('POST', '/api/collections/users/auth-refresh')):
            with self.subTest(method=method, path=path):
                self.server.drop_second = False
                auth.close_connections()
                auth.send(self.cfg, 'GET', '/first')
                self.server.drop_second = True
                before = len(self.server.requests)
                with self.assertRaises(auth.Fail) as failure:
                    auth.send(self.cfg, method, path, {'op': 'save'}, 'secret-token')
                self.assertEqual([r[1] for r in self.server.requests[before:]], [path])
                self.assertNotIn('secret-token', str(failure.exception))
                self.assertEqual(auth._pool, {})

    def test_redirects_are_not_followed_and_connection_is_dropped_after_partial_read(self):
        with self.assertRaisesRegex(auth.Fail, 'redirects to https://elsewhere.invalid/'):
            auth.send(self.cfg, 'GET', '/redirect')
        self.assertEqual([r[1] for r in self.server.requests], ['/redirect'])
        status, _, raw = auth.http_request(self.cfg['url'] + '/big', limit=1000)
        self.assertEqual((status, len(raw)), (200, 1000))
        self.assertEqual(auth._pool, {})
        auth.send(self.cfg, 'GET', '/after')
        self.assertEqual(self.server.connections, 2)

    def test_idle_closed_connection_is_detected_before_a_write(self):
        self.server.close_after = True
        auth.send(self.cfg, 'GET', '/first')
        conn, _ = next(iter(auth._pool.values()))
        for _ in range(100):
            if not auth._quiet(conn.sock):
                break
            time.sleep(.01)
        self.server.close_after = False
        before = len(self.server.requests)
        self.assertEqual(auth.send(self.cfg, 'POST', '/api/collections/vault_actions/records', {'op': 'save'})[0], 200)
        self.assertEqual(len(self.server.requests) - before, 1)
        self.assertEqual(self.server.connections, 2)

    def test_stale_idle_connection_is_not_reused(self):
        auth.send(self.cfg, 'GET', '/first')
        with patch.object(auth.time, 'monotonic', return_value=auth.time.monotonic() + auth.IDLE_REUSE + 1):
            auth.send(self.cfg, 'POST', '/api/collections/vault_actions/records', {'op': 'save'})
        self.assertEqual(self.server.connections, 2)

    def test_protected_download_reuses_connection(self):
        import hashlib
        body = json.dumps({'path': '/api/files/version_chunks/c/f?token=file-token'}).encode()
        chunk = {'id': 'c', 'ciphertext': 'f', 'sha256': hashlib.sha256(body).hexdigest()}
        with patch.object(cli, 'request', return_value={'token': 'file-token'}):
            cli.download_chunk(self.cfg, chunk)
            cli.download_chunk(self.cfg, chunk)
        self.assertEqual(self.server.connections, 1)
        self.assertEqual({r[3] for r in self.server.requests}, {auth.RELEASE_ID})

    def test_https_uses_verified_tls(self):
        connection = auth._new_connection(('https', 'synthetic.invalid', 443), 5)
        context = connection._context
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, auth.ssl.CERT_REQUIRED)


if __name__ == '__main__':
    unittest.main()
