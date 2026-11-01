#!/usr/bin/env python3
"""Hosted identity renewals fail closed and keep direct fallback explicit."""
import os
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch
from vaultcontext_client import auth as cli
from vaultcontext_client import cli as commands, session as sessions


class IdentityError(Exception):
    pass


class IdentityClientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict(os.environ, {'VAULTCONTEXT_SESSION_DIR': self.tmp.name})
        env.start()
        self.addCleanup(env.stop)
        self.cfg = {'url': 'https://app.example.com', 'email': 'member@example.com', 'password': 'must-not-fallback'}
        self.response = {'token': 'synthetic-token', 'record': {'collectionName': 'users', 'id': 'user00000000001', 'email': self.cfg['email']}, 'meta': {'accessToken': 'never-store'}}
        self.identity = types.SimpleNamespace(IdentityError=IdentityError, login=Mock(), assertion=Mock(return_value='synthetic-assertion'))
        modules = patch.dict(sys.modules, {'pocketcontext_identity': self.identity})
        modules.start()
        self.addCleanup(modules.stop)

    def test_bare_login_selects_hosted_flow(self):
        args = commands.parser().parse_args(['login', '--no-browser'])
        self.assertFalse(args.google)
        self.assertFalse(args.password)
        self.assertTrue(commands.parser().parse_args(['login', '--google']).google)

    def test_exchange_checks_identity_and_only_saves_app_token(self):
        with patch.object(cli, 'oauth_send', return_value=(200, self.response)) as send:
            session = cli.identity_login(self.cfg, interactive=True, no_browser=True, timeout=60)
        self.identity.login.assert_called_once_with(self.cfg['email'], no_browser=True, timeout=60)
        self.identity.assertion.assert_called_once_with(self.cfg['email'], self.cfg['url'])
        self.assertEqual(send.call_args.args[2], '/api/context/auth-with-assertion')
        self.assertEqual(session['method'], 'identity')
        saved = cli.session_file(self.cfg).read_text()
        self.assertNotIn('synthetic-assertion', saved)
        self.assertNotIn('never-store', saved)
        self.assertEqual(cli.load_session(self.cfg), session)

    def test_wrong_account_never_saved(self):
        self.response['record']['email'] = 'other@example.com'
        with patch.object(cli, 'oauth_send', return_value=(200, self.response)), self.assertRaises(cli.Fail):
            cli.identity_login(self.cfg)
        self.assertIsNone(cli.load_session(self.cfg))

    def test_central_rejection_never_downgrades_or_sends_app_request(self):
        cli.save_session(self.cfg, {'url': self.cfg['url'], 'email': self.cfg['email'], 'method': 'identity', 'token': 'expired', 'refreshed_at': 0})
        self.identity.assertion.side_effect = IdentityError('secret provider detail')
        with patch.object(cli, 'login') as password, patch.object(cli, 'google_login') as google, patch.object(cli, 'send') as send:
            with self.assertRaises(cli.Fail) as caught:
                cli.call(self.cfg, 'POST', '/api/context/query', {'sql': 'SELECT 1'})
        self.assertNotIn('secret provider detail', str(caught.exception))
        password.assert_not_called()
        google.assert_not_called()
        send.assert_not_called()
        self.identity.login.assert_not_called()

    def test_expired_session_renews_through_identity_before_request(self):
        cli.save_session(self.cfg, {'url': self.cfg['url'], 'email': self.cfg['email'], 'method': 'identity', 'token': 'expired', 'refreshed_at': 0})
        with patch.object(cli, 'oauth_send', return_value=(200, self.response)) as exchange, patch.object(cli, 'send', return_value=(200, {'ok': True})) as send:
            self.assertEqual(cli.call(self.cfg, 'GET', '/api/context/schema'), (200, {'ok': True}))
        self.assertEqual(exchange.call_args.args[2], '/api/context/auth-with-assertion')
        self.assertEqual(send.call_args.args[4], 'synthetic-token')
        self.identity.login.assert_not_called()

    def test_whoami_refresh_uses_new_identity_token_without_extending_it(self):
        cli.save_session(self.cfg, {'url': self.cfg['url'], 'email': self.cfg['email'], 'method': 'identity', 'token': 'previous', 'refreshed_at': 0})
        with patch.object(cli, 'oauth_send', return_value=(200, self.response)) as exchange, patch.object(cli, 'send', return_value=(200, self.response)) as send:
            status, data = cli.call(self.cfg, 'POST', '/api/collections/users/auth-refresh')
        self.assertEqual(status, 200)
        self.assertEqual(data['record']['email'], self.cfg['email'])
        self.assertEqual(exchange.call_args.args[2], '/api/context/auth-with-assertion')
        self.assertEqual(send.call_args.args[4], 'synthetic-token')
        self.identity.login.assert_not_called()

    def test_rejected_fresh_app_token_never_downgrades(self):
        session = {'method': 'identity', 'token': 'fresh', 'refreshed_at': time.time()}
        with patch.object(cli, 'load_session', return_value=session), patch.object(cli, 'oauth_refresh_needed', return_value=False), patch.object(cli, 'send', return_value=(401, {})), patch.object(cli, 'login') as password:
            with self.assertRaises(cli.Fail):
                cli.call(self.cfg, 'POST', '/api/context/query', {'sql': 'SELECT 1'})
        password.assert_not_called()
        self.identity.assertion.assert_not_called()


    def test_unlocked_account_cannot_change_on_renewal(self):
        self.cfg['_expected_account'] = 'original0000001'
        cli.save_session(self.cfg, {'url': self.cfg['url'], 'email': self.cfg['email'], 'method': 'identity', 'account': 'original0000001', 'token': 'expired', 'refreshed_at': 0})
        with patch.object(cli, 'oauth_send', return_value=(200, self.response)), patch.object(cli, 'send') as send:
            with self.assertRaises(cli.Fail):
                cli.call(self.cfg, 'POST', '/api/context/query', {'sql': 'SELECT 1'})
        send.assert_not_called()
        self.assertEqual(cli.load_session(self.cfg)['account'], 'original0000001')

    def test_unlocked_session_rejects_replaced_cache_account(self):
        self.cfg['_expected_account'] = 'original0000001'
        session = {'method': 'identity', 'token': 'fresh', 'account': 'other0000000001', 'refreshed_at': time.time()}
        with patch.object(cli, 'load_session', return_value=session), patch.object(cli, 'oauth_refresh_needed', return_value=False), patch.object(cli, 'send') as send:
            with self.assertRaises(cli.Fail):
                cli.call(self.cfg, 'POST', '/api/context/query', {'sql': 'SELECT 1'})
        send.assert_not_called()

    def test_unlocked_session_without_cache_does_not_reauthenticate(self):
        self.cfg['_expected_account'] = 'original0000001'
        with patch.object(cli, 'login') as password, patch.object(cli, 'identity_login') as identity:
            with self.assertRaises(cli.Fail):
                cli.call(self.cfg, 'POST', '/api/context/query', {'sql': 'SELECT 1'})
        password.assert_not_called(); identity.assert_not_called()

    def test_operation_carries_unlocked_account_constraint(self):
        with patch.object(cli, 'require_release'), patch.object(commands, 'rows', return_value=[]) as rows:
            self.assertEqual(commands.execute(self.cfg, {}, 'original0000001', {'command': 'vaults'}), [])
        self.assertEqual(rows.call_args.args[0]['_expected_account'], 'original0000001')
        self.assertNotIn('_expected_account', self.cfg)

    def test_worker_renewal_does_not_extend_unlock_deadline(self):
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        server = Mock()
        server.accept.return_value = (connection, None)
        # Two authenticated operations complete before the fixed deadline. Even
        # successful authentication renewal must not permit a third operation.
        with patch.object(sessions.time, 'monotonic', side_effect=[0, 0, 99, 99, 101]), patch.object(commands, 'recv_frame', return_value={'command': 'vaults'}), patch.object(commands, 'execute', return_value=[]) as execute:
            sessions.serve(server, self.cfg, {}, 'original0000001', 100, peer_uid=lambda _: os.getuid())
        self.assertEqual(execute.call_count, 2)
        self.assertEqual(server.accept.call_count, 2)

    def test_logout_stops_memory_worker_and_keeps_shared_identity(self):
        with patch.object(cli, 'config', return_value=self.cfg), patch.object(sessions, 'stop', return_value={'locked': True}) as stop:
            commands.run(commands.parser().parse_args(['logout']))
        stop.assert_called_once_with(self.cfg, logout=True)
        self.identity.login.assert_not_called(); self.identity.assertion.assert_not_called()


if __name__ == '__main__':
    unittest.main()
