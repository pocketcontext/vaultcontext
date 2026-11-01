"""Login defaults operate without exports and never select another account's token."""
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
from vaultcontext_client import cli, settings
from vaultcontext_client import auth

class SavedLogin(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = patch.dict(os.environ, {'XDG_STATE_HOME': self.tmp.name, 'XDG_CACHE_HOME': self.tmp.name + '/cache'}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        release = patch.object(auth, 'require_release')
        release.start()
        self.addCleanup(release.stop)
        self.cfg = {'url': 'https://one.example.com', 'email': 'one@example.com', 'password': None}
        self.response = {'token': 'synthetic-token', 'record': {'id': 'syntheticuser01', 'email': self.cfg['email'], 'collectionName': 'users'}}

    def parse(self, argv):
        return cli.parser().parse_args(argv)

    def sign_in(self):
        with patch.dict(os.environ, {'VAULTCONTEXT_USER_PASSWORD': 'synthetic-password'}), patch.object(auth, 'send', return_value=(200, self.response)), patch.object(auth, 'say'):
            cli.run(self.parse(['login', '--password', '--url', self.cfg['url'], '--email', self.cfg['email']]))

    def test_fresh_login_saved_config_and_permissions(self):
        self.sign_in()
        cfg = auth.config()
        self.assertEqual((cfg['url'], cfg['email']), (self.cfg['url'], self.cfg['email']))
        path = settings.directory('vaultcontext') / 'default.json'
        self.assertEqual(json.loads(path.read_text()), {'url': cfg['url'], 'email': cfg['email']})
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(auth.load_session(cfg)['token'], 'synthetic-token')

    def test_precedence_and_session_separation(self):
        self.sign_in()
        with patch.dict(os.environ, {'VAULTCONTEXT_URL': 'https://two.example.com', 'VAULTCONTEXT_USER_EMAIL': 'two@example.com'}):
            cfg = auth.config()
            self.assertEqual(cfg['url'], 'https://two.example.com')
            self.assertIsNone(auth.load_session(cfg))
            args = self.parse(['--url', self.cfg['url'], 'whoami', '--email', self.cfg['email']])
            cfg = auth.config(args)
            self.assertEqual(auth.load_session(cfg)['token'], 'synthetic-token')
        self.assertEqual(settings.read('vaultcontext')['email'], self.cfg['email'])

    def test_logout_retains_defaults_and_forget_removes_them(self):
        self.sign_in()
        cli.run(self.parse(['logout']))
        self.assertIsNone(auth.load_session(auth.config()))
        self.assertEqual(settings.read('vaultcontext')['url'], self.cfg['url'])
        cli.run(self.parse(['logout', '--forget']))
        self.assertEqual(settings.read('vaultcontext'), {})
        with self.assertRaises(auth.Fail):
            auth.config()

    def test_failed_login_preserves_default(self):
        self.sign_in()
        with patch.dict(os.environ, {'VAULTCONTEXT_USER_PASSWORD': 'synthetic-password'}), patch.object(auth, 'send', return_value=(401, {})):
            with self.assertRaises(auth.Fail):
                cli.run(self.parse(['login', '--password', '--url', 'https://other.example.com', '--email', 'other@example.com']))
        self.assertEqual(settings.read('vaultcontext')['url'], self.cfg['url'])

    def test_wrong_identity_does_not_save(self):
        response = dict(self.response, record=dict(self.response['record'], email='wrong@example.com'))
        with patch.object(auth, 'send', return_value=(200, response)):
            with self.assertRaises(auth.Fail):
                auth.login(dict(self.cfg, password='synthetic-password'))
        self.assertEqual(settings.read('vaultcontext'), {})
        self.assertIsNone(auth.load_session(self.cfg))

    def test_refresh_does_not_change_default(self):
        self.sign_in()
        other = dict(self.cfg, url='https://other.example.com')
        auth.auth_session(other, self.response, 'google')
        self.assertEqual(settings.read('vaultcontext')['url'], self.cfg['url'])

    def test_forget_other_account_keeps_default(self):
        self.sign_in()
        cli.run(self.parse(['logout', '--forget', '--email', 'other@example.com']))
        self.assertEqual(settings.read('vaultcontext')['email'], self.cfg['email'])

    def test_saved_session_failure_does_not_change_default(self):
        self.sign_in()
        with patch.object(auth, 'save_session', return_value=False), patch.object(auth, 'send', return_value=(200, self.response)):
            other = dict(self.cfg, url='https://other.example.com', password='synthetic')
            saved = auth.login(other)
            with self.assertRaises(auth.Fail):
                auth.remember_login(other, saved)
        self.assertEqual(settings.read('vaultcontext')['url'], self.cfg['url'])

    def test_invalid_or_unsafe_defaults_fail_closed(self):
        self.sign_in()
        path = settings.directory('vaultcontext') / 'default.json'
        path.chmod(0o644)
        with self.assertRaises(auth.Fail):
            auth.config()
        path.chmod(0o600)
        path.write_text('{bad')
        with self.assertRaises(auth.Fail):
            auth.config()
        path.unlink()
        path.symlink_to(Path(self.tmp.name) / 'missing')
        with self.assertRaises(auth.Fail):
            auth.config()

    def test_remote_http_rejected_before_auth(self):
        with patch.object(auth, 'send') as send:
            with self.assertRaises(auth.Fail):
                auth.config(self.parse(['login', '--google', '--url', 'http://remote.example.com', '--email', self.cfg['email']]))
            send.assert_not_called()

if __name__ == '__main__':
    unittest.main()
