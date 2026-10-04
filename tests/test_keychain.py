"""Synthetic bridge and lifecycle checks; never access the user's Keychain."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from vaultcontext_client import cli, keychain


CFG = {'url': 'https://vault.example.test', 'email': 'synthetic@example.test'}
ACCOUNT = 'syntheticuserid1'
SECRET = 'synthetic vault passphrase'


class BridgeTests(unittest.TestCase):
    def call(self, response, code=0, command='get', **kwargs):
        with patch.object(keychain, 'require_helper', return_value=Path('/synthetic/helper')), \
                patch.object(keychain.subprocess, 'run', return_value=subprocess.CompletedProcess(
                    [], code, json.dumps(response).encode(), b'sensitive helper stderr')) as run:
            result = keychain.call(CFG, ACCOUNT, command, **kwargs)
            return result, run.call_args

    def test_secret_only_in_private_pipes(self):
        result, call = self.call({'ok': True}, command='store', passphrase=SECRET)
        self.assertIsNone(result)
        self.assertEqual(call.args[0], ['/synthetic/helper', 'store'])
        self.assertNotIn(SECRET, repr(call.args))
        self.assertNotIn(SECRET, repr(call.kwargs['env']))
        self.assertEqual(json.loads(call.kwargs['input']), {
            'origin': CFG['url'], 'account': ACCOUNT, 'passphrase': SECRET})
        self.assertEqual(call.kwargs['stdout'], subprocess.PIPE)
        self.assertEqual(call.kwargs['stderr'], subprocess.PIPE)
        self.assertTrue(call.kwargs['close_fds'])
        self.assertNotIn('shell', call.kwargs)

    def test_retrieval_and_safe_errors(self):
        self.assertEqual(self.call({'ok': True, 'passphrase': SECRET})[0], SECRET)
        for response, code in (({'ok': False, 'error': SECRET}, 1),
                               ({'ok': True, 'passphrase': SECRET}, 1),
                               ({'ok': True}, 0), ({'ok': True, 'passphrase': ''}, 0),
                               ({'ok': True, 'passphrase': 'a' * 1025}, 0),
                               ({'ok': False, 'error': {'secret': SECRET}}, 1)):
            with self.subTest(response=response):
                with self.assertRaises(cli.auth.Fail) as error:
                    self.call(response, code)
                self.assertNotIn(SECRET, str(error.exception))
                self.assertNotIn('sensitive helper stderr', str(error.exception))

    def test_cancellation_and_missing_entry(self):
        for code, message in (('cancelled', 'cancelled'), ('not_found', 'keychain-enroll'),
                              ('interaction_not_allowed', 'interactive macOS')):
            with self.assertRaisesRegex(cli.auth.Fail, message):
                self.call({'ok': False, 'error': code}, 1)

    def test_timeout_does_not_expose_captured_secret(self):
        with patch.object(keychain, 'require_helper', return_value=Path('/synthetic/helper')), \
                patch.object(keychain.subprocess, 'run', side_effect=subprocess.TimeoutExpired(
                    'helper', 120, output=SECRET.encode(), stderr=SECRET.encode())):
            with self.assertRaises(cli.auth.Fail) as error:
                keychain.call(CFG, ACCOUNT, 'get')
            self.assertNotIn(SECRET, str(error.exception))

    def test_origin_scoping(self):
        self.assertEqual(keychain.origin({'url': 'https://VAULT.example.test:443/'}), CFG['url'])
        self.assertEqual(keychain.origin({'url': 'https://vault.example.test:8443'}), CFG['url'] + ':8443')
        self.assertEqual(keychain.origin({'url': 'http://[::1]:8090'}), 'http://[::1]:8090')
        for url in ('https://vault.example.test/path', 'https://user@vault.example.test',
                    'https://vault.example.test?x=1', 'https://vault.example.test#fragment'):
            with self.assertRaises(cli.auth.Fail):
                keychain.origin({'url': url})

    def test_unsupported_platform_never_starts_helper(self):
        with patch.object(keychain.sys, 'platform', 'linux'), patch.object(keychain.subprocess, 'run') as run:
            with self.assertRaises(cli.auth.Fail):
                keychain.call(CFG, ACCOUNT, 'get')
            run.assert_not_called()

    def test_unsafe_helper_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            helper = Path(directory) / 'helper'
            helper.write_text('synthetic')
            helper.chmod(0o777)
            with patch.object(keychain.sys, 'platform', 'darwin'), \
                    patch.object(keychain, 'helper_path', return_value=helper):
                with self.assertRaisesRegex(cli.auth.Fail, 'permissions'):
                    keychain.require_helper()
                helper.unlink()
                helper.symlink_to('/usr/bin/true')
                with self.assertRaisesRegex(cli.auth.Fail, 'permissions'):
                    keychain.require_helper()


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.identity = cli.crypto.generate_identity()
        self.bundle = cli.crypto.wrap_identity(self.identity, SECRET, ACCOUNT)
        for name, value in (
                ('whoami', ACCOUNT), ('one', {'key_bundle': json.dumps(self.bundle)}),
                ('prompt_passphrase', SECRET), ('verify_user', None)):
            p = patch.object(cli, name, return_value=value)
            setattr(self, name, p.start())
            self.addCleanup(p.stop)
        self.helper = patch.object(keychain, 'require_helper', return_value=Path('/synthetic/helper')).start()
        self.addCleanup(patch.stopall)

    def test_enrollment_verifies_passphrase_and_fingerprint_before_store(self):
        with patch.object(keychain, 'call') as call, patch.object(cli, 'session_call') as session:
            self.assertEqual(cli.keychain_enroll(CFG), {'keychain_enrolled': True})
            self.verify_user.assert_called_once_with(CFG, ACCOUNT, cli.crypto.fingerprint(
                cli.crypto.public_identity(self.identity)))
            call.assert_called_once_with(CFG, ACCOUNT, 'store', SECRET)
            session.assert_not_called()

    def test_invalid_passphrase_never_enrolls(self):
        self.prompt_passphrase.return_value = 'wrong synthetic passphrase'
        with patch.object(keychain, 'call') as call:
            with self.assertRaises(Exception):
                cli.keychain_enroll(CFG)
            call.assert_not_called()
            self.verify_user.assert_not_called()

    def test_fingerprint_failure_never_enrolls(self):
        self.verify_user.side_effect = cli.auth.Fail(1, 'Synthetic fingerprint mismatch')
        with patch.object(keychain, 'call') as call:
            with self.assertRaises(cli.auth.Fail):
                cli.keychain_enroll(CFG)
            call.assert_not_called()

    def test_stale_or_cancelled_credential_keeps_existing_session(self):
        for value in ('stale synthetic passphrase', cli.auth.Fail(1, 'Keychain authentication cancelled')):
            with patch.object(keychain, 'call', **({'side_effect': value} if isinstance(value, Exception)
                                                   else {'return_value': value})), \
                    patch.object(cli, 'session_call') as session, patch.object(cli.session, 'start') as start:
                with self.assertRaises(cli.auth.Fail):
                    cli.unlock(CFG, 30, use_keychain=True)
                self.prompt_passphrase.assert_not_called()
                session.assert_not_called()
                start.assert_not_called()

    def test_keychain_unlock_uses_existing_memory_session_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'session.sock'
            with patch.object(cli, 'socket_path', return_value=path), \
                    patch.object(keychain, 'call', return_value=SECRET) as call, \
                    patch.object(cli.session, 'start', return_value={'unlocked': True, 'expires_in': 30}) as start:
                self.assertEqual(cli.unlock(CFG, 30, use_keychain=True), {'unlocked': True, 'expires_in': 30})
                call.assert_called_once_with(CFG, ACCOUNT, 'get')
                self.prompt_passphrase.assert_not_called()
                start.assert_called_once_with(CFG, self.identity, ACCOUNT, 30)

    def test_forget_requires_authenticated_id_and_does_not_lock(self):
        with patch.object(cli.auth, 'config', return_value=CFG), patch.object(keychain, 'call') as call, \
                patch.object(cli, 'session_call') as session:
            self.assertEqual(cli.run(cli.parser().parse_args(['keychain-forget'])), {'keychain_forgotten': True})
            call.assert_called_once_with(CFG, ACCOUNT, 'delete')
            session.assert_not_called()

    def test_default_remains_terminal_and_keychain_is_explicit(self):
        self.assertFalse(cli.parser().parse_args(['unlock']).keychain)
        self.assertTrue(cli.parser().parse_args(['unlock', '--keychain']).keychain)


if __name__ == '__main__':
    unittest.main()
