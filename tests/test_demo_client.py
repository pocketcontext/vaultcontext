import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vaultcontext_client import auth, cli, demo


class DemoClientTests(unittest.TestCase):
    def test_production_compatibility_and_fail_closed_status(self):
        for response in ((404, {}), (200, {'enabled': False})):
            with patch.object(auth, 'send', return_value=response):
                self.assertIsNone(demo.discover({}))
        for response in ((503, {}), (200, {}), (200, {'enabled': True, 'generation': 'x'})):
            with patch.object(auth, 'send', return_value=response), self.assertRaises(auth.Fail):
                demo.discover({})

    def test_worker_generation_change_rejected_before_file_access(self):
        cfg = {'_demo_generation': '2026-10-09'}
        for current in (None, {'generation': '2026-10-10'}):
            with patch.object(demo, 'discover', return_value=current), patch.object(cli.crypto, 'read_file') as read:
                with self.assertRaises(auth.Fail):
                    cli.execute(cfg, {}, 'synthetic', {'command': 'save'})
                read.assert_not_called()

    def test_demo_cannot_change_passphrase_or_enroll_keychain(self):
        info = {'generation': '2099-10-09', 'resetAt': '2099-10-10T00:00:00Z'}
        for command in ('share', 'change-passphrase', 'keychain-enroll'):
            with patch.object(demo, 'discover', return_value=info), self.assertRaises(auth.Fail):
                demo.configure({}, command)

    def test_expired_demo_rejected(self):
        with patch.object(auth, 'send', return_value=(200, {
            'enabled': True, 'generation': '2000-01-01', 'resetAt': '2000-01-02T00:00:00Z'
        })), self.assertRaises(auth.Fail):
            demo.discover({})

    def test_demo_errors_do_not_mislabel_conflict_or_outage_as_enrollment(self):
        cfg = {'url': 'https://demo.example', '_demo_generation': '2099-10-09'}
        for status, expected in ((401, 'sign-in expired'), (403, 'same Google account'),
                                 (409, 'state changed'), (503, 'temporarily unavailable')):
            with self.subTest(status=status), patch.object(auth, 'call', return_value=(status, {'message': 'PRIVATE_RESPONSE'})):
                with self.assertRaises(auth.Fail) as error:
                    cli.request(cfg, 'POST', '/api/collections/vault_actions/records', {'op': 'vault_create'})
                self.assertIn(expected, str(error.exception))
                self.assertNotIn('PRIVATE_RESPONSE', str(error.exception))
                self.assertNotIn('Complete enrollment', str(error.exception))

    def test_duplicate_init_race_reports_existing_identity(self):
        for cfg in ({}, {'url': 'https://demo.example', '_demo_generation': '2099-10-09'}):
            with patch.object(auth, 'call', return_value=(409, {})):
                with self.assertRaises(auth.Fail) as error:
                    cli.action(cfg, 'identity_init', {})
                self.assertIn('vaultcontext unlock', str(error.exception))
                self.assertNotIn('enrollment', str(error.exception))

    def test_init_checks_access_and_existing_identity_before_passphrase(self):
        from types import SimpleNamespace
        cfg = {'url': 'https://demo.example', '_demo_generation': '2099-10-09'}
        for result in ([{'id': 'synthetic'}], auth.Fail(1, 'Demo access denied')):
            with patch.object(auth, 'config', return_value=cfg), patch.object(demo, 'configure'), \
                 patch.object(cli, 'whoami', return_value='synthetic'), \
                 patch.object(cli, 'rows', side_effect=result if isinstance(result, Exception) else None, return_value=result) as rows, \
                 patch.object(cli, 'prompt_passphrase') as prompt, \
                 patch.object(cli.crypto, 'generate_identity') as generate, \
                 patch.object(cli, 'action') as action:
                with self.assertRaises(auth.Fail):
                    cli.run(SimpleNamespace(command='init'))
                rows.assert_called_once_with(cfg, 'identities', "account='synthetic'")
                prompt.assert_not_called(); generate.assert_not_called(); action.assert_not_called()

    def test_pins_reject_insecure_file_directory_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / 'private'
            directory.mkdir(mode=0o700)
            path = directory / 'pins.json'
            path.write_text(json.dumps({'synthetic': 'fingerprint'}))
            path.chmod(0o600)
            with patch.object(cli, 'pin_path', return_value=path):
                self.assertEqual(cli.pins({}), {'synthetic': 'fingerprint'})
                path.chmod(0o644)
                with self.assertRaises(auth.Fail): cli.pins({})
                path.chmod(0o600)
                directory.chmod(0o755)
                with self.assertRaises(auth.Fail): cli.pins({})
                directory.chmod(0o700)
                path.unlink()
                path.symlink_to('/dev/null')
                with self.assertRaises(OSError): cli.pins({})


if __name__ == '__main__':
    unittest.main()
