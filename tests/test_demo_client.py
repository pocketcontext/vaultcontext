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
