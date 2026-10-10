"""Synthetic regressions backported from demo eadfcf6 and 8b8b177."""
import json
import io
import urllib.error
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vaultcontext_client import auth, cli, crypto


class IdentitySecurityTests(unittest.TestCase):
    def setUp(self):
        guard = patch.object(auth, 'require_release', create=True)
        guard.start()
        self.addCleanup(guard.stop)

    def test_duplicate_init_race_reports_existing_identity(self):
        with patch.object(auth, 'call', return_value=(409, {'message': 'PRIVATE'})):
            with self.assertRaises(auth.Fail) as error:
                cli.action({}, 'identity_init', {})
            self.assertIn('vaultcontext unlock', str(error.exception))
            self.assertNotIn('PRIVATE', str(error.exception))

    def test_init_preflight_prevents_prompt_keys_and_write(self):
        for result in ([{'id': 'synthetic'}], auth.Fail(1, 'Access denied')):
            with patch.object(auth, 'config', return_value={}), \
                 patch.object(cli, 'whoami', return_value='synthetic'), \
                 patch.object(cli, 'rows', side_effect=result if isinstance(result, Exception) else None, return_value=result) as rows, \
                 patch.object(cli, 'prompt_passphrase') as prompt, \
                 patch.object(crypto, 'generate_identity') as generate, \
                 patch.object(cli, 'action') as action:
                with self.assertRaises(auth.Fail):
                    cli.run(SimpleNamespace(command='init'))
                rows.assert_called_once_with({}, 'identities', "account='synthetic'")
                prompt.assert_not_called()
                generate.assert_not_called()
                action.assert_not_called()

    def test_replacement_signed_by_current_identity(self):
        identity = crypto.generate_identity()
        with patch.object(cli, 'one', return_value={'revision': 3}), \
             patch.object(crypto, 'wrap_identity', return_value={'synthetic': 'bundle'}), \
             patch.object(cli, 'action') as action:
            cli.execute({}, identity, 'synthetic', {'command': 'change-passphrase', 'new_passphrase': 'synthetic'})
        cfg, op, payload = action.call_args.args
        signature = payload.pop('signature')
        self.assertEqual(op, 'identity_rewrap')
        crypto.verify_manifest(crypto.public_identity(identity), dict(payload, account='synthetic', purpose='identity-rewrap'), signature)

    def test_pin_permissions_links_and_shape(self):
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
                hardlink = directory / 'hardlink'
                os.link(path, hardlink)
                with self.assertRaises(auth.Fail): cli.pins({})
                hardlink.unlink()
                for value in ([], {'synthetic': 1}):
                    path.write_text(json.dumps(value))
                    with self.assertRaises(auth.Fail): cli.pins({})
                path.unlink()
                path.symlink_to('/dev/null')
                with self.assertRaises(OSError): cli.pins({})

    def test_download_upgrade_race_does_not_suppress_upgrade_guidance(self):
        error = urllib.error.HTTPError('https://synthetic.invalid', 403, 'Forbidden', {},
            io.BytesIO(json.dumps({'data': {'code': 'client_upgrade_required'}, 'message': 'PRIVATE'}).encode()))
        with patch.object(cli, 'request', return_value={'token': 'synthetic'}), \
             patch.object(auth.opener, 'open', side_effect=error):
            with self.assertRaises(auth.UpgradeRequired) as caught:
                cli.download_chunk({'url': 'https://synthetic.invalid'}, {'id': 'synthetic', 'ciphertext': 'synthetic'})
        self.assertNotIn('PRIVATE', str(caught.exception))
