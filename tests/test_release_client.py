"""Exact release checks are fail-closed and never replay an operation."""
import io
import json
import unittest
import urllib.error
from unittest.mock import Mock, patch

from vaultcontext_client import auth, cli


class ReleaseTests(unittest.TestCase):
    def test_preflight_accepts_only_matching_release(self):
        for response in ((200, {'release_id': 'older'}), (404, {})):
            with self.subTest(response=response), patch.object(auth, 'send', return_value=response):
                with self.assertRaises(auth.UpgradeRequired):
                    auth.require_release({'url': 'https://synthetic.example'})
        with patch.object(auth, 'send', return_value=(200, {'release_id': auth.RELEASE_ID})):
            auth.require_release({'url': 'https://synthetic.example'})

    def test_unavailable_discovery_does_not_claim_upgrade(self):
        for response in ((503, None), (429, {}), (200, {})):
            with patch.object(auth, 'send', return_value=response):
                with self.assertRaises(auth.Fail) as failure:
                    auth.require_release({})
                self.assertNotIsInstance(failure.exception, auth.UpgradeRequired)

    def test_transport_sends_release_and_handles_upgrade_without_retry(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.status = 200
        response.read.return_value = b'{}'
        with patch.object(auth.opener, 'open', return_value=response) as request:
            auth.send({'url': 'https://synthetic.example'}, 'GET', '/api/context/schema')
            self.assertEqual(request.call_args.args[0].get_header('X-vaultcontext-release'), auth.RELEASE_ID)
        body = json.dumps({'data': {'code': 'client_upgrade_required'}, 'message': 'PRIVATE SERVER CONTENT'}).encode()
        error = urllib.error.HTTPError('https://synthetic.example', 403, '', {}, io.BytesIO(body))
        with patch.object(auth.opener, 'open', side_effect=error) as request, patch.object(auth, 'login') as login:
            with self.assertRaises(auth.UpgradeRequired) as failure:
                auth.send({'url': 'https://synthetic.example'}, 'POST', '/api/collections/vault_actions/records', {})
            request.assert_called_once()
            login.assert_not_called()
            self.assertNotIn('PRIVATE SERVER CONTENT', str(failure.exception))

    def test_worker_checks_before_file_or_key_operation(self):
        with patch.object(auth, 'require_release', side_effect=auth.UpgradeRequired()), patch.object(cli.crypto, 'read_file') as read:
            with self.assertRaises(auth.UpgradeRequired):
                cli.execute({}, {}, 'synthetic', {'command': 'save'})
            read.assert_not_called()

    def test_oauth_preserves_upgrade_guidance(self):
        with patch.object(auth, 'send', side_effect=auth.UpgradeRequired()):
            with self.assertRaises(auth.UpgradeRequired):
                auth.oauth_send({}, 'POST', '/api/collections/users/auth-refresh')

    def test_local_lock_does_not_need_compatible_server(self):
        args = cli.parser().parse_args(['lock'])
        with patch.object(auth, 'config', return_value={}), patch.object(auth, 'require_release') as check, patch.object(cli.session, 'stop', return_value={'locked': True}):
            self.assertEqual(cli.run(args), {'locked': True})
            check.assert_not_called()


if __name__ == '__main__':
    unittest.main()
