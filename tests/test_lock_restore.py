"""A failed memory worker or retired lease must never publish a partial recovery set."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from vaultcontext_client import cli


class LockRestoreTests(TestCase):
    def test_restore_requires_a_complete_verified_set_and_current_lease(self):
        vault = 'v'*15
        entries = [{'id':c*15, 'revision':1, 'version':c*15, 'archived':False} for c in 'ab']
        grant = {'lease_id':'l'*15, 'generation':1, 'documents':entries}
        for fail_at in ('download', 'renew'):
            with self.subTest(fail_at=fail_at), TemporaryDirectory() as tmp:
                destination = Path(tmp)/'restore'
                destination.mkdir()
                args = cli.parser().parse_args(['lock','acquire',vault,'--restore-to',str(destination)])

                def worker(cfg, payload):
                    if payload['command'] == 'unlock-probe':
                        return {'unlocked': True}
                    if fail_at == 'download' and payload['document'] == entries[1]['id']:
                        raise FileNotFoundError('sensitive local detail')
                    Path(payload['to']).write_bytes(b'synthetic fixture')

                def action(cfg, op, payload):
                    if op == 'lock_acquire':
                        return grant
                    self.assertEqual(op, 'lock_renew')
                    raise cli.LockRefused({'code':'lock_lost'})

                with patch.object(cli, 'session_call', side_effect=worker), patch.object(cli, 'action', side_effect=action):
                    result = cli.run_lock({}, args)
                self.assertTrue(result['restore_failed'])
                self.assertEqual(result['fence'], '1:' + 'l'*15)
                self.assertNotIn('sensitive local detail', str(result))
                self.assertEqual(list(destination.iterdir()), [])
                self.assertEqual(list(destination.parent.iterdir()), [destination])
