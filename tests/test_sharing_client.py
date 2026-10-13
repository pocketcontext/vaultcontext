"""Synthetic sharing identity and first-use trust regression checks."""
from pathlib import Path
import fcntl
import os
import tempfile
import unittest
from unittest.mock import patch

from vaultcontext_client import cli


class SharingClientTests(unittest.TestCase):
    def setUp(self):
        guard = patch.object(cli.auth, 'require_release')
        guard.start()
        self.addCleanup(guard.stop)

    def test_first_use_pins_and_explicit_verification_cannot_replace_pin(self):
        first = cli.crypto.public_identity(cli.crypto.generate_identity())
        second = cli.crypto.public_identity(cli.crypto.generate_identity())
        def directory(public):
            return dict(public_key=public['enc_public'], signing_key=public['sign_public'],
                        fingerprint=cli.crypto.fingerprint(public))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'pins.json'
            with patch.object(cli, 'pin_path', return_value=path), patch.object(cli, 'one', return_value=directory(first)):
                self.assertEqual(cli.verify_user({}, 'alice'), first)
                self.assertEqual(cli.pins({}), {'alice': cli.crypto.fingerprint(first)})
                self.assertEqual(cli.verify_user({}, 'alice'), first)
                with self.assertRaises(cli.auth.Fail):
                    cli.verify_user({}, 'alice', 'wrong')
            with patch.object(cli, 'pin_path', return_value=path), patch.object(cli, 'one', return_value=directory(second)):
                for fingerprint in (None, cli.crypto.fingerprint(second)):
                    with self.assertRaisesRegex(cli.auth.Fail, 'changed public key'):
                        cli.verify_user({}, 'alice', fingerprint)
                self.assertEqual(cli.pins({})['alice'], cli.crypto.fingerprint(first))

    def test_pin_write_rereads_other_process_additions_and_conflicts(self):
        public = cli.crypto.public_identity(cli.crypto.generate_identity())
        actual = cli.crypto.fingerprint(public)
        row = dict(public_key=public['enc_public'], signing_key=public['sign_public'], fingerprint=actual)
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(cli, 'pin_path', return_value=Path(temporary) / 'pins.json'), \
                 patch.object(cli, 'one', return_value=row):
                with patch.object(cli, 'pins', side_effect=[{}, {'bob': 'existing'}]):
                    cli.verify_user({}, 'alice')
                self.assertEqual(cli.pins({}), {'bob': 'existing', 'alice': actual})
                with patch.object(cli, 'pins', side_effect=[{}, {'alice': 'conflicting'}]):
                    with self.assertRaisesRegex(cli.auth.Fail, 'changed public key'):
                        cli.verify_user({}, 'alice')

    def test_first_use_rejects_unsafe_or_busy_pin_lock(self):
        public = cli.crypto.public_identity(cli.crypto.generate_identity())
        row = dict(public_key=public['enc_public'], signing_key=public['sign_public'],
                   fingerprint=cli.crypto.fingerprint(public))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'pins.json'
            lock = Path(str(path) + '.lock')
            lock.touch(mode=0o600)
            with patch.object(cli, 'pin_path', return_value=path), patch.object(cli, 'one', return_value=row):
                with lock.open('rb') as held:
                    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    with self.assertRaisesRegex(cli.auth.Fail, 'busy'):
                        cli.verify_user({}, 'alice')
                os.chmod(lock, 0o644)
                with self.assertRaisesRegex(cli.auth.Fail, 'Unsafe fingerprint lock'):
                    cli.verify_user({}, 'alice')
                self.assertFalse(path.exists())

    def test_repeat_share_confirms_backend_without_redistributing_keys(self):
        for status in ('pending', 'active'):
            with self.subTest(status=status), \
                 patch.object(cli, 'resolve_recipient', return_value=dict(id='recipient', email='alice@example.com')), \
                 patch.object(cli, 'one', return_value=dict(id='vault', revision=4)), \
                 patch.object(cli, 'rows', side_effect=[[dict(role='reader')], []]), \
                 patch.object(cli, 'verify_user') as verify, \
                 patch.object(cli, 'seal') as seal, \
                 patch.object(cli, 'action', return_value=dict(status=status, role='reader')) as action:
                result = cli.execute({}, {}, 'owner', dict(command='share', vault='vault', account='alice@example.com'))
                verify.assert_not_called()
                seal.assert_not_called()
                self.assertEqual(action.call_args.args[2]['envelopes'], [])
                self.assertEqual(action.call_args.args[2]['account'], 'recipient')
                self.assertEqual(result['email'], 'alice@example.com')
                self.assertEqual(result['scope'], 'whole-vault-and-retained-history')
                self.assertEqual(result['status'], status)

    def test_share_refuses_implicit_role_change(self):
        with patch.object(cli, 'resolve_recipient', return_value=dict(id='recipient', email='alice@example.com')), \
             patch.object(cli, 'one', return_value=dict(id='vault', revision=4)), \
             patch.object(cli, 'rows', side_effect=[[dict(role='editor')], []]), \
             patch.object(cli, 'action') as action:
            with self.assertRaisesRegex(cli.auth.Fail, 'different role'):
                cli.execute({}, {}, 'owner', dict(command='share', vault='vault', account='recipient'))
            action.assert_not_called()

    def test_corrupt_directory_fingerprint_is_never_pinned(self):
        public = cli.crypto.public_identity(cli.crypto.generate_identity())
        row = dict(public_key=public['enc_public'], signing_key=public['sign_public'], fingerprint='wrong')
        with patch.object(cli, 'one', return_value=row), patch.object(cli, 'pins') as pins:
            with self.assertRaisesRegex(cli.auth.Fail, 'Directory fingerprint mismatch'):
                cli.verify_user({}, 'alice')
            pins.assert_not_called()

    def test_email_resolution_is_exact_case_insensitive_and_returns_stable_id(self):
        with patch.object(cli, 'rows', side_effect=[[dict(id='stable', sharing_eligible=1)], [dict(id='identity')]]) as rows:
            self.assertEqual(cli.resolve_account({}, 'Name.Surname@PocketContext.com', sharing=True), 'stable')
        self.assertEqual(rows.call_args_list[0].args[2], "lower(email)='name.surname@pocketcontext.com'")
        self.assertEqual(rows.call_args_list[1].args[2], "account='stable'")

    def test_sharing_requires_unique_eligible_initialized_recipient(self):
        for records in ([], [dict(id='a'), dict(id='b')], [dict(id='a')],
                        [dict(id='a', sharing_eligible=0)]):
            with self.subTest(records=records), patch.object(cli, 'rows', return_value=records):
                with self.assertRaises(cli.auth.Fail):
                    cli.resolve_account({}, 'alice@example.com', sharing=True)
        with patch.object(cli, 'rows', side_effect=[[dict(id='a', sharing_eligible=True)], []]):
            with self.assertRaisesRegex(cli.auth.Fail, 'initialize encryption'):
                cli.resolve_account({}, 'a', sharing=True)

    def test_disabled_recipient_can_still_be_resolved_for_revocation(self):
        with patch.object(cli, 'rows', return_value=[dict(id='stable', sharing_eligible=False)]):
            self.assertEqual(cli.resolve_account({}, 'alice@example.com'), 'stable')

    def test_share_and_accept_fingerprints_are_optional(self):
        share = cli.parser().parse_args(['share', 'vault', 'alice@example.com'])
        self.assertEqual((share.account, share.role, share.fingerprint), ('alice@example.com', 'reader', None))
        self.assertIsNone(cli.parser().parse_args(['accept', 'invitation']).fingerprint)
        self.assertEqual(cli.parser().parse_args(['revoke', 'vault', 'alice@example.com']).account, 'alice@example.com')
        self.assertTrue(next(a for a in cli.parser()._subparsers._group_actions[0].choices['verify-user']._actions
                             if a.dest == 'fingerprint').required)


if __name__ == '__main__':
    unittest.main()
