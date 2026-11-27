"""Batched `vaults` listing: bounded queries, unchanged output and fail-closed checks."""
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from vaultcontext_client import cli as vc


class VaultListingTests(unittest.TestCase):
    def setUp(self):
        guard = patch.object(vc.auth, 'require_release')
        guard.start()
        self.addCleanup(guard.stop)
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
            CREATE TABLE vaults (id TEXT, owner TEXT, metadata TEXT, archived INTEGER);
            CREATE TABLE identities (id TEXT, account TEXT, public_key TEXT, signing_key TEXT, fingerprint TEXT);
            CREATE TABLE key_envelopes (id TEXT, vault TEXT, account TEXT, epoch INTEGER, envelope TEXT);
            CREATE TABLE memberships (id TEXT, vault TEXT, account TEXT, role TEXT, active INTEGER);
        ''')
        self.identities = {name: vc.crypto.generate_identity() for name in ('me', 'alice', 'bob')}
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict(os.environ, {'XDG_CACHE_HOME': os.path.realpath(self.tmp.name)})
        env.start()
        self.addCleanup(env.stop)
        self.cfg = {'url': 'https://synthetic.example', 'email': 'me@example.com'}
        self.calls = []
        self.transform = lambda sql, rows: rows
        for name, identity in self.identities.items():
            public = vc.crypto.public_identity(identity)
            self.db.execute('INSERT INTO identities VALUES (?,?,?,?,?)',
                            (name, name, public['enc_public'], public['sign_public'], vc.crypto.fingerprint(public)))

    def add_vault(self, vault, owner, archived=0, role=None):
        key = vc.crypto.new_vault_key()
        metadata = vc.metadata(key, {'name': f'Synthetic {vault}'}, {'kind': 'vault-metadata', 'vault': vault})
        self.db.execute('INSERT INTO vaults VALUES (?,?,?,?)', (vault, owner, metadata, archived))
        context = vc.key_context(vault, 'me', 1, owner)
        sealed = vc.crypto.seal_key(key, vc.crypto.public_identity(self.identities['me']), self.identities[owner], context)
        self.db.execute('INSERT INTO key_envelopes VALUES (?,?,?,?,?)',
                        ('e' + vault, vault, 'me', 1, vc.encode({'signer': owner, 'sealed': sealed})))
        self.db.execute('INSERT INTO memberships VALUES (?,?,?,?,?)',
                        ('m' + vault, vault, 'me', role or ('owner' if owner == 'me' else 'reader'), 1))

    def populate(self, count):
        owners = ('me', 'alice', 'bob')
        for index in range(count):
            self.add_vault(f'vault{index:03}', owners[index % 3], archived=int(index % 7 == 0))

    def request(self, cfg, method, path, body):
        self.assertEqual((method, path), ('POST', '/api/context/query'))
        self.calls.append(body['sql'])
        records = [dict(row) for row in self.db.execute(body['sql'])]
        return {'rows': self.transform(body['sql'], records), 'truncated': False}

    def run_command(self, **args):
        original_verify, original_restore = vc.verify_user, vc.crypto.restore_file
        self.pin_writes = 0

        def restore(path, data, overwrite=False):
            self.pin_writes += 1
            return original_restore(path, data, overwrite=overwrite)
        with patch.object(vc, 'request', side_effect=self.request), \
             patch.object(vc.crypto, 'restore_file', side_effect=restore), \
             patch.object(vc, 'verify_user', side_effect=original_verify) as verified:
            self.verified = verified
            return vc.execute(self.cfg, self.identities['me'], 'me', dict({'command': 'vaults'}, **args))

    def legacy(self, **args):
        """The previous per-vault algorithm, as a byte-for-byte reference."""
        where = '1=1' if args.get('all') else 'archived=' + ('1' if args.get('archived') else '0')
        result = []
        with patch.object(vc, 'request', side_effect=self.request):
            for vault in vc.rows(self.cfg, 'vaults', where):
                key = vc.vault_key(self.cfg, self.identities['me'], 'me', vault['id'], 1)
                result.append(dict(id=vault['id'], **vc.decrypt_metadata(key, vault['metadata'], {'kind': 'vault-metadata', 'vault': vault['id']}), archived=bool(vault['archived']), role=vc.one(self.cfg, 'memberships', f'vault={vc.quote(vault["id"])} AND account={vc.quote("me")} AND active=1')['role']))
        return result

    def pin_all(self, **changes):
        known = {name: vc.crypto.fingerprint(vc.crypto.public_identity(identity))
                 for name, identity in self.identities.items()}
        known.update(changes)
        path = vc.pin_path(self.cfg)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        vc.crypto.restore_file(path, vc.encode(known).encode(), overwrite=True)

    def test_many_vaults_use_bounded_queries_and_identical_output(self):
        self.populate(60)
        self.pin_all()
        for args in ({}, {'archived': True}, {'all': True}):
            with self.subTest(args=args):
                expected = self.legacy(**args)
                self.calls = []
                result = self.run_command(**args)
                self.assertEqual(vc.encode(result), vc.encode(expected))
                self.assertLessEqual(len(self.calls), 9)  # previously four queries per vault
                # Three distinct signers are verified once each, not once per vault.
                self.assertEqual(self.verified.call_count, 3)
        self.calls = []
        self.run_command(all=True)
        # 60 vaults: two vault pages, three envelope/membership chunks each, one identity chunk.
        self.assertEqual(len(self.calls), 2 + 3 + 3 + 1)
        self.assertEqual(len(self.run_command(all=True)), 60)

    def test_fourteen_vaults_need_four_queries(self):
        self.populate(14)
        self.pin_all()
        result = self.run_command(all=True)
        self.assertEqual(len(result), 14)
        self.assertEqual(len(self.calls), 4)
        self.assertEqual(result[1], {'id': 'vault001', 'name': 'Synthetic vault001', 'archived': False, 'role': 'reader'})

    def test_empty_listing_needs_one_query(self):
        self.assertEqual(self.run_command(), [])
        self.assertEqual(len(self.calls), 1)

    def test_first_use_pins_each_signer_once(self):
        self.populate(9)
        self.assertEqual(len(self.run_command(all=True)), 9)
        self.assertEqual(set(vc.pins(self.cfg)), {'me', 'alice', 'bob'})
        self.assertEqual(self.pin_writes, 3)
        self.run_command(all=True)
        self.assertEqual(self.pin_writes, 0)

    def test_changed_signer_key_rejected(self):
        self.populate(6)
        self.pin_all(alice='0' * 64)
        with self.assertRaisesRegex(vc.auth.Fail, 'Unverified or changed'):
            self.run_command(all=True)

    def test_directory_fingerprint_mismatch_rejected(self):
        self.populate(3)
        self.pin_all()
        self.db.execute("UPDATE identities SET fingerprint=? WHERE account='bob'", ('f' * 64,))
        with self.assertRaisesRegex(vc.auth.Fail, 'Directory fingerprint mismatch'):
            self.run_command(all=True)

    def test_missing_or_duplicate_rows_fail_closed(self):
        self.populate(5)
        self.pin_all()
        for table in ('key_envelopes', 'memberships', 'identities'):
            marker = f'FROM {table} '
            for name, change in (('missing', lambda rows: rows[:-1]), ('duplicate', lambda rows: rows + rows[:1]),
                                 ('unexpected', lambda rows: rows + [dict(rows[0], vault='other', account='other')])):
                with self.subTest(table=table, change=name):
                    self.transform = lambda sql, rows, marker=marker, change=change: change(rows) if marker in sql else rows
                    with self.assertRaisesRegex(vc.auth.Fail, 'Incomplete or duplicate'):
                        self.run_command(all=True)
        self.transform = lambda sql, rows: rows

    def test_inactive_or_absent_membership_and_envelope_fail_closed(self):
        self.populate(4)
        self.pin_all()
        self.db.execute("UPDATE memberships SET active=0 WHERE vault='vault002'")
        with self.assertRaisesRegex(vc.auth.Fail, 'Incomplete or duplicate vault memberships'):
            self.run_command(all=True)
        self.db.execute("UPDATE memberships SET active=1")
        self.db.execute("INSERT INTO memberships VALUES ('dup','vault001','me','editor',1)")
        with self.assertRaisesRegex(vc.auth.Fail, 'Incomplete or duplicate vault memberships'):
            self.run_command(all=True)
        self.db.execute("DELETE FROM memberships WHERE id='dup'")
        self.db.execute("UPDATE key_envelopes SET epoch=2 WHERE vault='vault003'")
        with self.assertRaisesRegex(vc.auth.Fail, 'Incomplete or duplicate vault-key envelopes'):
            self.run_command(all=True)

    def test_envelope_signer_must_be_vault_owner(self):
        self.populate(3)
        self.pin_all()
        self.db.execute("UPDATE vaults SET owner='bob' WHERE id='vault001'")
        with self.assertRaisesRegex(vc.auth.Fail, 'not signed by its owner'):
            self.run_command(all=True)

    def test_envelope_context_and_metadata_context_are_checked(self):
        self.populate(2)
        self.pin_all()
        swapped = self.db.execute("SELECT metadata FROM vaults WHERE id='vault000'").fetchone()['metadata']
        self.db.execute("UPDATE vaults SET metadata=? WHERE id='vault001'", (swapped,))
        with self.assertRaises(Exception):
            self.run_command(all=True)


if __name__ == '__main__':
    unittest.main()
