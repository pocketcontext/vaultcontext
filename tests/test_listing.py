"""Synthetic batched listing checks with real envelopes, signatures and SQL paging."""
import json
import sqlite3
import unittest
from unittest.mock import patch

from nacl.exceptions import BadSignatureError

from vaultcontext_client import cli as vc


class ListingTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.db.row_factory = sqlite3.Row
        self.identities = {name: vc.crypto.generate_identity() for name in ('owner', 'editor')}
        self.known = {}
        self.calls = []
        self.transform = lambda sql, rows: rows
        self.truncated = False
        self.insert('vaults', {'id': 'vault', 'owner': 'owner'})
        for name, identity in self.identities.items():
            public = vc.crypto.public_identity(identity)
            fingerprint = vc.crypto.fingerprint(public)
            self.known[name] = fingerprint
            self.insert('identities', dict(id=name, account=name, public_key=public['enc_public'],
                                          signing_key=public['sign_public'], fingerprint=fingerprint))
        self.keys = {epoch: vc.crypto.new_vault_key() for epoch in (1, 2)}
        for epoch, key in self.keys.items():
            context = vc.key_context('vault', 'owner', epoch, 'owner')
            sealed = vc.crypto.seal_key(key, vc.crypto.public_identity(self.identities['owner']),
                                        self.identities['owner'], context)
            self.insert('key_envelopes', dict(id=str(epoch), vault='vault', account='owner', epoch=epoch,
                                            envelope=vc.encode({'signer': 'owner', 'sealed': sealed})))
        self.db.execute('CREATE TABLE documents (id TEXT, vault TEXT, revision INTEGER, current_version TEXT, archived INTEGER)')
        self.db.execute('CREATE TABLE versions (id TEXT, document TEXT, vault TEXT, epoch INTEGER, author TEXT, revision INTEGER, manifest TEXT, signature TEXT)')

    def insert(self, table, row):
        columns = ','.join(f'{key} {"INTEGER" if isinstance(value, int) else "TEXT"}' for key, value in row.items())
        self.db.execute(f'CREATE TABLE IF NOT EXISTS {table} ({columns})')
        self.db.execute(f'INSERT INTO {table} ({",".join(row)}) VALUES ({",".join("?" for _ in row)})', list(row.values()))

    def populate(self, count, mixed=False):
        for index in range(count):
            document, version = f'doc{index:03}', f'ver{index:03}'
            epoch = 1 + index % 2 if mixed else 1
            author = 'editor' if mixed and index % 2 else 'owner'
            context = vc.document_context('vault', document, version, epoch)
            info = dict(name=f'Synthetic File {index:03}', size=index, plaintext_sha256='a' * 64)
            manifest = dict(context=context, author=author, revision=1,
                            metadata=vc.metadata(self.keys[epoch], info, dict(context, kind='file-metadata')),
                            sha256='b' * 64)
            self.insert('documents', dict(id=document, vault='vault', revision=1, current_version=version, archived=0))
            self.insert('versions', dict(id=version, document=document, vault='vault', epoch=epoch, author=author,
                                        revision=1, manifest=vc.encode(manifest),
                                        signature=vc.crypto.sign_manifest(self.identities[author], manifest)))

    def request(self, cfg, method, path, body):
        self.assertEqual((method, path), ('POST', '/api/context/query'))
        sql = body['sql']
        self.calls.append(sql)
        records = [dict(row) for row in self.db.execute(sql)]
        return {'rows': self.transform(sql, records), 'truncated': self.truncated and 'FROM versions ' in sql}

    def run_listing(self, **args):
        with patch.object(vc, 'request', side_effect=self.request), patch.object(vc, 'pins', side_effect=lambda cfg: dict(self.known)), \
             patch.object(vc, 'download_chunk', side_effect=AssertionError('listing downloaded content')):
            return vc.execute({}, self.identities['owner'], 'owner', dict({'command': 'list', 'vault': 'vault'}, **args))

    def test_fifteen_files_fit_six_queries(self):
        self.populate(15)
        result = self.run_listing()
        self.assertEqual([row['name'] for row in result], [f'Synthetic File {i:03}' for i in range(15)])
        self.assertEqual(len(self.calls), 6)
        self.assertNotIn('plaintext_sha256', vc.encode(result))
        self.assertNotIn('a' * 64, vc.encode(result))

    def test_more_than_fifty_documents_and_distinct_epochs_and_writers(self):
        self.populate(63, mixed=True)
        result = self.run_listing()
        self.assertEqual(len(result), 63)
        self.assertEqual(len(self.calls), 12)
        self.assertEqual(len({row['id'] for row in result}), 63)
        self.assertEqual(sum('FROM versions ' in sql for sql in self.calls), 3)
        self.assertEqual(sum('FROM key_envelopes ' in sql for sql in self.calls), 2)

    def test_archive_and_casefold_search_filters(self):
        self.populate(3)
        self.db.execute("UPDATE documents SET archived=1 WHERE id='doc001'")
        for args, expected in (({}, ['doc000', 'doc002']), ({'archived': True}, ['doc001']),
                               ({'all': True}, ['doc000', 'doc001', 'doc002']),
                               ({'command': 'search', 'text': 'sYNTHETIC fILE 001'}, []),
                               ({'command': 'search', 'text': 'sYNTHETIC fILE 001', 'all': True}, ['doc001'])):
            with self.subTest(args=args):
                result = self.run_listing(**args)
                self.assertEqual([row['id'] for row in result], expected)

    def test_empty_listing_requires_only_document_query(self):
        self.assertEqual(self.run_listing(), [])
        self.assertEqual(len(self.calls), 1)

    def test_missing_duplicate_and_unexpected_versions_fail_closed(self):
        self.populate(2)
        for transform in (lambda rows: rows[:-1], lambda rows: rows + rows[:1],
                          lambda rows: rows + [dict(rows[0], id='unexpected')]):
            self.transform = lambda sql, rows: transform(rows) if 'FROM versions ' in sql else rows
            with self.assertRaisesRegex(vc.auth.Fail, 'Incomplete or duplicate'):
                self.run_listing()

    def test_truncated_response_fails_closed(self):
        self.populate(2)
        self.truncated = True
        with self.assertRaisesRegex(vc.auth.Fail, 'truncated'):
            self.run_listing()

    def test_version_document_vault_and_revision_mismatches_fail(self):
        self.populate(2)
        for field, value in (('document', 'other'), ('vault', 'other'), ('revision', 2)):
            self.transform = lambda sql, rows: [dict(row, **{field: value}) for row in rows] if 'FROM versions ' in sql else rows
            with self.subTest(field=field), self.assertRaises(vc.auth.Fail):
                self.run_listing()

    def test_manifest_tamper_fails(self):
        self.populate(2)
        row = self.db.execute("SELECT manifest FROM versions WHERE id='ver001'").fetchone()
        manifest = json.loads(row['manifest'])
        manifest['revision'] = 2
        self.db.execute("UPDATE versions SET manifest=? WHERE id='ver001'", (vc.encode(manifest),))
        with self.assertRaises(BadSignatureError):
            self.run_listing()

    def test_signed_manifest_context_author_and_revision_mismatch(self):
        self.populate(1)
        original = json.loads(self.db.execute('SELECT manifest FROM versions').fetchone()['manifest'])
        for changes in ({'context': dict(original['context'], document='other')}, {'author': 'editor'}, {'revision': 2}):
            manifest = dict(original, **changes)
            self.db.execute('UPDATE versions SET manifest=?,signature=?',
                            (vc.encode(manifest), vc.crypto.sign_manifest(self.identities['owner'], manifest)))
            with self.subTest(changes=changes), self.assertRaisesRegex(vc.auth.Fail, 'Signed manifest identity mismatch'):
                self.run_listing()

    def test_next_command_rechecks_pins_and_envelope(self):
        self.populate(2, mixed=True)
        self.assertEqual(len(self.run_listing()), 2)
        self.known['editor'] = '0' * 64
        with self.assertRaisesRegex(vc.auth.Fail, 'Unverified or changed'):
            self.run_listing()
        self.known['editor'] = vc.crypto.fingerprint(vc.crypto.public_identity(self.identities['editor']))
        self.db.execute('DELETE FROM key_envelopes WHERE epoch=2')
        with self.assertRaisesRegex(vc.auth.Fail, 'Expected one accessible key_envelopes'):
            self.run_listing()


if __name__ == '__main__':
    unittest.main()
