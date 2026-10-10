"""Synthetic signed metadata, comparison privacy and legacy compatibility checks."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vaultcontext_client import cli as vc


class CompareTests(unittest.TestCase):
    def setUp(self):
        guard = patch.object(vc.auth, 'require_release')
        guard.start()
        self.addCleanup(guard.stop)
        self.identity = vc.crypto.generate_identity()
        self.key = vc.crypto.new_vault_key()
        self.data = b'synthetic\x00file\xff'
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'local'
        self.path.write_bytes(self.data)
        self.info = {'name': 'synthetic', 'size': len(self.data),
                     'plaintext_sha256': hashlib.sha256(self.data).hexdigest()}
        self.configure()

    def configure(self):
        context = vc.document_context('vault', 'document', 'version', 1)
        self.payload = vc.encode(vc.crypto.encrypt_bytes(self.key, self.data, context))
        manifest = {'context': context, 'author': 'owner', 'revision': 1,
                    'metadata': vc.metadata(self.key, self.info, dict(context, kind='file-metadata')),
                    'sha256': hashlib.sha256(self.payload.encode()).hexdigest()}
        self.version = {'id': 'version', 'document': 'document', 'vault': 'vault', 'epoch': 1,
                        'author': 'owner', 'revision': 1, 'chunk_count': 1,
                        'manifest': vc.encode(manifest), 'signature': vc.crypto.sign_manifest(self.identity, manifest)}
        self.document = {'id': 'document', 'vault': 'vault', 'revision': 1, 'current_version': 'version', 'archived': False}

    def run_command(self, command='compare', forbid_download=False, **args):
        def one(cfg, table, where):
            if table == 'vaults':
                return {'id': 'vault', 'owner': 'owner'}
            if table == 'documents':
                return self.document
            if table == 'versions':
                return self.version
            if table == 'version_chunks':
                return {'id': 'chunk'}
            raise AssertionError(table)
        with patch.object(vc, 'one', side_effect=one), \
             patch.object(vc, 'vault_key', return_value=self.key), \
             patch.object(vc, 'verify_user', return_value=vc.crypto.public_identity(self.identity)), \
             patch.object(vc, 'query', side_effect=lambda cfg, sql: [self.version] if 'FROM versions ' in sql else [{'id': 'chunk', 'position': 0}]) as query, \
             patch.object(vc, 'download_chunk', return_value=self.payload,
                          side_effect=AssertionError('unexpected payload download') if forbid_download else None) as download:
            result = vc.execute({}, self.identity, 'owner',
                                dict(command=command, document='document', path=str(self.path), **args))
            return result, query.call_count, download.call_count

    def test_metadata_only_equal_different_empty_binary_and_size(self):
        for data in (b'', self.data, bytes(range(256))):
            self.data = data
            self.info.update(size=len(data), plaintext_sha256=hashlib.sha256(data).hexdigest())
            self.configure()
            for local in (data, data + b'x'):
                self.path.write_bytes(local)
                result, queries, downloads = self.run_command()
                self.assertEqual(result, {'document': 'document', 'version': 'version',
                                         'same': local == data, 'method': 'encrypted-sha256'})
                self.assertEqual((queries, downloads), (0, 0))
            if data:
                self.path.write_bytes(bytes([data[0] ^ 1]) + data[1:])
                self.assertFalse(self.run_command()[0]['same'])

    def test_legacy_fallback_and_explicit_history(self):
        del self.info['plaintext_sha256']
        self.configure()
        self.document.update(current_version='new-version', revision=2)
        for local in (self.data, b'different'):
            self.path.write_bytes(local)
            result, queries, downloads = self.run_command(version='version')
            self.assertEqual(result['method'], 'legacy-download')
            self.assertEqual(result['same'], local == self.data)
            self.assertEqual(result['version'], 'version')
            self.assertEqual((queries, downloads), (1, 1))
        self.assertEqual(list(Path(self.directory.name).iterdir()), [self.path])

    def test_invalid_checksum_rejected_without_fallback(self):
        for invalid in (None, '', 123, True, [], {}, 'F' * 64, 'a' * 63, 'g' * 64, 'a' * 64 + '\n'):
            self.info['plaintext_sha256'] = invalid
            self.configure()
            with self.subTest(invalid=invalid):
                with self.assertRaises(vc.auth.Fail):
                    self.run_command(forbid_download=True)

    def test_content_read_checks_signed_digest_before_output(self):
        self.info['plaintext_sha256'] = '0' * 64
        self.configure()
        for command in ('cat', 'restore'):
            with self.subTest(command=command), patch.object(vc.crypto, 'restore_file') as restore:
                with self.assertRaisesRegex(vc.auth.Fail, 'checksum mismatch'):
                    self.run_command(command=command, to=str(self.path))
                restore.assert_not_called()

    def test_export_checks_digest_before_writing_archive(self):
        self.info['plaintext_sha256'] = '0' * 64
        self.configure()
        with patch.object(vc, 'rows', side_effect=[[self.document], [self.version]]), \
             patch.object(vc.crypto, 'encrypt_export') as encrypt, \
             patch.object(vc.crypto, 'restore_file') as restore:
            with self.assertRaisesRegex(vc.auth.Fail, 'checksum mismatch'):
                self.run_command(command='export', vault='vault', to=str(self.path))
            encrypt.assert_not_called()
            restore.assert_not_called()

    def test_save_keeps_digest_only_inside_signed_encrypted_metadata(self):
        with patch.object(vc, 'one', return_value={'id': 'vault', 'epoch': 1}), \
             patch.object(vc, 'vault_key', return_value=self.key), \
             patch.object(vc, 'action', side_effect=lambda cfg, op, payload: payload):
            payload = vc.execute({}, self.identity, 'owner', {'command': 'save', 'vault': 'vault', 'path': str(self.path)})
        digest = hashlib.sha256(self.data).hexdigest()
        self.assertNotIn(digest, vc.encode(payload))
        self.assertNotIn('plaintext_sha256', vc.encode(payload))
        manifest = json.loads(payload['manifest'])
        vc.crypto.verify_manifest(vc.crypto.public_identity(self.identity), manifest, payload['signature'])
        self.assertEqual(manifest['metadata'], payload['metadata'])
        info = vc.decrypt_metadata(self.key, manifest['metadata'], dict(manifest['context'], kind='file-metadata'))
        self.assertEqual(info['plaintext_sha256'], digest)
        self.assertEqual(info['size'], len(self.data))

    def test_signature_tamper_fails_before_comparison(self):
        manifest = json.loads(self.version['manifest'])
        changed = dict(self.info, plaintext_sha256='0' * 64)
        context = vc.document_context('vault', 'document', 'version', 1)
        manifest['metadata'] = vc.metadata(self.key, changed, dict(context, kind='file-metadata'))
        self.version['manifest'] = vc.encode(manifest)
        with self.assertRaises(Exception):
            self.run_command()

    def test_local_symlink_fifo_oversize_and_race_rejected(self):
        original = self.path.with_name('original')
        self.path.rename(original)
        self.path.symlink_to(original)
        with self.assertRaises(OSError):
            self.run_command()
        self.path.unlink()
        os.mkfifo(self.path)
        with self.assertRaises(ValueError):
            self.run_command()
        self.path.unlink()
        with self.path.open('wb') as stream:
            stream.truncate(vc.crypto.MAX_FILE_SIZE + 1)
        with self.assertRaises(ValueError):
            self.run_command()
        self.path.write_bytes(self.data)
        fstat = os.fstat
        calls = []
        def changed(fd):
            if calls:
                self.path.write_bytes(self.data + b'x')
            calls.append(True)
            return fstat(fd)
        with patch.object(vc.crypto.os, 'fstat', side_effect=changed):
            with self.assertRaises(ValueError):
                self.run_command()

    def test_listing_outputs_do_not_disclose_digest(self):
        for command in ('list', 'search', 'history'):
            with patch.object(vc, 'rows', return_value=[dict(self.document, id='version' if command == 'history' else 'document')]):
                result, _, _ = self.run_command(command=command, vault='vault', text='synthetic')
            self.assertEqual(result[0]['name'], self.info['name'])
            self.assertNotIn('plaintext_sha256', result[0])
            self.assertNotIn(self.info['plaintext_sha256'], vc.encode(result))

    def test_cli_session_transport_resolves_local_path(self):
        args = vc.parser().parse_args(['compare', 'document', 'relative-file', '--version', 'version'])
        with patch.object(vc.auth, 'config', return_value={}), patch.object(vc, 'session_call', return_value={'same': True}) as call:
            self.assertEqual(vc.run(args), {'same': True})
        self.assertEqual(call.call_args.args[1], {'command': 'compare', 'document': 'document',
                                                'path': os.path.abspath('relative-file'), 'version': 'version'})


if __name__ == '__main__':
    unittest.main()
