"""Synthetic primitive and filesystem security regression checks."""
import copy
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from vaultcontext_client import crypto as vc
from nacl.exceptions import CryptoError


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.alice = vc.generate_identity()
        self.bob = vc.generate_identity()
        self.public = vc.public_identity(self.alice)
        self.context = {'vault': 'v1', 'document': 'd1', 'version': 1, 'generation': 1}
        self.key = vc.new_vault_key()

    def test_all_bytes_empty_random_nonce_and_context(self):
        for value in (b'', bytes(range(256)) * 1024):
            encrypted = vc.encrypt_bytes(self.key, value, self.context)
            self.assertEqual(vc.decrypt_bytes(self.key, encrypted, self.context), value)
            self.assertNotEqual(encrypted, vc.encrypt_bytes(self.key, value, self.context))
            for field in self.context:
                changed = dict(self.context, **{field: 'changed'})
                with self.assertRaises(CryptoError):
                    vc.decrypt_bytes(self.key, encrypted, changed)
            raw = bytearray(vc.unb64(encrypted['ciphertext']))
            raw[-1] ^= 1
            encrypted['ciphertext'] = vc.b64(raw)
            with self.assertRaises(CryptoError):
                vc.decrypt_bytes(self.key, encrypted, self.context)

    def test_identity_passphrase_user_binding_and_kdf_bounds(self):
        wrapped = vc.wrap_identity(self.alice, 'synthetic passphrase', 'alice')
        self.assertEqual(vc.unwrap_identity(wrapped, 'synthetic passphrase', 'alice'), self.alice)
        for password, user in [('incorrect', 'alice'), ('synthetic passphrase', 'bob')]:
            with self.assertRaises(CryptoError):
                vc.unwrap_identity(wrapped, password, user)
        for field, value in [('memory', 1 << 50), ('ops', -1), ('v', True), ('salt', 'not-base64')]:
            changed = dict(wrapped, **{field: value})
            with patch.object(vc.pwhash.argon2id, 'kdf', side_effect=AssertionError('must reject before KDF')):
                with self.assertRaises(ValueError):
                    vc.unwrap_identity(changed, 'synthetic passphrase', 'alice')

    def test_sharing_sender_recipient_context_signature(self):
        bob_public = vc.public_identity(self.bob)
        sealed = vc.seal_key(self.key, bob_public, self.alice, self.context)
        self.assertEqual(vc.open_key(sealed, self.bob, self.public, self.context), self.key)
        with self.assertRaises(ValueError):
            vc.open_key(sealed, self.alice, self.public, self.context)
        with self.assertRaises(CryptoError):
            vc.open_key(sealed, self.bob, bob_public, self.context)
        with self.assertRaises(ValueError):
            vc.open_key(sealed, self.bob, self.public, dict(self.context, generation=2))
        tampered = copy.deepcopy(sealed)
        tampered['body']['context']['generation'] = 2
        with self.assertRaises(CryptoError):
            vc.open_key(tampered, self.bob, self.public, dict(self.context, generation=2))
        self.assertNotEqual(vc.fingerprint(self.public), vc.fingerprint(bob_public))

    def test_manifest_authenticates_author_and_content(self):
        manifest = {'ciphertext_hash': 'synthetic', **self.context}
        signature = vc.sign_manifest(self.alice, manifest)
        vc.verify_manifest(self.public, manifest, signature)
        with self.assertRaises(CryptoError):
            vc.verify_manifest(self.public, dict(manifest, version=2), signature)
        with self.assertRaises(CryptoError):
            vc.verify_manifest(vc.public_identity(self.bob), manifest, signature)

    def test_malformed_and_size_limits(self):
        for invalid in ('###', 'YQ===', 'é', 12, 'AB=='):
            with self.assertRaises(ValueError):
                vc.unb64(invalid)
        for envelope in ({}, {'v': 2, 'alg': 'xchacha20poly1305', 'ciphertext': ''},
                         {'v': True, 'alg': 'xchacha20poly1305', 'ciphertext': ''}):
            with self.assertRaises(ValueError):
                vc.decrypt_bytes(self.key, envelope, self.context)
        with self.assertRaises(ValueError):
            vc.encrypt_bytes(self.key, b'a' * (vc.MAX_PLAINTEXT + 1), self.context)
        with self.assertRaises(ValueError):
            vc.encrypt_bytes(self.key, b'', {})
        with self.assertRaises(ValueError):
            vc.encrypt_bytes(self.key, b'', {'oversize': 'a' * 4096})

    def test_independent_export_no_identity(self):
        data = bytes(range(256))
        exported = vc.encrypt_export(data, 'archive passphrase')
        self.assertEqual(vc.decrypt_export(exported, 'archive passphrase'), data)
        with self.assertRaises(CryptoError):
            vc.decrypt_export(exported, 'incorrect')
        with self.assertRaises(ValueError):
            vc.decrypt_export(dict(exported, ops=100000), 'archive passphrase')
        raw = bytearray(vc.unb64(exported['ciphertext']))
        raw[-1] ^= 1
        with self.assertRaises(CryptoError):
            vc.decrypt_export(dict(exported, ciphertext=vc.b64(raw)), 'archive passphrase')


class FileTests(unittest.TestCase):
    def test_roundtrip_permissions_and_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'anything.bin'
            data = bytes(range(256))
            vc.restore_file(target, data)
            self.assertEqual(vc.read_file(target), data)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                vc.restore_file(target, b'new')
            self.assertEqual(target.read_bytes(), data)
            vc.restore_file(target, b'', overwrite=True)
            self.assertEqual(vc.read_file(target), b'')
            self.assertEqual(list(Path(directory).iterdir()), [target])

    def test_symlinks_ancestors_fifo_and_size(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'original'
            target.write_bytes(b'abc')
            link = root / 'link'
            link.symlink_to(target)
            for fn in (lambda: vc.read_file(link), lambda: vc.restore_file(link, b'bad', overwrite=True)):
                with self.assertRaises((OSError, ValueError)):
                    fn()
            folder = root / 'folder'
            folder.mkdir()
            (root / 'folder-link').symlink_to(folder, target_is_directory=True)
            with self.assertRaises(OSError):
                vc.restore_file(root / 'folder-link' / 'file', b'bad')
            with self.assertRaises(ValueError):
                vc.read_file(target, max_size=2)
            fifo = root / 'fifo'
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                vc.read_file(fifo)
            self.assertEqual(target.read_bytes(), b'abc')

    def test_read_change_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'file'
            target.write_bytes(b'abcd')
            fstat = os.fstat
            calls = []
            def changed(fd):
                if calls:
                    target.write_bytes(b'abcde')
                calls.append(True)
                return fstat(fd)
            with patch.object(vc.os, 'fstat', side_effect=changed):
                with self.assertRaises(ValueError):
                    vc.read_file(target)

    def test_no_overwrite_race_does_not_clobber(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'file'
            link = os.link
            def raced(*args, **kwargs):
                target.write_bytes(b'concurrent')
                return link(*args, **kwargs)
            with patch.object(vc.os, 'link', side_effect=raced):
                with self.assertRaises(FileExistsError):
                    vc.restore_file(target, b'our write')
            self.assertEqual(target.read_bytes(), b'concurrent')
            self.assertEqual(list(Path(directory).iterdir()), [target])


if __name__ == '__main__':
    unittest.main()
