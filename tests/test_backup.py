#!/usr/bin/env python3
"""Synthetic complete-backup tests: WAL snapshot, evidence hashes, hostile archives."""
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('backup', Path(__file__).resolve().parents[1] / 'tests/legacy_backup.py')
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.exceptions = type('Exceptions', (), {'ClientError': KeyError})

    def upload_file(self, path, bucket, key):
        self.objects[key] = Path(path).read_bytes()

    def put_object(self, Bucket, Key, Body, **kwargs):
        self.objects[Key] = Body

    def get_object(self, Bucket, Key):
        return {'Body': io.BytesIO(self.objects[Key])}

    def download_file(self, bucket, key, path):
        Path(path).write_bytes(self.objects[key])


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / 'live'
        self.original = self.data / 'storage/col/doc/synthetic.txt'
        self.original.parent.mkdir(parents=True)
        self.original.write_bytes(b'Synthetic opaque encrypted bytes\n')
        self.conn = sqlite3.connect(self.data / 'data.db')
        self.addCleanup(self.conn.close)
        self.conn.executescript('PRAGMA journal_mode=WAL; CREATE TABLE _collections(id TEXT,name TEXT); INSERT INTO _collections VALUES("col","version_chunks"); CREATE TABLE version_chunks(id TEXT,ciphertext TEXT,sha256 TEXT);')
        self.conn.execute('INSERT INTO version_chunks VALUES(?,?,?)', ('doc','synthetic.txt',backup.digest(self.original)))
        self.conn.commit()

    def archive(self, source, path):
        with tarfile.open(path,'w:gz') as tar:
            for p in source.rglob('*'):
                if p.is_file():
                    tar.add(p,arcname=str(p.relative_to(source)),recursive=False)

    def test_snapshot_recovers_wal_database_and_exact_original(self):
        snapshot = self.root / 'snapshot'
        backup.snapshot(self.data, snapshot)
        archive = self.root / 'snapshot.tar.gz'
        self.archive(snapshot, archive)
        backup.unpack(archive, self.root / 'restored')
        backup.verify(self.root / 'restored')
        self.assertEqual((self.root / 'restored/storage/col/doc/synthetic.txt').read_bytes(),self.original.read_bytes())
        with sqlite3.connect(self.root / 'restored/data.db') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM version_chunks').fetchone()[0],1)

    def test_missing_original_refuses_snapshot_and_startup(self):
        self.original.unlink()
        with self.assertRaises(RuntimeError): backup.verify(self.data)
        with self.assertRaises(RuntimeError): backup.snapshot(self.data,self.root/'snapshot')

    def test_corrupt_original_refuses_snapshot(self):
        self.original.write_bytes(b'changed')
        with self.assertRaises(RuntimeError): backup.snapshot(self.data,self.root/'snapshot')

    def test_corrupt_archive_fails_checksum(self):
        snapshot = self.root/'snapshot'
        backup.snapshot(self.data,snapshot)
        (snapshot/'storage/col/doc/synthetic.txt').write_bytes(b'changed')
        archive=self.root/'snapshot.tar.gz'
        self.archive(snapshot,archive)
        with self.assertRaises(RuntimeError): backup.unpack(archive,self.root/'restored')

    def test_path_traversal_rejected(self):
        archive=self.root/'evil.tar.gz'
        with tarfile.open(archive,'w:gz') as tar:
            info=tarfile.TarInfo('../outside');info.size=1
            tar.addfile(info,io.BytesIO(b'x'))
        with self.assertRaises(RuntimeError): backup.unpack(archive,self.root/'restored')
        self.assertFalse((self.root/'outside').exists())

    def test_existing_database_never_fetches_remote(self):
        with patch.object(backup,'remote') as remote:
            backup.restore(self.data)
            remote.assert_not_called()

    def test_newer_live_reference_not_in_snapshot_is_detected(self):
        backup.snapshot(self.data,self.root/'snapshot')
        self.conn.execute('INSERT INTO version_chunks VALUES(?,?,?)',('later','absent.txt','a'*64));self.conn.commit()
        with self.assertRaises(RuntimeError): backup.verify(self.data)
        backup.verify(self.root/'snapshot')

    def test_remote_pointer_restores_complete_snapshot(self):
        remote = FakeS3()
        with patch.object(backup, 'remote', return_value=(remote, 'synthetic-bucket', 'synthetic/full-backups')):
            backup.upload(self.data)
            self.assertIn('synthetic/full-backups/latest.json', remote.objects)
            backup.restore(self.root / 'remote-restore')
            backup.verify(self.root / 'remote-restore')
            self.assertEqual((self.root / 'remote-restore/storage/col/doc/synthetic.txt').read_bytes(), self.original.read_bytes())

    def test_archive_upload_failure_never_publishes_pointer(self):
        remote = FakeS3()
        with patch.object(backup, 'remote', return_value=(remote, 'synthetic-bucket', 'synthetic/full-backups')), patch.object(remote, 'upload_file', side_effect=OSError):
            with self.assertRaises(OSError): backup.upload(self.data)
            self.assertFalse(remote.objects)

    def test_corrupt_remote_archive_never_installs_database(self):
        remote = FakeS3()
        with patch.object(backup, 'remote', return_value=(remote, 'synthetic-bucket', 'synthetic/full-backups')):
            backup.upload(self.data)
            pointer = json.loads(remote.objects['synthetic/full-backups/latest.json'])
            remote.objects[pointer['key']] = b'corrupt archive'
            with self.assertRaises(RuntimeError): backup.restore(self.root / 'remote-restore')
            self.assertFalse((self.root / 'remote-restore/data.db').exists())


if __name__=='__main__': unittest.main()
