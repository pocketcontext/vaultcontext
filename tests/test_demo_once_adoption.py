"""A successful adoption of standalone WAL-mode SQLite backup files."""
from contextlib import closing
import hashlib
import json
import sqlite3
import unittest

import test_demo_once_runtime as fixtures
from test_demo_once_runtime import IMAGE, REVISION, LocalBackend, fixture_bindings


class WalAdoptionTests(unittest.TestCase):
    setUp=fixtures.OnceRuntimeStateTests.setUp
    close_all=fixtures.OnceRuntimeStateTests.close_all
    instance=fixtures.OnceRuntimeStateTests.instance
    populated=fixtures.OnceRuntimeStateTests.populated
    def test_checkpointed_wal_backups_do_not_leave_staging_sidecars(self):
        # Use the ordinary runtime's helper fixture, but import SQLite backup files
        # carrying journal_mode=WAL, as the real frozen PocketBase databases do.
        old, backend=self.populated()
        old.close()
        snapshots=[]
        for path in old.paths():
            with closing(sqlite3.connect(path)) as source:
                source.execute('PRAGMA journal_mode=WAL')
                target=path.with_name(path.name+'.snapshot')
                with closing(sqlite3.connect(target)) as destination:source.backup(destination)
            snapshots.append(target.read_bytes())
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            target_backend=LocalBackend(root)
            target=self.module.Runtime(root,REVISION,target_backend,clock=lambda:self.day[0])
            try:
                target.start();target.configure(fixture_bindings())
                header={'generation':self.day[0],'image':IMAGE,'revision':REVISION,'files':{}}
                for name,data in zip(('data.db','auxiliary.db','contacts.db'),snapshots):
                    header['files'][name]={'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}
                target.adopt_begin(header)
                for name,data in zip(('data.db','auxiliary.db','contacts.db'),snapshots):
                    (root/'runtime/adoption'/name).write_bytes(data)
                result=target.adopt_finish()
                self.assertTrue(result['ready'])
                self.assertFalse((root/'control/adoption-pending.json').exists())
                self.assertFalse((root/'runtime/adoption').exists())
                self.assertEqual(target_backend.contents(),backend.contents())
            finally:target.close()

    def test_live_baseline_keeps_uncheckpointed_wal_rows(self):
        path=self.root/'live.db';path.parent.mkdir(parents=True)
        with closing(sqlite3.connect(path)) as writer:
            writer.execute('PRAGMA journal_mode=WAL')
            writer.execute('CREATE TABLE payload(id TEXT)');writer.commit()
            writer.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            before=self.module.database_snapshot(path)
            writer.execute("INSERT INTO payload VALUES ('synthetic encrypted record')");writer.commit()
            after=self.module.database_snapshot(path)
            self.assertNotEqual(before['hashes'],after['hashes'])
            self.assertEqual(sum(after['hashes']['payload'].values()),1)
