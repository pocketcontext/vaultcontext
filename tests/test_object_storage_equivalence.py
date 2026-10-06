"""The migration equality gate rejects stale state and preserves private aux files."""
import importlib.util
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

HELPER = Path(__file__).with_name('object_storage_equivalence.py')
spec = importlib.util.spec_from_file_location('equivalence', HELPER)
equivalence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(equivalence)

class EquivalenceTests(unittest.TestCase):
    def test_stale_rows_and_schema_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, restored = Path(tmp)/'source.db', Path(tmp)/'restored.db'
            for path in (source, restored):
                with sqlite3.connect(path) as db:
                    db.execute('CREATE TABLE example(id INTEGER PRIMARY KEY, payload BLOB)')
                    db.execute('INSERT INTO example VALUES(1,?)', (b'synthetic',))
            equivalence.verify_equivalent(source, restored)
            with sqlite3.connect(restored) as db: db.execute('UPDATE example SET payload=?', (b'stale',))
            with self.assertRaises(RuntimeError): equivalence.verify_equivalent(source, restored)
            with sqlite3.connect(restored) as db:
                db.execute('UPDATE example SET payload=?', (b'synthetic',))
                db.execute('CREATE TABLE unexpected(id TEXT)')
            with self.assertRaises(RuntimeError): equivalence.verify_equivalent(source, restored)

    def test_private_auxiliary_snapshot_includes_wal_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, target = Path(tmp)/'source.db', Path(tmp)/'target.db'
            with sqlite3.connect(source) as db:
                db.execute('PRAGMA journal_mode=WAL')
                db.execute('CREATE TABLE example(payload TEXT)')
                db.execute('INSERT INTO example VALUES("synthetic")'); db.commit()
                command = [sys.executable,str(HELPER),str(source),str(source),str(source),str(target)]
                result = subprocess.run(command,capture_output=True)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(target.stat().st_mode & 0o777,0o600)
                equivalence.verify_equivalent(source,target)
                result = subprocess.run(command,capture_output=True)
                self.assertNotEqual(result.returncode,0)

if __name__ == '__main__': unittest.main()
