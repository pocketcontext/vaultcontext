"""Pinned Litestream paired-database recovery, using isolated local replicas."""
from contextlib import closing
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('paired_replication_runtime', ROOT / 'docker/entrypoint.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class RealPairedRecovery(unittest.TestCase):
    def test_populated_pair_restores_from_actual_litestream(self):
        binary = os.environ.get('VAULTCONTEXT_TEST_LITESTREAM')
        if not binary:
            self.skipTest('set VAULTCONTEXT_TEST_LITESTREAM to the pinned binary')
        today = datetime.now(timezone.utc).date().isoformat()
        with tempfile.TemporaryDirectory(prefix='demo-real-replication-') as temp:
            root = Path(temp)
            data = root / 'data'
            data.mkdir()
            config = root / 'local.json'
            names = ('data.db', 'auxiliary.db')
            for name in names:
                with closing(sqlite3.connect(data / name)) as db:
                    db.execute('PRAGMA journal_mode=WAL')
                    db.execute('CREATE TABLE sentinel(value TEXT)')
                    db.execute('INSERT INTO sentinel VALUES(?)', (name + '-preserved',))
                    if name == 'data.db':
                        db.execute('CREATE TABLE demo_policy(id TEXT,enabled INTEGER,generation TEXT)')
                        db.execute('INSERT INTO demo_policy VALUES(?,?,?)', ('demopolicy00001', 1, today))
                    else:
                        db.execute('CREATE TABLE _logs(message TEXT)')
                        db.execute("INSERT INTO _logs VALUES('synthetic migration event')")
                    db.commit()
            config.write_text(json.dumps({'dbs': [
                {'path': str(data / name), 'replica': {'type': 'file', 'path': str(root / 'replicas' / name)}}
                for name in names
            ]}))
            subprocess.run([binary, 'replicate', '-once', '-config', str(config)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
            shutil.rmtree(data)
            data.mkdir()
            with patch.dict(os.environ, {'VAULTCONTEXT_DEMO_MODE': 'true', 'VAULTCONTEXT_DEMO_GENERATION': today}), \
                 patch.multiple(runtime, LITESTREAM=binary, DATA=data, DEMO_CONFIG=str(config)), \
                 patch.object(runtime, 'verify_remote'):
                self.assertTrue(runtime.restore_database(data))
            for name in names:
                with closing(sqlite3.connect(data / name)) as db:
                    self.assertEqual(db.execute('PRAGMA integrity_check').fetchone(), ('ok',))
                    self.assertEqual(db.execute('SELECT value FROM sentinel').fetchone(), (name + '-preserved',))
            self.assertFalse((data / 'restoration.pending').exists())


if __name__ == '__main__':
    unittest.main()
