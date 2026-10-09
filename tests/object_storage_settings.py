"""Synthetic primary-storage configuration and immutable-file verification."""
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'VAULTCONTEXT_S3_'  # Also run from renamed checkouts and Git worktrees.
spec = importlib.util.spec_from_file_location('backup', ROOT / 'docker/entrypoint.py')
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


class StorageTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.data = Path(tmp.name)
        self.env = {PREFIX + key: 'synthetic-' + key.lower() for key in
                    ('BUCKET', 'ENDPOINT', 'REGION', 'ACCESS_KEY_ID', 'SECRET_ACCESS_KEY')}
        self.payload = b'synthetic immutable original ciphertext'
        self.key = 'col/doc/synthetic.bin'
        with sqlite3.connect(self.data / 'data.db') as db:
            db.executescript('CREATE TABLE _collections(id TEXT,name TEXT,type TEXT,fields TEXT); CREATE TABLE version_chunks(id TEXT,ciphertext TEXT,sha256 TEXT); CREATE TABLE _params(id TEXT,value TEXT);')
            db.execute('INSERT INTO _collections VALUES(?,?,?,?)', ('col','version_chunks','base',json.dumps([{'name':'ciphertext','type':'file','maxSelect':1}])))
            db.execute('INSERT INTO version_chunks VALUES(?,?,?)', ('doc', 'synthetic.bin', backup.hashlib.sha256(self.payload).hexdigest()))

    def freeze(self):
        settings = {field: self.env[PREFIX + name] for field, name in
                    {'bucket':'BUCKET','endpoint':'ENDPOINT','region':'REGION','accessKey':'ACCESS_KEY_ID','secret':'SECRET_ACCESS_KEY'}.items()}
        settings.update(enabled=True, forcePathStyle=True)
        with sqlite3.connect(self.data / 'data.db') as db:
            db.execute('INSERT INTO _params VALUES(?,?)', ('settings', json.dumps({'s3':settings})))
        (self.data / 'maintenance.json').write_text(json.dumps({'readOnly':True,'generation':1}))
        (self.data / 'maintenance.json').chmod(0o600)

    def test_remote_hashes_without_local_files(self):
        objects = {self.key:self.payload}
        class Client:
            def get_object(client, Bucket, Key):
                self.assertEqual(Bucket, self.env[PREFIX+'BUCKET'])
                return {'Body':io.BytesIO(objects[Key])}
        with patch.dict(os.environ, self.env, clear=True):
            backup.verify_remote(self.data, Client())
            objects[self.key] = b'corrupt'
            with self.assertRaises(RuntimeError): backup.verify_remote(self.data, Client())
            del objects[self.key]
            with self.assertRaises(KeyError): backup.verify_remote(self.data, Client())

    def test_frozen_remote_configuration_must_match(self):
        self.freeze()
        with patch.dict(os.environ, self.env, clear=True), patch.object(backup, 'verify_remote') as verify:
            backup.verify(self.data)
            verify.assert_called_once_with(self.data)
        cases = [{}] + [dict(self.env, **{key:'changed'}) for key in self.env]
        cases += [dict(self.env, **{PREFIX+'FORCE_PATH_STYLE':'false'})]
        for env in cases:
            with patch.dict(os.environ, env, clear=True), patch.object(backup, 'verify_remote') as verify:
                with self.assertRaises(RuntimeError): backup.verify(self.data)
                verify.assert_not_called()

    def test_stored_remote_never_silently_falls_back(self):
        self.freeze()
        (self.data / 'maintenance.json').unlink()
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(RuntimeError):
            backup.verify(self.data)

    def test_frozen_local_cannot_switch_backend(self):
        (self.data / 'maintenance.json').write_text('{"readOnly":true,"generation":1}')
        with patch.dict(os.environ, self.env, clear=True), self.assertRaises(RuntimeError):
            backup.verify_frozen_storage(self.data)

    def test_bootstrap_settings_fail_closed(self):
        # Exercise the maintained JS helper with a minimal PocketBase settings adapter.
        script = r"""
const assert = require('assert');
const helper = require(process.argv[1]);
const prefix = process.argv[2];
let env = {}, stored = {s3:{}}, saves = 0;
global.$os = {getenv: key => env[key] || ''};
const app = {settings: () => stored, save: () => {saves++;}};
helper.settings(app); assert.equal(saves,0);
env[prefix+'FORCE_PATH_STYLE']='true'; assert.throws(()=>helper.settings(app), /Incomplete/); env={};
env[prefix+'BUCKET']='synthetic-bucket';
assert.throws(()=>helper.settings(app), /Incomplete/);
for (const key of ['BUCKET','ENDPOINT','REGION','ACCESS_KEY_ID','SECRET_ACCESS_KEY']) env[prefix+key]='synthetic-'+key;
env.LITESTREAM_BUCKET=env[prefix+'BUCKET']; assert.throws(()=>helper.settings(app), /separate buckets/); delete env.LITESTREAM_BUCKET;
env.LITESTREAM_ACCESS_KEY_ID=env[prefix+'ACCESS_KEY_ID']; assert.throws(()=>helper.settings(app), /separate credentials/); delete env.LITESTREAM_ACCESS_KEY_ID;
helper.settings(app); assert.equal(stored.s3.enabled,true); assert.equal(saves,1);
helper.settings(app); assert.equal(saves,1);
env[prefix+'FORCE_PATH_STYLE']='invalid'; assert.throws(()=>helper.settings(app), /path style/);
delete env[prefix+'FORCE_PATH_STYLE'];
app.save=()=>{throw new Error('synthetic-secret-must-not-escape')};
env[prefix+'BUCKET']='changed'; assert.throws(()=>helper.settings(app), /^Error: Could not apply/);
env={}; assert.throws(()=>helper.settings(app), /explicit/);
"""
        # Chat also applies appName; give that group its expected existing value.
        script = script.replace('stored = {s3:{}}', 'stored = {s3:{},meta:{appName:"ChatContext"}}')
        subprocess.run(['node', '-e', script, str(ROOT/'pb_hooks/deploy.js'), PREFIX], check=True, capture_output=True)


if __name__ == '__main__':
    unittest.main()
