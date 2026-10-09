"""Role-bound deployment bucket names; synthetic inputs, no provider calls."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'deploy/demo'))
import contact_replica
import docker_lifecycle
import reset

CHOSEN = ('once-v2-vaultcontext-demo-files', 'once-v2-vaultcontext-demo-replica',
          'once-v2-vaultcontext-demo-contacts-replica')
LEGACY = ('vaultcontext-demo-files', 'vaultcontext-demo-replicas', 'vaultcontext-demo-contacts-private')


class StorageNamesTests(unittest.TestCase):
    def test_role_bound_docker_and_reset_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'vaultcontext-demo'
            root.mkdir(mode=0o700)
            env_file = root / 'runtime.env'
            config_file = root / 'reset.json'
            for names in (CHOSEN, LEGACY, (CHOSEN[1], CHOSEN[0], CHOSEN[2]),
                          (CHOSEN[2], CHOSEN[1], CHOSEN[0]),
                          (CHOSEN[0] + '-other', CHOSEN[1], CHOSEN[2]),
                          (CHOSEN[0], CHOSEN[1], 'once-v2-production-contacts')):
                valid = names in (CHOSEN, LEGACY)
                values = {key: 'synthetic-value' for key in docker_lifecycle.REQUIRED}
                values.update(zip(('VAULTCONTEXT_S3_BUCKET', 'LITESTREAM_BUCKET', 'CONTACTS_LITESTREAM_BUCKET'), names))
                values.update(VAULTCONTEXT_S3_ACCESS_KEY_ID='primary-key', LITESTREAM_ACCESS_KEY_ID='replica-key',
                              CONTACTS_LITESTREAM_ACCESS_KEY_ID='contacts-key', VAULTCONTEXT_DEMO_CONTACT_TOKEN='x' * 32)
                env_file.write_text(''.join(key + '=' + value + '\n' for key, value in values.items()))
                env_file.chmod(0o600)
                cfg = {'deployment': 'vaultcontext-demo', 'origin': 'https://vault-demo.example.com', 'root': str(root),
                       'storage': dict(zip(('primary_bucket', 'replica_bucket', 'durable_bucket'), names), kind='r2'),
                       'hooks': {phase: ['/bin/true'] for phase in ('fence', 'stop', 'assert_stopped', 'initialize', 'start', 'health', 'unfence')}}
                config_file.write_text(json.dumps(cfg)); config_file.chmod(0o600)
                with self.subTest(names=names):
                    if valid:
                        docker_lifecycle.environment(env_file)
                        reset.configuration(config_file)
                    else:
                        with self.assertRaises(reset.ResetError): docker_lifecycle.environment(env_file)
                        with self.assertRaises(reset.ResetError): reset.configuration(config_file)

    def test_contact_replica_accepts_only_contact_role(self):
        for name in (*CHOSEN, LEGACY[2], CHOSEN[2] + '-other'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                env = {'CONTACTS_LITESTREAM_' + key: 'synthetic' for key in ('REGION', 'PATH', 'ACCESS_KEY_ID', 'SECRET_ACCESS_KEY')}
                env.update(CONTACTS_LITESTREAM_BUCKET=name, CONTACTS_LITESTREAM_ENDPOINT='https://storage.example.com')
                with patch.dict(os.environ, env, clear=True):
                    args = (Path(tmp) / 'state/contacts.db', 'unused', 'unused', 'unused')
                    if name in (CHOSEN[2], LEGACY[2]): contact_replica.Replica(*args)
                    else:
                        with self.assertRaises(contact_replica.ReplicaError): contact_replica.Replica(*args)

    def test_backend_primary_and_replica_role_guards(self):
        # Execute the real guard without starting a server or contacting storage.
        script = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const source=fs.readFileSync(process.argv[1],'utf8');
for(const [primary,replica,valid] of JSON.parse(process.argv[2])) {
 const env={};
 for(const prefix of ['VAULTCONTEXT_S3_','LITESTREAM_'])
  for(const field of ['ENDPOINT','REGION','ACCESS_KEY_ID','SECRET_ACCESS_KEY'])env[prefix+field]=prefix+field;
 env.VAULTCONTEXT_S3_BUCKET=primary;env.LITESTREAM_BUCKET=replica;
 const context={module:{exports:{}},$os:{getenv:key=>env[key]||''}};
 vm.createContext(context);vm.runInContext(source+'\nmodule.exports.storageBoundary=storageBoundary;',context);
 const run=()=>context.module.exports.storageBoundary({settings:()=>({s3:{enabled:false}})});
 if(valid)assert.doesNotThrow(run);else assert.throws(run);
}
'''
        cases = [(CHOSEN[0], CHOSEN[1], True), (LEGACY[0], LEGACY[1], True),
                 (CHOSEN[1], CHOSEN[0], False), (CHOSEN[2], CHOSEN[1], False),
                 (CHOSEN[0], CHOSEN[2], False), (CHOSEN[0] + '-other', CHOSEN[1], False)]
        result = subprocess.run(['node', '-e', script, str(ROOT / 'pb_hooks/demo.js'), json.dumps(cases)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__': unittest.main()
