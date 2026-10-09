"""Public artifact allowlist, integrity, and reproducibility checks; synthetic output."""
import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('demo_downloads', ROOT/'scripts/build-demo-downloads.py')
builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)


class PublicDownloads(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node required for hook runtime test')
    def test_fixed_hash_tool_fallback_and_failure(self):
        program = r"""
const vm=require('vm'),fs=require('fs'),assert=require('assert');
const release='0.1.0-'+'a'.repeat(20),prefix='/demo/downloads/'+release+'/';
const manifest={schema:1,package:'vaultcontext-client',version:'0.1.0',release,
 origin:'https://vault-demo.pocketcontext.com',artifacts:{}};
for(const [key,name] of Object.entries({wheel:'vaultcontext_client-0.1.0-py3-none-any.whl',skill:'vaultcontext-skill.tar.gz',launcher:'vaultcontext'}))
 manifest.artifacts[key]={path:prefix+name,size:3,sha256:'b'.repeat(64)};
for(const mode of ['linux','macos','failed','corrupt']) {
 const calls=[],cache=new Map();
 const context={module:{exports:{}},toString:value=>String(value),$os:{
  getenv:()=>manifest.origin,
  readFile:path=>path.endsWith('manifest.json')?Buffer.from(JSON.stringify(manifest)):Buffer.from([0,128,255]),
  cmd:(...args)=>({output:()=>{
   calls.push(args);
   if(mode==='failed'||(mode!=='linux'&&args[0]==='/usr/bin/sha256sum'))throw Error('unavailable');
   return ['wheel','skill','launcher'].map(key=>(mode==='corrupt'?'c':'b').repeat(64)+'  pb_public'+manifest.artifacts[key].path).join('\n');
  }})}};
 vm.createContext(context);vm.runInContext(fs.readFileSync('pb_hooks/demo.js','utf8'),context);
 const result=context.publicDownloads({store:()=>({get:key=>cache.get(key),set:(key,value)=>cache.set(key,value)})});
 assert.equal(!!result,mode==='linux'||mode==='macos');
 assert.equal(calls.length,mode==='linux'?1:2);
 assert.equal(calls[0][0],'/usr/bin/sha256sum');
 if(mode!=='linux')assert.deepEqual(calls[1].slice(0,3),['/usr/bin/shasum','-a','256']);
 for(const call of calls)assert.deepEqual(call.slice(mode!=='linux'&&call[0].endsWith('shasum')?3:1),['wheel','skill','launcher'].map(key=>'pb_public'+manifest.artifacts[key].path));
}
"""
        subprocess.run(['node', '-e', program], cwd=ROOT, check=True)

    def test_origin_safety(self):
        for value in ('https://vault-demo.pocketcontext.com', 'http://127.0.0.1:18770'):
            self.assertEqual(builder.origin(value), value)
        for value in ('http://public.example', 'https://user:secret@example.com', 'https://example.com/path', 'https://example.com?token=x', "https://example.com/'"):
            with self.assertRaises(ValueError): builder.origin(value)

    def test_allowlisted_reproducible_artifacts(self):
        with tempfile.TemporaryDirectory(prefix='demo-downloads-test-') as temporary:
            first, second = Path(temporary)/'first', Path(temporary)/'second'
            for target in (first, second):
                builder.build(ROOT, target, 'https://vault-demo.pocketcontext.com', 'uv')
            inventory = lambda root: {str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()}
            self.assertEqual(inventory(first), inventory(second))
            manifest = json.loads((first/'manifest.json').read_text())
            self.assertEqual(set(manifest['artifacts']), {'wheel','skill','launcher'})
            artifacts = {}
            for key, artifact in manifest['artifacts'].items():
                self.assertTrue(artifact['path'].startswith('/demo/downloads/'+manifest['release']+'/'))
                data = (first/Path(artifact['path']).relative_to('/demo/downloads')).read_bytes()
                self.assertEqual(len(data), artifact['size'])
                self.assertEqual(hashlib.sha256(data).hexdigest(), artifact['sha256'])
                artifacts[key] = data
            with tarfile.open(fileobj=io.BytesIO(artifacts['skill']),mode='r:gz') as archive:
                expected = {'vaultcontext/'+name for name in (*builder.SKILL_FILES,'vaultcontext')}
                self.assertEqual(set(archive.getnames()),expected)
                for item in archive.getmembers():
                    self.assertTrue(item.isfile()); self.assertFalse(item.issym() or item.islnk())
                    self.assertFalse(Path(item.name).is_absolute()); self.assertNotIn('..',Path(item.name).parts)
                    text = archive.extractfile(item).read().decode()
                    self.assertNotIn('git+',text)
                    self.assertNotIn('github.com/pocketcontext',text)
                self.assertEqual(archive.extractfile('vaultcontext/vaultcontext').read(),artifacts['launcher'])
            self.assertIn('#sha256='+manifest['artifacts']['wheel']['sha256'],artifacts['launcher'].decode())
            self.assertIn('uv run --no-project --with',artifacts['launcher'].decode())
            with zipfile.ZipFile(io.BytesIO(artifacts['wheel'])) as archive:
                self.assertTrue(all(name.startswith(('vaultcontext_client/','vaultcontext_client-0.1.0.dist-info/')) for name in archive.namelist()))
                self.assertIn('vaultcontext_client/schema.json',archive.namelist())


if __name__ == '__main__': unittest.main()
