"""Public artifact allowlist, integrity, and reproducibility checks; synthetic output."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('demo_downloads', ROOT/'scripts/build-demo-downloads.py')
builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)


class PublicDownloads(unittest.TestCase):
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
