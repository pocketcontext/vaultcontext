#!/usr/bin/env python3
"""Build deterministic public demo artifacts from allowlisted source.

Only the wheel, an allowlisted skill bundle, a launcher, and their public metadata
are copied to --output. No credentials or Git metadata belong in the result.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
from urllib.parse import urlsplit
import zipfile

EPOCH = 315532800  # Stable ZIP-compatible 1980-01-01 timestamp.
SKILL_FILES = ('SKILL.md', 'references/schema.md', 'references/workflows.md')


def digest(value):
    return hashlib.sha256(value).hexdigest()


def origin(value):
    parsed = urlsplit(value)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path or not parsed.hostname:
        raise ValueError('origin must contain only scheme, host and optional port')
    if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost', '[::1]', '::1')):
        raise ValueError('HTTPS required except explicit loopback test origins')
    if not re.fullmatch(r'[A-Za-z0-9.:/\[\]-]+', value):
        raise ValueError('invalid public origin')
    return value


def build(source, output, public_origin, uv):
    source = source.resolve(); output = output.resolve()
    project = tomllib.loads((source / 'pyproject.toml').read_text())['project']
    if project['name'] != 'vaultcontext-client' or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', project['version']):
        raise ValueError('unexpected client package identity')
    env = dict(os.environ, SOURCE_DATE_EPOCH=str(EPOCH), UV_NO_PROGRESS='1')
    with tempfile.TemporaryDirectory(prefix='vaultcontext-public-build-') as temporary:
        temp = Path(temporary)
        # uv/build backend dependencies come from public PyPI, never a Git URL.
        subprocess.run([uv, 'build', '--wheel', '--no-sources', '--no-create-gitignore', '--out-dir', str(temp / 'wheel'), str(source)], env=env, check=True)
        wheels = list((temp / 'wheel').glob('*.whl'))
        if len(wheels) != 1:
            raise ValueError('expected exactly one built wheel')
        wheel = wheels[0]; wheel_data = wheel.read_bytes()
        with zipfile.ZipFile(io.BytesIO(wheel_data)) as archive:
            for name in archive.namelist():
                if not (name.startswith('vaultcontext_client/') or name.startswith('vaultcontext_client-' + project['version'] + '.dist-info/')) or '..' in Path(name).parts:
                    raise ValueError('unexpected wheel contents')
            metadata = archive.read(next(n for n in archive.namelist() if n.endswith('.dist-info/METADATA'))).decode()
            if re.search(r'^Requires-Dist:.*(?:git\+|https?://|file:)', metadata, re.M | re.I):
                raise ValueError('wheel dependencies must use public package-index names')
        texts = {name: (source / 'skills/vaultcontext' / name).read_text() for name in SKILL_FILES}
        # Origin is part of the immutable release identity because the launcher
        # binds its wheel URL to this deployment. Source docs/template changes
        # also create new paths instead of silently replacing a prior bundle.
        identity = json.dumps({'wheel': digest(wheel_data), 'origin': public_origin,
            'skill': {name: digest(text.encode()) for name, text in texts.items()},
            'builder': digest(Path(__file__).read_bytes())}, sort_keys=True).encode()
        release = project['version'] + '-' + digest(identity)[:20]
        prefix = '/demo/downloads/' + release + '/'
        wheel_url = public_origin + prefix + wheel.name + '#sha256=' + digest(wheel_data)
        launcher = ("#!/usr/bin/env sh\n# Public demo client; immutable wheel verified by uv. No GitHub access required.\n"
            "exec uv run --no-project --with '" + wheel_url + "' vaultcontext \"$@\"\n").encode()
        # Bundle-specific instructions replace repository-only installation notes.
        skill_header = '''---
name: vaultcontext
description: Store, compare, version and restore encrypted files using the public VaultContext demo client. Never inspect or execute stored content.
---

# VaultContext public demo client

This downloaded bundle works without cloning the public source repository. Install uv,
then run this bundle's `vaultcontext` launcher by absolute path or copy it onto PATH.
It uses `uv run --no-project --with` and an immutable public wheel URL with a SHA-256
fragment. PyNaCl and its dependencies are fetched from public PyPI. Linux and macOS
are supported; installation and the first command require network access. No GitHub
credentials are required. Never request operator credentials or put tokens in URLs.

Read [workflows](references/workflows.md) and [schema](references/schema.md).
Before replacing a client, lock active sessions; unlock only as an explicit user
action in a private terminal. The server URL is ''' + public_origin + '''.
Use only synthetic files in the disposable demo. Complete browser enrollment first.

'''
        source_skill = texts['SKILL.md']
        body = source_skill[source_skill.index('## Identity and trust'):]
        if '## Disposable demo' in body:
            start = body.index('## Disposable demo'); end = body.index('## Failures', start)
            body = body[:start] + '''## Disposable demo

Google sign-in and required demo terms precede vault use. Commercial contact and
newsletter choices are separate and optional. Accounts, encrypted keys and vault
files reset daily at 00:00 UTC; contact preferences have separate retention.
After reset, lock stale sessions and explicitly initialize a fresh identity.
Never silently replace fingerprint pins. Sharing, Keychain enrollment and
passphrase changes are unavailable in this personal-vault demo.

''' + body[end:]
        texts['SKILL.md'] = skill_header + body
        texts['references/workflows.md'] = texts['references/workflows.md'].replace(
            'The launcher is self-contained and pins the client package to a full Git commit.',
            'The launcher is self-contained and pins the public client wheel by SHA-256; no repository access is required.')
        # Remove repository checkout installation alternative from the public guide.
        workflows = texts['references/workflows.md']
        start = workflows.find('For an existing Python 3.11+ setup,')
        end = workflows.find('## Sign in and initialize', start)
        if start >= 0 and end > start:
            workflows = workflows[:start] + workflows[end:]
        texts['references/workflows.md'] = workflows.replace('https://vault.example.com', public_origin)
        payload = {name: text.encode() for name, text in texts.items()}
        payload['vaultcontext'] = launcher
        archive_bytes = io.BytesIO()
        with gzip.GzipFile(fileobj=archive_bytes, mode='wb', filename='', mtime=EPOCH) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                for name in sorted(payload):
                    entry = tarfile.TarInfo('vaultcontext/' + name)
                    entry.size = len(payload[name]); entry.mtime = EPOCH
                    entry.mode = 0o755 if name == 'vaultcontext' else 0o644
                    entry.uid = entry.gid = 0; entry.uname = entry.gname = ''
                    archive.addfile(entry, io.BytesIO(payload[name]))
        artifacts = {'wheel': (wheel.name, wheel_data), 'skill': ('vaultcontext-skill.tar.gz', archive_bytes.getvalue()), 'launcher': ('vaultcontext', launcher)}
        destination = output / release
        destination.mkdir(parents=True, exist_ok=True)
        records = {}
        for key, (name, data) in artifacts.items():
            target = destination / name
            if target.exists() and target.read_bytes() != data:
                raise ValueError('immutable release collision')
            target.write_bytes(data); target.chmod(0o755 if key == 'launcher' else 0o644)
            records[key] = {'path': prefix + name, 'sha256': digest(data), 'size': len(data)}
        sums = ''.join(records[key]['sha256'] + '  ' + name + '\n' for key, (name, _) in artifacts.items())
        (destination / 'SHA256SUMS').write_text(sums)
        manifest = {'schema': 1, 'package': project['name'], 'version': project['version'], 'release': release,
            'origin': public_origin, 'artifacts': records}
        encoded = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
        (destination / 'manifest.json').write_bytes(encoded)
        # Atomically select the built release; old content-addressed directories remain.
        selected = output / '.manifest.json.tmp'; selected.write_bytes(encoded)
        selected.replace(output / 'manifest.json')
        print(json.dumps({'release': release, 'manifest': str(output / 'manifest.json')}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--origin', type=origin, default='https://vault-demo.pocketcontext.com')
    parser.add_argument('--uv', default='uv')
    args = parser.parse_args()
    build(args.source, args.output, args.origin, args.uv)


if __name__ == '__main__':
    main()
