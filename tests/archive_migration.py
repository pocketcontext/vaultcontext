#!/usr/bin/env python3
"""Populated pre-archive schema upgrades preserve encrypted document history."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile
from integration import ROOT, server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='vaultcontext-archive-upgrade-') as tmp:
        tmp = Path(tmp)
        migrations = tmp / 'legacy_migrations'
        shutil.copytree(ROOT / 'pb_migrations', migrations)
        (migrations / '1790300300_document_archive.js').unlink()
        data = tmp / 'pb_data'
        legacy_config = json.loads((ROOT / 'pocketcontext.json').read_text())
        legacy_config['tables']['documents'] = [c for c in legacy_config['tables']['documents']
                                                if c not in ('archived', 'archive_revision')]
        (tmp / 'pocketcontext.json').write_text(json.dumps(legacy_config))
        path = lambda table: '/api/collections/' + table + '/records'
        def admin(request):
            return request('POST', '/api/collections/_superusers/auth-with-password',
                           {'identity': 'admin@example.com', 'password': 'SyntheticAdminPassword123!'})['token']
        with server(args.binary, migrations=migrations, data_dir=data, cwd=tmp) as request:
            token = admin(request)
            # Provision synthetic pre-migration data through maintenance REST APIs.
            request('POST', path('documents'), {'id': 'd'*15, 'vault': 'v'*15,
                    'metadata': 'synthetic-encrypted-metadata', 'revision': 7,
                    'current_version': 'x'*15}, token)
            request('POST', path('versions'), {'id': 'x'*15, 'vault': 'v'*15,
                    'document': 'd'*15, 'revision': 7, 'epoch': 1,
                    'manifest': 'synthetic-signed-manifest', 'signature': 'synthetic-signature',
                    'author': 'a'*15, 'chunk_count': 0}, token)
            document = request('GET', path('documents') + '/' + 'd'*15, token=token)
            version = request('GET', path('versions') + '/' + 'x'*15, token=token)
            assert 'archived' not in document
        with server(args.binary, data_dir=data) as request:
            token = admin(request)
            upgraded = request('GET', path('documents') + '/' + 'd'*15, token=token)
            assert upgraded.pop('archived') is False
            assert upgraded.pop('archive_revision') == 0
            assert upgraded == document, (upgraded, document)
            assert request('GET', path('versions') + '/' + 'x'*15, token=token) == version
    print('VaultContext populated archive migration: PASS')


if __name__ == '__main__':
    main()
