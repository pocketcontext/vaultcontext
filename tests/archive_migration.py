#!/usr/bin/env python3
"""Populated pre-archive schema upgrades preserve encrypted document history."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile
from integration import ROOT, server


def upgrade(binary, document_archiving):
    with tempfile.TemporaryDirectory(prefix='vaultcontext-archive-upgrade-') as tmp:
        tmp = Path(tmp)
        migrations = tmp / 'legacy_migrations'
        shutil.copytree(ROOT / 'pb_migrations', migrations)
        if not document_archiving:
            (migrations / '1790300300_document_archive.js').unlink()
        (migrations / '1790300400_vault_archive.js').unlink()
        data = tmp / 'pb_data'
        legacy_config = json.loads((ROOT / 'pocketcontext.json').read_text())
        if not document_archiving:
            legacy_config['tables']['documents'] = [c for c in legacy_config['tables']['documents']
                                                    if c not in ('archived', 'archive_revision')]
        legacy_config['tables']['vaults'] = [c for c in legacy_config['tables']['vaults']
                                             if c not in ('archived', 'archive_revision')]
        (tmp / 'pocketcontext.json').write_text(json.dumps(legacy_config))
        path = lambda table: '/api/collections/' + table + '/records'
        def admin(request):
            return request('POST', '/api/collections/_superusers/auth-with-password',
                           {'identity': 'admin@example.com', 'password': 'SyntheticAdminPassword123!'})['token']
        with server(binary, migrations=migrations, data_dir=data, cwd=tmp) as request:
            token = admin(request)
            # Provision synthetic pre-migration data through maintenance REST APIs.
            request('POST', path('vaults'), {'id': 'v'*15, 'owner': 'a'*15,
                    'metadata': 'synthetic-encrypted-vault', 'revision': 9,
                    'epoch': 3, 'frozen': True}, token)
            request('POST', path('audit_log'), {'id': 'h'*15, 'vault': 'v'*15,
                    'actor': 'a'*15, 'action': 'save', 'target': 'd'*15}, token)
            request('POST', path('documents'), {'id': 'd'*15, 'vault': 'v'*15,
                    'metadata': 'synthetic-encrypted-metadata', 'revision': 7,
                    'current_version': 'x'*15,
                    **({'archived': True, 'archive_revision': 3} if document_archiving else {})}, token)
            request('POST', path('versions'), {'id': 'x'*15, 'vault': 'v'*15,
                    'document': 'd'*15, 'revision': 7, 'epoch': 1,
                    'manifest': 'synthetic-signed-manifest', 'signature': 'synthetic-signature',
                    'author': 'a'*15, 'chunk_count': 0}, token)
            document = request('GET', path('documents') + '/' + 'd'*15, token=token)
            version = request('GET', path('versions') + '/' + 'x'*15, token=token)
            vault = request('GET', path('vaults') + '/' + 'v'*15, token=token)
            audit = request('GET', path('audit_log') + '/' + 'h'*15, token=token)
            assert 'archived' not in vault
            assert ('archived' in document) == document_archiving
        with server(binary, data_dir=data) as request:
            token = admin(request)
            upgraded = request('GET', path('documents') + '/' + 'd'*15, token=token)
            if not document_archiving:
                assert upgraded.pop('archived') is False
                assert upgraded.pop('archive_revision') == 0
            assert upgraded == document, (upgraded, document)
            assert request('GET', path('versions') + '/' + 'x'*15, token=token) == version
            upgraded_vault = request('GET', path('vaults') + '/' + 'v'*15, token=token)
            assert upgraded_vault.pop('archived') is False
            assert upgraded_vault.pop('archive_revision') == 0
            assert upgraded_vault == vault, (upgraded_vault, vault)
            assert request('GET', path('audit_log') + '/' + 'h'*15, token=token) == audit


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    for document_archiving in (False, True):
        upgrade(args.binary, document_archiving)
    print('VaultContext populated archive migration: PASS')


if __name__ == '__main__':
    main()
