#!/usr/bin/env python3
"""A populated pre-email-sharing database retains keys, grants and readable history."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile
from unittest.mock import patch

from integration import ROOT, server
from vaultcontext_client import cli, crypto


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='vaultcontext-sharing-upgrade-') as temporary:
        tmp = Path(temporary)
        migrations = tmp / 'legacy_migrations'
        shutil.copytree(ROOT / 'pb_migrations', migrations)
        (migrations / '1790300500_sharing_identity.js').unlink()
        config = json.loads((ROOT / 'pocketcontext.json').read_text())
        config['tables']['user_directory'].remove('sharing_eligible')
        (tmp / 'pocketcontext.json').write_text(json.dumps(config))
        data = tmp / 'pb_data'
        path = lambda table: '/api/collections/' + table + '/records'
        def admin(request):
            return request('POST', '/api/collections/_superusers/auth-with-password',
                           {'identity': 'admin@example.com',
                            'password': 'SyntheticAdminPassword123!'})['token']
        def login(request, email):
            return request('POST', '/api/collections/users/auth-with-password',
                           {'identity': email, 'password': 'SyntheticUserPassword123!'})['token']
        tables = ('identities', 'identity_secrets', 'vaults', 'memberships',
                  'key_envelopes', 'invitations', 'documents', 'versions', 'audit_log')
        def snapshot(request, token):
            return {table: request('GET', path(table) + '?sort=id&perPage=100',
                                   token=token)['items'] for table in tables}
        owner, reader, pending, vault = ('a' * 15, 'b' * 15, 'c' * 15, 'v' * 15)
        identities = {account: crypto.generate_identity() for account in (owner, reader, pending)}
        key = crypto.new_vault_key()
        with server(args.binary, migrations=migrations, data_dir=data, cwd=tmp,
                    workspace_domain='example.com') as request:
            token = admin(request)
            for account, name in ((owner, 'owner'), (reader, 'reader'), (pending, 'pending')):
                request('POST', path('users'), {'id': account, 'email': name + '@example.com',
                        'name': name, 'password': 'SyntheticUserPassword123!',
                        'passwordConfirm': 'SyntheticUserPassword123!'}, token)
                public = crypto.public_identity(identities[account])
                request('POST', path('identities'), {'id': account, 'account': account,
                        'public_key': public['enc_public'], 'signing_key': public['sign_public'],
                        'fingerprint': crypto.fingerprint(public)}, token)
                request('POST', path('identity_secrets'), {'id': account, 'account': account,
                        'key_bundle': cli.encode(crypto.wrap_identity(identities[account],
                         'synthetic migration passphrase', account)), 'revision': 1}, token)
                request('POST', path('memberships'), {'vault': vault, 'account': account,
                        'role': 'owner' if account == owner else 'reader',
                        'active': account != pending}, token)
                envelope = cli.encode({'signer': owner, 'sealed': crypto.seal_key(
                    key, public, identities[owner], cli.key_context(vault, account, 1, owner))})
                request('POST', path('key_envelopes'), {'vault': vault, 'account': account,
                        'epoch': 1, 'envelope': envelope}, token)
            request('POST', path('vaults'), {'id': vault, 'owner': owner,
                    'metadata': 'synthetic-encrypted-title', 'epoch': 1, 'revision': 5}, token)
            request('POST', path('invitations'), {'vault': vault, 'account': pending,
                    'role': 'reader', 'status': 'pending', 'invited_by': owner}, token)
            request('POST', path('documents'), {'id': 'd'*15, 'vault': vault,
                    'metadata': 'synthetic-encrypted-name', 'revision': 1,
                    'current_version': 'x'*15, 'archived': True, 'archive_revision': 2}, token)
            request('POST', path('versions'), {'id': 'x'*15, 'vault': vault,
                    'document': 'd'*15, 'epoch': 1, 'revision': 1,
                    'manifest': 'synthetic-manifest', 'signature': 'synthetic-signature',
                    'author': owner, 'chunk_count': 0}, token)
            request('POST', path('audit_log'), {'vault': vault, 'actor': owner,
                    'action': 'share', 'target': pending}, token)
            before = snapshot(request, token)
            directory = request('GET', path('user_directory') + '?sort=id', token=token)['items']
            assert all('sharing_eligible' not in row for row in directory)

        with server(args.binary, data_dir=data, workspace_domain='example.com') as request:
            token = admin(request)
            assert snapshot(request, token) == before
            upgraded = request('GET', path('user_directory') + '?sort=id', token=token)['items']
            assert all(row.pop('sharing_eligible') is False for row in upgraded)
            assert upgraded == directory
            reader_token = login(request, 'reader@example.com')
            # Password authentication cannot backfill verified Google provenance.
            rows = request('POST', '/api/context/query',
                           {'sql': 'SELECT sharing_eligible FROM user_directory'}, reader_token)['rows']
            assert len(rows) == 3 and all(not row[0] for row in rows)
            pins = tmp / 'private-pins' / 'fingerprints.json'
            pins.parent.mkdir(mode=0o700)
            crypto.restore_file(pins, cli.encode({owner: crypto.fingerprint(
                crypto.public_identity(identities[owner]))}).encode())
            original_pin = pins.read_bytes()
            def client_request(cfg, method, endpoint, body=None):
                return request(method, endpoint, body, reader_token)
            # The current client still authenticates the original signed envelope
            # using its existing owner pin, despite both accounts being ineligible.
            with patch.object(cli, 'request', client_request), patch.object(cli, 'pin_path', return_value=pins):
                assert cli.vault_key({}, identities[reader], reader, vault, 1) == key
                assert len(cli.rows({}, 'versions')) == 1
                assert len(cli.rows({}, 'documents')) == 1
            assert pins.read_bytes() == original_pin
            owner_token = login(request, 'owner@example.com')
            request('POST', path('vault_actions'), {'op': 'share', 'payload': {
                'vault': vault, 'account': reader, 'role': 'reader',
                'expected_revision': 5, 'envelopes': []}}, owner_token, 403)
            assert snapshot(request, token) == before
    print('VaultContext populated sharing migration: PASS')


if __name__ == '__main__':
    main()
