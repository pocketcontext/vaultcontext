#!/usr/bin/env python3
"""Exact release enforcement through real HTTP with synthetic isolated records."""
import argparse
import json
import urllib.error
import urllib.request
from integration import ROOT, server

RELEASE = json.loads((ROOT / 'pb_hooks/release.json').read_text())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    with server(args.binary) as request:
        def raw(method, path, body=None, token=None, release=None, expected=200):
            headers = {'Content-Type': 'application/json'}
            if token:
                headers['Authorization'] = token
            if release is not None:
                headers['X-VaultContext-Release'] = release
            req = urllib.request.Request(request.base_url + path, headers=headers, method=method,
                data=None if body is None else json.dumps(body).encode())
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    status, data = response.status, response.read()
            except urllib.error.HTTPError as error:
                status, data = error.code, error.read()
            assert status == expected, (method, path, status, data)
            try:
                return json.loads(data) if data else None
            except ValueError:
                return data

        assert raw('GET', '/api/vaultcontext/compatibility') == RELEASE
        raw('GET', '/api/health')
        raw('GET', '/')
        admin = raw('POST', '/api/collections/_superusers/auth-with-password',
            {'identity': 'admin@example.com', 'password': 'SyntheticAdminPassword123!'})['token']
        user = raw('POST', '/api/collections/users/records',
            {'email': 'release@example.com', 'name': 'Synthetic', 'password': 'SyntheticUserPassword123!',
             'passwordConfirm': 'SyntheticUserPassword123!'}, token=admin)
        login = {'identity': 'release@example.com', 'password': 'SyntheticUserPassword123!'}
        raw('POST', '/api/collections/users/auth-with-password', login, expected=403)
        token = raw('POST', '/api/collections/users/auth-with-password', login,
            release=RELEASE['release_id'])['token']
        routes = [
            ('GET', '/api/context/schema', None),
            ('POST', '/api/context/query', {'sql': 'SELECT * FROM vaults'}),
            ('GET', '/api/collections/vaults/records', None),
            ('POST', '/api/collections/vault_actions/records', {'op': 'identity_init', 'payload': {}}),
            ('POST', '/api/files/token', {}),
            ('GET', '/api/files/version_chunks/' + 'a' * 15 + '/synthetic.bin?token=invalid', None),
            ('POST', '/api/realtime', {'clientId': 'synthetic', 'subscriptions': ['vaults/*']}),
            ('GET', '/api/realtime', None),
            ('POST', '/api/batch', {'requests': []}),
            ('POST', '/api/collections/users/auth-refresh', {}),
        ]
        actions = raw('GET', '/api/collections/vault_actions', token=admin)
        routes.extend([
            ('POST', '/api/collections/' + actions['id'] + '/records', {'op': 'identity_init', 'payload': {}}),
            ('POST', '/%61pi/context/query', {'sql': 'SELECT * FROM vaults'}),
            ('GET', '/api/context/schema/', None),
            ('GET', '/api/collections/_superusers/../vaults/records', None),
        ])
        for release in (None, 'previous-release', RELEASE['release_id'] + '-future'):
            for method, path, body in routes:
                result = raw(method, path, body, token, release, 403)
                assert result['data'] == dict(RELEASE, code='client_upgrade_required'), result
        # Release claims never replace authentication, SQL restrictions, or REST rules.
        raw('POST', '/api/context/query', {'sql': 'SELECT * FROM vaults'},
            release=RELEASE['release_id'], expected=401)
        raw('POST', '/api/context/query', {'sql': 'SELECT * FROM users'}, token,
            RELEASE['release_id'], 400)
        raw('POST', '/api/collections/versions/records', {}, token,
            RELEASE['release_id'], 403)
        raw('POST', '/api/context/query', {'sql': 'SELECT * FROM vaults'}, token,
            RELEASE['release_id'])
        # A rejected mutation never initializes an identity.
        result = raw('POST', '/api/context/query', {'sql': 'SELECT * FROM identity_secrets'},
            token, RELEASE['release_id'])
        assert result['rows'] == []
        # Operator reads are available without a release claim.
        raw('GET', '/api/collections/users/records/' + user['id'], token=admin)
        # Anonymous SSE exists only for OAuth setup. Record subscriptions still
        # require the matching release, and mixed subscriptions cannot bypass it.
        stream = urllib.request.urlopen(request.base_url + '/api/realtime', timeout=5)
        try:
            for line in stream:
                if line.startswith(b'data:'):
                    client_id = json.loads(line[5:])['clientId']
                    break
            else:
                raise AssertionError('Missing realtime connection event')
            raw('POST', '/api/realtime', {'clientId': client_id, 'subscriptions': ['@oauth2']}, expected=204)
            raw('POST', '/api/realtime', {'clientId': client_id, 'subscriptions': ['vaults/*']}, expected=403)
            raw('POST', '/api/realtime', {'clientId': client_id, 'subscriptions': ['vaults/*']},
                token, RELEASE['release_id'], 204)
        finally:
            stream.close()
        # An invalid callback still reaches PocketBase's normal redirect handler.
        raw('GET', '/api/oauth2-redirect?state=synthetic&error=access_denied')
        # OAuth-only subscription bypass reaches PocketBase's client-id validation.
        raw('POST', '/api/realtime', {'clientId': 'synthetic', 'subscriptions': ['@oauth2']}, expected=404)
        for subscriptions in (['@oauth2', 'vaults/*'], ['vaults/*'], [], '@oauth2'):
            result = raw('POST', '/api/realtime', {'clientId': 'synthetic', 'subscriptions': subscriptions}, expected=403)
            assert result['data']['code'] == 'client_upgrade_required'
        # A valid file token is insufficient without the matching release, while
        # matching releases still receive the independently authorized bytes.
        request('POST', '/api/collections/vault_actions/records', {'op': 'identity_init', 'payload': {
            'public_key': 'synthetic-public', 'signing_key': 'synthetic-signing',
            'fingerprint': 'synthetic-fingerprint', 'key_bundle': 'synthetic-ciphertext'}}, token)
        request('POST', '/api/collections/vault_actions/records', {'op': 'vault_create', 'payload': {
            'id': 'v' * 15, 'metadata': 'ciphertext', 'envelope': 'ciphertext'}}, token)
        request('POST', '/api/collections/vault_actions/records', {'op': 'save', 'payload': {
            'vault': 'v' * 15, 'document': 'd' * 15, 'version': 'z' * 15, 'expected_revision': 0,
            'epoch': 1, 'metadata': 'ciphertext', 'manifest': 'ciphertext', 'signature': 'synthetic',
            'chunks': ['synthetic-file-bytes']}}, token)
        query = request('POST', '/api/context/query', {'sql': 'SELECT * FROM version_chunks'}, token)
        chunk = dict(zip(query['columns'], query['rows'][0]))
        file_token = request('POST', '/api/files/token', {}, token)['token']
        path = '/api/files/version_chunks/' + chunk['id'] + '/' + chunk['ciphertext'] + '?token=' + file_token
        assert raw('GET', path, expected=403)['data']['code'] == 'client_upgrade_required'
        assert raw('GET', path, release=RELEASE['release_id']) == b'synthetic-file-bytes'
        # Exercise the container primary-storage helper against the real gate;
        # its owner download must claim the release without bypassing file auth.
        import hashlib
        import importlib.util
        spec = importlib.util.spec_from_file_location('primary_storage_smoke', ROOT / 'docker/object_storage_smoke.py')
        primary = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(primary)
        assert primary.protected_checksum(request.base_url + path) == hashlib.sha256(b'synthetic-file-bytes').hexdigest()

    print('VaultContext exact release gate: PASS')


if __name__ == '__main__':
    main()
