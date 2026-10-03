#!/usr/bin/env python3
"""Synthetic account lifecycle checks through independent HTTP access paths."""
import argparse
import os
from unittest.mock import patch

from integration import server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    with patch.dict(os.environ, {'VAULTCONTEXT_GOOGLE_CLIENT_ID': 'synthetic-client',
                                 'VAULTCONTEXT_GOOGLE_CLIENT_SECRET': 'synthetic-secret'}), server(args.binary) as request:
        admin = request('POST', '/api/collections/_superusers/auth-with-password', {
            'identity': 'admin@example.com', 'password': 'SyntheticAdminPassword123!',
        })['token']
        collections = request('GET', '/api/collections', token=admin)['items']
        assert {c['name'] for c in collections if c['type'] == 'auth'} == {'_superusers', 'users'}
        settings = request('GET', '/api/collections/users', token=admin)
        assert settings['id'] == '_pb_users_auth_'
        assert settings['createRule'] == "@request.context = 'oauth2'"
        assert settings['authToken']['duration'] == 604800
        assert settings['oauth2']['enabled']
        credentials = {'identity': 'member@example.test', 'password': 'SyntheticMemberPassword123!'}
        user = request('POST', '/api/collections/users/records', {
            'email': credentials['identity'], 'name': 'Member', 'password': credentials['password'],
            'passwordConfirm': credentials['password'],
        }, admin)
        path = '/api/collections/users/records/' + user['id']
        token = request('POST', '/api/collections/users/auth-with-password', credentials)['token']
        for value in (True, False):
            request('PATCH', path, {'disabled': value}, token, expected=(400, 403, 404))
            request('POST', '/api/batch', {'requests': [
                {'method': 'PATCH', 'url': path, 'body': {'disabled': value}},
            ]}, token, expected=(400, 403))
        # Neither self-service privilege escalation nor account erasure is permitted.
        request('DELETE', path, token=admin, expected=(400, 403))
        request('PATCH', path, {'disabled': True}, admin)

        def rejected(old_token):
            for method, endpoint, body in [
                ('GET', '/api/context/schema', None),
                ('POST', '/api/context/query', {'sql': 'SELECT * FROM vaults'}),
                ('GET', '/api/collections/vaults/records', None),
                ('POST', '/api/collections/vault_actions/records', {'op': 'identity_init', 'payload': {}}),
                ('GET', path, None),
                ('POST', '/api/collections/users/auth-refresh', None),
                ('POST', '/api/files/token', None),
                ('POST', '/api/batch', {'requests': [
                    {'method': 'POST', 'url': '/api/collections/vault_actions/records',
                     'body': {'op': 'identity_init', 'payload': {}}},
                ]}),
            ]:
                request(method, endpoint, body, old_token, expected=(400, 401, 403, 404))

        rejected(token)
        request('POST', '/api/collections/users/auth-with-password', credentials, expected=(400, 401, 403))
        assert request('GET', path, token=admin)['disabled']
        request('PATCH', path, {'disabled': False}, admin)
        rejected(token)
        fresh = request('POST', '/api/collections/users/auth-with-password', credentials)['token']
        request('GET', '/api/context/schema', token=fresh)
        assert request('GET', path, token=admin)['id'] == user['id']
    print('PASS: default users, Google settings, account disable/re-enable and stale-token rejection')


if __name__ == '__main__':
    main()
