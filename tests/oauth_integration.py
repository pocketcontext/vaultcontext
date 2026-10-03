#!/usr/bin/env python3
"""Exercise PocketBase's Google exchange with a local provider and synthetic users."""
import argparse
import base64
import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import secrets
import threading
import time
import urllib.parse
from unittest.mock import patch

from integration import server


@contextlib.contextmanager
def google_fixture():
    codes, tokens = {}, {}

    class Provider(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, data):
            body = json.dumps(data).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.path != '/token':
                return self.reply(404, {})
            form = urllib.parse.parse_qs(self.rfile.read(int(self.headers.get('Content-Length', 0))).decode())
            get = lambda key: form.get(key, [''])[0]
            pending = codes.get(get('code'))
            challenge = base64.urlsafe_b64encode(hashlib.sha256(get('code_verifier').encode()).digest()).decode().rstrip('=')
            if not pending or challenge != pending['challenge'] or get('redirect_uri') != REDIRECT:
                return self.reply(400, {'error': 'invalid_grant'})
            if get('grant_type') != 'authorization_code':
                return self.reply(400, {'error': 'unsupported_grant_type'})
            del codes[get('code')]
            token = secrets.token_urlsafe(24)
            tokens[token] = pending['user']
            self.reply(200, {'access_token': token, 'token_type': 'Bearer', 'expires_in': 3600})

        def do_GET(self):
            user = tokens.get(self.headers.get('Authorization', '').removeprefix('Bearer '))
            if self.path != '/userinfo' or user is None:
                return self.reply(401, {})
            self.reply(200, user)

    http = ThreadingHTTPServer(('127.0.0.1', 0), Provider)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{http.server_port}', codes
    finally:
        http.shutdown()
        http.server_close()
        thread.join()


REDIRECT = 'http://127.0.0.1:8765/callback'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    with patch.dict(os.environ, {'VAULTCONTEXT_GOOGLE_WORKSPACE_DOMAIN': 'example.com'}), google_fixture() as (url, codes), server(args.binary) as request:
        admin = request('POST', '/api/collections/_superusers/auth-with-password', {
            'identity': 'admin@example.com', 'password': 'SyntheticAdminPassword123!',
        })['token']
        provider = {'name': 'google', 'clientId': 'synthetic-client', 'clientSecret': 'synthetic-secret',
                    'authURL': url + '/authorize', 'tokenURL': url + '/token', 'userInfoURL': url + '/userinfo'}
        request('PATCH', '/api/collections/users', {'oauth2': {'enabled': True, 'providers': [provider]}}, admin)
        signup = {'email': 'member@example.com', 'name': 'Provisioned member', 'password': 'SyntheticPassword123!',
                  'passwordConfirm': 'SyntheticPassword123!', 'verified': True, 'disabled': False}
        request('POST', '/api/collections/users/records', signup, expected=(400, 403))
        request('POST', '/api/collections/users/records?context=oauth2', signup, expected=(400, 403))

        def exchange(email='member@example.com', *, hd='example.com', verified=True, expected=200,
                     create_data=None, subject=None, token=None, wrong_verifier=False):
            metadata = request('GET', '/api/collections/users/auth-methods')['oauth2']['providers'][0]
            code = secrets.token_urlsafe(24)
            identity = {'sub': subject or email, 'email': email, 'email_verified': verified, 'name': 'Google name'}
            if hd is not None:
                identity['hd'] = hd
            codes[code] = {'challenge': metadata['codeChallenge'], 'user': identity}
            body = {'provider': 'google', 'code': code, 'redirectURL': REDIRECT,
                    'codeVerifier': 'wrong' if wrong_verifier else metadata['codeVerifier']}
            if create_data is not None:
                body['createData'] = create_data
            return request('POST', '/api/collections/users/auth-with-oauth2', body, token, expected)

        # New identities cannot enter through malformed or forged Google claims.
        for options in [{'hd': None}, {'hd': 'outside.com'}, {'hd': 'example.com.attacker.test'},
                        {'verified': False}, {'verified': 'true'}, {'email': 'new@outside.com'},
                        {'email': 'new@example.com.attacker.test'}]:
            exchange(**{'email': 'new@example.com', **options}, create_data={**signup, 'hd': 'example.com'}, expected=(400, 403))
        # Existing explicitly provisioned accounts must keep their identity.
        assert request('GET', '/api/collections/users/records', token=admin)['totalItems'] == 0
        user = request('POST', '/api/collections/users/records', signup, admin)
        for options in [{'hd': None}, {'hd': 'outside.com'}, {'verified': False}, {'verified': 'true'},
                        {'email': 'member@outside.com'}, {'wrong_verifier': True}]:
            exchange(**options, expected=(400, 403))
        auth = exchange(create_data={'disabled': True, 'name': 'Forged', 'id': 'forged000000001'})
        assert auth['record']['id'] == user['id'] and auth['record']['name'] == signup['name']
        assert not auth['record']['disabled']
        assert exchange()['record']['id'] == user['id']
        assert exchange(email='MEMBER@example.com', subject='member@example.com')['record']['id'] == user['id']
        token = auth['token']
        request('GET', '/api/context/schema', token=token)
        refreshed = request('POST', '/api/collections/users/auth-refresh', token=token)
        claims = json.loads(base64.urlsafe_b64decode(refreshed['token'].split('.')[1] + '=='))
        assert abs(claims['exp'] - time.time() - 604800) < 30
        path = '/api/collections/users/records/' + user['id']
        request('PATCH', path, {'disabled': True}, admin)
        exchange(expected=(400, 403))
        request('GET', '/api/context/schema', token=token, expected=(401, 403))
        request('PATCH', path, {'disabled': False}, admin)
        request('GET', '/api/context/schema', token=token, expected=(401, 403))
        exchange()
        assert request('GET', '/api/collections/users', token=admin)['createRule'] == "@request.context = 'oauth2'"
        assert request('GET', '/api/collections/users/records', token=admin)['totalItems'] == 1
        # First verified Workspace login creates a standard users identity and
        # directory entry, ignoring every untrusted client provisioning field.
        forged = {**signup, 'id': 'forged000000001', 'disabled': True, 'name': 'Forged', 'email': 'attacker@outside.com'}
        fresh = exchange(email='new@example.com', create_data=forged)
        new_user = fresh['record']
        assert new_user['collectionName'] == 'users' and new_user['id'] != forged['id']
        assert new_user['email'] == 'new@example.com' and new_user['name'] == 'Google name'
        assert new_user['verified'] and not new_user['disabled']
        assert request('GET', '/api/collections/user_directory/records/' + new_user['id'], token=admin)['name'] == 'Google name'
        assert exchange(email='new@example.com')['record']['id'] == new_user['id']
        request('POST', '/api/collections/users/auth-with-password', {
            'identity': 'new@example.com', 'password': signup['password'],
        }, expected=(400, 401, 403))
        request('POST', '/api/collections/users/records', signup, token=fresh['token'], expected=(400, 403))
        assert request('GET', '/api/collections/users/records', token=admin)['totalItems'] == 2
        new_path = '/api/collections/users/records/' + new_user['id']
        request('PATCH', new_path, {'disabled': True}, admin)
        exchange(email='NEW@example.com', subject='new@example.com', expected=(400, 403))
        request('GET', '/api/context/schema', token=fresh['token'], expected=(401, 403))
        request('PATCH', new_path, {'disabled': False}, admin)
        request('GET', '/api/context/schema', token=fresh['token'], expected=(401, 403))
        assert exchange(email='new@example.com')['record']['id'] == new_user['id']
    no_domain_checks(args.binary)
    print('PASS: Google Workspace JIT, trusted identity claims, PKCE, existing identity preservation and revocation')


def no_domain_checks(binary):
    with patch.dict(os.environ, {'VAULTCONTEXT_GOOGLE_WORKSPACE_DOMAIN': ''}), google_fixture() as (url, codes), server(binary) as request:
        admin = request('POST', '/api/collections/_superusers/auth-with-password', {
            'identity': 'admin@example.com', 'password': 'SyntheticAdminPassword123!',
        })['token']
        provider = {'name': 'google', 'clientId': 'synthetic-client', 'clientSecret': 'synthetic-secret',
                    'authURL': url + '/authorize', 'tokenURL': url + '/token', 'userInfoURL': url + '/userinfo'}
        request('PATCH', '/api/collections/users', {'oauth2': {'enabled': True, 'providers': [provider]}}, admin)
        def exchange(expected):
            metadata = request('GET', '/api/collections/users/auth-methods')['oauth2']['providers'][0]
            code = secrets.token_urlsafe(24)
            codes[code] = {'challenge': metadata['codeChallenge'], 'user': {
                'sub': 'existing', 'email': 'existing@example.com', 'email_verified': True, 'hd': 'example.com', 'name': 'Google name',
            }}
            return request('POST', '/api/collections/users/auth-with-oauth2', {
                'provider': 'google', 'code': code, 'redirectURL': REDIRECT, 'codeVerifier': metadata['codeVerifier'],
            }, expected=expected)
        exchange((400, 403))
        assert request('GET', '/api/collections/users/records', token=admin)['totalItems'] == 0
        existing = request('POST', '/api/collections/users/records', {
            'email': 'existing@example.com', 'name': 'Existing',
            'password': 'SyntheticPassword123!', 'passwordConfirm': 'SyntheticPassword123!',
        }, admin)
        assert exchange(200)['record']['id'] == existing['id']


if __name__ == '__main__':
    main()
