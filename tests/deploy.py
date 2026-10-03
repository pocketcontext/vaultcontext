#!/usr/bin/env python3
"""Check first-start deployment settings and the image's REST/SQL smoke client."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.request
from unittest.mock import patch

from integration import ROOT, server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    spec = importlib.util.spec_from_file_location('smoke', ROOT / 'docker/smoke.py')
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    env = smoke.once_env({'VAULTCONTEXT_RATE_LIMITS': 'true',
                          'VAULTCONTEXT_TRUSTED_PROXY_HEADER': 'X-Forwarded-For'})
    with patch.dict(os.environ, env), server(binary) as request:
        with urllib.request.urlopen(request.base_url + '/up') as response:
            assert response.status == 200 and response.read() == b'OK'
        token = request('POST', '/api/collections/_superusers/auth-with-password', {
            'identity': 'admin@example.com', 'password': 'SyntheticAdminPassword123!',
        })['token']
        settings = request('GET', '/api/settings', token=token)
        assert settings['meta']['appURL'] == env['BASE_URL']
        assert settings['smtp']['enabled'] and settings['smtp']['host'] == env['SMTP_ADDRESS']
        assert settings['rateLimits']['enabled']
        assert settings['trustedProxy']['headers'] == ['X-Forwarded-For']
        assert env['SMTP_PASSWORD'] not in json.dumps(settings)
        collection = request('GET', '/api/collections/users', token=token)
        assert collection['id'] == '_pb_users_auth_'
        assert collection['oauth2']['enabled'] and collection['createRule'] == "@request.context = 'oauth2'"
        assert collection['passwordAuth']['enabled']
        assert collection['oauth2']['providers'][0]['clientId'] == env['VAULTCONTEXT_GOOGLE_CLIENT_ID']
        assert env['VAULTCONTEXT_GOOGLE_CLIENT_SECRET'] not in json.dumps(collection)
        request('POST', '/api/collections/users/records', {
            'email': 'public@example.test', 'name': 'Public signup',
            'password': 'SyntheticPublicPassword123!', 'passwordConfirm': 'SyntheticPublicPassword123!',
        }, expected=(400, 403))
        password = smoke.secret('SyntheticSmokeUser123!')
        user = smoke.provision_user(request.base_url, token, 'smoke@example.test', password)
        client = smoke.Client(request.base_url, 'smoke@example.test', password, None)
        assert client.user['id'] == user
        client.run('check')
        document, expected = smoke.write_record(client, user)
        smoke.check_records(client, document, expected)
    # Invalid provider credentials fail closed on an empty database before serving.
    for values in [
        {'VAULTCONTEXT_GOOGLE_CLIENT_ID': 'synthetic-client'},
        {'VAULTCONTEXT_GOOGLE_CLIENT_SECRET': 'synthetic-secret'},
        {'VAULTCONTEXT_GOOGLE_CLIENT_ID': 'has whitespace', 'VAULTCONTEXT_GOOGLE_CLIENT_SECRET': 'synthetic-secret'},
    ]:
        with tempfile.TemporaryDirectory(prefix='vaultcontext-invalid-config-') as tmp:
            clean_env = {k: v for k, v in os.environ.items() if not k.startswith('VAULTCONTEXT_')}
            result = subprocess.run([binary, 'serve', '--http=127.0.0.1:0', '--dir=' + tmp,
                                     '--hooksDir=' + str(ROOT / 'pb_hooks'),
                                     '--migrationsDir=' + str(ROOT / 'pb_migrations')],
                                    cwd=ROOT, env={**clean_env, **values}, capture_output=True,
                                    text=True, timeout=20)
            assert result.returncode != 0
            assert 'Server started' not in result.stdout + result.stderr
            for value in values.values():
                assert value not in result.stdout + result.stderr
    print('PASS: first-start deployment settings, default users Google OAuth, smoke records, invalid provider configuration')


if __name__ == '__main__':
    main()
