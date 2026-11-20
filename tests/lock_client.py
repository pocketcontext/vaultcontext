#!/usr/bin/env python3
"""Vault lock CLI against an isolated server: labels, fences, force/break and restore."""
import argparse
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

from integration import server
from client_command import client_command
from vaultcontext_client import cli as vc, crypto


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--client', help='Copy and execute this standalone launcher outside the repository')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='vault-lock-client-') as tmp, server(args.binary, workspace_domain='example.com') as req:
        command = client_command(args.client, tmp)
        os.environ['XDG_CACHE_HOME'] = str(Path(tmp) / 'cache')
        os.environ['XDG_STATE_HOME'] = str(Path(tmp) / 'state')
        os.environ.pop('VAULTCONTEXT_SESSION_DIR', None)
        admin = req('POST', '/api/collections/_superusers/auth-with-password',
                    {'identity': 'admin@example.com', 'password': 'SyntheticAdminPassword123!'})['token']
        users = {}
        for name in ['alice', 'bob']:
            row = req('POST', '/api/collections/users/records', {
                'email': name + '@example.com', 'workspace_google_email': name + '@example.com',
                'workspace_google_domain': 'example.com', 'name': name,
                'password': 'SyntheticUserPassword123!', 'passwordConfirm': 'SyntheticUserPassword123!'}, admin)
            cfg = {'url': req.base_url.replace('127.0.0.1', 'localhost'), 'email': name + '@example.com',
                   'password': 'SyntheticUserPassword123!'}
            vc.auth.login(cfg)
            identity = crypto.generate_identity()
            pub = crypto.public_identity(identity)
            fingerprint = crypto.fingerprint(pub)
            vc.action(cfg, 'identity_init', {'public_key': pub['enc_public'], 'signing_key': pub['sign_public'],
                                             'fingerprint': fingerprint,
                                             'key_bundle': vc.encode(crypto.wrap_identity(identity, 'synthetic passphrase', row['id']))})
            vc.verify_user(cfg, row['id'], fingerprint)
            users[name] = (cfg, identity, row['id'])
        (a, ai, aid), (b, bi, bid) = users['alice'], users['bob']

        def execute(user, command_name, **kw):
            cfg, identity, account = user
            return vc.execute(cfg, identity, account, dict(command=command_name, **kw))

        vault = execute(users['alice'], 'create', name='Deployment vault')['id']
        files = {}
        work = Path(tmp) / 'files'
        work.mkdir()
        for name, content in (('state', b'state-v1'), ('envrc', b'export X=synthetic')):
            path = work / name
            path.write_bytes(content)
            files[name] = execute(users['alice'], 'save', vault=vault, path=str(path), name=name)
        invitation = execute(users['alice'], 'share', vault=vault, account='bob@example.com', role='editor')['id']
        execute(users['bob'], 'accept', invitation=invitation)

        def cli(user, *words, stdin=subprocess.DEVNULL):
            cfg = user[0]
            env = dict(os.environ, VAULTCONTEXT_URL=cfg['url'], VAULTCONTEXT_USER_EMAIL=cfg['email'],
                       VAULTCONTEXT_USER_PASSWORD=cfg['password'])
            result = subprocess.run(command + list(words), cwd=tmp, env=env, capture_output=True, text=True,
                                    timeout=120, stdin=stdin)
            assert 'Traceback' not in result.stderr, result.stderr
            return result

        def ok(result):
            assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
            return json.loads(result.stdout)

        def refused(result, code):
            assert result.returncode == 5, (result.returncode, result.stdout, result.stderr)
            error = json.loads(result.stdout)['error']
            assert error['code'] == code, error
            assert (code + ':') in result.stderr, result.stderr
            return error

        # Bare `lock` still closes a memory session.
        assert ok(cli(users['alice'], 'lock')) is not None
        status = ok(cli(users['alice'], 'lock', 'status', vault))
        assert status['state'] == 'free' and status['lock_policy'] == 'none'

        acquired = ok(cli(users['alice'], 'lock', 'acquire', vault, '--label', 'alice@laptop',
                          '--info', '{"label":"ignored","command":"converge"}', '--ttl', '120'))
        fence = acquired['fence']
        assert fence == f"{acquired['generation']}:{acquired['lease_id']}"
        assert {d['id'] for d in acquired['documents']} == {f['id'] for f in files.values()}
        assert all('metadata' not in d for d in acquired['documents'])
        held = refused(cli(users['bob'], 'lock', 'acquire', vault, '--label', 'bob@desk'), 'lock_held')
        assert held['info'] == {'label': 'alice@laptop', 'command': 'converge'}
        stderr = cli(users['bob'], 'lock', 'acquire', vault).stderr
        assert 'label "alice@laptop"' in stderr
        started = time.monotonic()
        refused(cli(users['bob'], 'lock', 'acquire', vault, '--wait', '2'), 'lock_held')
        assert time.monotonic() - started >= 2
        status = ok(cli(users['bob'], 'lock', 'status', vault))
        assert status['label'] == 'alice@laptop' and status['holder_email'] == 'alice@example.com'
        assert status['state'] == 'held' and status['lock_policy'] == 'required'

        # Fenced saves through the unlocked memory session.
        with patch.object(vc, 'prompt_passphrase', return_value='synthetic passphrase'):
            vc.unlock(a, 300)
        try:
            source = work / 'state'
            source.write_bytes(b'state-v2')
            refused(cli(users['alice'], 'save', vault, str(source), '--document', files['state']['id']), 'lock_required')
            stale = cli(users['alice'], 'save', vault, str(source), '--document', files['state']['id'],
                        '--fence', fence, '--expect-revision', '7')
            assert stale.returncode == 4, stale.stderr
            saved = ok(cli(users['alice'], 'save', vault, str(source), '--document', files['state']['id'],
                           '--fence', fence, '--expect-revision', '1'))
            assert saved['revision'] == 2
            assert cli(users['alice'], 'save', vault, str(source), '--fence', 'bad').returncode == 2
            ok(cli(users['alice'], 'lock', 'renew', vault, '--fence', fence, '--progress', 'applications'))
            assert ok(cli(users['bob'], 'lock', 'status', vault))['progress'] == 'applications'

            # Force needs a reason, a current generation, ownership and explicit confirmation.
            assert cli(users['alice'], 'lock', 'break', vault, '--observed-generation', str(acquired['generation'])).returncode == 2
            no_tty = cli(users['alice'], 'lock', 'break', vault, '--observed-generation', str(acquired['generation']),
                         '--reason', 'crashed')
            assert no_tty.returncode == 2 and 'alice@laptop' in no_tty.stderr and '--yes' in no_tty.stderr
            assert cli(users['bob'], 'lock', 'break', vault, '--observed-generation', str(acquired['generation']),
                       '--reason', 'crashed', '--yes').returncode == 1  # owner only (HTTP 403)
            refused(cli(users['alice'], 'lock', 'release', vault, '--force', '--observed-generation', '99',
                        '--reason', 'crashed', '--yes'), 'generation_changed')
            broken = ok(cli(users['alice'], 'lock', 'release', vault, '--force', '--observed-generation',
                            str(acquired['generation']), '--reason', 'laptop crashed', '--yes'))
            assert broken['broken'] is True
            refused(cli(users['alice'], 'lock', 'renew', vault, '--fence', fence), 'lock_lost')
            refused(cli(users['alice'], 'save', vault, str(source), '--document', files['state']['id'], '--fence', fence),
                    'stale_fence')

            # Restore-under-lock: a stale local manifest locks anyway and restores the pinned set by document ID.
            manifest = Path(tmp) / 'receipt.json'
            manifest.write_text(json.dumps({'vault': vault, 'documents': [
                {'id': files['state']['id'], 'revision': 1, 'version': files['state']['version'], 'name': 'state'},
                {'id': files['envrc']['id'], 'revision': 1, 'version': files['envrc']['version'], 'name': 'envrc'}]}))
            refused(cli(users['alice'], 'lock', 'acquire', vault, '--local-manifest', str(manifest)), 'local_mismatch')
            assert ok(cli(users['alice'], 'lock', 'status', vault))['state'] == 'broken'
            restore_dir = Path(tmp) / 'restore'
            restore_dir.mkdir(mode=0o700)
            restored = ok(cli(users['alice'], 'lock', 'acquire', vault, '--local-manifest', str(manifest),
                              '--on-mismatch', 'lock', '--restore-to', str(restore_dir), '--label', 'alice-restore'))
            assert restored['local_status'] == 'stale' and restored['local_details']['stale'] == [files['state']['id']]
            assert (restore_dir / files['state']['id']).read_bytes() == b'state-v2'
            assert (restore_dir / files['envrc']['id']).read_bytes() == b'export X=synthetic'
            assert (restore_dir / files['state']['id']).stat().st_mode & 0o777 == 0o600
            fence = restored['fence']
            # Force-acquire by the owner retires the previous lease in one step.
            forced = ok(cli(users['alice'], 'lock', 'acquire', vault, '--force', '--observed-generation',
                            str(restored['generation']), '--reason', 'coordinated takeover', '--yes'))
            assert forced['previous']['clean'] is False
            refused(cli(users['alice'], 'lock', 'release', vault, '--fence', fence, '--clean'), 'lock_lost')
            released = ok(cli(users['alice'], 'lock', 'release', vault, '--fence', forced['fence'], '--clean'))
            assert released['released'] is True
            assert ok(cli(users['alice'], 'lock', 'status', vault))['state'] == 'released'
            assert cli(users['alice'], 'lock', 'release', vault, '--fence', forced['fence']).returncode == 2
            assert cli(users['bob'], 'lock', 'clear-policy', vault).returncode == 1  # owner only
            assert ok(cli(users['alice'], 'lock', 'clear-policy', vault))['lock_policy'] == 'none'
            ok(cli(users['alice'], 'save', vault, str(source), '--document', files['state']['id']))
        finally:
            vc.session.stop(a)
    print('lock client checks passed')


if __name__ == '__main__':
    main()
