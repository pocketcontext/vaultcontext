#!/usr/bin/env python3
"""Synthetic multi-author sharing and first-use trust against an isolated server."""
import argparse
import base64
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

from integration import server
from vaultcontext_client import cli, crypto


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='vault-sharing-client-') as temporary, \
         patch.dict(os.environ, {'XDG_CACHE_HOME': str(Path(temporary) / 'cache')}), \
         server(args.binary, workspace_domain='example.com') as request:
        admin = request('POST', '/api/collections/_superusers/auth-with-password',
                        {'identity': 'admin@example.com', 'password': 'SyntheticAdminPassword123!'})['token']
        users = {}
        for name in ('owner', 'editor', 'reader', 'removed'):
            email = name + '@example.com'
            row = request('POST', '/api/collections/users/records', {
                'email': email, 'name': name, 'workspace_google_email': email,
                'workspace_google_domain': 'example.com',
                'password': 'SyntheticUserPassword123!', 'passwordConfirm': 'SyntheticUserPassword123!',
            }, admin)
            cfg = dict(url=request.base_url, email=email, password='SyntheticUserPassword123!')
            cli.auth.login(cfg)
            identity = crypto.generate_identity()
            public = crypto.public_identity(identity)
            cli.action(cfg, 'identity_init', dict(
                public_key=public['enc_public'], signing_key=public['sign_public'],
                fingerprint=crypto.fingerprint(public),
                key_bundle=cli.encode(crypto.wrap_identity(identity, 'synthetic passphrase', row['id']))))
            # No verify-user calls, including for each client's own key.
            users[name] = (cfg, identity, row['id'])

        def run(actor, command, **arguments):
            cfg, identity, account = users[actor]
            return cli.execute(cfg, identity, account, dict(command=command, **arguments))

        def deny(callback):
            try:
                callback()
            except cli.auth.Fail:
                return
            raise AssertionError('unauthorized or changed-key operation succeeded')

        vault = run('owner', 'create', name='Synthetic shared vault')['id']
        for name, role in (('editor', 'editor'), ('reader', 'reader'), ('removed', 'reader')):
            invitation = run('owner', 'share', vault=vault, account=(name + '@EXAMPLE.COM'), role=role)
            assert invitation['email'] == name + '@example.com'
            assert invitation['status'] == 'pending' and invitation['role'] == role
            assert invitation['scope'] == 'whole-vault-and-retained-history'
            duplicate = run('owner', 'share', vault=vault, account=name + '@example.com', role=role)
            assert duplicate['id'] == invitation['id'] and duplicate['revision'] == invitation['revision']
            run(name, 'accept', invitation=invitation['id'])
            member = run('owner', 'share', vault=vault, account=name + '@example.com', role=role)
            assert member['status'] == 'active' and member['role'] == role

        content = b'synthetic editor-authored opaque bytes\x00\xff'
        source = Path(temporary) / 'synthetic.binary'
        source.write_bytes(content)
        document = run('editor', 'save', vault=vault, path=str(source))['id']
        reader_cfg, _, _ = users['reader']
        editor_cfg, editor_identity, editor_id = users['editor']
        assert editor_id not in cli.pins(reader_cfg), 'accept unexpectedly pinned unrelated authors'
        assert base64.b64decode(run('reader', 'cat', document=document)['data']) == content
        assert cli.pins(reader_cfg)[editor_id] == crypto.fingerprint(crypto.public_identity(editor_identity))

        # A changed local author pin is rejected even with a matching explicit
        # directory fingerprint. Restore only this synthetic fixture afterward.
        pin_path = cli.pin_path(reader_cfg)
        saved_pins = pin_path.read_bytes()
        wrong = cli.pins(reader_cfg)
        wrong[editor_id] = '0' * 64
        crypto.restore_file(pin_path, cli.encode(wrong).encode(), overwrite=True)
        deny(lambda: run('reader', 'cat', document=document))
        deny(lambda: cli.verify_user(reader_cfg, editor_id, crypto.fingerprint(crypto.public_identity(editor_identity))))
        crypto.restore_file(pin_path, saved_pins, overwrite=True)

        # Historical signatures remain verifiable after the author is disabled.
        # Remove only the synthetic author's pin to model a new machine's first read.
        request('PATCH', '/api/collections/users/records/' + editor_id, {'disabled': True}, admin)
        known = cli.pins(reader_cfg)
        del known[editor_id]
        crypto.restore_file(pin_path, cli.encode(known).encode(), overwrite=True)
        assert base64.b64decode(run('reader', 'cat', document=document)['data']) == content
        deny(lambda: run('owner', 'share', vault=vault, account='editor@example.com', role='editor'))

        # Rotation discovers remaining members' keys on first use. Dropping only
        # synthetic local pins models an owner resuming on a different computer.
        owner_cfg, _, owner_id = users['owner']
        owner_pins = cli.pins(owner_cfg)
        crypto.restore_file(cli.pin_path(owner_cfg), cli.encode({owner_id: owner_pins[owner_id]}).encode(), overwrite=True)
        run('owner', 'revoke', vault=vault, account='REMOVED@example.com')
        assert run('removed', 'vaults') == []
        deny(lambda: run('removed', 'cat', document=document))
        assert users['reader'][2] in cli.pins(owner_cfg)
        assert editor_id in cli.pins(owner_cfg), 'disabled remaining member key not pinned for rotation'
        source.write_bytes(b'synthetic content after rotation')
        after = run('owner', 'save', vault=vault, path=str(source))['id']
        assert base64.b64decode(run('reader', 'cat', document=after)['data']) == source.read_bytes()
        assert base64.b64decode(run('reader', 'cat', document=document)['data']) == content
        deny(lambda: run('removed', 'cat', document=after))
        # Disabled accounts are still resolvable for explicit removal by email.
        run('owner', 'revoke', vault=vault, account='editor@example.com')
        assert base64.b64decode(run('reader', 'cat', document=document)['data']) == content
    print('VaultContext email sharing, author pinning, historical reads and rotation: PASS')


if __name__ == '__main__':
    main()
