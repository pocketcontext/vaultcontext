#!/usr/bin/env python3
"""Installed package and optional copied launcher against an isolated server."""
import argparse
import json
import os
import socket
from pathlib import Path
import subprocess
import tempfile
import time
from unittest.mock import patch
from integration import server
from client_command import client_command
from vaultcontext_client import cli as vc, crypto



def cat_checks(command, temporary, request, owner, other, document, historical, content):
    """Exercise verified bytes through the real broker and foreground CLI."""
    cfg, identity, account, fingerprint = owner
    stranger, _, _, _ = other
    env = dict(os.environ, VAULTCONTEXT_URL=cfg['url'],
               VAULTCONTEXT_USER_EMAIL=cfg['email'], VAULTCONTEXT_USER_PASSWORD=cfg['password'])

    def cat(*words, environment=env):
        return subprocess.run(command + ['cat', document, *words], cwd=temporary,
                              env=environment, capture_output=True, timeout=45)

    def rejected(result):
        assert result.returncode != 0 and result.stdout == b'', 'failed cat emitted contents'
        assert result.stderr and b'Traceback' not in result.stderr

    rejected(cat())  # A signed-in but locked user cannot read.
    with patch.object(vc, 'prompt_passphrase', return_value='synthetic passphrase'):
        vc.unlock(cfg, 180)
        vc.unlock(stranger, 180)
    try:
        result = cat()
        assert result.returncode == 0 and result.stdout == b'new bytes' and result.stderr == b''
        result = cat('--version', historical)
        assert result.returncode == 0 and result.stdout == content and result.stderr == b''
        assert len(result.stdout) == crypto.MAX_FILE_SIZE
        rejected(cat(environment=dict(env, VAULTCONTEXT_USER_EMAIL=stranger['email'])))

        # Empty documents are successful, zero-byte output; version IDs cannot cross documents.
        empty = Path(temporary) / 'empty'
        empty.write_bytes(b'')
        vault = vc.one(cfg, 'documents', 'id=' + vc.quote(document))['vault']
        saved = vc.execute(cfg, identity, account, dict(command='save', vault=vault, path=str(empty)))
        result = subprocess.run(command + ['cat', saved['id']], cwd=temporary, env=env,
                                capture_output=True, timeout=45)
        assert result.returncode == 0 and result.stdout == b'' and result.stderr == b''
        rejected(cat('--version', saved['version']))

        # Fingerprint checks are repeated during reading, even in an unlocked session.
        pinned = vc.pin_path(cfg).read_bytes()
        vc.pin_path(cfg).write_text('{}')
        try:
            result = cat()
            rejected(result)
            assert b'Unverified' in result.stderr
        finally:
            vc.pin_path(cfg).write_bytes(pinned)

        # Corrupt the final chunk of an isolated synthetic ciphertext. A failed read
        # must not leak a verified prefix before the full file has been checked.
        chunks = vc.query(cfg, 'SELECT ciphertext FROM version_chunks WHERE version=' +
                          vc.quote(historical) + ' ORDER BY position DESC LIMIT 1')
        paths = list(request.data_dir.joinpath('storage').rglob(chunks[0]['ciphertext']))
        assert len(paths) == 1
        ciphertext_path = paths[0]
        ciphertext = ciphertext_path.read_bytes()
        ciphertext_path.write_bytes(ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]))
        try:
            rejected(cat('--version', historical))
        finally:
            ciphertext_path.write_bytes(ciphertext)

        # Both a buffered small write (flush) and a large write handle a closed
        # stdout pipe without a shutdown traceback or damage to the broker.
        for words in ([], ['--version', historical]):
            reader, writer = os.pipe()
            os.close(reader)
            try:
                result = subprocess.run(command + ['cat', document, *words], cwd=temporary,
                                        env=env, stdout=writer, stderr=subprocess.PIPE, timeout=45)
            finally:
                os.close(writer)
            assert result.returncode == 1 and b'Traceback' not in result.stderr
            assert b'Exception ignored' not in result.stderr
            assert vc.session_call(cfg, {'command': 'vaults'})[0]['id'] == vault

        # A client may also disconnect while the broker is fetching bytes.
        with socket.socket(socket.AF_UNIX) as abandoned:
            abandoned.connect(str(vc.socket_path(cfg)))
            abandoned.sendall((vc.encode(dict(command='cat', document=document, version=historical)) + '\n').encode())
        assert vc.session_call(cfg, {'command': 'vaults'})[0]['id'] == vault
        # An attached client that never drains a maximum-size response triggers
        # sendall's timeout, not BrokenPipeError/ConnectionResetError. The broker
        # must accept the following request after its five-second send timeout.
        with socket.socket(socket.AF_UNIX) as stalled:
            stalled.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            stalled.connect(str(vc.socket_path(cfg)))
            stalled.sendall((vc.encode(dict(command='cat', document=document, version=historical)) + '\n').encode())
            started = time.monotonic()
            assert vc.session_call(cfg, {'command': 'vaults'})[0]['id'] == vault
            assert time.monotonic() - started >= 4, 'large broker response unexpectedly bypassed stalled reader'
        assert cat().stdout == b'new bytes'
    finally:
        vc.session_call(cfg, {'command': 'lock'})
        vc.session_call(stranger, {'command': 'lock'})
    print('VaultContext cat exact bytes, integrity, privacy and pipes: PASS')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--binary',required=True)
    parser.add_argument('--client',help='Copy and execute this standalone launcher outside the repository')
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='vault-skill-') as tmp, server(args.binary) as req:
        command=client_command(args.client,tmp)
        os.environ['XDG_CACHE_HOME']=str(Path(tmp)/'cache')
        admin=req('POST','/api/collections/_superusers/auth-with-password',{'identity':'admin@example.com','password':'SyntheticAdminPassword123!'})['token']
        users=[]
        for name in ['alice','bob','eve']:
            row=req('POST','/api/collections/users/records',{'email':name+'@example.com','name':name,'password':'SyntheticUserPassword123!','passwordConfirm':'SyntheticUserPassword123!'},admin)
            cfg={'url':req.base_url,'email':name+'@example.com','password':'SyntheticUserPassword123!'}
            vc.auth.login(cfg)
            identity=crypto.generate_identity();pub=crypto.public_identity(identity);fingerprint=crypto.fingerprint(pub)
            vc.action(cfg,'identity_init',{'public_key':pub['enc_public'],'signing_key':pub['sign_public'],'fingerprint':fingerprint,'key_bundle':vc.encode(crypto.wrap_identity(identity,'synthetic passphrase',row['id']))})
            vc.verify_user(cfg,row['id'],fingerprint)
            users.append((cfg,identity,row['id'],fingerprint))
        a,ai,aid,af=users[0]; b,bi,bid,bf=users[1]; e,ei,eid,ef=users[2]
        def run(cfg,identity,actor,command,**kw):return vc.execute(cfg,identity,actor,dict(command=command,**kw))
        vault=run(a,ai,aid,'create',name='Personal test')['id']
        source=Path(tmp)/'binary';content=b'\x00\xff\r\n'+os.urandom(crypto.MAX_FILE_SIZE-4);source.write_bytes(content)
        saved=run(a,ai,aid,'save',vault=vault,path=str(source),name='opaque binary')
        doc=saved['id'];ver=saved['version']
        assert run(a,ai,aid,'list',vault=vault)[0]['name']=='opaque binary'
        assert run(a,ai,aid,'search',vault=vault,text='binary')[0]['id']==doc
        out=Path(tmp)/'restored';run(a,ai,aid,'restore',document=doc,to=str(out));assert out.read_bytes()==content;assert out.stat().st_mode&0o777==0o600
        assert run(e,ei,eid,'vaults')==[]
        inv=run(a,ai,aid,'share',vault=vault,account=bid,role='reader',fingerprint=bf)['id']
        run(b,bi,bid,'accept',invitation=inv,fingerprint=af)
        bout=Path(tmp)/'bob';run(b,bi,bid,'restore',document=doc,to=str(bout));assert bout.read_bytes()==content
        try:run(b,bi,bid,'save',vault=vault,path=str(source))
        except vc.auth.Fail:pass
        else:raise AssertionError('reader wrote')
        run(a,ai,aid,'revoke',vault=vault,account=bid)
        assert run(b,bi,bid,'vaults')==[]
        assert run(a,ai,aid,'vaults')[0]['name']=='Personal test'
        source.write_bytes(b'new bytes')
        run(a,ai,aid,'save',vault=vault,path=str(source),document=doc)
        assert len(run(a,ai,aid,'history',document=doc))==2
        archive=Path(tmp)/'export';run(a,ai,aid,'export',vault=vault,to=str(archive),export_passphrase='separate archive passphrase')
        exported=json.loads(crypto.decrypt_export(json.loads(archive.read_text()),'separate archive passphrase'));assert len(exported['files'])==2
        restored_export=Path(tmp)/'archive-output'
        parsed=vc.parser().parse_args(['restore-export',str(archive),'--document',doc,'--version',ver,'--to',str(restored_export)])
        with patch.object(vc,'prompt_passphrase',return_value='separate archive passphrase'):vc.run(parsed)
        assert restored_export.read_bytes()==content
        # Wrong public-key pins fail closed, even if the directory itself is valid.
        try:vc.verify_user(a,bid,'0'*64)
        except vc.auth.Fail:pass
        else:raise AssertionError('wrong fingerprint accepted')
        # The initial source-release CI still carries the previous launcher pin.
        # Source cat coverage is mandatory; a copied launcher is tested when it advertises cat.
        help_result=subprocess.run(command+['cat','--help'],cwd=tmp,capture_output=True)
        if not args.client or help_result.returncode == 0:
            assert help_result.returncode == 0, help_result.stderr
            cat_checks(command,tmp,req,users[0],users[2],doc,ver,content)
        else:
            print('Copied launcher predates cat; source cat checks run separately.')
        # Real fork/socket lifecycle: no private material in cache, restore via broker, lock.
        with patch.object(vc,'prompt_passphrase',return_value='synthetic passphrase'):
            vc.unlock(a,30)
        assert vc.session_call(a,{'command':'vaults'})[0]['id']==vault
        cache=Path(tmp)/'cache'
        private_values=[identity[field].encode() for _,identity,_,_ in users for field in ('enc_private','sign_private')]
        # uv also uses XDG_CACHE_HOME and may fetch public schema/config JSON
        # containing the field name key_bundle. Actual private key values must
        # remain absent throughout that cache, including dependency checkouts.
        for path in cache.rglob('*.json'):
            value=path.read_bytes()
            assert not any(secret in value for secret in private_values), str(path.relative_to(cache))
        # Check all regular application cache files, regardless of extension:
        # neither plaintext keys nor an encrypted bundle may persist here.
        for path in vc.auth.cache_file(a).parent.rglob('*'):
            if path.is_file():
                value=path.read_bytes()
                assert b'key_bundle' not in value and not any(secret in value for secret in private_values), path.name
        vc.session_call(a,{'command':'lock'})
        for _ in range(100):
            if not vc.socket_path(a).exists():break
            time.sleep(.01)
        # Advance the broker clock across its fixed lifetime after its first accept timeout.
        with patch.object(vc,'prompt_passphrase',return_value='synthetic passphrase'), patch.object(vc.time,'monotonic',side_effect=[0,0,31]):
            vc.unlock(a,30)
        for _ in range(300):
            if not vc.socket_path(a).exists():break
            time.sleep(.01)
        assert not vc.socket_path(a).exists(), 'expired daemon retained its socket'
        # Validate schema snapshot against live schema.
        os.environ['VAULTCONTEXT_URL']=a['url'];os.environ['VAULTCONTEXT_USER_EMAIL']=a['email'];os.environ['VAULTCONTEXT_USER_PASSWORD']=a['password']
        vc.run(vc.parser().parse_args(['check']))
        result=subprocess.run(command+['check'],cwd=tmp,capture_output=True,text=True,check=True)
        assert json.loads(result.stdout)['compatible'] is True
        result=subprocess.run(command+['whoami'],cwd=tmp,capture_output=True,text=True,check=True)
        assert json.loads(result.stdout)['id']==aid
        run(a,ai,aid,'change-passphrase',new_passphrase='replacement vault passphrase')
        bundle=json.loads(vc.one(a,'identity_secrets','account='+vc.quote(aid))['key_bundle'])
        assert crypto.unwrap_identity(bundle,'replacement vault passphrase',aid)==ai
        print('VaultContext packaged portable client: PASS')
if __name__=='__main__':main()
