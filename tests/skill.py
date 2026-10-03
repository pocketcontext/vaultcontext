#!/usr/bin/env python3
"""Installed package and optional copied launcher against an isolated server."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from unittest.mock import patch
from integration import server
from client_command import client_command
from vaultcontext_client import cli as vc, crypto


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
        # Real fork/socket lifecycle: no private material in cache, restore via broker, lock.
        with patch.object(vc,'prompt_passphrase',return_value='synthetic passphrase'):
            vc.unlock(a,30)
        assert vc.session_call(a,{'command':'vaults'})[0]['id']==vault
        cache=Path(tmp)/'cache'
        for path in cache.rglob('*.json'):
            value=path.read_text();assert ai['enc_private'] not in value and ai['sign_private'] not in value and 'key_bundle' not in value
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
