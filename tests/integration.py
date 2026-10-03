#!/usr/bin/env python3
"""Exercise VaultContext through HTTP against an isolated temporary database."""
import argparse
import concurrent.futures
import contextlib
import json
from pathlib import Path
import socket
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]

@contextlib.contextmanager
def server(binary):
    with tempfile.TemporaryDirectory(prefix='vaultcontext-test-') as tmp:
        hooks=Path(tmp)/'pb_hooks'
        shutil.copytree(ROOT/'pb_hooks',hooks)
        (hooks/'failure_fixture.pb.js').write_text('''
onRecordCreateExecute((e) => {
  if(e.record.getString('target') === 'auditfailure001') throw new Error('Synthetic audit failure');
  e.next();
}, 'audit_log');
onRecordCreateExecute((e) => {
  if(e.record.id === 'dirfailure00001') throw new Error('Synthetic directory failure');
  e.next();
}, 'user_directory');
''')
        common = [str(Path(binary).resolve()), '--dir', str(Path(tmp)/'pb_data'), '--migrationsDir', str(ROOT/'pb_migrations'), '--hooksDir', str(hooks)]
        result = subprocess.run(common+['superuser','upsert','admin@example.com','SyntheticAdminPassword123!'],cwd=ROOT,capture_output=True,text=True)
        assert result.returncode == 0, result.stdout+result.stderr
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
        with open(Path(tmp)/'server.log','w+') as log:
            proc=subprocess.Popen(common+['serve','--http',f'127.0.0.1:{port}'],cwd=ROOT,stdout=log,stderr=log)
            def request(method,path,body=None,token=None,expected=200):
                headers={'Content-Type':'application/json'}
                if token: headers['Authorization']=token
                req=urllib.request.Request(f'http://127.0.0.1:{port}'+path,data=None if body is None else json.dumps(body).encode(),headers=headers,method=method)
                try:
                    with urllib.request.urlopen(req,timeout=20) as r: status,raw=r.status,r.read()
                except urllib.error.HTTPError as e: status,raw=e.code,e.read()
                assert status in (expected if isinstance(expected,tuple) else (expected,)), (method,path,status,raw.decode())
                return (raw if path.startswith('/api/files/') and path!='/api/files/token' else json.loads(raw)) if raw else None
            try:
                for _ in range(150):
                    try: request('GET','/api/health'); break
                    except (OSError,AssertionError):
                        if proc.poll() is not None: log.seek(0); raise AssertionError(log.read())
                        time.sleep(.1)
                else: raise AssertionError('Server startup timed out')
                request.data_dir=Path(tmp)/'pb_data'
                request.base_url = f'http://127.0.0.1:{port}'
                yield request
            finally:
                proc.terminate();proc.wait(timeout=15)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--binary',required=True);args=parser.parse_args()
    with server(args.binary) as request:
        path=lambda t:'/api/collections/'+t+'/records'
        admin=request('POST','/api/collections/_superusers/auth-with-password',{'identity':'admin@example.com','password':'SyntheticAdminPassword123!'})['token']
        accounts=[]
        for n in ['alice','bob','eve']:
            u=request('POST',path('users'),{'email':n+'@example.com','name':n,'password':'SyntheticUserPassword123!','passwordConfirm':'SyntheticUserPassword123!'},admin)
            t=request('POST','/api/collections/users/auth-with-password',{'identity':n+'@example.com','password':'SyntheticUserPassword123!'})['token']
            accounts.append((u['id'],t))
        (alice,at),(bob,bt),(eve,et)=accounts
        def act(token,op,p,expected=200):
            r=request('POST',path('vault_actions'),{'op':op,'payload':p},token,expected)
            return r.get('result',r)
        def query(token,sql):
            r=request('POST','/api/context/query',{'sql':sql},token)
            return [dict(zip(r['columns'],row)) for row in r['rows']]
        for uid,t in accounts:act(t,'identity_init',{'public_key':'synthetic-public','signing_key':'synthetic-signing','fingerprint':'synthetic-fingerprint','key_bundle':'encrypted-bundle'})
        assert len(query(at,'SELECT * FROM identity_secrets'))==1
        assert query(at,'SELECT * FROM identity_secrets')[0]['account']==alice
        v='syntheticvault1';d='syntheticdoc001';ver='syntheticver001'
        # IDs must have exactly fifteen characters.
        v='v'*15;d='d'*15;ver='a'*15
        act(at,'vault_create',{'id':v,'metadata':'encrypted-title','envelope':'alice-envelope'})
        save={'vault':v,'document':d,'version':ver,'expected_revision':0,'epoch':1,'metadata':'encrypted-name','manifest':'encrypted-manifest','signature':'signature','chunks':['encrypted-binary-chunk']}
        act(at,'save',save)
        chunk=query(at,'SELECT * FROM version_chunks')[0]
        file_path='/api/files/version_chunks/'+chunk['id']+'/'+chunk['ciphertext']
        aft=request('POST','/api/files/token',{},at)['token']
        bft=request('POST','/api/files/token',{},bt)['token']
        assert request('GET',file_path+'?token='+aft)==b'encrypted-binary-chunk'
        request('GET',file_path,expected=(401,403,404))
        request('GET',file_path+'?token='+bft,expected=(401,403,404))
        assert len(query(at,'SELECT * FROM versions'))==1
        assert query(bt,'SELECT * FROM versions')==[]
        assert query(et,'SELECT * FROM audit_log')==[]
        act(at,'save',dict(save,version='b'*15),409)
        assert len(query(at,'SELECT * FROM versions'))==1
        request('POST',path('versions'),save,at,403)
        request('GET',path('versions')+'/'+ver,token=at,expected=403)
        inv=act(at,'share',{'vault':v,'account':bob,'role':'reader','expected_revision':1,'envelopes':[{'epoch':1,'envelope':'bob-envelope'}]})
        assert query(bt,'SELECT * FROM vaults')==[]
        assert len(query(bt,'SELECT * FROM key_envelopes'))==1
        act(et,'accept',{'invitation':inv['id']},403)
        accepted=act(bt,'accept',{'invitation':inv['id']})
        assert len(query(bt,'SELECT * FROM versions'))==1
        assert request('GET',file_path+'?token='+bft)==b'encrypted-binary-chunk'
        act(bt,'save',dict(save,version='b'*15,expected_revision=1),403)
        revoked=act(at,'revoke',{'vault':v,'account':bob,'expected_revision':accepted['revision']})
        assert query(bt,'SELECT * FROM versions')==[]
        assert query(bt,'SELECT * FROM key_envelopes')==[]
        request('GET',file_path+'?token='+bft,expected=(401,403,404))
        act(at,'save',dict(save,version='b'*15,expected_revision=1),409)
        act(at,'rotate',{'vault':v,'expected_revision':revoked['revision'],'epoch':2,'envelopes':[{'account':bob,'envelope':'bad'}]},400)
        rotated=act(at,'rotate',{'vault':v,'expected_revision':revoked['revision'],'epoch':2,'envelopes':[{'account':alice,'envelope':'new-alice'}]})
        act(at,'save',dict(save,version='b'*15,expected_revision=1,epoch=2))
        assert len(query(at,'SELECT * FROM versions'))==2
        # A failed audit must roll back the document, version and chunk transaction.
        act(at,'save',dict(save,document='auditfailure001',version='c'*15,epoch=2),400)
        assert len(query(at,'SELECT * FROM documents'))==1
        assert len(query(at,'SELECT * FROM versions'))==2
        request('POST','/api/batch',{'requests':[]},at,403)
        request('POST','/api/context/query',{'sql':'SELECT * FROM users'},at,400)
        request('POST',path('users'),{'email':'public@example.com','password':'SyntheticUserPassword123!','passwordConfirm':'SyntheticUserPassword123!'},expected=400)
        # Reinvite as editor with complete history, then race two saves at one revision.
        inv=act(at,'share',{'vault':v,'account':bob,'role':'editor','expected_revision':rotated['revision'],'envelopes':[{'epoch':1,'envelope':'bob-old'},{'epoch':2,'envelope':'bob-new'}]})
        accepted=act(bt,'accept',{'invitation':inv['id']})
        act(bt,'share',{'vault':v,'account':eve,'role':'reader','expected_revision':accepted['revision'],'envelopes':[]},403)
        def race(version):
            return act(bt,'save',dict(save,version=version,expected_revision=2,epoch=2),(200,409))
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(race,['e'*15,'f'*15]))
        assert sum('version' in r for r in results)==1
        assert len(query(at,'SELECT * FROM versions'))==3
        assert len(query(bt,'SELECT * FROM versions'))==3
        # Pending invites see their envelope, not file data; revoke cancels all offers.
        inv=act(at,'share',{'vault':v,'account':eve,'role':'reader','expected_revision':accepted['revision'],'envelopes':[{'epoch':1,'envelope':'eve-old'},{'epoch':2,'envelope':'eve-new'}]})
        assert len(query(et,'SELECT * FROM key_envelopes'))==2
        for table in ['vaults','memberships','documents','versions','version_chunks','audit_log']:
            assert query(et,'SELECT * FROM '+table)==[],table
        revoked=act(at,'revoke',{'vault':v,'account':bob,'expected_revision':inv['revision']})
        assert query(et,'SELECT * FROM key_envelopes')==[]
        act(et,'accept',{'invitation':inv['id']},403)
        # Alternate REST mutation/read paths stay closed on every internal table.
        for table in ['identities','identity_secrets','vaults','memberships','key_envelopes','documents','versions','version_chunks','invitations','audit_log']:
            row=request('GET',path(table)+'?perPage=1',token=admin)['items'][0]
            for token in [at,bt,et]:
                request('GET',path(table)+'/'+row['id'],token=token,expected=(403,404))
                request('PATCH',path(table)+'/'+row['id'],{'metadata':'forged'},token,403)
                request('DELETE',path(table)+'/'+row['id'],token=token,expected=(403,404))
                request('POST',path(table),{'id':'z'*15},token,403)
        # Rewrap is private and revision checked; server never changes public keys.
        act(at,'identity_rewrap',{'key_bundle':'new-encrypted-bundle','expected_revision':1})
        act(at,'identity_rewrap',{'key_bundle':'stale','expected_revision':1},409)
        assert query(at,'SELECT key_bundle FROM identity_secrets')[0]['key_bundle']=='new-encrypted-bundle'
        assert query(bt,'SELECT key_bundle FROM identity_secrets')[0]['key_bundle']=='encrypted-bundle'
        request('PATCH',path('users')+'/'+alice,{'disabled':True},admin)
        act(at,'identity_rewrap',{'key_bundle':'forged','expected_revision':2},(401,403))
        request('POST','/api/context/query',{'sql':'SELECT * FROM vaults'},at,(401,403))
        print('VaultContext integration: PASS')
if __name__=='__main__':main()
