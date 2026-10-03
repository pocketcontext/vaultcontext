#!/usr/bin/env python3
"""Forward exercise of the documented skill through real CLI/terminal prompts."""
import argparse
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from integration import server, ROOT


def terminal(argv, env):
    pid, fd=pty.fork()
    if pid==0:
        os.execve(argv[0],argv,env)
    output=b'';prompts=0;deadline=time.monotonic()+30
    try:
        while time.monotonic()<deadline:
            ready,_,_=select.select([fd],[],[],.1)
            if ready:
                try:part=os.read(fd,65536)
                except OSError:break
                if not part:break
                output+=part
                # Only synthetic passphrases are supplied; no secret appears in argv/env.
                seen=output.lower().count(b'passphrase:')
                while prompts<seen:
                    os.write(fd,b'Synthetic terminal passphrase 123!\n');prompts+=1
            done,status=os.waitpid(pid,os.WNOHANG)
            if done:
                assert os.waitstatus_to_exitcode(status)==0,'terminal command failed'
                pid=0
                break
        else:raise AssertionError('terminal prompt timed out')
        if pid:
            _,status=os.waitpid(pid,0);pid=0
            assert os.waitstatus_to_exitcode(status)==0,'terminal command failed'
        text=output.decode()
        assert 'Synthetic terminal passphrase 123!' not in text,'passphrase echoed'
        # Terminal prompts precede the single JSON response.
        return json.loads(text[text.find('{'):].strip())
    finally:
        os.close(fd)
        if pid:
            os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)


def main():
    p=argparse.ArgumentParser();p.add_argument('--binary',required=True);args=p.parse_args()
    with tempfile.TemporaryDirectory(prefix='vault-forward-') as tmp, server(args.binary) as request:
        copied=Path(tmp)/'copied';shutil.copytree(ROOT/'skills/vaultcontext',copied)
        command=[sys.executable,str(copied/'scripts/vc.py')]
        admin=request('POST','/api/collections/_superusers/auth-with-password',{'identity':'admin@example.com','password':'SyntheticAdminPassword123!'})['token']
        actors=[]
        for name in ['owner','colleague']:
            user=request('POST','/api/collections/users/records',{'email':name+'@example.com','name':name,'password':'SyntheticUserPassword123!','passwordConfirm':'SyntheticUserPassword123!'},admin)
            env=dict(os.environ,VAULTCONTEXT_URL=request.base_url,VAULTCONTEXT_USER_EMAIL=name+'@example.com',VAULTCONTEXT_USER_PASSWORD='SyntheticUserPassword123!',XDG_CACHE_HOME=str(Path(tmp)/'cache'))
            def cli(*words,env=env):
                result=subprocess.run(command+list(words),env=env,cwd=tmp,capture_output=True,text=True)
                assert result.returncode==0,'CLI failed: '+result.stderr
                return json.loads(result.stdout)
            cli('login');cli('check')
            initialized=terminal(command+['init'],env)
            terminal(command+['unlock','--timeout','60'],env)
            actors.append((user['id'],initialized['fingerprint'],cli))
        owner,owner_fp,a=actors[0];colleague,colleague_fp,b=actors[1]
        try:
            vault=a('create','Synthetic isolated shared project')['id']
            source=Path(tmp)/'arbitrary.binary';content=b'\x00\xff\r\n'+os.urandom(8192);source.write_bytes(content)
            saved=a('save',vault,str(source))
            assert b('vaults')==[]
            # Fingerprints originate from each user's own init output and are explicitly exchanged.
            invitation=a('share',vault,colleague,'--role','reader','--fingerprint',colleague_fp)['id']
            b('accept',invitation,'--fingerprint',owner_fp)
            listing=b('list',vault);assert listing[0]['id']==saved['id']
            destination=Path(tmp)/'restored.binary'
            b('restore',saved['id'],'--to',str(destination))
            assert destination.read_bytes()==content
            assert destination.stat().st_mode&0o777==0o600
            assert len(b('history',saved['id']))==1
        finally:
            a('lock');b('lock')
    print('VaultContext independent CLI forward exercise: PASS')
if __name__=='__main__':main()
