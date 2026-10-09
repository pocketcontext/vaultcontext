#!/usr/bin/env python3
"""Dedicated Docker demo lifecycle. Never targets ONCE-managed production containers.

The only published socket is a loopback nginx gate. App and retention share a
private namespace anchor; stopping the gate closes existing public connections.
TLS must terminate in a separately authorized host proxy routing to that gate.
"""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit
from urllib.request import urlopen

from reset import ResetError, atomic_json, safe_path

PREFIX = 'vaultcontext-demo-'
LABEL = 'com.pocketcontext.demo.'
ROLES = ('network', 'retention', 'gate', 'app', 'init')
APP_IMAGE = re.compile(r'ghcr\.io/pocketcontext/vaultcontext@sha256:[a-f0-9]{64}')
GATE_IMAGE = re.compile(r'(?:docker\.io/library/)?nginx@sha256:[a-f0-9]{64}')
PRIMARY = {'VAULTCONTEXT_S3_' + name for name in ('BUCKET', 'ENDPOINT', 'REGION', 'ACCESS_KEY_ID', 'SECRET_ACCESS_KEY')}
REPLICA = {'LITESTREAM_' + name for name in ('BUCKET', 'ENDPOINT', 'REGION', 'PATH', 'ACCESS_KEY_ID', 'SECRET_ACCESS_KEY')}
REQUIRED = PRIMARY | REPLICA | {'VAULTCONTEXT_GOOGLE_CLIENT_ID','VAULTCONTEXT_GOOGLE_CLIENT_SECRET','VAULTCONTEXT_DEMO_CONTACT_TOKEN'}
OPTIONAL = {'VAULTCONTEXT_S3_FORCE_PATH_STYLE','LITESTREAM_SYNC_INTERVAL'}


def private_file(path):
    path = safe_path(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 65536:
        raise ResetError('private owned configuration required')
    return path


def environment(path):
    # Credential contents are parsed only in process memory, never logged.
    values = {}
    for line in private_file(path).read_text().splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator or key not in REQUIRED | OPTIONAL or key in values or not value or '\x00' in value:
            raise ResetError('invalid dedicated demo environment file')
        values[key] = value
    if not REQUIRED <= values.keys():
        raise ResetError('incomplete dedicated demo environment file')
    for key in ('VAULTCONTEXT_S3_BUCKET','LITESTREAM_BUCKET'):
        if not re.fullmatch(r'vaultcontext-demo-[a-z0-9][a-z0-9-]{1,40}',values[key]):
            raise ResetError('only dedicated demo storage is accepted')
    if values['VAULTCONTEXT_S3_BUCKET'] == values['LITESTREAM_BUCKET'] or values['VAULTCONTEXT_S3_ACCESS_KEY_ID'] == values['LITESTREAM_ACCESS_KEY_ID']:
        raise ResetError('primary and replica storage must be independent')
    if len(values['VAULTCONTEXT_DEMO_CONTACT_TOKEN']) < 32:
        raise ResetError('strong private contact token required')
    return values


def load(root):
    root = safe_path(root)
    info=root.stat()
    if root.name!='vaultcontext-demo' or not re.fullmatch(r'/[A-Za-z0-9_./-]+',str(root)) or info.st_uid!=os.getuid() or info.st_mode&0o077:
        raise ResetError('private dedicated demo root required')
    config = json.loads(private_file(root/'control/docker.json').read_text())
    if set(config) != {'image','gate_image','port','origin','env_file'} or not APP_IMAGE.fullmatch(config['image']) or not GATE_IMAGE.fullmatch(config['gate_image']):
        raise ResetError('immutable reviewed demo images required')
    if type(config['port']) is not int or not 1024 <= config['port'] <= 65535:
        raise ResetError('invalid loopback gate port')
    origin = urlsplit(config['origin'])
    if origin.scheme != 'https' or origin.path or origin.query or origin.fragment or origin.username or origin.password or origin.port or not re.fullmatch(r'(vault-demo|demo-vault|vaultcontext-demo)\.[a-z0-9.-]+',origin.hostname or ''):
        raise ResetError('an exact HTTPS demo origin is required')
    if Path(config['env_file']) != root/'control/runtime.env':
        raise ResetError('dedicated runtime environment must live under demo control')
    environment(config['env_file'])
    return config


class Docker:
    """Raw inspect results exist in memory only; callers receive this allowlist."""
    def run(self, *arguments, timeout=60):
        try:
            result = subprocess.run(['docker','--host','unix:///var/run/docker.sock',*arguments],
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
        except Exception:
            raise ResetError('local Docker operation failed') from None
        if result.returncode:
            raise ResetError('local Docker operation failed')
        return result.stdout

    def inspect(self, identifier):
        try:
            raw = json.loads(self.run('inspect',identifier))[0]
            labels = raw.get('Config',{}).get('Labels') or {}
            host = raw['HostConfig']
            result = {'id':raw['Id'],'name':raw['Name'].lstrip('/'),'image':raw['Config']['Image'],
                'running':raw['State']['Running'],'exit':raw['State'].get('ExitCode',0),
                'restart':host['RestartPolicy']['Name'],'network':host['NetworkMode'],
                'ports':host.get('PortBindings') or {},
                'labels':{key:labels.get(LABEL+key) for key in ('deployment','root','role')},
                'mounts':[{'source':m.get('Source',''),'target':m['Destination'],'type':m['Type'],'rw':m['RW']} for m in raw.get('Mounts',[])]}
            del raw, labels
            return result
        except ResetError:
            raise
        except Exception:
            raise ResetError('invalid Docker inspection metadata') from None

    def inventory(self):
        identifiers = self.run('ps','--all','--quiet').decode().split()
        if any(not re.fullmatch('[a-f0-9]{12,64}',value) for value in identifiers):
            raise ResetError('invalid Docker inventory')
        return [self.inspect(value) for value in identifiers]


class Lifecycle:
    def __init__(self,root,config,docker=None):
        self.root=safe_path(root);self.config=config;self.docker=docker or Docker()

    def containers(self):
        found={}
        inventory=self.docker.inventory()
        anchors={PREFIX+'network'} | {item['id'] for item in inventory if item['name']==PREFIX+'network'}
        for item in inventory:
            touches=any(m['type']=='bind' and (Path(m['source'])==self.root or self.root in Path(m['source']).parents) for m in item['mounts'])
            named=item['name'].startswith(PREFIX)
            labelled=item['labels'].get('deployment')=='vaultcontext-demo'
            shared=item['network'].startswith('container:') and item['network'].split(':',1)[1] in anchors
            if not (touches or named or labelled or shared):
                continue
            role=item['labels'].get('role')
            if role not in ROLES or item['name']!=PREFIX+role or item['labels']!={'deployment':'vaultcontext-demo','root':str(self.root),'role':role}:
                raise ResetError('unrecognized container overlaps the dedicated demo')
            if role in found:
                raise ResetError('duplicate demo container role')
            expected=self.config['gate_image'] if role=='gate' else self.config['image']
            if item['image']!=expected:
                raise ResetError('demo container image differs from reviewed digest')
            if item['restart'] not in ('no',''):
                # Authorized exact binding only; disable before any lifecycle action.
                self.docker.run('update','--restart=no',item['id'])
                item=self.docker.inspect(item['id'])
                if item['restart'] not in ('no',''):
                    raise ResetError('demo automatic restart could not be disabled')
            expected_ports={'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':str(self.config['port'])}]} if role=='network' else {}
            if item['ports']!=expected_ports:
                raise ResetError('demo has unexpected published ports')
            if role=='network':
                if item['network']!='bridge':raise ResetError('demo anchor must use bridge isolation')
            allowed={'app':{('/storage',str(self.root/'runtime'),True),('/demo-control',str(self.root/'control'),False)},
                     'init':{('/storage',str(self.root/'runtime'),True),('/demo-control',str(self.root/'control'),False)},
                     'retention':{('/demo-persistent',str(self.root/'persistent'),True)},
                     'gate':{('/etc/nginx/nginx.conf',str(self.root/'control/nginx.conf'),False)},'network':set()}[role]
            binds={(m['target'],m['source'],m['rw']) for m in item['mounts'] if m['type']=='bind'}
            if binds!=allowed or any(m['type']=='volume' for m in item['mounts']):
                raise ResetError('demo mounts differ from dedicated storage binding')
            found[role]=item
        for role,item in found.items():
            if role!='network' and item['network'] not in ('container:'+PREFIX+'network','container:'+found.get('network',{}).get('id','')):
                raise ResetError('demo components must share their isolated namespace')
        return found

    def stop(self,role):
        item=self.containers().get(role)
        if not item or not item['running']:return
        self.docker.run('kill','--signal=SIGTERM',item['id'])
        deadline=time.monotonic()+240
        while time.monotonic()<deadline:
            if not self.docker.inspect(item['id'])['running']:return
            time.sleep(.2)
        raise ResetError('graceful demo shutdown timed out')

    def remove(self,role):
        self.stop(role)
        item=self.containers().get(role)
        if item:self.docker.run('rm',item['id'])

    def create(self,role,command,phase=None):
        args=['create','--name',PREFIX+role,'--restart=no','--log-driver=none','--cap-drop=ALL','--security-opt=no-new-privileges']
        for key,value in {'deployment':'vaultcontext-demo','root':str(self.root),'role':role}.items():
            args+=['--label',LABEL+key+'='+value]
        if role=='network':
            args+=['--network=bridge','--publish',f"127.0.0.1:{self.config['port']}:8080",'--read-only','--tmpfs','/storage','--entrypoint','python3']
        else:
            args+=['--network','container:'+PREFIX+'network']
        if role in ('app','init'):
            args+=['--cap-add=NET_BIND_SERVICE']
            args+=['--mount',f'type=bind,src={self.root / "runtime"},dst=/storage',
                   '--mount',f'type=bind,src={self.root / "control"},dst=/demo-control,readonly',
                   '--env-file',self.config['env_file']]
            values={'VAULTCONTEXT_DEMO_MODE':'true','VAULTCONTEXT_DEMO_GENERATION':os.environ['VAULTCONTEXT_DEMO_GENERATION'],
                    'VAULTCONTEXT_DEMO_RESET_FENCE':'/demo-control/reset-pending.json','VAULTCONTEXT_DEMO_RESET_PHASE':phase,
                    'VAULTCONTEXT_DEMO_CONTACT_URL':'http://127.0.0.1:8781','BASE_URL':self.config['origin'],
                    'VAULTCONTEXT_RATE_LIMITS':'true'}
            for key,value in values.items():args+=['--env',key+'='+value]
        elif role=='retention':
            # Pass only the contact token by name through a private process env;
            # do not give the durable service object-storage or OAuth credentials.
            args+=['--read-only','--tmpfs','/storage','--tmpfs','/tmp','--mount',f'type=bind,src={self.root / "persistent"},dst=/demo-persistent',
                   '--env-file',str(self.root/'control/contact.env'),'--entrypoint','python3']
        elif role=='gate':
            args+=['--user','65534:65534','--read-only','--tmpfs','/tmp','--mount',f'type=bind,src={self.root / "control/nginx.conf"},dst=/etc/nginx/nginx.conf,readonly','--entrypoint','nginx']
        args+=[self.config['gate_image'] if role=='gate' else self.config['image'],*command]
        self.docker.run(*args)

    def ensure_services(self):
        items=self.containers()
        if 'network' not in items:
            # An unknown listener is a conflict, never permission to replace it.
            with socket.socket() as probe:probe.bind(('127.0.0.1',self.config['port']))
            self.create('network',['-c','import signal; signal.pause()'])
        items=self.containers()
        if not items['network']['running']:self.docker.run('start',items['network']['id'])
        (self.root/'persistent').mkdir(mode=0o700,exist_ok=True)
        if 'retention' not in items:
            self.create('retention',['/usr/local/bin/vaultcontext-demo-retention.py','--database','/demo-persistent/contacts.db'])
        retention=self.containers()['retention']
        if not retention['running']:self.docker.run('start',retention['id'])

    def probe(self):
        # Only allowlisted, non-secret health fields leave the container.
        code="import json,urllib.request; r=json.load(urllib.request.urlopen('http://127.0.0.1:80/api/demo/status',timeout=2)); print(json.dumps({k:r.get(k) for k in ('enabled','generation')}))"
        raw=self.docker.run('exec',PREFIX+'network','python3','-c',code,timeout=5)
        try:return json.loads(raw)
        except Exception:raise ResetError('invalid demo health response') from None

    def health(self):
        items=self.containers()
        if not items.get('app',{}).get('running') or not items.get('retention',{}).get('running'):
            raise ResetError('demo components are not running')
        result=self.probe()
        if result!={'enabled':True,'generation':os.environ['VAULTCONTEXT_DEMO_GENERATION']}:
            raise ResetError('demo generation health mismatch')
        dbpath=safe_path(self.root/'runtime/pb_data/data.db')
        with sqlite3.connect(dbpath.as_uri()+'?mode=ro',uri=True) as db:
            for table in ('users','identities','identity_secrets','vaults','memberships','key_envelopes','documents','versions','version_chunks','invitations','audit_log','demo_enrollments'):
                if db.execute('SELECT COUNT(*) FROM "'+table+'"').fetchone()[0]:
                    raise ResetError('fresh demo contains visitor state')

    def action(self,name):
        if name=='fence':self.stop('gate')
        elif name=='stop':
            for role in ('app','init'):self.stop(role)
        elif name=='assert_stopped':
            items=self.containers()
            if any(items.get(role,{}).get('running') for role in ('gate','app','init')):
                raise ResetError('demo writer or ingress remains running')
        elif name=='initialize':
            self.ensure_services();self.remove('init')
            if (self.root/'runtime/pb_data').exists():raise ResetError('demo initialization requires fresh storage')
            self.create('init',['init'],'initialize')
            self.docker.run('start',PREFIX+'init')
            deadline=time.monotonic()+240
            while time.monotonic()<deadline:
                item=self.containers()['init']
                if not item['running']:
                    if item['exit']!=0:raise ResetError('demo initialization failed')
                    self.remove('init');return
                time.sleep(.2)
            raise ResetError('demo initialization timed out')
        elif name=='start':
            self.ensure_services();self.remove('app');self.create('app',[],'start')
            self.docker.run('start',PREFIX+'app')
            deadline=time.monotonic()+120
            while time.monotonic()<deadline:
                try:self.health();return
                except Exception:time.sleep(.5)
            raise ResetError('fresh demo health timed out')
        elif name=='health':self.health()
        elif name=='unfence':
            self.health();self.remove('gate');self.create('gate',['-g','daemon off;'])
            self.docker.run('start',PREFIX+'gate')
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                try:
                    with urlopen(f"http://127.0.0.1:{self.config['port']}/api/demo/status",timeout=1) as response:
                        data=json.load(response)
                    if data.get('generation')==os.environ['VAULTCONTEXT_DEMO_GENERATION']:return
                except Exception:pass
                time.sleep(.2)
            raise ResetError('loopback ingress gate failed health check')
        else:raise ResetError('unknown demo lifecycle phase')


def configure(root,image,gate_image,port,origin,kind):
    root=safe_path(Path(root).absolute())
    if root.name!='vaultcontext-demo':raise ResetError('dedicated demo root required')
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    (root/'control').mkdir(mode=0o700,exist_ok=True)
    for directory in (root,root/'control'):
        info=directory.stat()
        if info.st_uid!=os.getuid() or info.st_mode&0o077:raise ResetError('private owned demo directories required')
    if (root/'control/docker.json').exists():raise ResetError('Docker demo already configured')
    config={'image':image,'gate_image':gate_image,'port':port,'origin':origin,'env_file':str(root/'control/runtime.env')}
    atomic_json(root/'control/docker.json',config)
    try:load(root)
    except Exception:
        (root/'control/docker.json').unlink();raise
    values=environment(config['env_file'])
    # Separate least-privilege service configuration; never emitted to stdout.
    target=root/'control/contact.env'
    descriptor=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'w') as stream:stream.write('VAULTCONTEXT_DEMO_CONTACT_TOKEN='+values['VAULTCONTEXT_DEMO_CONTACT_TOKEN']+'\n')
    nginx='''pid /tmp/nginx.pid;
error_log /dev/null;
events { worker_connections 1024; }
http {
 access_log off;
 client_body_temp_path /tmp/client;
 proxy_temp_path /tmp/proxy;
 server {
  listen 8080;
  client_max_body_size 14m;
  location / {
   proxy_pass http://127.0.0.1:80;
   proxy_http_version 1.1;
   proxy_set_header Host DEMO_ORIGIN_HOST;
   proxy_set_header X-Forwarded-Proto https;
   proxy_set_header Connection "";
   proxy_buffering off;
   proxy_request_buffering off;
   proxy_read_timeout 300s;
  }
 }
}
'''
    nginx=nginx.replace('DEMO_ORIGIN_HOST',urlsplit(origin).hostname)
    (root/'control/nginx.conf').write_text(nginx);os.chmod(root/'control/nginx.conf',0o644)
    script=str(Path(__file__).resolve())
    reset={'deployment':'vaultcontext-demo','origin':origin,'root':str(root),'storage':{'kind':kind,'primary_bucket':values['VAULTCONTEXT_S3_BUCKET'],'replica_bucket':values['LITESTREAM_BUCKET']},
           'hooks':{name:[sys.executable,script,name] for name in ('fence','stop','assert_stopped','initialize','start','health','unfence')}}
    atomic_json(root/'control/reset.json',reset)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=['configure','fence','stop','assert_stopped','initialize','start','health','unfence'])
    parser.add_argument('--root',default=os.environ.get('VAULTCONTEXT_DEMO_RESET_ROOT'))
    parser.add_argument('--image');parser.add_argument('--gate-image');parser.add_argument('--origin')
    parser.add_argument('--port',type=int,default=18782);parser.add_argument('--storage',choices=['s3','r2'],default='r2')
    args=parser.parse_args();os.umask(0o077)
    try:
        if os.geteuid()!=0:raise ResetError('Docker lifecycle requires root-owned state and a privileged local operator')
        if args.action=='configure':configure(args.root,args.image,args.gate_image,args.port,args.origin,args.storage)
        else:Lifecycle(Path(args.root),load(Path(args.root))).action(args.action)
    except Exception:
        print('Docker demo lifecycle failed; private configuration or fence requires operator review',file=sys.stderr)
        raise SystemExit(1)

if __name__=='__main__':main()
