"""Synthetic command/metadata tests; never invoke Docker or cloud providers."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'deploy/demo'))
import docker_lifecycle as module

IMAGE='ghcr.io/pocketcontext/vaultcontext@sha256:'+'a'*64
GATE='nginx@sha256:'+'b'*64

class FakeDocker:
    def __init__(self,root,config):self.root=root;self.config=config;self.items={};self.commands=[];self.counter=0
    def inventory(self):return copy.deepcopy(list(self.items.values()))
    def inspect(self,name):
        for item in self.items.values():
            if name in (item['id'],item['name']):return copy.deepcopy(item)
        raise module.ResetError('not found')
    def run(self,*args,**kwargs):
        self.commands.append(args)
        if args[0]=='create':
            role=args[args.index('--name')+1].removeprefix(module.PREFIX);self.counter+=1
            labels={};mounts=[]
            for i,value in enumerate(args):
                if value=='--label':
                    key,val=args[i+1].split('=',1);labels[key.removeprefix(module.LABEL)]=val
                if value=='--mount':
                    values=dict(p.split('=',1) if '=' in p else (p,'') for p in args[i+1].split(','))
                    mounts.append({'source':values['src'],'target':values['dst'],'type':'bind','rw':'readonly' not in values})
            self.items[role]={'id':f'{self.counter:064x}','name':module.PREFIX+role,'image':GATE if role=='gate' else IMAGE,
                'running':False,'exit':0,'restart':'no','network':'bridge' if role=='network' else 'container:'+module.PREFIX+'network',
                'ports':{'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':str(self.config['port'])}]} if role=='network' else {},
                'labels':labels,'mounts':mounts}
        elif args[0] in ('start','kill','rm','update'):
            name=args[-1] if args[0]!='start' else args[1]
            key=next(role for role,item in self.items.items() if name in (item['id'],item['name']))
            if args[0]=='rm':del self.items[key]
            elif args[0]=='start':self.items[key]['running']=key!='init'
            elif args[0]=='kill':self.items[key]['running']=False
            else:self.items[key]['restart']='no'
        elif args[0]=='exec':return json.dumps({'enabled':True,'generation':os.environ['VAULTCONTEXT_DEMO_GENERATION']}).encode()
        return b''

class DockerDemoTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'vaultcontext-demo';(self.root/'control').mkdir(parents=True,mode=0o700);os.chmod(self.root,0o700)
        values={key:'synthetic-value' for key in module.REQUIRED}
        values.update(VAULTCONTEXT_S3_BUCKET='vaultcontext-demo-files',LITESTREAM_BUCKET='vaultcontext-demo-replicas',
                      VAULTCONTEXT_S3_ACCESS_KEY_ID='primary-key',LITESTREAM_ACCESS_KEY_ID='replica-key',VAULTCONTEXT_DEMO_CONTACT_TOKEN='synthetic-contact-token-'+'x'*32)
        self.env_file=self.root/'control/runtime.env';self.env_file.write_text(''.join(k+'='+v+'\n' for k,v in values.items()));self.env_file.chmod(0o600)
        with socket.socket() as listener:listener.bind(('127.0.0.1',0));self.port=listener.getsockname()[1]
        module.configure(self.root,IMAGE,GATE,self.port,'https://vault-demo.example.com','r2')
        self.config=module.load(self.root);self.docker=FakeDocker(self.root,self.config);self.life=module.Lifecycle(self.root,self.config,self.docker)
        self.environment=patch.dict(os.environ,{'VAULTCONTEXT_DEMO_GENERATION':'2026-10-09'});self.environment.start();self.addCleanup(self.environment.stop)
        (self.root/'runtime').mkdir(mode=0o700)

    def test_configuration_is_concrete_and_dedicated(self):
        reset=json.loads((self.root/'control/reset.json').read_text())
        self.assertEqual(set(reset['hooks']),{'fence','stop','assert_stopped','initialize','start','health','unfence'})
        for phase,command in reset['hooks'].items():
            self.assertEqual(command[-1],phase);self.assertTrue(command[-2].endswith('docker_lifecycle.py'))
        self.assertEqual(reset['storage']['primary_bucket'],'vaultcontext-demo-files')
        self.assertEqual((self.root/'control/contact.env').read_text().count('\n'),1)
        self.assertNotIn('synthetic-contact-token',(self.root/'control/nginx.conf').read_text())

    def test_only_anchor_publishes_loopback_and_contact_is_least_privilege(self):
        self.life.ensure_services();self.life.create('app',[],'start');self.life.create('gate',['-g','daemon off;'])
        self.assertEqual(set(self.life.containers()),{'network','retention','app','gate'})
        creates=[cmd for cmd in self.docker.commands if cmd[0]=='create']
        self.assertEqual(sum('--publish' in cmd for cmd in creates),1)
        self.assertIn(f'127.0.0.1:{self.port}:8080',creates[0])
        retention=next(cmd for cmd in creates if module.PREFIX+'retention' in cmd)
        self.assertIn(str(self.root/'control/contact.env'),retention)
        self.assertNotIn(str(self.env_file),retention)
        app=next(cmd for cmd in creates if module.PREFIX+'app' in cmd)
        self.assertIn('VAULTCONTEXT_DEMO_RESET_PHASE=start',app)
        self.assertIn('VAULTCONTEXT_DEMO_RESET_FENCE=/demo-control/reset-pending.json',app)
        self.assertTrue(all('--restart=no' in cmd and '--log-driver=none' in cmd for cmd in creates))

    def test_stop_gate_precedes_writer_absence(self):
        self.life.ensure_services();self.life.create('app',[],'start');self.life.create('gate',['-g','daemon off;'])
        for role in ('app','gate'):self.docker.run('start',module.PREFIX+role)
        with self.assertRaises(module.ResetError):self.life.action('assert_stopped')
        self.life.action('fence');self.assertFalse(self.docker.items['gate']['running']);self.assertTrue(self.docker.items['app']['running'])
        self.life.action('stop');self.life.action('assert_stopped')
        self.assertTrue(self.docker.items['retention']['running'])
        self.assertFalse(any('--signal=SIGKILL' in cmd for cmd in self.docker.commands))

    def test_unrecognized_writer_bind_is_rejected(self):
        self.life.ensure_services();item=copy.deepcopy(self.docker.items['retention'])
        item['id']='f'*64;item['name']='unrelated-writer';item['labels']={};item['mounts']=[{'type':'bind','source':str(self.root/'runtime'),'target':'/data','rw':True}]
        self.docker.items['rogue']=item
        with self.assertRaisesRegex(module.ResetError,'unrecognized'):self.life.action('assert_stopped')

    def test_unrecognized_namespace_participant_rejected(self):
        self.life.ensure_services();item=copy.deepcopy(self.docker.items['retention'])
        item.update(id='f'*64,name='unrelated-sidecar',labels={},mounts=[])
        self.docker.items['rogue']=item
        with self.assertRaisesRegex(module.ResetError,'unrecognized'):self.life.containers()

    def test_image_port_and_namespace_mismatch_rejected(self):
        self.life.ensure_services()
        for field,value in [('image','ghcr.io/production:latest'),('ports',{'80/tcp':[{'HostIp':'0.0.0.0','HostPort':'80'}]}),('network','host')]:
            original=self.docker.items['network'][field];self.docker.items['network'][field]=value
            with self.assertRaises(module.ResetError):self.life.containers()
            self.docker.items['network'][field]=original

    def test_restart_disabled_before_stop(self):
        self.life.ensure_services();self.docker.items['network']['restart']='always'
        self.life.containers()
        self.assertEqual(self.docker.items['network']['restart'],'no')
        self.assertTrue(any(cmd[:2]==('update','--restart=no') for cmd in self.docker.commands))

    def test_initialize_explicit_init_no_ingress(self):
        self.life.action('initialize')
        command=next(cmd for cmd in self.docker.commands if cmd[0]=='create' and module.PREFIX+'init' in cmd)
        self.assertEqual(command[-1],'init');self.assertIn('VAULTCONTEXT_DEMO_RESET_PHASE=initialize',command)
        self.assertNotIn('gate',self.docker.items);self.assertNotIn('init',self.docker.items)

    def test_existing_runtime_refuses_initialization(self):
        (self.root/'runtime/pb_data').mkdir()
        with self.assertRaisesRegex(module.ResetError,'fresh storage'):self.life.action('initialize')
        self.assertFalse(any(cmd[0]=='create' and module.PREFIX+'init' in cmd for cmd in self.docker.commands))

    def test_unfence_requires_health(self):
        with patch.object(self.life,'health',side_effect=module.ResetError('not healthy')):
            with self.assertRaises(module.ResetError):self.life.action('unfence')
        self.assertFalse(any(cmd[0]=='create' for cmd in self.docker.commands))

    def test_immutable_images_and_env_allowlist(self):
        raw=json.loads((self.root/'control/docker.json').read_text());raw['image']='ghcr.io/pocketcontext/vaultcontext:latest'
        (self.root/'control/docker.json').write_text(json.dumps(raw))
        with self.assertRaises(module.ResetError):module.load(self.root)
        with self.env_file.open('a') as stream:stream.write('VAULTCONTEXT_SUPERUSER_PASSWORD=forbidden\n')
        with self.assertRaises(module.ResetError):module.environment(self.env_file)

    def test_raw_inspect_secrets_never_escape(self):
        raw={'Id':'a'*64,'Name':'/vaultcontext-demo-network','Config':{'Image':IMAGE,'Env':['SECRET=must-not-escape'],
             'Labels':{module.LABEL+'deployment':'vaultcontext-demo','secret':'must-not-escape'}},
             'State':{'Running':True,'ExitCode':0},'HostConfig':{'RestartPolicy':{'Name':'no'},'NetworkMode':'bridge'},'Mounts':[]}
        docker=module.Docker()
        with patch.object(docker,'run',return_value=json.dumps([raw]).encode()):result=docker.inspect('a'*64)
        self.assertNotIn('must-not-escape',repr(result));self.assertNotIn('Env',repr(result))
        with patch.object(docker,'run',return_value=b'must-not-escape'):
            with self.assertRaises(module.ResetError) as error:docker.inspect('a'*64)
        self.assertNotIn('must-not-escape',str(error.exception))

if __name__=='__main__':unittest.main()
