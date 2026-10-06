#!/usr/bin/env python3
"""Synthetic real-image primary S3 storage and Litestream recovery release gate."""
import argparse
import importlib.util
import json
import hashlib
import urllib.request
from pathlib import Path
import secrets
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
APP = 'vaultcontext'
PREFIX = APP.upper()
spec = importlib.util.spec_from_file_location('smoke', ROOT / 'docker/smoke.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--minio-image', default=s.MINIO_IMAGE)
    args = parser.parse_args()
    run_id = secrets.token_hex(5)
    network = APP + '-primary-' + run_id
    minio = network + '-minio'
    failed = True
    try:
        s.docker('network', 'create', network); s.networks.append(network)
        root_key = s.secret('root' + run_id)
        root_secret = s.secret(secrets.token_hex(24))
        mc = {'MC_HOST_test': s.secret(f'http://{root_key}:{root_secret}@127.0.0.1:9000')}
        s.containers.append(minio)
        s.docker('run', '-d', '--name', minio, '--network', network,
                 '-e', 'MINIO_ROOT_USER', '-e', 'MINIO_ROOT_PASSWORD', args.minio_image,
                 'server', '/data', env={'MINIO_ROOT_USER': root_key, 'MINIO_ROOT_PASSWORD': root_secret})
        for _ in range(30):
            status, _ = s.docker('exec', '-e', 'MC_HOST_test', minio, 'mc', 'mb',
                                 '--ignore-existing', 'test/files', 'test/replica', env=mc, ok=False)
            if status == 0: break
            time.sleep(1)
        else: raise RuntimeError('synthetic MinIO startup failed')
        with tempfile.TemporaryDirectory(prefix=APP + '-primary-') as td:
            tmp = Path(td)
            keys = {}
            for bucket in ('files', 'replica'):
                key = s.secret(bucket + run_id)
                password = s.secret(secrets.token_hex(24))
                keys[bucket] = (key, password)
                policy = {'Version':'2012-10-17', 'Statement':[{'Effect':'Allow','Action':['s3:*'],
                           'Resource':[f'arn:aws:s3:::{bucket}',f'arn:aws:s3:::{bucket}/*']}]}
                path = tmp / (bucket + '-policy.json'); path.write_text(json.dumps(policy))
                s.docker('cp', str(path), minio + ':/tmp/' + bucket + '-policy.json')
                s.docker('exec', '-e', 'MC_HOST_test', '-e', 'FIXTURE_USER', '-e', 'FIXTURE_PASSWORD',
                         minio, 'sh', '-c', 'mc admin user add test "$FIXTURE_USER" "$FIXTURE_PASSWORD"',
                         env={**mc,'FIXTURE_USER':key,'FIXTURE_PASSWORD':password})
                s.docker('exec', '-e', 'MC_HOST_test', minio, 'mc', 'admin', 'policy', 'create',
                         'test', bucket, '/tmp/' + bucket + '-policy.json', env=mc)
                s.docker('exec', '-e', 'MC_HOST_test', minio, 'mc', 'admin', 'policy', 'attach',
                         'test', bucket, '--user', key, env=mc)
            env = s.once_env({PREFIX+'_S3_BUCKET':'files', PREFIX+'_S3_ENDPOINT':f'http://{minio}:9000',
                PREFIX+'_S3_REGION':'us-east-1', PREFIX+'_S3_ACCESS_KEY_ID':keys['files'][0],
                PREFIX+'_S3_SECRET_ACCESS_KEY':keys['files'][1], 'LITESTREAM_BUCKET':'replica',
                'LITESTREAM_PATH':'test/data', 'LITESTREAM_ENDPOINT':f'http://{minio}:9000',
                'LITESTREAM_REGION':'us-east-1', 'LITESTREAM_ACCESS_KEY_ID':keys['replica'][0],
                'LITESTREAM_SECRET_ACCESS_KEY':keys['replica'][1], 'LITESTREAM_SYNC_INTERVAL':'1h'})
            probe = ['run','--rm']
            for key in env: probe.extend(['-e',key])
            status, output = s.docker(*probe,args.image,'serve',env=env,ok=False)
            s.check(status != 0 and 'initial replica synchronization failed' in output and
                    'starting server on port 80' not in output, 'missing IPC refuses HTTP startup')
            first, second = network+'-a', network+'-b'
            s.run_app(args.image,first,first,env,network); base=s.wait_up(first)
            admin=s.superuser_token(base,env[PREFIX+'_SUPERUSER_EMAIL'],env[PREFIX+'_SUPERUSER_PASSWORD'])
            password=s.secret(secrets.token_urlsafe(24))
            user=s.provision_user(base,admin,'recovery@example.test',password)
            s.provision_user(base,admin,'foreign@example.test',password)
            client=s.Client(base,'recovery@example.test',password,tmp/'home-a')
            doc,meta=s.write_record(client,user); s.check_records(client,doc,meta)
            s.check('initial replica synchronization complete' in s.logs(first), 'initial remote sync precedes HTTP')
            s.check(s.docker('exec',first,'sh','-c','find /storage/pb_data/storage -type f 2>/dev/null || true')[1].strip()=='',
                    'all uploaded originals are remote')
            collection,field = {'accountcontext':('documents','original'), 'chatcontext':('attachments','original'),
                                'vaultcontext':('version_chunks','ciphertext')}[APP]
            record=client.sql('SELECT id,'+field+',sha256 FROM '+collection+' LIMIT 1')[0]
            def check_foreign(origin):
                path=origin+'/api/files/'+collection+'/'+record[0]+'/'+record[1]+'?token='
                status,_,token=s.http('POST',origin+'/api/files/token',{},token=client.token)
                s.check(status==200,'owner receives file token for exact remote object')
                owner_token=s.secret(token['token'])
                with urllib.request.urlopen(path+owner_token) as response:
                    checksum=hashlib.sha256(response.read()).hexdigest()
                s.check(checksum==record[2],'exact authorization-test URL returns expected object bytes to owner')
                foreign=s.Client(origin,'foreign@example.test',password,tmp/'foreign')
                status,_,token=s.http('POST',origin+'/api/files/token',{},token=foreign.token)
                s.check(status==200,'unrelated user can request own file token')
                foreign_token=s.secret(token['token'])
                status,_,_=s.http('GET',path+foreign_token)
                s.check(status in (401,403,404),'unrelated user cannot download protected remote object')
            check_foreign(base)
            status,_,state=s.http('GET',base+'/api/context/maintenance',token=admin)
            s.check(status==200,'operator maintenance state available')
            status,_,frozen=s.http('PUT',base+'/api/context/maintenance',
                {'readOnly':True,'expectedGeneration':state['generation']},token=admin)
            s.check(status==200 and frozen['state']=='read_only','source freezes after late writes')
            s.check_records(client,doc,meta)
            for token in (admin,client.token):
                status,_,_=s.http('POST',base+'/api/collections/users/records',{},token=token)
                s.check(status==503,'frozen writes rejected')
            s.stop(first)
            # A frozen restart must preserve backend and identity settings and keep the replica initialized.
            s.docker('start',first); base=s.wait_up(first); client.base=base
            status,_,state=s.http('GET',base+'/api/context/maintenance',token=admin)
            s.check(status==200 and state['state']=='read_only' and state['generation']==frozen['generation'],
                    'frozen restart preserves state and operator token')
            s.check_records(client,doc,meta)
            s.check(s.logs(first).count('initial replica synchronization complete')>=2,'frozen startup synchronizes replica')
            s.stop(first)
            s.check('uploaded verified database and originals' not in s.logs(first),'legacy archive supervisor absent')
            s.docker('volume','create',second); s.volumes.append(second)
            restore=['run','--rm','--network',network,'-v',second+':/storage']
            for key in env: restore.extend(['-e',key])
            s.docker(*restore,'--entrypoint','sh',args.image,'-c',
                'mkdir -p /storage/pb_data; exec litestream restore -config /etc/litestream.yml /storage/pb_data/data.db',env=env)
            # Compare all tables before starting a writer; carry the independent durable freeze marker.
            s.docker('run','--rm','-v',first+':/source:ro','-v',second+':/restored',
                '-v',str(ROOT/'tests')+':/tests:ro','--entrypoint','sh',args.image,'-c',
                'cp -a /source/pb_data /tmp/source; cp -a /restored/pb_data /tmp/restored; '
                'python3 /tests/object_storage_equivalence.py /tmp/source/data.db /tmp/restored/data.db /tmp/source/auxiliary.db /restored/pb_data/auxiliary.db && '
                'cp /source/pb_data/maintenance.json /restored/pb_data/maintenance.json && chmod 600 /restored/pb_data/maintenance.json')
            s.check(True,'all stopped database rows match restored replica before source destruction')
            s.docker('rm',first); s.docker('volume','rm',first); s.volumes.remove(first); s.containers.remove(first)
            s.run_app(args.image,second,second,env,network); s.volumes.remove(second); base=s.wait_up(second)
            # Frozen restoration uses the pre-existing operator token; ordinary logins may write and are deferred.
            status,_,state=s.http('GET',base+'/api/context/maintenance',token=admin)
            s.check(status==200 and state['state']=='read_only' and state['generation']==frozen['generation'],
                    'new host remains frozen until explicitly thawed')
            client.base=base; s.check_records(client,doc,meta)
            status,_,thawed=s.http('PUT',base+'/api/context/maintenance',
                {'readOnly':False,'expectedGeneration':state['generation']},token=admin)
            s.check(status==200 and thawed['state']=='writable','destination thaws only after source volume destroyed')
            restored=s.Client(base,'recovery@example.test',password,tmp/'home-b'); s.check_records(restored,doc,meta)
            check_foreign(base)
            s.check('restored verified database and originals' not in s.logs(second),'legacy archive restore absent')
            late_doc,late_meta=s.write_record(restored,user)
            s.check_records(restored,late_doc,late_meta)
            s.stop(second); s.check_logs(second)
            s.docker('rm',second); s.docker('volume','rm',second)
            s.containers.remove(second); s.volumes.remove(second)
            # Ordinary disaster recovery exercises the real entrypoint from a
            # completely empty volume: no manual main/auxiliary DB or marker copy.
            third=network+'-automatic'
            s.run_app(args.image,third,third,env,network); base=s.wait_up(third)
            recovered=s.Client(base,'recovery@example.test',password,tmp/'home-c')
            s.check_records(recovered,doc,meta); s.check_records(recovered,late_doc,late_meta)
            check_foreign(base)
            text=s.logs(third)
            s.check('database present after the restore step' in text and
                    'restored verified database and originals' not in text,
                    'empty-volume entrypoint restores main SQLite only through Litestream')
            s.check('initial replica synchronization complete' in text,'automatic restore synchronizes before serving')
            s.docker('exec',third,'test','-f','/storage/pb_data/auxiliary.db')
            s.check(True,'writable restore initializes its auxiliary database')
            s.stop(third); s.check_logs(third)
            s.check('full-backups/' not in s.docker('exec','-e','MC_HOST_test',minio,'mc','ls','--recursive','test/replica',env=mc)[1],
                    'no legacy full archives emitted')
            fresh=network+'-google-only'
            bootstrap={key:value for key,value in env.items() if not key.startswith(PREFIX+'_SUPERUSER_')}
            bootstrap['LITESTREAM_PATH']='google-only/data'
            s.run_app(args.image,fresh,fresh,bootstrap,network); s.wait_up(fresh)
            s.check('initial replica synchronization complete' in s.logs(fresh),'fresh Google-only database synchronizes before HTTP')
            s.stop(fresh)
        failed=False
        print('PASS: real primary S3 uploads, frozen restart, full Litestream recovery, source destruction and explicit thaw')
    finally:
        s.report_and_clean(failed)


if __name__=='__main__': main()
