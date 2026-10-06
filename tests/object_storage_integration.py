#!/usr/bin/env python3
"""Synthetic private S3 upload/recovery drill; requires dedicated disposable bucket.

Set VAULTCONTEXT_S3_* to a local MinIO fixture. Never target real application buckets.
This test deliberately corrupts/deletes only its own uploaded synthetic object.
"""
import argparse
from contextlib import closing, ExitStack
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.request
from unittest.mock import patch

import boto3
from botocore.config import Config
from backup_integration import load
from integration import ROOT, server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--synthetic-bucket', required=True, help='Exact dedicated test bucket; authorizes destructive fixture checks')
    args = parser.parse_args()
    bucket = os.environ['VAULTCONTEXT_S3_BUCKET']
    assert bucket == args.synthetic_bucket
    endpoint = os.environ['VAULTCONTEXT_S3_ENDPOINT']
    if '://' not in endpoint:
        endpoint = 'https://' + endpoint
    s3 = boto3.client('s3', endpoint_url=endpoint, region_name=os.environ['VAULTCONTEXT_S3_REGION'],
        aws_access_key_id=os.environ['VAULTCONTEXT_S3_ACCESS_KEY_ID'],
        aws_secret_access_key=os.environ['VAULTCONTEXT_S3_SECRET_ACCESS_KEY'],
        config=Config(s3={'addressing_style': 'path'}))
    backup = load('remote_backup', ROOT / 'docker/entrypoint.py')
    smoke = load('remote_smoke', ROOT / 'docker/smoke.py')
    with tempfile.TemporaryDirectory(prefix='vaultcontext-s3-test-') as tmp, ExitStack() as stack:
        request = stack.enter_context(server(args.binary))
        admin = smoke.superuser_token(request.base_url, 'admin@example.com', 'SyntheticAdminPassword123!')
        password = 'SyntheticRemotePassword123!'
        user = smoke.provision_user(request.base_url, admin, 'remote@example.test', password)
        smoke.provision_user(request.base_url, admin, 'foreign@example.test', password)
        client = smoke.Client(request.base_url, 'remote@example.test', password, None)
        doc, meta = smoke.write_record(client, user)
        references = backup.refs(request.data_dir)
        assert references, 'fixture must upload immutable originals'
        keys = [name.removeprefix('storage/') for name in references]
        key = keys[0]
        def denied_foreign(base):
            foreign = smoke.Client(base, 'foreign@example.test', password, None)
            status, _, token = smoke.http('POST', base + '/api/files/token', {}, token=foreign.token)
            assert status == 200
            status, _, _ = smoke.http('GET', base + '/api/files/' + key + '?token=' + token['token'])
            assert status in (400, 403, 404), 'unrelated user must not download protected objects'
        try:
            smoke.check_records(client, doc, meta)
            denied_foreign(request.base_url)
            assert all(not (request.data_dir / 'storage' / item).exists() for item in keys)
            backup.verify(request.data_dir)
            # Database-only recovery must work without any local original-file copies.
            restored = Path(tmp) / 'restored'
            restored.mkdir()
            with closing(sqlite3.connect(f'file:{request.data_dir / "data.db"}?mode=ro', uri=True)) as source:
                with closing(sqlite3.connect(restored / 'data.db')) as dest:
                    source.backup(dest)
            stack.close()  # Stop the original writer before opening the recovered database.
            backup.verify(restored)
            without_s3 = {key: value for key, value in os.environ.items() if not key.startswith('VAULTCONTEXT_S3_')}
            with patch.dict(os.environ, without_s3, clear=True):
                try: backup.verify(restored)
                except RuntimeError: pass
                else: raise AssertionError('stored remote configuration accepted without S3 environment')
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
            base = f'http://127.0.0.1:{port}'
            with (Path(tmp) / 'server.log').open('w+') as log:
                proc = subprocess.Popen([args.binary, 'serve', '--http=' + base.removeprefix('http://'),
                    '--dir=' + str(restored), '--hooksDir=' + str(ROOT / 'pb_hooks'),
                    '--migrationsDir=' + str(ROOT / 'pb_migrations')], cwd=ROOT, stdout=log, stderr=log)
                try:
                    for _ in range(150):
                        try:
                            urllib.request.urlopen(base + '/up', timeout=1).close(); break
                        except OSError:
                            if proc.poll() is not None: raise AssertionError('restore startup failed')
                            time.sleep(.1)
                    else: raise AssertionError('restore startup timed out')
                    smoke.check_records(smoke.Client(base, 'remote@example.test', password, None), doc, meta)
                    denied_foreign(base)
                finally:
                    proc.terminate(); proc.wait(timeout=15)
            s3.put_object(Bucket=bucket, Key=key, Body=b'Corrupted synthetic original')
            try: backup.verify(restored)
            except RuntimeError: pass
            else: raise AssertionError('corrupt original accepted')
            s3.delete_object(Bucket=bucket, Key=key)
            try: backup.verify(restored)
            except Exception: pass
            else: raise AssertionError('missing original accepted')
        finally:
            for item in keys:
                s3.delete_object(Bucket=bucket, Key=item)
    print('PASS: API S3 upload, remote checksum, protected download, database-only recovery, corrupt/missing rejection')


if __name__ == '__main__':
    main()
