#!/usr/bin/env python3
"""Complete immutable-ciphertext snapshots; never restore a DB without its originals.

Online SQLite backup establishes the snapshot point. Version chunks are immutable and cannot
be deleted, so copying exactly the snapshot's references afterwards is consistent. Each
snapshot has its own DB/file checksums. A latest pointer is published only after the archive
upload succeeds. Nothing is automatically deleted. Replica credentials never reach the server; primary-storage credentials do.
"""
import argparse
from contextlib import closing
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

DATA = Path(os.environ.get('VAULTCONTEXT_DATA_DIR', '/storage/pb_data'))


def digest(path):
    with open(path, 'rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def refs(data):
    """Get immutable original paths and recorded hashes from the snapshot DB."""
    db = data / 'data.db'
    if not db.exists():
        return {}
    with closing(sqlite3.connect(f'file:{db}?mode=ro', uri=True)) as conn:
        if conn.execute('PRAGMA quick_check').fetchone() != ('ok',):
            raise RuntimeError('database integrity check failed')
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='version_chunks' AND type='table'").fetchone():
            return {}
        collection = conn.execute("SELECT id FROM _collections WHERE name='version_chunks'").fetchone()[0]
        result = {}
        for record, filename, sha in conn.execute('SELECT id, ciphertext, sha256 FROM version_chunks'):
            if not filename:
                raise RuntimeError('chunk has no ciphertext')
            parts = (collection, record, filename)
            if any(not x or x in ('.', '..') or '/' in x or '\\' in x for x in parts):
                raise RuntimeError('unsafe ciphertext path')
            if len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha):
                raise RuntimeError('chunk has no valid checksum')
            result['storage/' + '/'.join(parts)] = sha
        return result


def stored_storage_settings(data):
    db = data / 'data.db'
    if not db.exists():
        return {}
    with closing(sqlite3.connect(f'file:{db}?mode=ro', uri=True)) as conn:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='_params'").fetchone():
            return {}
        row = conn.execute("SELECT value FROM _params WHERE id='settings'").fetchone()
    if not row:
        return {}
    try:
        settings = json.loads(row[0]).get('s3', {})
        if not isinstance(settings, dict):
            raise ValueError('invalid storage settings')
        return settings
    except (ValueError, AttributeError):
        raise RuntimeError('cannot determine persisted storage mode') from None


def stored_remote_storage(data):
    return bool(stored_storage_settings(data).get('enabled'))


def verify_frozen_storage(data):
    """The frozen app cannot apply environment changes: verify its actual backend."""
    marker = data / 'maintenance.json'
    try:
        state = json.loads(marker.read_text())
    except FileNotFoundError:
        return
    except (ValueError, OSError):
        raise RuntimeError('invalid maintenance state') from None
    if not isinstance(state, dict) or type(state.get('readOnly')) is not bool:
        raise RuntimeError('invalid maintenance state')
    if not state['readOnly']:
        return
    fields = {'bucket': 'BUCKET', 'endpoint': 'ENDPOINT', 'region': 'REGION',
              'accessKey': 'ACCESS_KEY_ID', 'secret': 'SECRET_ACCESS_KEY'}
    desired = {field: os.environ.get('VAULTCONTEXT_S3_' + name, '').strip()
               for field, name in fields.items()}
    current = stored_storage_settings(data)
    remote = any(desired.values())
    if not remote and not current.get('enabled'):
        return
    style = os.environ.get('VAULTCONTEXT_S3_FORCE_PATH_STYLE', 'true').strip()
    desired.update(enabled=True, forcePathStyle=style == 'true')
    if (not remote or not all(desired[field] for field in fields)
            or style not in ('true', 'false')
            or any(current.get(field) != value for field, value in desired.items())):
        raise RuntimeError('frozen object storage configuration differs from stored settings; startup refused')


def verify(data):
    verify_frozen_storage(data)
    if not os.environ.get('VAULTCONTEXT_S3_BUCKET') and stored_remote_storage(data):
        raise RuntimeError('remote storage requires explicit environment configuration')
    if os.environ.get('VAULTCONTEXT_S3_BUCKET'):
        return verify_remote(data)
    for name, expected in refs(data).items():
        path = data / name
        if path.is_symlink() or not path.is_file() or digest(path) != expected:
            raise RuntimeError('missing or corrupt original evidence; startup refused')


def verify_remote(data, client=None):
    """Verify the restored database against immutable objects, without local copies."""
    names = ('BUCKET', 'ENDPOINT', 'REGION', 'ACCESS_KEY_ID', 'SECRET_ACCESS_KEY')
    config = {name: os.environ.get('VAULTCONTEXT_S3_' + name, '') for name in names}
    if not all(config.values()):
        raise RuntimeError('incomplete object storage configuration')
    if client is None:
        import boto3
        from botocore.config import Config
        endpoint = config['ENDPOINT']
        if '://' not in endpoint:
            endpoint = 'https://' + endpoint
        client = boto3.client('s3', endpoint_url=endpoint, region_name=config['REGION'],
            aws_access_key_id=config['ACCESS_KEY_ID'], aws_secret_access_key=config['SECRET_ACCESS_KEY'],
            config=Config(connect_timeout=10, read_timeout=60, retries={'max_attempts': 3},
                s3={'addressing_style': 'path' if os.environ.get('VAULTCONTEXT_S3_FORCE_PATH_STYLE', 'true') == 'true' else 'virtual'}))
    for name, expected in refs(data).items():
        response = client.get_object(Bucket=config['BUCKET'], Key=name.removeprefix('storage/'))
        with closing(response['Body']) as body:
            checksum = hashlib.sha256()
            for chunk in iter(lambda: body.read(1024 * 1024), b''):
                checksum.update(chunk)
        if checksum.hexdigest() != expected:
            raise RuntimeError('missing or corrupt remote original; startup refused')


def snapshot(data, dest):
    dest.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(f'file:{data / "data.db"}?mode=ro', uri=True)) as source:
        with closing(sqlite3.connect(dest / 'data.db')) as target:
            source.backup(target)
            target.execute('PRAGMA journal_mode=DELETE')
    expected = refs(dest)
    for name, sha in expected.items():
        source, target = data / name, dest / name
        if source.is_symlink() or not source.is_file():
            raise RuntimeError('missing original ciphertext')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if digest(target) != sha:
            raise RuntimeError('original checksum mismatch')
    expected['data.db'] = digest(dest / 'data.db')
    (dest / 'manifest.json').write_text(json.dumps({'version': 1, 'files': expected}, sort_keys=True))
    verify(dest)


def unpack(archive, dest):
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, 'r:gz') as tar:
        for member in tar.getmembers():
            path = Path(member.name)
            if path.is_absolute() or '..' in path.parts or not member.isfile():
                raise RuntimeError('unsafe snapshot archive')
            target = dest / path
            target.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as source, target.open('wb') as output:
                shutil.copyfileobj(source, output)
    manifest = json.loads((dest / 'manifest.json').read_text())
    if manifest.get('version') != 1:
        raise RuntimeError('unsupported snapshot')
    expected = manifest['files']
    actual = {str(p.relative_to(dest)) for p in dest.rglob('*') if p.is_file()} - {'manifest.json'}
    if actual != set(expected) or 'data.db' not in expected:
        raise RuntimeError('incomplete snapshot manifest')
    for name, sha in expected.items():
        if digest(dest / name) != sha:
            raise RuntimeError('snapshot checksum mismatch')
    verify(dest)


def remote():
    import boto3
    from botocore.config import Config
    client = boto3.client('s3', endpoint_url=os.environ.get('LITESTREAM_ENDPOINT') or None,
                          region_name=os.environ.get('LITESTREAM_REGION') or 'us-east-1',
                          aws_access_key_id=os.environ['LITESTREAM_ACCESS_KEY_ID'],
                          aws_secret_access_key=os.environ['LITESTREAM_SECRET_ACCESS_KEY'],
                          config=Config(connect_timeout=10, read_timeout=30,
                                        retries={'max_attempts': 2}, s3={'addressing_style': 'path'}))
    return client, os.environ['LITESTREAM_BUCKET'], os.environ['LITESTREAM_PATH'].rstrip('/') + '/full-backups'


def upload(data):
    # Manual drills and scheduled/final snapshots serialize on this volume.
    with (data / '.complete-backup.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _upload(data)


def _upload(data):
    client, bucket, prefix = remote()
    with tempfile.TemporaryDirectory(prefix='vaultcontext-snapshot-') as temp:
        root = Path(temp)
        snapshot(data, root / 'snapshot')
        archive = root / 'snapshot.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            for path in sorted((root / 'snapshot').rglob('*')):
                if path.is_file():
                    tar.add(path, arcname=str(path.relative_to(root / 'snapshot')), recursive=False)
        key = prefix + '/' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex + '.tar.gz'
        client.upload_file(str(archive), bucket, key)
        pointer = json.dumps({'key': key, 'sha256': digest(archive), 'created': int(time.time())}).encode()
        client.put_object(Bucket=bucket, Key=prefix + '/latest.json', Body=pointer, ContentType='application/json')
    print('complete backup: uploaded verified database and originals', flush=True)


def restore(data):
    # An existing local database always wins. Never roll it backwards automatically.
    if (data / 'data.db').exists():
        verify(data)
        return
    client, bucket, prefix = remote()
    try:
        response = client.get_object(Bucket=bucket, Key=prefix + '/latest.json')
    except client.exceptions.ClientError as error:
        if error.response['Error']['Code'] in ('NoSuchKey', '404'):
            return  # Entry point still checks the Litestream replica; not assumed empty.
        raise
    pointer = json.loads(response['Body'].read())
    if not pointer['key'].startswith(prefix + '/') or not pointer['key'].endswith('.tar.gz'):
        raise RuntimeError('snapshot pointer outside dedicated prefix')
    data.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='vaultcontext-restore-', dir=data.parent) as temp:
        root = Path(temp)
        archive = root / 'snapshot.tar.gz'
        client.download_file(bucket, pointer['key'], str(archive))
        if digest(archive) != pointer['sha256']:
            raise RuntimeError('snapshot archive checksum mismatch')
        unpack(archive, root / 'snapshot')
        data.mkdir(parents=True, exist_ok=True)
        if (data / 'storage').exists():
            raise RuntimeError('partial local storage exists; operator recovery required')
        if (root / 'snapshot/storage').exists():
            shutil.move(str(root / 'snapshot/storage'), data / 'storage')
        # Install the DB last, so partial restores never appear complete.
        os.replace(root / 'snapshot/data.db', data / 'data.db')
    verify(data)
    print('complete backup: restored verified database and originals', flush=True)


def supervise(command):
    child = subprocess.Popen(command)
    stopping = False
    def stop(signum, frame):
        nonlocal stopping
        stopping = True
        if child.poll() is None:
            child.send_signal(signum)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    interval = int(os.environ.get('VAULTCONTEXT_BACKUP_INTERVAL', '3600'))
    if not 1 <= interval <= 3600:
        child.terminate()
        child.wait()
        raise RuntimeError('backup interval must be between 1 and 3600 seconds')
    due = time.monotonic() + 5
    try:
        while child.poll() is None:
            if not stopping and time.monotonic() >= due and (DATA / 'data.db').exists():
                upload(DATA)
                due = time.monotonic() + interval
            time.sleep(0.2)
        code = child.wait()
        if code == 0 and (DATA / 'data.db').exists():
            upload(DATA)
        return code
    except BaseException:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=45)
        raise


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['restore', 'verify', 'upload', 'supervise'])
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.mode == 'supervise':
        return supervise(args.command)
    {'restore': restore, 'verify': verify, 'upload': upload}[args.mode](DATA)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        # SDK errors can embed endpoints or credentials; never log their representations.
        print('complete backup failed (' + type(error).__name__ + '); operator recovery required', file=sys.stderr)
        sys.exit(1)
