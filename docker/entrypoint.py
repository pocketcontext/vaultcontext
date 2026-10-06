#!/usr/bin/python3 -I
"""S3 evidence verification and Litestream startup; no archive backup or supervisor.

The default command requires an existing database or a recoverable replica.
`init` is a one-shot fresh-install operation; `serve` is Litestream's child.
Python replaces itself with Litestream/PocketContext once preparation is done.
"""
import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile

APP = Path('/app')
DATA = Path(os.environ.get('VAULTCONTEXT_DATA_DIR', '/storage/pb_data'))
SERVER = '/usr/local/bin/pocketcontext'
LITESTREAM = '/usr/local/bin/litestream'
SELF = '/usr/local/bin/vaultcontext-entrypoint.py'
CONFIG = '/etc/litestream.yml'
SOCKET = '/run/litestream.sock'
S3_FIELDS = {'bucket': 'BUCKET', 'endpoint': 'ENDPOINT', 'region': 'REGION',
             'accessKey': 'ACCESS_KEY_ID', 'secret': 'SECRET_ACCESS_KEY'}


class StartupError(RuntimeError):
    """Only fixed, non-secret messages may be included."""


def log(message):
    print('entrypoint: ' + message, flush=True)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def validate_config():
    if os.environ.get('LITESTREAM_DISABLED'):
        raise StartupError('LITESTREAM_DISABLED is unsupported; replication is required')
    for prefix, names in (
        ('VAULTCONTEXT_S3_', S3_FIELDS.values()),
        ('LITESTREAM_', ('BUCKET', 'PATH', 'ACCESS_KEY_ID', 'SECRET_ACCESS_KEY')),
    ):
        missing = [prefix + name for name in names if not os.environ.get(prefix + name, '').strip()]
        if missing:
            raise StartupError('missing required configuration: ' + ', '.join(missing))
    if os.environ.get('VAULTCONTEXT_S3_FORCE_PATH_STYLE', 'true') not in ('true', 'false'):
        raise StartupError('invalid object storage path style')
    for left, right in (('VAULTCONTEXT_GOOGLE_CLIENT_ID', 'VAULTCONTEXT_GOOGLE_CLIENT_SECRET'),
                        ('VAULTCONTEXT_SUPERUSER_EMAIL', 'VAULTCONTEXT_SUPERUSER_PASSWORD')):
        if bool(os.environ.get(left)) != bool(os.environ.get(right)):
            raise StartupError(left + ' and ' + right + ' must be set together')
    if os.environ['VAULTCONTEXT_S3_BUCKET'].strip() == os.environ['LITESTREAM_BUCKET'].strip():
        raise StartupError('primary files and database replicas require separate buckets')
    if os.environ['VAULTCONTEXT_S3_ACCESS_KEY_ID'].strip() == os.environ['LITESTREAM_ACCESS_KEY_ID'].strip():
        raise StartupError('primary files and database replicas require separate credentials')
    for key, default in (('LITESTREAM_REGION', ''), ('LITESTREAM_ENDPOINT', ''),
                         ('LITESTREAM_SYNC_INTERVAL', '10s')):
        os.environ.setdefault(key, default)


def maintenance_state(data):
    marker = data / 'maintenance.json'
    try:
        info = marker.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 4096:
        raise StartupError('invalid maintenance state; startup stopped')
    try:
        state = json.loads(marker.read_text())
    except (ValueError, OSError):
        raise StartupError('invalid maintenance state; startup stopped') from None
    if (not isinstance(state, dict) or set(state) != {'readOnly', 'generation'}
            or type(state.get('readOnly')) is not bool
            or type(state.get('generation')) is not int
            or not 0 <= state['generation'] <= 18446744073709551615):
        raise StartupError('invalid maintenance state; startup stopped')
    return state['readOnly']


def database_connection(data):
    db = data / 'data.db'
    if db.is_symlink() or not db.is_file():
        raise StartupError('a regular database file is required')
    return sqlite3.connect(db.resolve().as_uri() + '?mode=ro', uri=True)


def identifier(value):
    if not isinstance(value, str) or not value or '\x00' in value:
        raise StartupError('invalid collection metadata')
    return '"' + value.replace('"', '""') + '"'


def path_part(value):
    if (not isinstance(value, str) or not value or value in ('.', '..')
            or '/' in value or '\\' in value or '\x00' in value):
        raise StartupError('unsafe original path')
    return value


def refs(data):
    """Inventory actual file fields, including avatars; ciphertext has a stored hash."""
    with closing(database_connection(data)) as conn:
        if conn.execute('PRAGMA quick_check').fetchone() != ('ok',):
            raise StartupError('database integrity check failed')
        collections = conn.execute('SELECT id,name,type,fields FROM _collections').fetchall()
        chunks = next((c for c in collections if c[1] == 'version_chunks' and c[2] == 'base'), None)
        if chunks is None:
            raise StartupError('database has no VaultContext ciphertext schema')
        result = {}
        for collection, table, kind, raw_fields in collections:
            if kind == 'view':
                continue  # Views refer to their underlying records, not independent objects.
            if kind not in ('base', 'auth'):
                raise StartupError('unsupported collection type')
            fields = json.loads(raw_fields)
            if not isinstance(fields, list) or any(not isinstance(f, dict) for f in fields):
                raise StartupError('invalid collection fields')
            for field in fields:
                if field.get('type') != 'file':
                    continue
                column = field.get('name')
                multiple = field.get('maxSelect', 1)
                if type(multiple) is not int or multiple < 1:
                    raise StartupError('invalid file cardinality')
                query = 'SELECT id,' + identifier(column) + ' FROM ' + identifier(table)
                for record, value in conn.execute(query):
                    if value is None or value == '':
                        continue
                    filenames = json.loads(value) if multiple > 1 else [value]
                    if not isinstance(filenames, list):
                        raise StartupError('invalid file reference list')
                    for filename in filenames:
                        key = '/'.join(path_part(v) for v in (collection, record, filename))
                        result[key] = None
        # Every ciphertext row must have exactly one valid immutable object and SHA-256.
        for record, filename, sha in conn.execute('SELECT id,ciphertext,sha256 FROM version_chunks'):
            key = '/'.join(path_part(v) for v in (chunks[0], record, filename))
            if key not in result:
                raise StartupError('ciphertext field missing from collection inventory')
            if not isinstance(sha, str) or len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha):
                raise StartupError('ciphertext has no valid checksum')
            result[key] = sha
        return result


def stored_storage_settings(data):
    with closing(database_connection(data)) as conn:
        row = conn.execute("SELECT value FROM _params WHERE id='settings'").fetchone()
    if not row:
        raise StartupError('missing persisted storage settings')
    try:
        settings = json.loads(row[0]).get('s3')
        if not isinstance(settings, dict):
            raise ValueError()
        return settings
    except (ValueError, AttributeError):
        raise StartupError('cannot determine persisted storage mode') from None


def verify_frozen_storage(data):
    if not maintenance_state(data):
        return
    desired = {field: os.environ.get('VAULTCONTEXT_S3_' + name, '').strip()
               for field, name in S3_FIELDS.items()}
    desired.update(enabled=True, forcePathStyle=os.environ.get('VAULTCONTEXT_S3_FORCE_PATH_STYLE', 'true') == 'true')
    current = stored_storage_settings(data)
    if any(current.get(field) != value for field, value in desired.items()):
        raise StartupError('frozen object storage configuration differs from stored settings; startup refused')


def verify_remote(data, client=None):
    config = {name: os.environ.get('VAULTCONTEXT_S3_' + name, '').strip() for name in S3_FIELDS.values()}
    if not all(config.values()):
        raise StartupError('incomplete object storage configuration')
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
        response = client.get_object(Bucket=config['BUCKET'], Key=name)
        with closing(response['Body']) as body:
            checksum = hashlib.sha256()
            received = 0
            for chunk in iter(lambda: body.read(1024 * 1024), b''):
                checksum.update(chunk)
                received += len(chunk)
        if 'ContentLength' in response and response['ContentLength'] != received:
            raise StartupError('incomplete remote original; startup refused')
        if expected is not None and checksum.hexdigest() != expected:
            raise StartupError('missing or corrupt remote original; startup refused')


def verify(data):
    verify_frozen_storage(data)
    verify_remote(data)


def app_flags(data):
    return ['--dir=' + str(data), '--migrationsDir=' + str(APP / 'pb_migrations'),
            '--hooksDir=' + str(APP / 'pb_hooks'), '--contextConfig=' + str(APP / 'pocketcontext.json')]


def run_command(args, env=None, timeout=None):
    """Forward termination during preparation; never expose child output/secrets."""
    child = subprocess.Popen(args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
    def interrupted(signum, frame):
        if child.poll() is None:
            os.killpg(child.pid, signum)
        raise SystemExit(128 + signum)
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        if child.wait(timeout=timeout) != 0:
            raise StartupError('startup command failed; refusing to serve')
    finally:
        try:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=45)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)


def restore_database(data, initialize=False):
    db = data / 'data.db'
    if db.exists() or db.is_symlink():
        if initialize:
            raise StartupError('init requires an empty database directory')
        if not db.is_file() or db.is_symlink():
            raise StartupError('a regular database file is required')
        log('database exists in the volume: no restore')
        return
    if any(data.iterdir()):
        raise StartupError('database missing but local state remains; operator recovery required')
    # A killed/failed restore cannot leave a database that a later start trusts.
    with tempfile.TemporaryDirectory(prefix='.vaultcontext-restore-', dir=data.parent) as temp:
        staged = Path(temp)
        command = [LITESTREAM, 'restore', '-config', CONFIG, '-o', str(staged / 'data.db'),
                   '-integrity-check', 'quick']
        if initialize:
            command.append('-if-replica-exists')
        command.append(str(db))
        try:
            run_command(command)
        except StartupError:
            raise StartupError('Litestream restore failed; check replica configuration and availability') from None
        if initialize:
            if (staged / 'data.db').exists():
                raise StartupError('init refused: replica already exists; use normal startup to restore it')
            return
        verify(staged)
        with (staged / 'data.db').open('rb') as restored:
            os.fsync(restored.fileno())
        os.replace(staged / 'data.db', db)
        sync_directory(data)
        log('database restored and remote originals verified')
        return True


def prepare(data, initialize=False):
    validate_config()
    frozen = maintenance_state(data)
    pending = data / 'initialization.pending'
    if pending.exists() or pending.is_symlink():
        raise StartupError('incomplete initialization; preserve this directory and recover into a fresh volume')
    if frozen and (initialize or not (data / 'data.db').is_file()):
        raise StartupError('frozen startup requires the existing database; initialization is forbidden')
    data.mkdir(parents=True, exist_ok=True)
    if initialize and any(data.iterdir()):
        raise StartupError('init requires an empty database directory')
    restored = False
    if not frozen:
        restored = restore_database(data, initialize)
    if initialize:
        # A failed/interrupted migrate or provisioning command must not turn into
        # an apparently healthy database on the next default startup.
        with pending.open('x') as marker:
            marker.write('Initialization must complete before normal startup.\n')
            marker.flush()
            os.fsync(marker.fileno())
        sync_directory(data)
        run_command([SERVER, 'migrate', 'up', *app_flags(data)])
    if frozen:
        auxiliary = data / 'auxiliary.db'
        if auxiliary.is_symlink() or not auxiliary.is_file():
            raise StartupError('frozen startup requires the existing auxiliary database')
        with closing(sqlite3.connect(auxiliary.resolve().as_uri() + '?mode=ro', uri=True)) as conn:
            if conn.execute('PRAGMA quick_check').fetchone() != ('ok',):
                raise StartupError('auxiliary database integrity check failed')
    if not restored:
        verify(data)
    if frozen:
        log('read-only maintenance state: skipping superuser provisioning')
    elif os.environ.get('VAULTCONTEXT_SUPERUSER_EMAIL'):
        run_command([SERVER, 'superuser', 'upsert', *app_flags(data), '--',
                     os.environ['VAULTCONTEXT_SUPERUSER_EMAIL'], os.environ['VAULTCONTEXT_SUPERUSER_PASSWORD']])
    if initialize:
        pending.unlink()
        sync_directory(data)
        log('database initialized; run normal startup on this volume to begin replication')


def serve():
    validate_config()
    try:
        run_command([LITESTREAM, 'sync', '-wait', '-timeout', '60', '-socket', SOCKET,
                     str(DATA / 'data.db')], timeout=65)
    except (StartupError, subprocess.TimeoutExpired):
        raise StartupError('initial replica synchronization failed; refusing to serve') from None
    log('initial replica synchronization complete')
    env = dict(os.environ)
    for key in ('LITESTREAM_ACCESS_KEY_ID', 'LITESTREAM_SECRET_ACCESS_KEY',
                'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
                'VAULTCONTEXT_SUPERUSER_PASSWORD'):
        env.pop(key, None)
    args = [SERVER, 'serve', '--http=0.0.0.0:80', *app_flags(DATA)]
    origin = env.get('BASE_URL', '').rstrip('/')
    if origin:
        args.append('--origins=' + origin)
    else:
        log('warning: BASE_URL is not set; email links and browser origins are not restricted to the public origin')
    log('starting server on port 80')
    os.execve(SERVER, args, env)


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('start', 'init', 'serve', 'verify'), nargs='?', default='start')
    args = parser.parse_args(argv)
    try:
        os.chdir(APP)
        if args.mode == 'serve':
            serve()
        elif args.mode == 'verify':
            validate_config()
            verify(DATA)
            log('database and remote originals verified')
        else:
            prepare(DATA, initialize=args.mode == 'init')
            if args.mode == 'start':
                log('starting Litestream, which starts and supervises the server')
                os.execve(LITESTREAM, [LITESTREAM, 'replicate', '-config', CONFIG,
                                      '-exec', SELF + ' serve'], dict(os.environ))
        return 0
    except StartupError as error:
        print('entrypoint: error: ' + str(error), file=sys.stderr)
    except Exception as error:
        # SDK/subprocess errors may contain credentials, URLs or application data.
        print('entrypoint: startup failed (' + type(error).__name__ + '); operator recovery required', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
