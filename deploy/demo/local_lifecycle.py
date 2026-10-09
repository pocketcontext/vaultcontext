#!/usr/bin/env python3
"""Concrete Linux loopback lifecycle for a synthetic local demo, never hosting."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from urllib.request import urlopen

from reset import ResetError, atomic_json, safe_path


def state(root):
    config = json.loads((root / 'control/local.json').read_text())
    if set(config) != {'binary', 'repo', 'port'} or type(config['port']) is not int or not 1024 <= config['port'] <= 65535:
        raise ResetError('invalid local lifecycle configuration')
    safe_path(config['binary'])
    safe_path(config['repo'])
    return config


def process_info(pid):
    try:
        parts = Path('/proc/' + str(pid) + '/stat').read_text().rsplit(')', 1)[1].split()
        return parts[0], parts[19]  # state and Linux process start ticks
    except (FileNotFoundError, IndexError):
        return None


def running(root):
    if (root / 'control/launch-pending.json').exists():
        raise ResetError('launch handoff is pending; refusing to infer process state')
    path = root / 'control/server.json'
    if not path.exists():
        return None
    record = json.loads(path.read_text())
    actual = process_info(record['pid'])
    if actual and actual[0] != 'Z':
        if actual[1] != record['start']:
            raise ResetError('PID identity changed; refusing to signal unrelated process')
        return record['pid']
    path.unlink()
    return None


def assert_port_free(config):
    # A missing/corrupt PID record is never proof that the listener is stopped.
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(('127.0.0.1', config['port']))
            probe.listen(1)
        except OSError:
            raise ResetError('unknown process owns the local demo port; refusing reset') from None


def local_environment():
    return {key:value for key,value in os.environ.items()
            if not key.startswith(('VAULTCONTEXT_S3_', 'LITESTREAM_', 'AWS_'))
            and key not in ('VAULTCONTEXT_GOOGLE_CLIENT_ID', 'VAULTCONTEXT_GOOGLE_CLIENT_SECRET',
                            'VAULTCONTEXT_SUPERUSER_EMAIL', 'VAULTCONTEXT_SUPERUSER_PASSWORD', 'VAULTCONTEXT_DATA_DIR')}


def stop(root):
    pid = running(root)
    if pid is None:
        assert_port_free(state(root))
        return
    os.killpg(pid, signal.SIGTERM)
    until = time.monotonic() + 20
    while time.monotonic() < until:
        if running(root) is None:
            assert_port_free(state(root))
            return
        time.sleep(.05)
    # No SIGKILL fallback: a failed graceful stop leaves the reset fenced.
    raise ResetError('local server did not stop')


def status(config):
    with urlopen('http://127.0.0.1:' + str(config['port']) + '/api/demo/status', timeout=1) as response:
        return json.load(response)


def start(root, config):
    if running(root) is not None:
        raise ResetError('local server already running')
    data = root / 'runtime/pb_data'
    data.mkdir(mode=0o700, parents=True, exist_ok=True)
    assert_port_free(config)
    # Child persists its own process identity BEFORE exec. If the parent crashes,
    # either no server executes or its durable identity already exists.
    atomic_json(root / 'control/launch-pending.json', {'generation':os.environ['VAULTCONTEXT_DEMO_GENERATION']})
    proc = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '_exec', '--root', str(root)],
                            cwd=config['repo'], env=local_environment(), stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    until = time.monotonic() + 30
    while time.monotonic() < until:
        if proc.poll() is not None:
            raise ResetError('local server failed to start')
        try:
            if status(config).get('generation') == os.environ['VAULTCONTEXT_DEMO_GENERATION']:
                return
        except Exception:
            pass
        time.sleep(.1)
    raise ResetError('local server did not become healthy')


def health(root, config):
    if running(root) is None or status(config).get('generation') != os.environ['VAULTCONTEXT_DEMO_GENERATION']:
        raise ResetError('local generation mismatch')
    dbpath = root / 'runtime/pb_data/data.db'
    db = sqlite3.connect(dbpath.as_uri() + '?mode=ro', uri=True)
    try:
        for table in ('users', 'vaults', 'documents', 'version_chunks', 'demo_enrollments'):
            if db.execute('SELECT COUNT(*) FROM "' + table + '"').fetchone()[0]:
                raise ResetError('fresh local demo contains visitor state')
    finally:
        db.close()


def configure(root, binary, repo, port):
    root = safe_path(Path(root).absolute())
    if root.name != 'vaultcontext-demo':
        raise ResetError('local root must be named vaultcontext-demo')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (root / 'control/local.json').exists():
        raise ResetError('local lifecycle already configured')
    (root / 'control').mkdir(mode=0o700, exist_ok=True)
    script = str(Path(__file__).resolve())
    atomic_json(root / 'control/local.json', {'binary': str(Path(binary).resolve()), 'repo': str(Path(repo).resolve()), 'port':port})
    config = {'deployment':'vaultcontext-demo', 'origin':'http://127.0.0.1:' + str(port),
              'root':str(root), 'storage':{'kind':'local'},
              'hooks':{name:[sys.executable,script,name] for name in ('fence','stop','assert_stopped','initialize','start','health','unfence')}}
    atomic_json(root / 'control/reset.json', config)


def exec_server(root, config):
    info = process_info(os.getpid())
    if not info:
        raise ResetError('cannot persist server process identity')
    if not (root / 'control/launch-pending.json').is_file():
        raise ResetError('missing durable launch intent')
    atomic_json(root / 'control/server.json', {'pid':os.getpid(), 'start':info[1]})
    (root / 'control/launch-pending.json').unlink()
    descriptor = os.open(root / 'control', os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    command = [config['binary'], '--dir=' + str(root / 'runtime/pb_data'), 'serve',
               '--http=127.0.0.1:' + str(config['port'])]
    os.chdir(config['repo'])
    os.execve(config['binary'], command, local_environment())


def action(root, name):
    root = safe_path(root)
    config = state(root)
    if name == '_exec':
        exec_server(root, config)
    elif name == 'fence':
        # Loopback-only fixture has no public ingress. Stop also closes its only listener.
        atomic_json(root / 'control/ingress-fenced.json', {'fenced':True})
        stop(root)
    elif name == 'stop':
        stop(root)
    elif name == 'assert_stopped':
        if running(root) is not None:
            raise ResetError('writer still running')
        assert_port_free(config)
    elif name == 'initialize':
        if (root / 'runtime/pb_data').exists():
            raise ResetError('local initialization requires an empty runtime')
        start(root, config)
        health(root, config)
        stop(root)
    elif name == 'start':
        if not (root / 'runtime/pb_data/data.db').is_file():
            raise ResetError('local database has not been initialized')
        start(root, config)
    elif name == 'health':
        health(root, config)
    elif name == 'unfence':
        health(root, config)
        (root / 'control/ingress-fenced.json').unlink(missing_ok=True)
    else:
        raise ResetError('unknown local lifecycle action')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['_exec','configure','fence','stop','assert_stopped','initialize','start','health','unfence'])
    parser.add_argument('--root', default=os.environ.get('VAULTCONTEXT_DEMO_RESET_ROOT'))
    parser.add_argument('--binary')
    parser.add_argument('--repo', default=str(Path(__file__).resolve().parents[2]))
    parser.add_argument('--port', type=int, default=8782)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.action == 'configure':
            configure(args.root, args.binary, args.repo, args.port)
        else:
            action(Path(args.root), args.action)
    except Exception:
        print('local demo lifecycle failed; inspect private configuration and fence', file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
