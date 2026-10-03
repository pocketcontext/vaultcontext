#!/usr/bin/env python3
"""Recover a live synthetic database and original into a separate isolated server."""
import argparse
import importlib.util
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request

from integration import ROOT, server


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    backup = load('complete_backup', ROOT / 'docker/backup.py')
    smoke = load('container_smoke', ROOT / 'docker/smoke.py')
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='vaultcontext-recovery-') as tmp, server(binary) as request:
        root = Path(tmp)
        admin = smoke.superuser_token(request.base_url, 'admin@example.com', 'SyntheticAdminPassword123!')
        password = 'SyntheticRestorePassword123!'
        owner = smoke.provision_user(request.base_url, admin, 'owner@example.test', password)
        foreign = smoke.provision_user(request.base_url, admin, 'foreign@example.test', password)
        client = smoke.Client(request.base_url, 'owner@example.test', password, None)
        doc, meta = smoke.write_record(client, owner)
        backup.snapshot(request.data_dir, root / 'restored')
        backup.verify(root / 'restored')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        base = f'http://127.0.0.1:{port}'
        command = [binary, 'serve', '--dir=' + str(root / 'restored'), '--http=' + f'127.0.0.1:{port}',
                   '--hooksDir=' + str(ROOT / 'pb_hooks'), '--migrationsDir=' + str(ROOT / 'pb_migrations')]
        with open(root / 'restore.log', 'w+') as log:
            proc = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=log)
            try:
                for _ in range(150):
                    try:
                        with urllib.request.urlopen(base + '/up', timeout=1) as response:
                            if response.status == 200: break
                    except OSError:
                        if proc.poll() is not None:
                            raise AssertionError('restored server failed to start')
                        time.sleep(.1)
                else:
                    raise AssertionError('restored server startup timeout')
                restored = smoke.Client(base, 'owner@example.test', password, None)
                smoke.check_records(restored, doc, meta)
                other = smoke.Client(base, 'foreign@example.test', password, None)
                assert other.sql('SELECT id FROM documents') == []
                status, _, token = smoke.http('POST', base + '/api/files/token', {}, token=other.token)
                assert status == 200
                chunk = restored.sql("SELECT id, ciphertext FROM version_chunks ORDER BY id LIMIT 1")[0]
                status, _, _ = smoke.http('GET', base + '/api/files/version_chunks/' + chunk[0] + '/' + chunk[1] + '?token=' + token['token'])
                assert status in (400, 403, 404)
            finally:
                proc.terminate()
                proc.wait(timeout=15)
        next(path for path in (root / 'restored/storage').rglob('*') if path.is_file()).unlink()
        try:
            backup.verify(root / 'restored')
        except RuntimeError:
            pass
        else:
            raise AssertionError('missing original did not fail verification')
    print(f'PASS: live DB/original snapshot, separate server recovery, ownership and checksums ({time.monotonic()-started:.1f}s)')


if __name__ == '__main__':
    main()
