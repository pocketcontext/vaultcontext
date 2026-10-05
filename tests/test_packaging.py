"""Exercise startup fail-closed and environment isolation without Docker."""
import os
from pathlib import Path
import subprocess
import sys
import shlex
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class EntrypointTests(unittest.TestCase):
    def run_entrypoint(self, values, restore_status=0):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app, data, bins = (root / name for name in ('app', 'data', 'bin'))
            for path in (app, data, bins):
                path.mkdir()
            calls = root / 'calls'
            server = bins / 'pocketcontext'
            server.write_text('''#!/bin/sh
printf '%s\\n' "$1" >> "$TEST_CALLS"
if [ "$1" = serve ]; then
  test -z "${LITESTREAM_ACCESS_KEY_ID:-}" || exit 91
  test -z "${LITESTREAM_SECRET_ACCESS_KEY:-}" || exit 92
  test -z "${AWS_ACCESS_KEY_ID:-}" || exit 93
  test -z "${AWS_SECRET_ACCESS_KEY:-}" || exit 94
  test -z "${VAULTCONTEXT_SUPERUSER_PASSWORD:-}" || exit 95
fi
''')
            server.chmod(0o755)
            litestream = bins / 'litestream'
            litestream.write_text('''#!/bin/sh
printf 'litestream %s\\n' "$1" >> "$TEST_CALLS"
if [ "$1" = restore ]; then exit "$RESTORE_STATUS"; fi
if [ "$1" = sync ]; then exit 0; fi
while [ "$#" -gt 0 ]; do
  if [ "$1" = -exec ]; then shift; exec sh -c "$1"; fi
  shift
done
exit 96
''')
            litestream.chmod(0o755)
            python = bins / 'python3'
            python.write_text("#!/bin/sh\nif [ \"$1\" = - ]; then exec " + shlex.quote(sys.executable) + " \"$@\"; fi\nprintf 'backup %s\\n' \"$2\" >> \"$TEST_CALLS\"\nif [ \"$2\" = supervise ]; then shift 2; exec \"$@\"; fi\n")
            python.chmod(0o755)
            entrypoint = root / 'entrypoint.sh'
            script = (ROOT / 'docker/entrypoint.sh').read_text()
            script = script.replace('APP_DIR=/app', f'APP_DIR={app}').replace('DATA_DIR=/storage/pb_data', f'DATA_DIR={data}')
            script = script.replace('SERVER=/usr/local/bin/pocketcontext', f'SERVER={server}').replace('SELF=/usr/local/bin/entrypoint.sh', f'SELF={entrypoint}')
            entrypoint.write_text(script)
            entrypoint.chmod(0o755)
            environment = {'PATH': str(bins) + ':/usr/bin:/bin', 'TEST_CALLS': str(calls), 'RESTORE_STATUS': str(restore_status), **values}
            result = subprocess.run([str(entrypoint)], env=environment, capture_output=True, text=True, timeout=10)
            return result, calls.read_text().splitlines() if calls.exists() else []

    def test_no_implicit_replication_disable(self):
        for settings in ({}, {'LITESTREAM_DISABLED': '1'}):
            result, calls = self.run_entrypoint(settings)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(calls, [])
            self.assertIn('LITESTREAM_BUCKET', result.stderr)

    def test_restore_failure_never_initializes_database(self):
        result, calls = self.run_entrypoint({
            'LITESTREAM_BUCKET': 'synthetic', 'LITESTREAM_PATH': 'isolated',
            'LITESTREAM_ACCESS_KEY_ID': 'secret-id', 'LITESTREAM_SECRET_ACCESS_KEY': 'secret-key',
            'VAULTCONTEXT_SUPERUSER_EMAIL': 'test@example.test', 'VAULTCONTEXT_SUPERUSER_PASSWORD': 'private-password',
        }, restore_status=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, ['backup restore', 'litestream restore'])
        self.assertNotIn('private-password', result.stdout + result.stderr)
        self.assertNotIn('secret-key', result.stdout + result.stderr)

    def test_server_child_does_not_receive_replica_or_operator_secrets(self):
        result, calls = self.run_entrypoint({
            'BASE_URL': 'https://vault.example.test', 'LITESTREAM_BUCKET': 'synthetic', 'LITESTREAM_PATH': 'isolated',
            'LITESTREAM_ACCESS_KEY_ID': 'secret-id', 'LITESTREAM_SECRET_ACCESS_KEY': 'secret-key',
            'AWS_ACCESS_KEY_ID': 'aws-id', 'AWS_SECRET_ACCESS_KEY': 'aws-secret',
            'VAULTCONTEXT_SUPERUSER_EMAIL': 'test@example.test', 'VAULTCONTEXT_SUPERUSER_PASSWORD': 'private-password',
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ['backup restore', 'litestream restore', 'backup verify', 'superuser', 'migrate', 'backup supervise', 'litestream replicate', 'litestream sync', 'serve'])

    def test_google_pair_required_before_restore(self):
        for values in ({'VAULTCONTEXT_GOOGLE_CLIENT_ID': 'test'}, {'VAULTCONTEXT_GOOGLE_CLIENT_SECRET': 'secret'}):
            result, calls = self.run_entrypoint(values)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(calls, [])

    def test_disabled_replication_is_explicit(self):
        result, calls = self.run_entrypoint({'LITESTREAM_DISABLED': 'true'})
        self.assertEqual(result.returncode, 0)
        self.assertEqual(calls, ['backup verify', 'serve'])


if __name__ == '__main__':
    unittest.main()
