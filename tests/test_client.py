import json
from importlib.metadata import distribution
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from vaultcontext_client import cli as vc

class ClientTests(unittest.TestCase):
    def test_native_peer_credentials(self):
        left, right = socket.socketpair()
        with left, right:
            self.assertEqual(vc.peer_uid_reader()(left), os.geteuid())

    def test_linux_peer_credentials(self):
        conn = Mock()
        conn.getsockopt.return_value = vc.struct.pack('3i', 123, 456, 789)
        with patch.object(sys, 'platform', 'linux'), patch.object(socket, 'SO_PEERCRED', 17, create=True):
            self.assertEqual(vc.peer_uid_reader()(conn), 456)
            conn.getsockopt.assert_called_once_with(socket.SOL_SOCKET, 17, 12)

    def test_darwin_credential_failure(self):
        libc = Mock()
        libc.getpeereid.return_value = -1
        with patch.object(sys, 'platform', 'darwin'), patch.object(vc.ctypes, 'CDLL', return_value=libc):
            with self.assertRaises(OSError):
                vc.peer_uid_reader()(Mock(fileno=lambda: 10))

    def test_unsupported_platform_fails_before_passphrase(self):
        with patch.object(sys, 'platform', 'unsupported'), patch.object(vc, 'prompt_passphrase') as prompt:
            with self.assertRaises(vc.auth.Fail):
                vc.unlock({}, 30)
            prompt.assert_not_called()

    def test_session_survives_rejected_peers(self):
        # First a credential lookup error, then a foreign UID, then native checks.
        native = vc.peer_uid_reader()
        attempts = 0
        def peer(conn):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise OSError('synthetic credential failure')
            if attempts == 2:
                return os.getuid() + 1
            return native(conn)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'session.sock'
            server = socket.socket(socket.AF_UNIX)
            server.bind(str(path))
            os.chmod(path, 0o600)
            server.listen(4)
            server.settimeout(.1)
            with patch.object(vc, 'socket_path', return_value=path), \
                 patch.object(vc, 'execute', return_value=[]):
                worker = threading.Thread(target=vc.session.serve, args=(
                    server, {}, vc.crypto.generate_identity(), 'synthetic',
                    time.monotonic() + 5), kwargs={'peer_uid': peer})
                worker.start()
                try:
                    for _ in range(2):
                        with self.assertRaises((OSError, ValueError)):
                            vc.session_call({}, {'command': 'vaults'})
                    self.assertEqual(vc.session_call({}, {'command': 'vaults'}), [])
                    self.assertEqual(vc.session_call({}, {'command': 'vaults'}), [])
                    self.assertEqual(vc.session_call({}, {'command': 'lock'}), {'locked': True})
                finally:
                    worker.join(6)
                    server.close()
                self.assertFalse(worker.is_alive())

    def test_session_serving_loop_expires(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = socket.socket(socket.AF_UNIX)
            with server:
                server.bind(str(Path(tmp) / 'expiry.sock'))
                server.listen(4)
                server.settimeout(.05)
                started = time.monotonic()
                vc.session.serve(server, {}, {}, 'synthetic', started + .15)
                self.assertGreaterEqual(time.monotonic() - started, .15)
                self.assertLess(time.monotonic() - started, 2)

    def test_query_objects_and_truncation(self):
        with patch.object(vc,'request',return_value={'columns':['id'],'rows':[{'id':'x'}]}):
            self.assertEqual(vc.query({},'SELECT id'),[{'id':'x'}])
        with patch.object(vc,'request',return_value={'columns':['id'],'rows':[{'id':'x'}],'truncated':True}):
            with self.assertRaises(vc.auth.Fail):vc.query({},'SELECT id')

    def test_archive_filters_retain_pagination(self):
        for command in ('list', 'search'):
            for flag, clause, archived in ((None, ' AND archived=0', False),
                                           ('archived', ' AND archived=1', True),
                                           ('all', '', False)):
                with self.subTest(command=command, flag=flag):
                    documents = [{'id': str(index), 'archived': archived} for index in range(51)]
                    queries = []
                    def query(cfg, sql):
                        queries.append(sql)
                        expected = "SELECT * FROM documents WHERE vault='vault'" + clause + ' ORDER BY id LIMIT 50 OFFSET '
                        self.assertTrue(sql.startswith(expected), sql)
                        offset = int(sql[len(expected):])
                        return documents[offset:offset + 50]
                    def version(cfg, identity, account, document, content):
                        self.assertFalse(content)
                        return None, {'name': 'MATCH-' + document, 'size': 1}, {'revision': 1}
                    values = dict(command=command, vault='vault', text='match')
                    if flag:
                        values[flag] = True
                    with patch.object(vc, 'query', side_effect=query), patch.object(vc, 'get_version', side_effect=version):
                        result = vc.execute({}, {}, 'owner', values)
                    self.assertEqual([row['id'] for row in result], [str(index) for index in range(51)])
                    self.assertTrue(all(row['archived'] is archived for row in result))
                    self.assertEqual(len(queries), 2)

    def test_archive_export_versions_are_explicit(self):
        entry = dict(document='d' * 15, version='v' * 15, revision=1, name='./synthetic/file', data='')
        def parse(version, record):
            return vc.crypto.parse_export(vc.encode({'format': version, 'files': [record]}).encode())
        self.assertEqual(parse('vaultcontext-export-v1', entry)['files'], [entry])
        for archived in (False, True):
            current = dict(entry, archived=archived)
            self.assertEqual(parse('vaultcontext-export-v2', current)['files'], [current])
            with self.assertRaises(ValueError):
                parse('vaultcontext-export-v1', current)
        for record in (entry, dict(entry, archived=1), dict(entry, archived='false')):
            with self.assertRaises(ValueError):
                parse('vaultcontext-export-v2', record)

    def test_noninteractive_passphrase_rejected(self):
        with patch.object(sys.stdin,'isatty',return_value=False):
            with self.assertRaises(vc.auth.Fail):vc.prompt_passphrase()

    def test_installed_cli_help(self):
        commands = {entry.name for entry in distribution('vaultcontext-client').entry_points
                    if entry.group == 'console_scripts'}
        self.assertEqual(commands, {'vaultcontext'})
        with tempfile.TemporaryDirectory() as temporary:
            command = Path(sys.executable).parent / 'vaultcontext'
            result = subprocess.run([str(command), '--help'], cwd=temporary,
                                    capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith('usage: vaultcontext '), result.stdout)
        self.assertIn('vaultcontext login --google', result.stdout)

    def test_cli_no_secret_argument(self):
        with self.assertRaises(SystemExit):vc.parser().parse_args(['unlock','--passphrase','secret'])
        args=vc.parser().parse_args(['login','--google','--port','9876'])
        self.assertEqual(args.port,9876)

    def test_session_regular_file_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'fake.sock';path.write_text('not a socket')
            with patch.object(vc,'socket_path',return_value=path):
                with self.assertRaises(vc.auth.Fail):vc.session_call({}, {'command':'lock'})

    def test_frame_limit(self):
        left,right=socket.socketpair()
        with left,right,patch.object(vc,'MAX_FRAME',8):
            left.sendall(b'123456789\n')
            with self.assertRaises(ValueError):vc.recv_frame(right)

    def test_pin_rejects_directory_substitution(self):
        identity=vc.crypto.generate_identity();pub=vc.crypto.public_identity(identity)
        row={'public_key':pub['enc_public'],'signing_key':pub['sign_public'],'fingerprint':vc.crypto.fingerprint(pub)}
        with patch.object(vc,'one',return_value=row),patch.object(vc,'pins',return_value={'alice':'old-fingerprint'}):
            with self.assertRaises(vc.auth.Fail):vc.verify_user({},'alice')

    def test_nonowner_envelope_refused_before_decryption(self):
        def fetch(cfg,table,where):
            return {'envelope':json.dumps({'signer':'editor','sealed':{}})} if table=='key_envelopes' else {'owner':'owner'}
        with patch.object(vc,'one',side_effect=fetch):
            with self.assertRaises(vc.auth.Fail):vc.vault_key({}, {},'recipient','vault',1)

    def test_manifest_substitution_rejected(self):
        identity=vc.crypto.generate_identity();pub=vc.crypto.public_identity(identity)
        context=vc.document_context('vault','different-doc','version',1)
        manifest={'context':context,'author':'owner','revision':1,'metadata':'unused','sha256':'unused'}
        version={'id':'version','document':'doc','vault':'vault','epoch':1,'author':'owner','revision':1,'manifest':vc.encode(manifest),'signature':vc.crypto.sign_manifest(identity,manifest)}
        def fetch(cfg,table,where):return {'id':'doc','vault':'vault','current_version':'version','revision':1} if table=='documents' else version
        with patch.object(vc,'one',side_effect=fetch),patch.object(vc,'vault_key',return_value=vc.crypto.new_vault_key()),patch.object(vc,'verify_user',return_value=pub):
            with self.assertRaises(vc.auth.Fail):vc.get_version({},identity,'owner','doc',content=False)

if __name__=='__main__':unittest.main()
