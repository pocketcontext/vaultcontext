import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

from vaultcontext_client import cli as vc

class ClientTests(unittest.TestCase):
    def test_query_objects_and_truncation(self):
        with patch.object(vc,'request',return_value={'columns':['id'],'rows':[{'id':'x'}]}):
            self.assertEqual(vc.query({},'SELECT id'),[{'id':'x'}])
        with patch.object(vc,'request',return_value={'columns':['id'],'rows':[{'id':'x'}],'truncated':True}):
            with self.assertRaises(vc.auth.Fail):vc.query({},'SELECT id')

    def test_noninteractive_passphrase_rejected(self):
        with patch.object(sys.stdin,'isatty',return_value=False):
            with self.assertRaises(vc.auth.Fail):vc.prompt_passphrase()

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
