"""Adversarial decrypted archive validation; fixtures never contain real secrets."""
import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'skills/vaultcontext/scripts'))
import vault_crypto as crypto

class ArchiveValidation(unittest.TestCase):
    def setUp(self):
        self.archive={'format':'vaultcontext-export-v1','files':[{'document':'d'*15,'version':'v'*15,'revision':1,'name':'../arbitrary filename','data':crypto.b64(b'\x00\xff')}]}
    def check_rejected(self,archive):
        with self.assertRaises((ValueError,TypeError)):
            crypto.parse_export(crypto.canonical(archive))
    def test_exact_roundtrip_metadata_inert(self):
        self.assertEqual(crypto.parse_export(crypto.canonical(self.archive)),self.archive)
    def test_unexpected_fields_not_displayed(self):
        self.archive['files'][0]['extra_secret']='must not display'
        self.check_rejected(self.archive)
    def test_duplicate_and_ambiguous_identity_rejected(self):
        self.archive['files'].append(copy.deepcopy(self.archive['files'][0]))
        self.check_rejected(self.archive)
    def test_missing_and_invalid_types(self):
        for field,value in [('document','../../escape'),('version',False),('revision',True),('revision',0),('name',{}),('data','%%%')]:
            with self.subTest(field=field,value=value):
                archive=copy.deepcopy(self.archive);archive['files'][0][field]=value
                self.check_rejected(archive)
    def test_oversized_file(self):
        self.archive['files'][0]['data']=crypto.b64(b'x'*(crypto.MAX_FILE_SIZE+1))
        self.check_rejected(self.archive)
    def test_wrong_format(self):
        self.archive['format']='other-format';self.check_rejected(self.archive)
if __name__=='__main__':unittest.main()
