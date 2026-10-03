"""Compile and reject invalid synthetic requests without invoking Keychain APIs."""
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == 'darwin', 'native helper requires macOS')
class NativeHelperRejectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='vc-native-helper-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.binary = Path(cls.directory.name) / 'helper'
        source = Path(__file__).resolve().parents[1] / 'native/macos/main.swift'
        subprocess.run(['/usr/bin/xcrun', 'swiftc', '-warnings-as-errors',
                        '-target', platform.machine() + '-apple-macosx12.0',
                        '-o', str(cls.binary), str(source)],
                       check=True, capture_output=True, timeout=180)

    def assert_rejected(self, args, payload):
        result = subprocess.run([str(self.binary), *args], input=payload,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout), {'ok': False, 'error': 'invalid_request'})
        self.assertEqual(result.stderr, b'')

    def test_missing_command(self):
        self.assert_rejected([], b'{}')

    def test_malformed_json(self):
        self.assert_rejected(['get'], b'not json')

    def test_missing_fields(self):
        self.assert_rejected(['store'], b'{}')

    def test_oversized_request(self):
        self.assert_rejected(['get'], b'x' * 65537)

    def test_secret_on_get(self):
        self.assert_rejected(['get'], json.dumps({
            'origin': 'https://example.test', 'account': 'synthetic',
            'passphrase': 'synthetic'}).encode())

    def test_oversized_passphrase(self):
        self.assert_rejected(['store'], json.dumps({
            'origin': 'https://example.test', 'account': 'synthetic',
            'passphrase': 'x' * 1025}).encode())

    def test_non_pipe_stdout(self):
        with tempfile.TemporaryFile() as output:
            result = subprocess.run([str(self.binary), 'get'], input=b'{}',
                                    stdout=output, stderr=subprocess.PIPE, timeout=10)
            output.seek(0)
            response = json.load(output)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(response, {'ok': False, 'error': 'invalid_request'})


if __name__ == '__main__':
    unittest.main()
