import unittest
from unittest.mock import patch

from tell_me_your_secrets.__main__ import SimpleMatch, RegexSignature


class RegexSignatureTest(unittest.TestCase):

    def test_extension_match(self):
        signature = RegexSignature('extension', 'Potential cryptographic private key', '^key(pair)?$')
        self.assertTrue(signature.match('/path/to/key.key', ''))
        self.assertTrue(signature.match('/path/to/key.keypair', ''))
        self.assertTrue(signature.match('/path/to/.key.keypair', ''))

    def test_extension_no_match(self):
        signature = RegexSignature('extension', 'Potential cryptographic private key', '^key(pair)?$')
        self.assertFalse(signature.match('/path/to/file.txt', ''))
        self.assertFalse(signature.match('/path/to/file', ''))
        self.assertFalse(signature.match('/path/to/.file', ''))
