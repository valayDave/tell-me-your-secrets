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

    def test_filename_match(self):
        signature = RegexSignature('filename', 'git-credential-store helper credentials file', '^\.?git-credentials$')
        self.assertTrue(signature.match('/path/to/.git-credentials', ''))
        self.assertTrue(signature.match('/path/to/git-credentials', ''))

    def test_filename_no_match(self):
        signature = RegexSignature('filename', 'git-credential-store helper credentials file', '^\.?git-credentials$')
        self.assertFalse(signature.match('/path/to/git-credentials-1', ''))
        self.assertFalse(signature.match('/path/to/.git', ''))

    def test_contents_match(self):
        signature = RegexSignature('contents', 'Contains a private ke',
                                   '-----BEGIN (EC|RSA|DSA|OPENSSH) PRIVATE KEY----')
        self.assertTrue(signature.match('/path/to/key', '''
        -----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgF0VVPpf0Z/xx2Z4tj9SZCE7fF9d9VquC2F6zCyJH4/6EqbR/tWg
IVhXJJRYzQui05AC4dZUB/6MJdLUpC/x3MaAl4N3CH1AHz1I82OQUuM1fA2xakM8
LuP12mcaK2pXZ+Q/1VatGmYzP52CxWD1M+XsdfUE/es0M5eU/vOZ1dhXAgMBAAEC
gYAB45bv5dXpOwzi5Xw9WLyzd/OUM+Hwzytn9QgDt1yunVKXlBdp2nASzOHvKMYw
gENu3sAai2YGIm36E1qppmzmjBIRSKvgPJKj0o+RsimtKuodW4iyLn/vJTmggyBb
AdQYp358oHItd6LkmhawPiv+JidDdj+aR7dtd6qXI8Y9UQJBAK36oSMTq9VqEGmc
D6CBJOZjFbWaVFQmvqldCTsBDywX7FyOD5JAlqfgWzXziJ2jWH2uyElITDo/qEE5
sRQAK+UCQQCI93l52CfybkQfvzfi2fTcIcU8ecGit180eS7C5WwSdl8i9mmSa1fb
X/upu3QWE2C/u7Mt1qBDJugv9TmZM8eLAkA3YxLpl9mcl6eh940CDBszPVgr+HXg
VHVedb/6iNvLrdIRpShP50APMd3XzzAu/1GssXgR3HJoGNv35+X3+BYBAkBLHRT0
elOmA0y+8FoQwaEkXCzTtp43w0Kl/1NitPjowxv3i5VoJBBBkcjtU40dUjE71Q81
sz+etCafrmeRGjFzAkAbSUeDF9K9SO1XyPc5G3WXzaYmOkhGs7il+H8jGKlEizBd
PiZodLoJ21/7Ph35BYzS43dtL7IrLAP/TarvYbeg
-----END RSA PRIVATE KEY-----
        '''))

    def test_contents_no_match(self):
        signature = RegexSignature('contents', 'Contains a private ke',
                                   '-----BEGIN (EC|RSA|DSA|OPENSSH) PRIVATE KEY----')
        self.assertFalse(signature.match('/path/to/key', '-----BEGIN PRIVATE KEY-----'))
        self.assertFalse(signature.match('/path/to/.git', ''))

    def test_path_match(self):
        signature = RegexSignature('path', 'GitHub Hub command-line client configuration file', 'config/hub$')
        self.assertTrue(signature.match('/path/to/config/hub', ''))

    def test_path_no_match(self):
        signature = RegexSignature('path', 'GitHub Hub command-line client configuration file', 'config/hub$')
        self.assertFalse(signature.match('/path/to/config/hub/more', ''))
        self.assertFalse(signature.match('/path/to/confi/hub', ''))

    def test_invalid(self):
        signature = RegexSignature('random', 'Random', '')
        self.assertFalse(signature.match('', ''))

