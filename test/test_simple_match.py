import unittest
from unittest.mock import patch

from tell_me_your_secrets.__main__ import SimpleMatch


class SimpleMatchTest(unittest.TestCase):

    @patch('tell_me_your_secrets.__main__.find_extension')
    def test_match_extension_match(self, mock_find_extension):
        mock_find_extension.return_value = '.pem'
        simple_match = SimpleMatch('extension', 'Potential cryptographic private key', '.pem')
        self.assertTrue(simple_match.match('/path/to/pem', '').is_match)

    @patch('tell_me_your_secrets.__main__.find_extension')
    def test_match_extension_no_match(self, mock_find_extension):
        mock_find_extension.return_value = '.jpg'
        simple_match = SimpleMatch('extension', 'Potential cryptographic private key', '.pem')
        self.assertFalse(simple_match.match('/path/to/no/pem', '').is_match)

    def test_match_filename_match(self):
        simple_match = SimpleMatch('filename', 'Ruby On Rails secret token configuration file', 'secret_token.rb')
        self.assertTrue(simple_match.match('/path/to/secret_token.rb', '').is_match)

    def test_match_filename_no_match(self):
        simple_match = SimpleMatch('filename', 'Ruby On Rails secret token configuration file', 'secret_token.rb')
        self.assertFalse(simple_match.match('/path/to/non_secret_token.rb', '').is_match)

    def test_match_contents_match(self):
        simple_match = SimpleMatch('contents', 'Sample content match', 'abcdef')
        self.assertTrue(simple_match.match('/path/to/file', 'abcdef').is_match)

    def test_match_contents_no_match(self):
        simple_match = SimpleMatch('contents', 'Sample content match', 'abcdef')
        self.assertFalse(simple_match.match('/path/to/file', 'xyz').is_match)

    def test_match_path_match(self):
        simple_match = SimpleMatch('path', 'Sample path match', '/path/to/secret')
        self.assertTrue(simple_match.match('/path/to/secret', '').is_match)

    def test_match_path_no_match(self):
        simple_match = SimpleMatch('path', 'Sample path match', '/path/to/secret')
        self.assertFalse(simple_match.match('/path/to/no_secret', '').is_match)

    def test_match_str(self):
        simple_match = SimpleMatch('Part', 'Name ', 'Sig')
        self.assertEqual("Type:<class 'tell_me_your_secrets.__main__.SimpleMatch'> Name:Name  Part:Part: Signature:Sig",
                         str(simple_match))

    def test_invalid(self):
        simple_match = SimpleMatch('unmapped', 'something ', '')
        self.assertFalse(simple_match.match('', '').is_match)
