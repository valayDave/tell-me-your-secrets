import unittest
from unittest.mock import patch

from tell_me_your_secrets.__main__ import SimpleMatch


class SimpleMatchTest(unittest.TestCase):

    @patch('tell_me_your_secrets.__main__.find_extension')
    def test_simple_match_extension_match(self, mock_find_extension):
        mock_find_extension.return_value = '.pem'
        match = SimpleMatch('extension', 'Potential cryptographic private key', '.pem')
        self.assertTrue(match.match('/path/to/pem', ''))

    @patch('tell_me_your_secrets.__main__.find_extension')
    def test_simple_match_extension_no_match(self, mock_find_extension):
        mock_find_extension.return_value = '.jpg'
        match = SimpleMatch('extension', 'Potential cryptographic private key', '.pem')
        self.assertFalse(match.match('/path/to/no/pem', ''))
