import unittest

from tell_me_your_secrets.__main__ import get_entropy


class EntropyTest(unittest.TestCase):
    def test_get_entropy_empty(self):
        self.assertEqual(0, get_entropy(''))

    def test_get_entropy(self):
        self.assertEqual(3.6792292966721747, get_entropy('4fded1464736e77865df232cbcb4cd19'))
