import tempfile
import unittest

from tell_me_your_secrets.__main__ import SignatureRecognizer
from tell_me_your_secrets.processor import SignatureMatch


class WriteResultsTest(unittest.TestCase):

    def test_write_results_to_file_no_issues(self):
        with tempfile.NamedTemporaryFile(suffix='.csv') as output_file:
            signature_recognizer = SignatureRecognizer({}, "", False, 1, write_results=True,
                                                       output_path=output_file.name)
            signature_recognizer.write_results_to_file()
            self.assertEqual(b"", output_file.read())

    def test_write_results_to_file_issues(self):
        with tempfile.NamedTemporaryFile(suffix='.csv') as output_file:
            signature_recognizer = SignatureRecognizer({}, "", False, 1, write_results=True,
                                                       output_path=output_file.name)
            signature_recognizer.matched_signatures = [
                SignatureMatch('Match', 'file', '/path/to/file')
            ]

            signature_recognizer.write_results_to_file()
            self.assertEqual(b',name,part,path\n0,Match,file,/path/to/file\n', output_file.read())
