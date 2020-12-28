import unittest
from typing import Optional

from tell_me_your_secrets.__main__ import (MatchResult, Signature,
                                           SignatureRecognizer)


class MockSignature(Signature):
    def match(self, file_path: str, file_content: str) -> MatchResult:
        return MatchResult(self.is_fail, self.matched_value or '')

    def __init__(self, is_fail: bool, matched_value: Optional[str] = None):
        super().__init__('file', 'Mock Signature', 'Mock Signature')
        self.is_fail = is_fail
        self.matched_value = matched_value


class RunSignaturesTest(unittest.TestCase):

    def test_run_signatures_matched(self):
        signature_recognizer = SignatureRecognizer({}, '.', False)
        signature_recognizer.signatures.append(MockSignature(True, 'matched-yada'))

        result = signature_recognizer.run_signatures('file/with/issues', 'dodgy-content')
        self.assertEquals('Mock Signature', result[0])
        self.assertEquals('file', result[1])

    def test_run_signatures_whitelisted(self):
        signature_recognizer = SignatureRecognizer({}, '.', False)
        signature_recognizer.whitelisted_strings.append('matched-yada')
        signature_recognizer.signatures.append(MockSignature(True, 'matched-yada'))

        result = signature_recognizer.run_signatures('file/with/issues', 'dodgy-content')
        self.assertIsNone(result[0])
        self.assertIsNone(result[1])
