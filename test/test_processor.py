import unittest
from typing import Optional

from tell_me_your_secrets.__main__ import MatchResult, Signature
from tell_me_your_secrets.processor import Processor


class MockSignature(Signature):
    def match(self, file_path: str, file_content: str) -> MatchResult:
        return MatchResult(self.is_fail, self.matched_value or '')

    def __init__(self, is_fail: bool, matched_value: Optional[str] = None):
        super().__init__('file', 'Mock Signature', 'Mock Signature')
        self.is_fail = is_fail
        self.matched_value = matched_value


class RunSignaturesTest(unittest.TestCase):

    def test_run_signatures_matched(self):
        signatures = [
            MockSignature(True, 'matched-yada')
        ]
        processor = Processor(signatures, [], False)

        results = processor.run_signatures('file/with/issues', 'dodgy-content')
        self.assertEqual(1, len(results))
        self.assertEqual('Mock Signature', results[0].name)
        self.assertEqual('file', results[0].part)
