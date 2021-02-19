from typing import List

from tell_me_your_secrets.logger import get_logger
from tell_me_your_secrets.utils import get_file_data

module_logger = get_logger()


class SignatureMatch:
    name: str
    part: str
    path: str

    def __init__(self, name: str, part: str, path: str):
        self.name = name
        self.part = part
        self.path = path


class Processor:
    def __init__(self, signatures: list, whitelisted_strings: list, print_results: bool):
        self.signatures = signatures
        self.whitelisted_strings = whitelisted_strings
        self.print_results = print_results

    def process_file(self, possible_compromised_path: str) -> List[SignatureMatch]:
        module_logger.debug(f'Opening File : {possible_compromised_path}')
        file_content = get_file_data(possible_compromised_path)
        if file_content is None:
            return []

        matched_signatures = self.run_signatures(possible_compromised_path, file_content)
        return matched_signatures

    def run_signatures(self, file_path, content) -> List[SignatureMatch]:
        matches: List[SignatureMatch] = []
        for signature in self.signatures:
            match_result = signature.match(file_path, content)
            if not match_result.is_match:
                continue

            if match_result.matched_value in self.whitelisted_strings:
                module_logger.debug(f'Signature {signature.name} matched {match_result.matched_value} but skipping'
                                    f' since it is whitelisted')
                continue

            if self.print_results:
                module_logger.info(f'Signature Matched : {signature.name} | On Part : {signature.part} | With '
                                   f'File : {file_path}')

            matches.append(SignatureMatch(signature.name, signature.part, file_path))

        return matches
