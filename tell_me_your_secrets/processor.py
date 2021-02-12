import logging
from typing import Optional, Tuple

from tell_me_your_secrets.logger import get_logger
from tell_me_your_secrets.utils import get_file_data

module_logger = get_logger()


class Processor:
    def __init__(self, signatures: list, whitelisted_strings: list, print_results: bool):
        self.signatures = signatures
        self.whitelisted_strings = whitelisted_strings
        self.print_results = print_results

    def process_file(self, possible_compromised_path: str) -> list:
        module_logger.debug(f'Opening File : {possible_compromised_path}')
        matched_signatures = []
        file_content = get_file_data(possible_compromised_path)
        if file_content is None:
            return matched_signatures
        # $ Run the Signature Checking Engine over here For different Pattern Signatures.
        signature_name, signature_part = self.run_signatures(possible_compromised_path, file_content)
        if signature_name is not None:
            matched_signatures.append(self.create_matched_signature_object(signature_name, signature_part,
                                                                           possible_compromised_path))
            if self.print_results:
                module_logger.info(f'Signature Matched : {signature_name} | On Part : {signature_part} | With '
                                   f'File : {possible_compromised_path}')
        return matched_signatures

    def run_signatures(self, file_path, content) -> Tuple[Optional[str], Optional[str]]:
        for signature in self.signatures:
            match_result = signature.match(file_path, content)
            if match_result.is_match:
                if match_result.matched_value in self.whitelisted_strings:
                    module_logger.debug(f'Signature {signature.name} matched {match_result.matched_value} but skipping'
                                        f' since it is whitelisted')
                    continue
                # $ Return the first signature Match.
                return signature.name, signature.part
        return None, None

    @staticmethod
    def create_matched_signature_object(name: str, part: str, file_path: str) -> dict:
        return {
            'name': name,
            'part': part,
            'path': file_path
        }
