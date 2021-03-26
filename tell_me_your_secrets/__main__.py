import abc
import argparse
import logging
import multiprocessing
import os
import re
import sys
import time
from multiprocessing import Pool
from typing import List, Optional, Tuple

import yaml
from gitignore_parser import parse_gitignore
from pandas import DataFrame

import tell_me_your_secrets
from tell_me_your_secrets.defaults import (DEFAULT_CONFIG_PATH,
                                           DEFAULT_OUTPUT_PATH, MAX_FILE_SIZE,
                                           SAVE_ON_COMPLETE, VERBOSE_OUTPUT)
from tell_me_your_secrets.logger import get_logger, setup_logger
from tell_me_your_secrets.processor import Processor, SignatureMatch
from tell_me_your_secrets.utils import (col_print, find_extension,
                                        get_available_names)

config_names = col_print('Available Signatures : \n', get_available_names())

module_description = f'''
Tell Me Your Secrets

Finds presence of secret files from lots of know signatures for a given folder path.

This module can be potentially be used to find secrets across the Linux systems

{config_names}

To use only some of the available signatures use the -f option.

Examples usage :

tell-me-your-secrets <PATH_TO_FOLDER> -f aws microsoft crypto digitalocean ssh sql google

'''
argument_parser = argparse.ArgumentParser(
    prog='tell-me-your-secrets',
    description=module_description,
    formatter_class=argparse.RawDescriptionHelpFormatter
)
argument_parser.add_argument('search_path', help='The root path to search from')
argument_parser.add_argument('-c', '--config', help='Path to alternative config.yml')
argument_parser.add_argument('-w', '--write', help='Path of the CSV file to which results are written')
argument_parser.add_argument('-f', '--filter', help='Filter the signatures you want to apply. ', nargs='+')
argument_parser.add_argument('-v', '--verbose', help='Enable debug level logging. ', action='store_true')
argument_parser.add_argument('-e', '--exit', help='Exit non-zero on results found. ', action='store_true')
argument_parser.add_argument('-g', '--gitignore', help='Ignore .gitignore mapped objects. ', action='store_true')
argument_parser.add_argument('-p', '--processes', help='Number of processes to use. ', type=int, default=multiprocessing.cpu_count())
argument_parser.add_argument('--version', help='Print version information', action='version',
                             version=f'%(prog)s {tell_me_your_secrets.__version__}')
module_logger = get_logger()

# Process:
#   - Import Config.yml or Use the one From defaults.
#   - Import the path if provided Or use Paths from the Defaults.: These Should be according to the OS(Can be in later Versions. Currently for Ubuntu)
#   - Initialize the Signature Object from config.yml
#   - Path Signatures
#   - Content Signatures.
#   - Extract FILTERED Files from the Path
#   - Run the FILTERED Files through signatures.


class MatchResult:
    def __init__(self, result: bool, matched_value: Optional[str] = None):
        self.is_match = result
        self.matched_value = matched_value


class Signature(metaclass=abc.ABCMeta):
    def __init__(self, part: str, name: str, signature: str):
        self.part = part
        self.name = name
        self.signature = signature

    @abc.abstractmethod
    def match(self, file_path: str, file_content: str) -> MatchResult:
        """Match Input of the With Signature of the part and Signature and Type of matching."""
        raise NotImplementedError

    def __str__(self):
        return f'Type:{self.__class__} Name:{self.name} Part:{self.part}: Signature:{self.signature}'


class RegexSignature(Signature):
    def __init__(self, part: str, name: str, signature: str):
        super().__init__(part, name, signature)
        try:
            self.regex = re.compile(self.signature)
        except re.error as e:
            raise TypeError(f'Failed to compile regex for {self.name} `{self.signature}` - {e}')

    def match(self, file_path: str, file_content: str) -> MatchResult:
        if self.part == 'extension':
            compare_variable = find_extension(file_path)[1:]
        elif self.part == 'filename':
            compare_variable = file_path.split(os.path.sep)[-1]
        elif self.part == 'contents':
            compare_variable = file_content
        elif self.part == 'path':
            compare_variable = file_path
        else:
            module_logger.warning(f'Unrecognised File Part Access {self.name}')
            return MatchResult(False)
        match = self.regex.search(compare_variable)

        if not match:
            return MatchResult(False)
        return MatchResult(True, match.group(0))


class SimpleMatch(Signature):
    def __init__(self, part: str, name: str, signature: str):
        super().__init__(part, name, signature)

    def match(self, file_path: str, file_content: str) -> MatchResult:
        if self.part == 'extension':
            compare_variable = find_extension(file_path)
        elif self.part == 'filename':
            compare_variable = file_path.split(os.path.sep)[-1]
        elif self.part == 'contents':
            compare_variable = file_content
        elif self.part == 'path':
            compare_variable = file_path
        else:
            module_logger.warning(f'Unrecognised File Part Access {self.name}')
            return MatchResult(False)

        return MatchResult(compare_variable == self.signature, compare_variable)


class SignatureRecognizer:
    def __init__(self, config_object: dict, search_path: str, use_gitignore: bool, processes_count: int,
                 print_results=VERBOSE_OUTPUT, write_results=SAVE_ON_COMPLETE, output_path=DEFAULT_OUTPUT_PATH,
                 user_filters: Optional[list] = None):
        self.start_time = time.time()
        self.search_path = search_path
        self.use_gitignore = use_gitignore
        if use_gitignore:
            gitignore_file = os.path.join(search_path, '.gitignore')
            if os.path.exists(gitignore_file):
                module_logger.debug(f'Using gitignore file: {gitignore_file}')
                self.gitignore_matcher = parse_gitignore(gitignore_file)
            else:
                self.use_gitignore = False
        self.processes_count = processes_count
        self.blacklisted_extensions = config_object.get('blacklisted_extensions', [])
        self.blacklisted_paths = [path.format(sep=os.path.sep) for path in config_object.get('blacklisted_paths', [])]
        self.red_flag_extensions = config_object.get('red_flag_extensions', [])
        self.max_file_size = config_object.get('max_file_size', MAX_FILE_SIZE)
        self.whitelisted_strings = config_object.get('whitelisted_strings', [])
        self.write_results = write_results
        self.print_results = print_results
        self.matched_signatures: List[SignatureMatch] = []
        self.output_path = output_path
        # $ Make Configuration Objects For each of the Signatures in the Config Object.
        self.signatures: List[Signature] = self.load_signatures(config_object.get('signatures', {}), user_filters or [])
        module_logger.info(f'Secret Sniffer Initialised For Path: {search_path}')

    # $ Create the signature objects over here.
    @staticmethod
    def load_signatures(raw_signatures: dict, user_filters: list) -> list:
        chosen_configs = []
        parsed_signatures: List[Signature] = []
        for signature_obj in raw_signatures:
            # $ Ignore Object if no Name/Part.
            if 'name' not in signature_obj or 'part' not in signature_obj:
                module_logger.warn('Signature definition missing either name or part')
                continue
            if len(user_filters) > 0:
                if len([filtered_val for filtered_val in user_filters if str(filtered_val).lower() in str(signature_obj['name']).lower()]) == 0:
                    module_logger.warning(f'Duplicate named used defined filter matching skipping '
                                          f'adding {signature_obj["name"]} from config')
                    continue
            if 'match' in signature_obj:
                parsed_signatures.append(SimpleMatch(signature_obj['part'], signature_obj['name'], signature_obj['match']))
            elif 'regex' in signature_obj:
                parsed_signatures.append(RegexSignature(signature_obj['part'], signature_obj['name'], signature_obj['regex']))
            else:
                module_logger.warning('No Match Method Of Access')
            chosen_configs.append(signature_obj['name'] + " In File " + signature_obj['part'])

        if len(user_filters) > 0:
            module_logger.info('Applying Filtered Signatures : \n\n\t%s\n', '\n\t'.join(chosen_configs))

        return parsed_signatures

    def find_vulnerable_files(self):
        filtered_files = self.get_files(self.search_path)
        module_logger.debug(f"Finished filtering {len(filtered_files)} in {self._get_time()} seconds")

        self.process(filtered_files)

        module_logger.info(f'Processed {len(filtered_files)} files and found {len(self.matched_signatures)} matches '
                           f'from the search_path {self.search_path} in {self._get_time()} seconds')
        if self.write_results:
            self.write_results_to_file()

    def _get_time(self) -> float:
        return round(time.time() - self.start_time, 2)

    def process(self, filtered_files: List[str]):
        processor = Processor(self.signatures, self.whitelisted_strings, self.print_results)

        with Pool(processes=self.processes_count) as pool:
            results: List[List[SignatureMatch]] = pool.map(processor.process_file, filtered_files)
            for result in results:
                for match in result:
                    self.matched_signatures.append(match)

    def write_results_to_file(self):
        if len(self.matched_signatures) > 0:
            write_df = DataFrame(map(vars, self.matched_signatures))
            if '.csv' not in self.output_path:
                self.output_path += '.csv'
            file_name = self.output_path
            write_df.to_csv(file_name)
            module_logger.info(f'Completed Writing Results to File : {self.output_path}')

    # $ Marks the files needed to be skipped for
    def check_skippable_file(self, file_path: str) -> bool:
        file_name = file_path.split(os.path.sep)[-1]
        if len([extension for extension in self.red_flag_extensions if extension in file_name]):
            return False

        if self.gitignore_check(file_path):
            module_logger.debug(f'Skipping file {file_path} due to gitignored')
            return True

        # $ Check if if File is is in blacklisted extension
        elif len([extension for extension in self.blacklisted_extensions if extension in file_name]):
            return True

        # $ Check if if File is larger than max size
        try:
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                return True
            return False
        except:
            return False

    def gitignore_check(self, matcher: str) -> bool:
        return self.use_gitignore and self.gitignore_matcher(matcher)

    def is_ignored_path(self, dir_path: str) -> bool:
        if len([matched_path for matched_path in self.blacklisted_paths if matched_path in dir_path]) > 0:
            return True

        if self.gitignore_check(dir_path):
            module_logger.debug(f'Skipping path {dir_path} due to gitignored')
            return True

        return False

    def get_files(self, search_path: str) -> List[str]:
        """ Get the files that should be tested. """
        files = []
        for (dir_path, dir_names, filenames) in os.walk(search_path):
            not_ignored = []
            for dir_name in dir_names:
                if not self.is_ignored_path(os.path.join(dir_path, dir_name)):
                    not_ignored.append(dir_name)
            dir_names[:] = not_ignored

            adding_files = [os.path.abspath(os.path.join(dir_path, file)) for file in filenames if not self.check_skippable_file(os.path.abspath(os.path.join(dir_path, file)))]
            files.extend(adding_files)
        return files


def init_signature(config: dict, search_path: str, write_path: Optional[str], user_filters: list, use_gitignore: bool,
                   processes_count: int):
    if write_path:
        return SignatureRecognizer(config, search_path, use_gitignore, processes_count, write_results=True,
                                   output_path=write_path, user_filters=user_filters)

    return SignatureRecognizer(config, search_path, use_gitignore, processes_count, user_filters=user_filters)


def run_service() -> Tuple[bool, bool]:
    # $ todo : Import Config.yml or Use the one From defaults.
    parsed_arguments = argument_parser.parse_args()
    if parsed_arguments.verbose:
        setup_logger(logging.DEBUG)
    else:
        setup_logger(logging.INFO)

    module_logger.debug(f'Parsed arguments {parsed_arguments}')

    config_path = DEFAULT_CONFIG_PATH
    if parsed_arguments.config is not None:
        config_path = os.path.abspath(
            os.path.join(os.path.abspath(sys.path[0]), os.path.abspath(parsed_arguments.config)))

    search_path = os.path.abspath(
        os.path.join(os.path.abspath(sys.path[0]), os.path.abspath(parsed_arguments.search_path)))
    module_logger.debug(f'Running config from path: {config_path}')

    with open(config_path) as f:
        config = yaml.load(f, Loader=yaml.FullLoader)
    module_logger.debug(f'Config contents: \n{config}\n')

    write_path = None
    if parsed_arguments.write is not None:
        write_path = os.path.abspath(os.path.join(os.path.abspath(sys.path[0]), os.path.abspath(parsed_arguments.write)))
        module_logger.debug(f'Write path : {write_path}')

    user_filters = []
    if parsed_arguments.filter is not None:
        user_filters = parsed_arguments.filter

    use_gitignore = False
    if parsed_arguments.gitignore:
        use_gitignore = True

    process_count = parsed_arguments.processes

    sig_recognizer = init_signature(config, search_path, write_path, user_filters, use_gitignore, process_count)
    sig_recognizer.find_vulnerable_files()

    return len(sig_recognizer.matched_signatures) > 0, parsed_arguments.exit


if __name__ == '__main__':
    has_matches, exit_val = run_service()
    if has_matches and exit_val:
        exit(1)

    exit(0)
# $ Move Signature.go and Match.go into this to make this work.
