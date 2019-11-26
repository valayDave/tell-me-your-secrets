import yaml
import os
import abc
import pathlib # For Python 3.4.. TODO : Check for this. 
from .defaults import *
from .logger import create_logger,logging
import re
from pandas import DataFrame
import datetime
import argparse
import sys


module_description = '''
Sniff My Secrets

Finds presence of secret files from lots of know signatures for a given folder path. 

This module can be potentially be used to find secrets accross the Linux systems

'''
arguement_parser = argparse.ArgumentParser(description=module_description)
arguement_parser.formatter_class = argparse.RawDescriptionHelpFormatter
arguement_parser.add_argument('search_path',help='The Root Directory From which the Search for the Key/Pem files is initiated')
arguement_parser.add_argument('-c','--config',help='Path To Another config.yml for Extracting The Data')
arguement_parser.add_argument('-w','--write',help='Path of the csv File to which results are written')

module_logger = create_logger(MODULE_NAME,level=logging.INFO)

# Options
    # --path <PATH>: Checks Signatures in the Path.
    # --config <CONFIG_PATH>: path to config or default config.yml is used. 
    
# Process:
#   - Import Config.yml or Use the one From defaults. 
#   - Import the path if provided Or use Paths from the Defaults.: These Should be according to the OS(Can be in later Versions. Currently for Ubuntu)     
#   - Initialize the Signature Object from config.yml
    # - Path Signatures
    # - Content Signatures. 
#   - Extract FILTERED Files from the Path 
#   - Run the FILTERED Files through signatures. 


def find_extension(file_path):
    return pathlib.Path(file_path).suffix

def get_file_data(file_path):
    f = open(file_path,encoding = "ISO-8859-1")
    data = f.read()
    f.close()
    return data

class Signature(metaclass=abc.ABCMeta):
    def __init__(self,part,name,signature):
        self.part = part
        self.name = name
        self.signature = signature
    
    @abc.abstractmethod
    def match(self, file_path,file_content) -> bool:
        """Match Input of the With Signature of the part and Signature and Type of matching."""
        return


class RegexSignature(Signature):
    def __init__(self, part, name,signature):
        super().__init__(part, name,signature)
        self.regex = re.compile(self.signature)
          
    def match(self, file_path,file_content) -> bool:
        compare_variable = None
        if self.part == 'extension':
            compare_variable = find_extension(file_path)
        elif self.part == 'filename':
            compare_variable = file_path.split(os.path.sep)[-1]
        elif self.part == 'contents':
            compare_variable = file_content
        elif self.part == 'path':
            compare_variable = file_path
        else:
            module_logger.warn('Unrecognised File Part Access %s',self.name)
            return False

        return self.regex.search(compare_variable) != None
    
    def __str__(self):
        return self.name + ' : ' + self.part + ' : Regex : '+ self



class SimpleMatch(Signature):
    def __init__(self, part, name,signature):
        super().__init__(part, name,signature)

    def match(self, file_path,file_content) -> bool:
        compare_variable = None
        if self.part == 'extension':
            compare_variable = find_extension(file_path)
        elif self.part == 'filename':
            compare_variable = file_path.split(os.path.sep)[-1]
        elif self.part == 'contents':
            compare_variable = file_content
        elif self.part == 'path':
            compare_variable = file_path
        else:
            module_logger.warn('Unrecognised File Part Access %s',self.name)
        
        return compare_variable == self.signature


class SignatureRecognizer:
    def __init__(self,config_object,path,print_results=VERBOSE_OUTPUT,write_results=SAVE_ON_COMPLETE,output_path=DEFAULT_OUTPUT_PATH):
        self.config = config_object # todo: Fix this Later. 
        self.path = path
        self.blacklisted_extensions = config_object['blacklisted_extensions']
        self.blacklisted_paths = [path.format(sep=os.path.sep) for path in config_object['blacklisted_paths']]
        self.red_flag_extensions = config_object['red_flag_extensions']
        self.max_file_size = MAX_FILE_SIZE
        if 'max_file_size' in config_object:
            self.max_file_size = config_object['max_file_size']
        self.write_results = write_results
        self.print_results = print_results
        self.signatures = []
        self.matched_signatures = []
        self.output_path = output_path
        # $ Make Configuration Objects For each of the Signatures in the Config Object.
        self.load_config()
        module_logger.info('Secret Sniffer Initailsed For Path  : %s',path)

    # $ Create the signature objects over here. 
    def load_config(self):
        for signature_obj in self.config['signatures']:
            # $ Ignore Object if no Name/Part.
            if 'name' not in signature_obj or 'part' not in signature_obj:
                continue
            if 'match' in signature_obj:
                self.signatures.append(SimpleMatch(signature_obj['part'],signature_obj['name'],signature_obj['match']))
            elif 'regex' in signature_obj:
                self.signatures.append(RegexSignature(signature_obj['part'],signature_obj['name'],signature_obj['regex']))
            else:
                module_logger.warn('No Match Method Of Access %s',self.name)
    
    def create_matched_signature_object(self,name,part,file_path):
        return {
            'name': name,
            'part':part,
            'path':file_path
        }
    
    def find_vulnerable_files(self):
        # $ todo
        filtered_files = self.get_files(self.path)
        for possible_compromised_path in filtered_files:
            # module_logger.debug("Opening File : %s",possible_compromised_path)
            file_content = get_file_data(possible_compromised_path)
            # $ Run the Signature Checking Engine over here For different Pattern Signatures. 
            signature_name,signature_part = self.run_signatures(possible_compromised_path,file_content)
            if signature_name is not None:
                self.matched_signatures.append(self.create_matched_signature_object(signature_name,signature_part,possible_compromised_path))
                if self.print_results:
                    module_logger.info('Signature Matched : %s | On Part : %s | With File : %s',signature_name,signature_part,possible_compromised_path)

        module_logger.info("Found %d Matches from the Path %s",len(self.matched_signatures),self.path)
        if self.write_results:
            self.write_results_to_file()
    
    def write_results_to_file(self):
        if len(self.matched_signatures) > 0:
            write_df = DataFrame(self.matched_signatures)
            if '.csv' not in self.output_path:
                self.output_path+='.csv'
            file_name = self.output_path
            write_df.to_csv(file_name)
            module_logger.info('Completed Writing Results to File : %s',self.output_path)
            
    
    def run_signatures(self,file_path,content):
        for signature in self.signatures:
            match_result = signature.match(file_path,content)
            if match_result:
                # $ Return the first signature Match.
                return (signature.name,signature.part)
        return (None,None)
    
    # $ Marks the files needed to be skipped for 
    def check_skippable_file(self,file_path):
        file_name = file_path.split(os.path.sep)[-1]
        if len([extension for extension in self.red_flag_extensions if extension in file_name]):
            return False
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

    def check_accepted_path(self,dir_path):
        if len([matched_path for matched_path in self.blacklisted_paths if matched_path in dir_path]) > 0:
            return False
        return True

    def get_files(self,mypath):
        f = []
        for (dirpath, dirnames, filenames) in os.walk(mypath):
            # Todo : Over here the Engine Will Test for the Different Types and other things. 
            if not self.check_accepted_path(dirpath):
                continue
            adding_files = [os.path.abspath(os.path.join(dirpath,file)) for file in filenames if not self.check_skippable_file(os.path.abspath(os.path.join(dirpath,file)))]
            f.extend(adding_files)
        return f

    
def init_signature(config,path,write_path):
    # $ todo : Create the signature Object with the methods that
    if write_path is None:
        return SignatureRecognizer(config,path)
    else:
        return SignatureRecognizer(config,path,write_results=True,output_path=write_path)

# $ Gets all subpaths for the directory. 


def run_service():
    # $ todo : Import Config.yml or Use the one From defaults. 
    parsed_arguements = arguement_parser.parse_args()
    config_path = DEFAULT_CONFIG_PATH
    if parsed_arguements.config is not None:
        config_path = os.path.abspath(os.path.join(os.path.abspath(sys.path[0]),os.path.abspath(parsed_arguements.config)))

    search_path =  os.path.abspath(os.path.join(os.path.abspath(sys.path[0])))
    if parsed_arguements.search_path != '.':
        search_path =  os.path.abspath(os.path.join(os.path.abspath(sys.path[0]),os.path.abspath(parsed_arguements.search_path)))
    
    module_logger.debug('Running Config From Path : %s',config_path)
    f = open(config_path)
    config = yaml.load(f,Loader=yaml.FullLoader)
    f.close()
    
    write_path = None
    if parsed_arguements.write is not None:
        write_path = os.path.abspath(os.path.join(os.path.abspath(sys.path[0]),parsed_arguements.write))
    
    # $ todo : Extract FILTERED Files from the Path 
    sig_recognizer = init_signature(config,search_path,write_path)
    sig_recognizer.find_vulnerable_files()
    

if __name__ == '__main__':
    run_service()
# $ Move Signature.go and Match.go into this to make this work. 
