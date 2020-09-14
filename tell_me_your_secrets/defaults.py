import os

MAX_FILE_SIZE = 3000 * 1000  # In Bytes == 3MB
VERBOSE_OUTPUT = True
SAVE_ON_COMPLETE = False
MODULE_NAME = 'Tell-Me-Your-Secrets'
DEFAULT_OUTPUT_PATH = 'Output/'
DEFAULT_CONFIG_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), 'config.yml'))
COL_PRINT_WIDTH = 170
