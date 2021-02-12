import logging

from tell_me_your_secrets import defaults


def setup_logger(level: int = logging.INFO):
    custom_logger = logging.getLogger(defaults.MODULE_NAME)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(formatter)
    custom_logger.addHandler(ch)
    custom_logger.setLevel(level)


def get_logger():
    return logging.getLogger(defaults.MODULE_NAME)
