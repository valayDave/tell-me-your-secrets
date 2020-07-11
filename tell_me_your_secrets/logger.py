import logging


def create_logger(logger_name: str, level: int = logging.INFO):
    custom_logger = logging.getLogger(logger_name)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(formatter)
    custom_logger.addHandler(ch)
    custom_logger.setLevel(level)
        
    return custom_logger
