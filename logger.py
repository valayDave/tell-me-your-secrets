import logging

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(formatter)


def create_logger(logger_name:str,level=logging.INFO):
    custom_logger = logging.getLogger(logger_name)
    if level != logging.INFO:
        ch1 = logging.StreamHandler()
        ch1.setLevel(level)
        ch1.setFormatter(formatter)
        custom_logger.addHandler(ch1)
        custom_logger.setLevel(level)
    else:
        custom_logger.addHandler(ch)
        custom_logger.setLevel(level)
        
    return custom_logger