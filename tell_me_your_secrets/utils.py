import math
import pathlib

import yaml

from tell_me_your_secrets.defaults import COL_PRINT_WIDTH, DEFAULT_CONFIG_PATH


def get_available_names() -> list:
    """
    Get list of available names from default configuration.

    :return: List of names
    """
    names = []
    with open(DEFAULT_CONFIG_PATH) as f:
        config = yaml.load(f, Loader=yaml.FullLoader)

    for signature in config.get('signatures', []):
        name = signature.get('name')
        if name:
            names.append(name)

    return names


def col_print(title: str, array: list, term_width: int = COL_PRINT_WIDTH, pad_size: int = 1) -> str:
    indent = " " * 4
    pad = " " * pad_size
    title += "\n"

    if not array:
        return title + indent + "<None>"

    max_item_width = max(map(len, array))
    num_rows = int(math.ceil(len(array) / ((term_width + pad_size) // (max_item_width + pad_size))))

    return title + "\n".join(
        indent + pad.join(item.ljust(max_item_width) for item in array[index::num_rows]) for index in range(num_rows)
    )


def find_extension(file_path: str) -> str:
    return pathlib.Path(file_path).suffix


def get_file_data(file_path):
    try:
        f = open(file_path, encoding="ISO-8859-1")
        data = f.read()
        f.close()
        return data
    except:
        return None
