import math
import pathlib # For Python 3.4.. TODO : Check for this. 

def col_print(title, array, term_width=150, pad_size=1):
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
        f = open(file_path,encoding = "ISO-8859-1")
        data = f.read()
        f.close()
        return data
    except:
        return None
