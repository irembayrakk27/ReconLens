import re
from product_normalizer import normalize_product

def parse_server_info(server_header):

    if not server_header:
        return {
            "product": None,
            "version": None
        }

    match = re.match(
        r"([A-Za-z0-9\-_]+)[/ _]?([\d\.]+)?",
        server_header
    )

    if match:

        product = normalize_product(match.group(1))

        version = match.group(2)

        return {
            "product": product,
            "version": version
        }

    return {
        "product": normalize_product(server_header),
        "version": None
    }