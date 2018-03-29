import base64
import math


def i2b64(x: int) -> str:
    """Return the b64 encoding of the smallest number of bytes needed to represent the int"""
    length = math.ceil(x.bit_length() / 8)
    x_bytes = x.to_bytes(length, "big")
    b = base64.b64encode(x_bytes).decode("utf-8")
    return b.replace("+", "-").replace("/", "_")


def b642i(b: str) -> int:
    """Return the big-endian integer represented by the bas64-encoded string"""
    # fix url encoding
    b = b.replace("-", "+").replace("_", "/")
    # add missing padding
    b += "=" * (len(b) % 4)
    x_bytes = base64.b64decode(b.encode("utf-8"))
    return int.from_bytes(x_bytes, "big")
