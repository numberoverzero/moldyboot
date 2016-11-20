import base64
import math

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers


def i2b64(x: int) -> str:
    """Return the b64 encoding of the smallest number of bytes needed to represent the int"""
    length = math.ceil(x.bit_length() / 8)
    x_bytes = x.to_bytes(length, "big")
    return base64.b64encode(x_bytes).decode("utf-8")


def b642i(b: str) -> int:
    """Return the big-endian integer represented by the bas64-encoded string"""
    x_bytes = base64.b64decode(b.encode("utf-8"))
    return int.from_bytes(x_bytes, "big")


def load_public_key(data, backend) -> RSAPublicKey:
    numbers = RSAPublicNumbers(e=b642i(data["e"]), n=b642i(data["n"]))
    return numbers.public_key(backend=backend)


def dump_public_key(key: RSAPublicKey) -> dict:
    numbers = key.public_numbers()
    return {
        "e": i2b64(numbers.e),
        "n": i2b64(numbers.n)
    }
