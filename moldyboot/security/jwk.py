import base64
import math

from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPrivateNumbers,
    RSAPublicKey,
    RSAPublicNumbers,
    rsa_crt_iqmp,
    rsa_crt_dmp1,
    rsa_crt_dmq1
)


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
    # JWK drops padding
    b += "=" * (len(b) % 4)
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


def load_private_key(data, backend) -> RSAPrivateKey:
    public_numbers = RSAPublicNumbers(e=b642i(data["e"]), n=b642i(data["n"]))
    p = b642i(data["p"])
    q = b642i(data["q"])
    d = b642i(data["d"])
    numbers = RSAPrivateNumbers(
        p, q, d,
        rsa_crt_dmp1(d, p),
        rsa_crt_dmq1(d, q),
        rsa_crt_iqmp(p, q),
        public_numbers
    )
    return numbers.private_key(backend)


def dump_private_key(key: RSAPrivateKey) -> dict:
    numbers = key.private_numbers()
    return {
        "p": i2b64(numbers.p),
        "q": i2b64(numbers.q),
        "d": i2b64(numbers.d),
        "e": i2b64(numbers.public_numbers.e),
        "n": i2b64(numbers.public_numbers.n),
    }
