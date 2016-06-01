from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256


class BadSignature(Exception):
    pass


def sign(method, uri, headers, body, headers_to_sign, private_key, key_id):
    """
    Return the headers that must be included in the request, including
    the Authorization header, which contains the computed signature.
    Most requested headers are populated if missing, such as x-content-sha-256.
    """
    method = method.lower()
    key = PKCS1_PSS.new(private_key)
    hash = SHA256.new()
    # TODO build string to hash
    return key.sign(hash)


def verify(method, uri, headers, body, headers_to_sign, public_key, signature):
    """
    Throws BadSignature with detailed info if any part of the signature
    verification fails.
    """
    method = method.lower()
    key = PKCS1_PSS.new(public_key)
    hash = SHA256.new()
    # TODO date within bounds
    # TODO body-sha-256 matches ("" for content-length 0)
    # TODO build string to hash
    if not key.verify(hash, signature):
        raise BadSignature("Signatures do not match.")
    return True
