from gaas.models.key import Key, PublicKeyType

import arrow
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256


def sign(private_key, data):
    """Returns b64 of signature"""
    hash = SHA256.new(data)
    padded = PKCS1_PSS.new(private_key)
    signature = padded.sign(hash)
    return base64.b64encode(signature)


def generate_key():
    """Returns private, public"""
    pair = RSA.generate(1024)
    return pair, pair.publickey()


def test_key_type():
    _, public = generate_key()
    serialized_public = base64.b64encode(public.exportKey(format="DER"))

    key_type = PublicKeyType()
    assert key_type.dynamo_dump(public) == serialized_public.decode("utf-8")
    assert key_type.dynamo_load(serialized_public) == public


def test_verify_success():
    private, public = generate_key()
    key = Key(public=public)

    data = b"Hello, World"
    signature = sign(private, data)
    assert key.verify(data, signature)


def test_expired():
    now = arrow.now()

    # key was valid until 5 seconds in the past
    key = Key(until=now.replace(seconds=-5))
    assert key.expired

    # key is valid until 5 seconds from now
    key = Key(until=now.replace(seconds=5))
    assert not key.expired
