import arrow
import base64

from gaas.models.key import Key, PublicKeyType


def test_key_type(rsa_pub):
    serialized_public = base64.b64encode(rsa_pub.exportKey(format="DER"))

    key_type = PublicKeyType()
    assert key_type.dynamo_dump(rsa_pub) == serialized_public.decode("utf-8")
    assert key_type.dynamo_load(serialized_public) == rsa_pub


def test_is_expired():
    now = arrow.now()

    # key was valid until 5 seconds in the past
    key = Key(until=now.replace(seconds=-5))
    assert key.is_expired

    # key is valid until 5 seconds from now
    key = Key(until=now.replace(seconds=5))
    assert not key.is_expired
