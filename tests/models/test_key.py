import arrow
import base64

from gaas.models.key import Key, PublicKeyType
from tests.helpers import as_der


def test_key_type(rsa_pub):
    pub_bytes = as_der(rsa_pub)
    serialized_public = base64.b64encode(pub_bytes)

    key_type = PublicKeyType()
    assert key_type.dynamo_dump(rsa_pub) == serialized_public.decode("utf-8")
    loaded = key_type.dynamo_load(serialized_public)
    assert loaded.public_numbers() == rsa_pub.public_numbers()


def test_is_expired():
    now = arrow.now()

    # key was valid until 5 seconds in the past
    key = Key(until=now.replace(seconds=-5))
    assert key.is_expired

    # key is valid until 5 seconds from now
    key = Key(until=now.replace(seconds=5))
    assert not key.is_expired
