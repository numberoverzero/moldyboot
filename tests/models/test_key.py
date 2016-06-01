from gaas.models.key import Key, PublicKeyType

import arrow
import base64


def test_key_type(crypto_pair):
    _, public = crypto_pair
    serialized_public = base64.b64encode(public.exportKey(format="DER"))

    key_type = PublicKeyType()
    assert key_type.dynamo_dump(public) == serialized_public.decode("utf-8")
    assert key_type.dynamo_load(serialized_public) == public


def test_expired():
    now = arrow.now()

    # key was valid until 5 seconds in the past
    key = Key(until=now.replace(seconds=-5))
    assert key.expired

    # key is valid until 5 seconds from now
    key = Key(until=now.replace(seconds=5))
    assert not key.expired
