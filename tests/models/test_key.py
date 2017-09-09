import base64
import uuid

import pendulum
from tests.helpers import as_der

from moldyboot.models.key import Key, PublicKeyType


def test_eq(generate_key):
    key = Key(user_id=uuid.uuid4(), key_id=uuid.uuid4(), public=generate_key().public_key(), until=pendulum.now())
    other = Key(user_id=key.user_id, key_id=key.key_id, public=key.public, until=key.until)

    assert key != object()
    assert key == other
    # missing an attribute
    for attr in ["user_id", "key_id", "public", "until"]:
        delattr(other, attr)
        assert key != other
        # reset the attribute
        setattr(other, attr, getattr(key, attr))
    # public key mismatch
    other.public = generate_key().public_key()
    assert key != other


def test_key_type(rsa_pub):
    pub_bytes = as_der(rsa_pub)
    serialized_public = base64.b64encode(pub_bytes)

    key_type = PublicKeyType()
    assert key_type.dynamo_dump(rsa_pub) == serialized_public.decode("utf-8")
    loaded = key_type.dynamo_load(serialized_public)
    assert loaded.public_numbers() == rsa_pub.public_numbers()


def test_is_expired():
    now = pendulum.now()

    # key was valid until 5 seconds in the past
    key = Key(until=now.subtract(seconds=5))
    assert key.is_expired

    # key is valid until 5 seconds from now
    key = Key(until=now.add(seconds=5))
    assert not key.is_expired
