from gaas.models import NotFound
from gaas.models.key import PublicKeyType, Key

import arrow
import base64
import bloop
import pytest
import uuid
from roughly import near


def test_key_type(rsa_pub):
    serialized_public = base64.b64encode(rsa_pub.exportKey(format="DER"))

    key_type = PublicKeyType()
    assert key_type.dynamo_dump(rsa_pub) == serialized_public.decode("utf-8")
    assert key_type.dynamo_load(serialized_public) == rsa_pub


def test_expired():
    now = arrow.now()

    # key was valid until 5 seconds in the past
    key = Key(until=now.replace(seconds=-5))
    assert key.expired

    # key is valid until 5 seconds from now
    key = Key(until=now.replace(seconds=5))
    assert not key.expired


def test_load_valid(key_manager):
    user_id = uuid.uuid4()
    key_id = uuid.uuid4()

    # Patch engine to return a key with expiry > now
    def load(item, *args, **kwargs):
        item.until = arrow.now().replace(seconds=5)
    key_manager.engine.load.side_effect = load

    key = key_manager.load(user_id, key_id)

    # Consistent load, followed by atomic save (refresh)
    # roughly.near lets us use exact matches (assert called) with approximate times
    expected_condition = Key.until >= near(arrow.now(), seconds=5)
    key_manager.engine.load.assert_called_once_with(key, consistent=True)
    key_manager.engine.save.assert_called_once_with(key, atomic=True, condition=expected_condition)


def test_load_expired(key_manager):
    user_id = uuid.uuid4()
    key_id = uuid.uuid4()

    # Patch engine to return a key with expiry < now
    def load(item, *args, **kwargs):
        item.until = arrow.now().replace(seconds=-2)
    key_manager.engine.load.side_effect = load

    with pytest.raises(NotFound):
        key_manager.load(user_id, key_id)

    # Consistent load, followed by atomic delete (revoke)
    expired_key = Key(user_id=user_id, key_id=key_id, until=near(arrow.now(), seconds=3))
    key_manager.engine.load.assert_called_once_with(expired_key, consistent=True)
    key_manager.engine.delete.assert_called_once_with(expired_key, atomic=True)


def test_load_missing(key_manager):
    user_id = uuid.uuid4()
    key_id = uuid.uuid4()

    def load(item, *args, **kwargs):
        raise bloop.NotModified("load", [item])
    key_manager.engine.load.side_effect = load

    with pytest.raises(NotFound):
        key_manager.load(user_id, key_id)
    key_manager.engine.load.assert_called_once_with(Key(user_id=user_id, key_id=key_id), consistent=True)
