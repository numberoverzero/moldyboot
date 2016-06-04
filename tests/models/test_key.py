from gaas.models import NotFound
from gaas.models.key import PublicKeyType, Key, KeyManager

import arrow
import base64
import bloop
import pytest
import uuid


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


def test_load_valid(crypto_pub, engine):
    user_id = uuid.uuid4()
    key_id = uuid.uuid4()
    key_manager = KeyManager(engine)

    def on_load(item, *args, **kwargs):
        item.until = arrow.now().replace(seconds=5)
    engine.on_load = on_load

    key = key_manager.load(user_id, key_id)

    # Verify load from dynamodb
    assert len(engine.captured_load_args) == 1
    item, _, kwargs = engine.captured_load_args[0]
    assert item is key
    assert kwargs["consistent"] is True

    # Verify conditional save (refresh) to dynamodb
    assert len(engine.captured_save_args) == 1
    item, args, kwargs = engine.captured_save_args[0]
    assert item is key
    condition = kwargs["condition"]
    # Condition should be against key.until against a very recent date (~now)
    assert condition.column is Key.until
    now = arrow.now()
    assert now.replace(seconds=-1) <= condition.value <= now.replace(seconds=1)
    # As a mutating operation against a public key, refresh should always be atomic
    assert kwargs["atomic"] is True


def test_load_expired(crypto_pub, engine):
    user_id = uuid.uuid4()
    key_id = uuid.uuid4()
    key_manager = KeyManager(engine)

    def on_load(item, *args, **kwargs):
        item.until = arrow.now().replace(seconds=-5)
    engine.on_load = on_load

    with pytest.raises(NotFound):
        key_manager.load(user_id, key_id)

    # Verify load from dynamodb
    assert len(engine.captured_load_args) == 1
    item, _, kwargs = engine.captured_load_args[0]
    assert item.user_id == user_id
    assert item.key_id == key_id
    assert kwargs["consistent"] is True

    # Verify atomic delete (revoke) from dynamodb
    assert len(engine.captured_delete_args) == 1
    item, _, kwargs = engine.captured_delete_args[0]
    assert item.user_id == user_id
    assert item.key_id == key_id
    assert kwargs["atomic"] is True


def test_load_missing(engine):
    user_id = uuid.uuid4()
    key_id = uuid.uuid4()
    key_manager = KeyManager(engine)

    def on_load(item, *args, **kwargs):
        raise bloop.NotModified("load", [item])
    engine.on_load = on_load

    with pytest.raises(NotFound):
        key_manager.load(user_id, key_id)

    # Verify load from dynamodb
    assert len(engine.captured_load_args) == 1
    item, _, kwargs = engine.captured_load_args[0]
    assert item.user_id == user_id
    assert item.key_id == key_id
    assert kwargs["consistent"] is True
