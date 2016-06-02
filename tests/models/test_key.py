from gaas.models import NotFound
from gaas.models.key import Key, PublicKeyType

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


def test_refresh(crypto_pub, mock_engine):
    user_id = uuid.uuid4()
    key_id = uuid.uuid4()
    key = Key(user_id=user_id, key_id=key_id, public=crypto_pub)

    called_save = 0

    def mock_save(item, *, condition=None, atomic=None):
        nonlocal called_save
        called_save += 1

        # Saving the key that's being refreshed
        assert item is key
        # Condition should be against key.until against a very recent date (~now)
        assert condition.column is Key.until
        now = arrow.now()
        assert now.replace(seconds=-1) <= condition.value <= now.replace(seconds=1)
        # As a mutating operation against a public key, refresh should always be atomic
        assert atomic is True
    mock_engine.save = mock_save

    key.refresh()
    assert called_save == 1


def test_load(mock_engine):
    user_id = uuid.uuid4()
    key_id = uuid.uuid4()

    called_load = 0

    def mock_load(item, *, consistent=None):
        nonlocal called_load
        called_load += 1
        assert item.user_id == user_id
        assert item.key_id == key_id
        assert consistent is True
    mock_engine.load = mock_load

    key = Key.load(user_id, key_id)
    assert key.user_id == user_id
    assert key.key_id == key_id
    assert called_load == 1


def test_load_missing(mock_engine):
    user_id = uuid.uuid4()
    key_id = uuid.uuid4()

    def mock_load(item, consistent=None):
        raise bloop.NotModified("load", [item])
    mock_engine.load = mock_load

    with pytest.raises(NotFound):
        Key.load(user_id, key_id)


def test_revoke(mock_engine):
    user_id = uuid.uuid4()
    key_id = uuid.uuid4()

    called_delete = 0

    def mock_delete(item, *, atomic=None):
        nonlocal called_delete
        called_delete += 1
        assert item.user_id == user_id
        assert item.key_id == key_id
        assert atomic is True
    mock_engine.delete = mock_delete

    Key(user_id=user_id, key_id=key_id).revoke()
    assert called_delete == 1
