import arrow
import bloop
import pytest
import uuid

from roughly import has_type, near

from gaas.controllers import InvalidParameter, NotFound, NotSaved
from gaas.models import Key


def test_new_invalid_user_id(rsa_pub, key_manager):
    user_id = "not a uuid"

    with pytest.raises(InvalidParameter) as excinfo:
        key_manager.new(user_id, rsa_pub)
    assert excinfo.value.parameter_name == "user_id"
    key_manager.engine.assert_not_called()


def test_new_invalid_public_key(key_manager):
    user_id = uuid.uuid4()
    public = "not an rsa public key"
    with pytest.raises(InvalidParameter) as excinfo:
        key_manager.new(user_id, public)
    assert excinfo.value.parameter_name == "public_key"
    key_manager.engine.assert_not_called()


def test_new_unique_fails(rsa_pub, key_manager):
    user_id = uuid.uuid4()
    public = rsa_pub.exportKey("PEM").decode("utf-8")

    roughly_one_hour = near(arrow.now().replace(hours=1), seconds=5)
    expected_key = Key(user_id=user_id, public=rsa_pub, until=roughly_one_hour, key_id=has_type(uuid.UUID))
    expected_condition = Key.user_id.is_(None) & Key.key_id.is_(None)
    key_manager.engine.save.side_effect = bloop.ConstraintViolation("save", expected_key)

    with pytest.raises(NotSaved) as excinfo:
        key_manager.new(user_id, public)
    assert excinfo.value.obj == expected_key

    key_manager.engine.save.assert_any_call(expected_key, condition=expected_condition)


def test_new_success(rsa_pub, key_manager):
    user_id = uuid.uuid4()
    public = rsa_pub.exportKey("PEM").decode("utf-8")

    key_manager.new(user_id, public)

    roughly_one_hour = near(arrow.now().replace(hours=1), seconds=5)
    expected_key = Key(user_id=user_id, public=rsa_pub, until=roughly_one_hour, key_id=has_type(uuid.UUID))
    expected_condition = Key.user_id.is_(None) & Key.key_id.is_(None)
    key_manager.engine.save.assert_called_once_with(expected_key, condition=expected_condition)


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
