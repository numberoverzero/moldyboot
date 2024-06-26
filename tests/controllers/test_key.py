import uuid

import bloop
import pytest
from tests.helpers import as_der

from moldyboot.controllers import InvalidParameter, NotFound, NotSaved
from moldyboot.models import Key


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


def test_new_unique_fails(rsa_pub, key_manager, fixed_now, fixed_uuid):
    public = as_der(rsa_pub)

    expected_key = Key(user_id=fixed_uuid, public=rsa_pub, until=fixed_now.add(hours=1))
    expected_condition = Key.user_id.is_(None) & Key.key_id.is_(None)
    key_manager.engine.save.side_effect = bloop.ConstraintViolation("save", expected_key)

    with pytest.raises(NotSaved) as excinfo:
        key_manager.new(fixed_uuid, public)
    # All fields except key_id are the fixed values
    actual_key = excinfo.value.obj
    assert actual_key.user_id == expected_key.user_id
    assert actual_key.until == expected_key.until
    assert actual_key.public.public_numbers() == expected_key.public.public_numbers()

    key_manager.engine.save.assert_any_call(actual_key, condition=expected_condition)


def test_new_success(rsa_pub, key_manager, fixed_now, fixed_uuid):
    user_id = uuid.uuid4()
    public = as_der(rsa_pub)

    key_manager.new(user_id, public)

    expected_key = Key(user_id=user_id, public=rsa_pub, until=fixed_now.add(hours=1), key_id=fixed_uuid)
    expected_condition = Key.user_id.is_(None) & Key.key_id.is_(None)
    key_manager.engine.save.assert_called_once_with(expected_key, condition=expected_condition)


def test_get_valid(key_manager, fixed_now):
    user_id = uuid.uuid4()
    key_id = uuid.uuid4()

    # Patch engine to return a key with expiry > now
    def load(item, *args, **kwargs):
        item.until = fixed_now.add(seconds=5)
    key_manager.engine.load.side_effect = load

    key = key_manager.get_key(user_id, key_id)

    # Consistent load, followed by atomic save (refresh)
    expected_condition = Key.until >= fixed_now
    key_manager.engine.load.assert_called_once_with(key, consistent=True)
    key_manager.engine.save.assert_called_once_with(key, atomic=True, condition=expected_condition)


def test_get_expired(key_manager, fixed_now):
    user_id = uuid.uuid4()
    key_id = uuid.uuid4()

    # Patch engine to return a key with expiry < now
    def load(item, *args, **kwargs):
        item.until = fixed_now.subtract(seconds=2)
    key_manager.engine.load.side_effect = load

    with pytest.raises(NotFound):
        key_manager.get_key(user_id, key_id)

    # Consistent load, followed by atomic delete (revoke)
    expired_key = Key(user_id=user_id, key_id=key_id, until=fixed_now.subtract(seconds=2), seconds=3)
    key_manager.engine.load.assert_called_once_with(expired_key, consistent=True)
    key_manager.engine.delete.assert_called_once_with(expired_key, atomic=True)


def test_get_missing(key_manager):
    user_id = uuid.uuid4()
    key_id = uuid.uuid4()

    def load(item, *args, **kwargs):
        raise bloop.MissingObjects(objects=[item])
    key_manager.engine.load.side_effect = load

    with pytest.raises(NotFound):
        key_manager.get_key(user_id, key_id)
    key_manager.engine.load.assert_called_once_with(Key(user_id=user_id, key_id=key_id), consistent=True)


def test_revoke(key_manager):
    key = Key(user_id=uuid.uuid4(), key_id=uuid.uuid4())
    key_manager.engine.delete.side_effect = bloop.ConstraintViolation("delete", key)

    with pytest.raises(NotSaved) as excinfo:
        key_manager.revoke(key)
    assert excinfo.value.obj is key
    key_manager.engine.delete.assert_called_once_with(key, atomic=True)


def test_revoke_force(key_manager):
    key = Key(user_id=uuid.uuid4(), key_id=uuid.uuid4())
    key_manager.engine.delete.side_effect = bloop.ConstraintViolation("delete", key)

    with pytest.raises(NotSaved) as excinfo:
        key_manager.revoke(key, force=True)
    assert excinfo.value.obj is key
    key_manager.engine.delete.assert_called_once_with(key, atomic=False)
