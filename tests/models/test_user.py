from gaas.models import AlreadyExists, NotSaved, NotFound
from gaas.models.validation import InvalidParameter
from gaas.models.user import UserName, User

import arrow
import bloop
import pytest
import uuid
from roughly import near, has_type


def test_user_is_verified():
    # If verification code is non-empty, it hasn't been visited yet.
    user = User(verification_code=uuid.uuid4())
    assert not user.is_verified

    user = User()
    assert not hasattr(user, "verification_code")
    assert user.is_verified

    user = User(verification_code=uuid.uuid4())
    del user.verification_code
    assert user.is_verified


def test_new_invalid_username(user_manager):
    username = "!abc"
    email = "a@b"
    password_hash = b"not-a-real-hash"

    with pytest.raises(InvalidParameter) as excinfo:
        user_manager.new(username, email, password_hash)
    assert excinfo.value.parameter_name == "username"
    user_manager.engine.assert_not_called()


def test_new_invalid_email(user_manager):
    username = "abc"
    email = "abc"
    password_hash = b"not-a-real-hash"

    with pytest.raises(InvalidParameter) as excinfo:
        user_manager.new(username, email, password_hash)
    assert excinfo.value.parameter_name == "email"
    user_manager.engine.assert_not_called()


# TODO test new invalid password hash

def test_new_username_exists(user_manager):
    username = "username"
    email = "email@domain.com"
    password_hash = b"not-a-real-hash"

    user_manager.engine.save.side_effect = bloop.ConstraintViolation("save", object())

    with pytest.raises(AlreadyExists):
        user_manager.new(username, email, password_hash)
    expected_username = UserName(username=username, created=near(arrow.now(), seconds=2))
    expected_condition = UserName.username.is_(None)
    user_manager.engine.save.assert_called_once_with(expected_username, condition=expected_condition)


def test_new_user_associate_fails(user_manager):

    user_manager.engine.save.side_effect = [None, None, bloop.ConstraintViolation("save", None)]

    username = "username"
    email = "email@domain.com"
    password_hash = b"not-a-real-hash"

    with pytest.raises(NotSaved):
        user_manager.new(username, email, password_hash)

    assert user_manager.engine.save.call_count == 3
    expected_user = User(
        password_hash=password_hash, email=email,
        verification_code=has_type(uuid.UUID), user_id=has_type(uuid.UUID))
    user_manager.engine.save.assert_any_call(expected_user, condition=User.user_id.is_(None))


def test_new_user_success(user_manager):
    """after UserName is created, a new user is created with a random user_id."""
    username = "username"
    email = "email@domain.com"
    password_hash = b"not-a-real-hash"

    returned_user = user_manager.new(username, email, password_hash)

    expected_username = UserName(username=username, created=near(arrow.now(), seconds=2), user_id=has_type(uuid.UUID))
    expected_user = User(
        password_hash=password_hash, email=email,
        verification_code=has_type(uuid.UUID),
        user_id=has_type(uuid.UUID))
    # username saved without user_id
    user_manager.engine.save.assert_any_call(expected_username, condition=UserName.username.is_(None))
    # intermediate call saves the User
    user_manager.engine.save.assert_any_call(expected_user, condition=User.user_id.is_(None))
    # last call updates the UserName with the User.user_id
    user_manager.engine.save.assert_called_with(expected_username, atomic=True)

    assert returned_user == expected_user


def test_load_invalid_user_id(user_manager):
    invalid_user_id = "not a uuid"

    with pytest.raises(InvalidParameter) as excinfo:
        user_manager.load_by_id(invalid_user_id)
    assert excinfo.value.parameter_name == "user_id"
    user_manager.engine.save.assert_not_called()


def test_load_unknown_user_id(user_manager):
    user_id = uuid.uuid4()
    expected_user = User(user_id=user_id)
    user_manager.engine.load.side_effect = bloop.NotModified("load", [expected_user])

    with pytest.raises(NotFound):
        user_manager.load_by_id(user_id)
    user_manager.engine.load.assert_called_once_with(expected_user)


def test_load_user_id_success(user_manager):
    user_id = uuid.uuid4()
    user = user_manager.load_by_id(user_id)
    assert user.user_id == user_id


# ==========================================

def test_load_invalid_username(user_manager):
    invalid_username = "0af"

    with pytest.raises(InvalidParameter) as excinfo:
        user_manager.load_by_name(invalid_username)
    assert excinfo.value.parameter_name == "username"
    user_manager.engine.load.assert_not_called()


def test_load_unknown_username(user_manager):
    username = "fooBar00"
    expected_username = UserName(username=username)
    user_manager.engine.load.side_effect = bloop.NotModified("load", [expected_username])

    with pytest.raises(NotFound):
        user_manager.load_by_name(username)
    user_manager.engine.load.assert_called_once_with(expected_username)


def test_load_username_success(user_manager):
    username = "fooBar00"
    user_id = uuid.uuid4()

    def load(obj, *args, **kwargs):
        if isinstance(obj, UserName):
            obj.user_id = user_id
    user_manager.engine.load.side_effect = load

    user = user_manager.load_by_name(username)
    assert user.user_id == user_id
    user_manager.engine.load.assert_any_call(UserName(username=username, user_id=user_id))
    user_manager.engine.load.assert_any_call(User(user_id=user_id))


def test_verify_constraint_violation(user_manager):
    user = User(user_id=uuid.uuid4())
    user_manager.engine.save.side_effect = bloop.ConstraintViolation("save", user)

    with pytest.raises(NotSaved) as excinfo:
        user_manager.verify(user)
    assert excinfo.value.obj is user
    user_manager.engine.save.assert_called_once_with(user, atomic=True)


def test_verify_success(user_manager):
    user = User(user_id=uuid.uuid4())

    user_manager.verify(user)
    user_manager.engine.save.assert_called_once_with(user, atomic=True)
    assert user.verification_code is None
