from gaas.models import AlreadyExists, NotSaved
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
        user_manager.new_user(username, email, password_hash)
    assert excinfo.value.parameter_name == "username"
    user_manager.engine.assert_not_called()


def test_new_invalid_email(user_manager):
    username = "abc"
    email = "abc"
    password_hash = b"not-a-real-hash"

    with pytest.raises(InvalidParameter) as excinfo:
        user_manager.new_user(username, email, password_hash)
    assert excinfo.value.parameter_name == "email"
    user_manager.engine.assert_not_called()


# TODO test new invalid password hash

def test_new_username_exists(user_manager):
    username = "username"
    email = "email@domain.com"
    password_hash = b"not-a-real-hash"

    user_manager.engine.save.side_effect = bloop.ConstraintViolation("save", object())

    with pytest.raises(AlreadyExists):
        user_manager.new_user(username, email, password_hash)
    expected_username = UserName(username=username, created=near(arrow.now(), seconds=2))
    expected_condition = UserName.username.is_(None)
    user_manager.engine.save.assert_called_once_with(expected_username, condition=expected_condition)


def test_new_user_associate_fails(user_manager):

    def save(obj, *args, **kwargs):
        # only catch the second UserName save
        if isinstance(obj, User):
            return
        # UserName won't have a user_id on the first call
        if not hasattr(obj, "user_id"):
            return
        # fail the second save
        raise bloop.ConstraintViolation("save", obj)
    user_manager.engine.save.side_effect = save

    username = "username"
    email = "email@domain.com"
    password_hash = b"not-a-real-hash"

    with pytest.raises(NotSaved):
        user_manager.new_user(username, email, password_hash)

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

    returned_user = user_manager.new_user(username, email, password_hash)

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
