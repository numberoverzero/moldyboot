import uuid

from moldyboot.models.user import User


def test_is_verified():
    # If verification code is non-empty, it hasn't been visited yet.
    user = User(verification_code=uuid.uuid4())
    assert not user.is_verified

    user = User()
    assert not hasattr(user, "verification_code")
    assert user.is_verified

    user = User(verification_code=uuid.uuid4())
    del user.verification_code
    assert user.is_verified
