from typing import Union

import arrow
import bloop
import uuid


from .common import AlreadyExists, NotFound, NotSaved, persist_unique
from .validation import validate
from ..models import User, UserName


class UserManager:
    def __init__(self, engine: bloop.Engine):
        self.engine = engine

    def new(self, username: str, email: str, password_hash: Union[str, bytes]) -> User:
        # 1) Validate username, email, password_hash
        username = validate("username", username)
        email = validate("email", email)
        password_hash = validate("password_hash", password_hash)
        # 2) Try to reserve username
        username = UserName(username=username, created=arrow.now())
        try:
            self.engine.save(username, condition=UserName.username.is_(None))
        except bloop.ConstraintViolation:
            raise AlreadyExists
        # 3) Try to create unique user_id
        user = User(password_hash=password_hash, email=email, verification_code=uuid.uuid4())
        persist_unique(user, self.engine, "user_id", uuid.uuid4)

        # 4) Store user_id on username
        try:
            username.user_id = user.user_id
            self.engine.save(username, atomic=True)
        except bloop.ConstraintViolation:
            # XXX username was modified during creation of user id.
            # XXX username and user_id may not sync, making login impossible.
            raise NotSaved(user)
        return user

    def get_user(self, user_id: Union[str, uuid.UUID]) -> User:
        user_id = validate("user_id", user_id)
        user = User(user_id=user_id)
        try:
            self.engine.load(user)
        except bloop.MissingObjects:
            raise NotFound
        return user

    def get_username(self, username: str) -> UserName:
        username = validate("username", username)
        username = UserName(username=username)
        try:
            self.engine.load(username)
        except bloop.MissingObjects:
            raise NotFound
        return username

    def get_username_by_user_id(self, user_id: Union[str, uuid.UUID]) -> UserName:  # pragma: no cover
        user_id = validate("user_id", user_id)
        query = self.engine.query(UserName.by_user_id)\
            .key(UserName.user_id == user_id)\
            .all(prefetch=0)
        first = next(query, None)
        if first is None:
            raise NotFound
        second = next(query, None)
        if second is not None:
            # TODO log duplicate id
            raise NotFound
        return first

    def delete_user(self, user_id: Union[str, uuid.UUID]) -> User:
        user_id = validate("user_id", user_id)
        user = User(user_id=user_id, deleted=True)
        try:
            self.engine.save(user, condition=User.user_id.is_not(None))
        except bloop.ConstraintViolation:
            raise NotSaved(user)
        return user

    def verify(self, user: User, verification_code: str):
        code = validate("verification_code", verification_code)
        current_code = getattr(user, "verification_code", None)
        # User already verified, nothing to do
        if current_code is None:
            return
        # Try to clear the verification code
        elif code == current_code:
            try:
                user.verification_code = None
                self.engine.save(user, atomic=True)
            except bloop.ConstraintViolation:
                raise NotSaved(user)
        # User has verification code, doesn't match the one we're trying to use
        else:
            raise NotSaved(user)
