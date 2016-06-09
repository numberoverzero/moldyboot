import arrow
import bloop
import uuid
from bloop import Column, UUID, DateTime, String, ConstraintViolation, Binary
from . import BaseModel, NotFound, NotSaved, AlreadyExists, persist_unique
from .validation import validate


class UserName(BaseModel):
    class Meta:
        # TODO should be loaded from config
        table_name = "gaas-user-names"
        write_units = 1
        read_units = 1
    username = Column(String, hash_key=True, name="n")
    user_id = Column(UUID, name="u")
    created = Column(DateTime, name="c")


class User(BaseModel):
    class Meta:
        # TODO should be loaded from config
        table_name = "gaas-users"
        write_units = 1
        read_units = 1
    user_id = Column(UUID, hash_key=True, name="u")
    password_hash = Column(Binary, name="p")
    email = Column(String, name="e")
    verification_code = Column(UUID, name="v")

    @property
    def is_verified(self):
        # bloop doesn't set attrs when values are missing
        return getattr(self, "verification_code", None) is None


class UserManager:
    def __init__(self, engine: bloop.Engine):
        self.engine = engine

    def new_user(self, username: str, email: str, password_hash: str):
        # 1) Try to reserve username
        # 2) Try to create unique user_id
        # 3) Store user_id on username
        email = validate("email", email)
        username = validate("username", username)
        # TODO validate password_hash matches bcrypt format
        username = UserName(username=username, created=arrow.now())
        try:
            self.engine.save(username, condition=UserName.username.is_(None))
        except ConstraintViolation:
            raise AlreadyExists
        user = User(password_hash=password_hash, email=email, verification_code=uuid.uuid4())
        persist_unique(user, self.engine, "user_id", uuid.uuid4)

        try:
            username.user_id = user.user_id
            self.engine.save(username, atomic=True)
        except ConstraintViolation:
            # XXX username was modified during creation of user id.
            # XXX username and user_id may not sync, making login impossible.
            raise NotSaved(user)
        return user

    def load_by_id(self, user_id):
        user_id = validate("user_id", user_id)
        user = User(user_id=user_id)
        try:
            self.engine.load(user)
        except bloop.NotModified:
            raise NotFound
        return user

    def load_by_name(self, username):
        username = validate("username", username)
        username = UserName(username=username)
        try:
            self.engine.load(username)
        except bloop.NotModified:
            raise NotFound
        return self.load_by_id(username.user_id)

    def verify(self, user: User):
        user.verification_code = None
        try:
            self.engine.save(user, atomic=True)
        except ConstraintViolation:
            raise NotSaved(user)
