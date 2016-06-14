import arrow
import bloop
import uuid


from .common import AlreadyExists, persist_unique, NotSaved, NotFound
from .validation import validate
from ..models import User, UserName
from gaas.tasks import Scheduler


class UserManager:
    def __init__(self, engine: bloop.Engine, scheduler: Scheduler):
        self.engine = engine
        self.scheduler = scheduler

    def new(self, username: str, email: str, password_hash: str) -> User:
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

        # 5) Success!  Kick of an async email with the verification_code
        self.scheduler.send_verification_email(username.username)
        return user

    def load_by_id(self, user_id) -> User:
        user_id = validate("user_id", user_id)
        user = User(user_id=user_id)
        try:
            self.engine.load(user)
        except bloop.NotModified:
            raise NotFound
        return user

    def load_by_name(self, username) -> User:
        username = validate("username", username)
        username = UserName(username=username)
        try:
            self.engine.load(username)
        except bloop.NotModified:
            raise NotFound
        return self.load_by_id(username.user_id)

    def verify(self, user: User, verification_code: str) -> None:
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
