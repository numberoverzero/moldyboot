import boto3.session
import rq
import urllib.parse

from .controllers import InvalidParameter, KeyManager, NotFound, NotSaved, UserManager
from . import templates

__all__ = ["AsyncTasks"]


class Result:
    empty = None

    def __init__(self, *, value, error):
        self._value = value
        self._error = error

    @property
    def value(self):
        if self._error:
            raise self._error
        return self._value

    @classmethod
    def of(cls, value):
        return cls(value=value, error=False)

    @classmethod
    def failed(cls, error_cls: Exception=RuntimeError):
        return cls(value=None, error=error_cls)


Result.empty = Result.of(None)


class AsyncTasks:
    def __init__(self, queue: rq.Queue):
        self.queue = queue

    def send_verification(self, username: str):
        return self.queue.enqueue(_send_verification, username)

    def delete_user(self, username: str):
        return self.queue.enqueue(_delete_user, username)


class RedisContext:
    singleton = None
    """Have to set up the context from wherever the rq.Queue runs"""
    def __init__(
            self,
            user_manager: UserManager,
            key_manager: KeyManager,
            session: boto3.session.Session,
            endpoint: urllib.parse.SplitResult):
        self.user_manager = user_manager
        self.key_manager = key_manager
        self.session = session
        self.endpoint = endpoint

    @classmethod
    def initialize(
            cls,
            user_manager: UserManager,
            key_manager: KeyManager,
            session: boto3.session.Session,
            endpoint: urllib.parse.SplitResult):
        if cls.singleton is not None:
            raise RuntimeError("Tried to initialize redis context twice")
        cls.singleton = cls(user_manager=user_manager, key_manager=key_manager, session=session, endpoint=endpoint)


def _get_context() -> RedisContext:
    if RedisContext.singleton is None:
        raise RuntimeError("Tried to get redis context before it was initialized")
    return RedisContext.singleton


def _send_verification(username: str):
    ctx = _get_context()
    try:
        username = ctx.user_manager.get_username(username)
        user = ctx.user_manager.get_user(username.user_id)
    except InvalidParameter as e:
        return Result.failed(e)
    except NotFound:
        # TODO log failure
        # If it's InvalidParameter there's no sense raising, since retries will always fail.
        # If it's NotFound, either the username is unknown or the user id is unknown.
        #   Either way, the next call, at best, will find a user that is NOT the user we had in mind when calling
        #   this function.  Don't retry this exception, either.
        return Result.failed(RuntimeError("Unknown username {!r}".format(username)))

    # User is already verified, no need to send another email
    if getattr(user, "verification_code", None) is None:
        return Result.empty

    # TODO use config
    support = "gaas-support@moldyboot.com"
    support_bounce = "gaas-support+bounce@moldyboot.com"
    verification_url = "{}/verify/{}/{}".format(ctx.endpoint.geturl(), user.user_id, user.verification_code)
    ctx.session.client("ses").send_email(
        Source=support,
        Destination={"ToAddresses": [user.email]},
        Message={
            "Subject": {"Data": "Please verify your email", "Charset": "UTF-8"},
            "Body": {
                "Text": {
                    "Data": templates.render("verify-email.txt", {
                        "username": username.username,
                        "verification_url": verification_url
                    }),
                    "Charset": "UTF-8"
                },
                "Html": {
                    "Data": templates.render("verify-email.html", {
                        "username": username.username,
                        "verification_url": verification_url
                    }),
                    "Charset": "UTF-8"
                }
            }
        },
        ReplyToAddresses=[support],
        ReturnPath=support_bounce
    )
    return Result.empty


def _delete_user(username: str):
    ctx = _get_context()
    users = ctx.user_manager
    keys = ctx.key_manager

    # 0) username -> UserName -> user id
    try:
        user_id = users.get_username(username).user_id
    except InvalidParameter as e:
        return Result.failed(e)
    except NotFound:
        # TODO log failure
        # Not worth retrying, since the user doesn't exist
        return Result.failed(RuntimeError("Unknown username {!r}".format(username)))

    # 1) Tombstone the User, preventing system-side actions
    try:
        users.delete_user(user_id)
    except NotSaved:
        # TODO log failure
        # Don't keep going, something's wrong.
        return Result.failed(RuntimeError("Unknown user id {!r}".format(user_id)))

    # 2) Revoke all user Keys, preventing api access.
    #    Ignore errors and delete as many as we can.
    for key in keys.list_keys(user_id):
        try:
            keys.revoke(key, force=True)
        except NotSaved:
            # TODO log failure
            continue

    return Result.of({"username": username, "user_id": user_id})
