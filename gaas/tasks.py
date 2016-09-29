import boto3.session
import rq
import urllib.parse

from .controllers import InvalidParameter, NotFound, UserManager
from . import templates

__all__ = ["AsyncTasks"]


class AsyncTasks:
    def __init__(self, queue: rq.Queue):
        self.queue = queue

    def send_verification(self, username: str):
        self.queue.enqueue(_send_verification, username)


class RedisContext:
    singleton = None
    """Have to set up the context from wherever the rq.Queue runs"""
    def __init__(self, user_manager: UserManager, session: boto3.session.Session, endpoint: urllib.parse.SplitResult):
        self.user_manager = user_manager
        self.session = session
        self.endpoint = endpoint

    @classmethod
    def initialize(cls, user_manager: UserManager, session: boto3.session.Session, endpoint: urllib.parse.SplitResult):
        if cls.singleton is not None:  # pragma: no cover
            raise ValueError("Tried to initialize redis context twice")
        cls.singleton = cls(user_manager=user_manager, session=session, endpoint=endpoint)


def _get_context() -> RedisContext:
    if RedisContext.singleton is None:
        raise ValueError("Tried to get redis context before it was initialized")
    return RedisContext.singleton


def _send_verification(username: str):
    ctx = _get_context()
    try:
        user = ctx.user_manager.load_by_name(username)
    except (InvalidParameter, NotFound):
        # TODO log failure
        # If it's InvalidParameter there's no sense raising, since retries will always fail.
        # If it's NotFound, either the username is unknown or the user id is unknown.
        #   Either way, the next call, at best, will find a user that is NOT the user we had in mind when calling
        #   this function.  Don't retry this exception, either.
        return

    # User is already verified, no need to send another email
    if getattr(user, "verification_code", None) is None:
        return

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
                    "Data": templates.render(
                        "verify-email.txt",
                        username=username,
                        verification_url=verification_url
                    ),
                    "Charset": "UTF-8"
                },
                "Html": {
                    "Data": templates.render(
                        "verify-email.html",
                        username=username,
                        verification_url=verification_url
                    ),
                    "Charset": "UTF-8"
                }
            }
        },
        ReplyToAddresses=[support],
        ReturnPath=support_bounce
    )
