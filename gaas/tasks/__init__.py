import boto3.session
import rq
# Local task imports are inside the scheduler and inject_dependencies functions
# to avoid circular dependencies when using the Scheduler as a type annotation in
# controllers

from ..controllers import InvalidParameter, NotFound, UserManager
from .. import templates

__all__ = ["AsyncEmail"]


class AsyncEmail:
    def __init__(self, queue: rq.Queue, user_manager: UserManager, session: boto3.session.Session, port: int):
        self.queue = queue
        self.user_manager = user_manager
        self.session = session
        self.port = port

    def send_verification(self, username: str):
        self.queue.enqueue(self._send_verification, username)

    def _send_verification(self, username: str):
        try:
            user = self.user_manager.load_by_name(username)
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
        verification_url = "http://localhost:{}/verify/{}/{}".format(self.port, user.user_id, user.verification_code)
        self.session.client("ses").send_email(
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
