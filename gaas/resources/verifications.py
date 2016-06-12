import falcon

from .meta import tag
from ..models import InvalidParameter, NotFound, NotSaved, UserManager


def fail(message):
    raise falcon.HTTPBadRequest("Bad Request", message)


class Verifications:
    def __init__(self, user_manager: UserManager):
        self.user_manager = user_manager

    # /verify/{user_id}/{verification_code}
    @tag("authentication-skip")
    def on_get(self, req: falcon.Request, resp: falcon.Response, user_id: str, verification_code: str):
        """Attempt to verify an account.

        200 if the verification code matches, or the account is already verified.
        400 if the user_id or verification_code is malformed, doesn't match, or user doesn't exist"""

        try:
            user = self.user_manager.load_by_id(user_id)
        except InvalidParameter as exception:
            fail("user_id must be a uuid but was '{}'".format(exception.value))
        except NotFound:
            fail("unknown user_id '{}'".format(user_id))

        try:
            self.user_manager.verify(user, verification_code)
        except InvalidParameter as exception:
            fail("verification_code must be a uuid but was '{}'".format(exception.value))
        except NotSaved:
            fail("verification code doesn't match")

        resp.status = falcon.HTTP_200
