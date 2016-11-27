import falcon

from .meta import tag
from ..security import passwords
from ..controllers import AlreadyExists, UserManager
from ..tasks import AsyncTasks


class Signup:
    def __init__(self, user_manager: UserManager, async_tasks: AsyncTasks):
        self.user_manager = user_manager
        self.async_tasks = async_tasks

    @tag("authentication-skip")
    def on_post(self, req: falcon.Request, resp: falcon.Response):
        """User logged in with username/password, persist the provided public key and return its id"""
        body = req.context["body"].json
        try:
            username = body["username"]
        except KeyError:
            raise falcon.HTTPBadRequest("Missing required parameter", "Must provide a username")
        try:
            password = body["password"]
        except KeyError:
            raise falcon.HTTPBadRequest("Missing required parameter", "Must provide a password")
        try:
            email = body["email"]
        except KeyError:
            raise falcon.HTTPBadRequest("Missing required parameter", "Must provide an email")

        hashed = passwords.hash(password=password, rounds=passwords.DEFAULT_SALT_ROUNDS)

        try:
            user = self.user_manager.new(username, email, hashed)
        except AlreadyExists:
            raise falcon.HTTPBadRequest("Invalid parameter", "Username {!r} is taken".format(username))

        self.async_tasks.send_verification(username)

        req.context["response"] = {"user_id": str(user.user_id)}
        resp.status = falcon.HTTP_200
