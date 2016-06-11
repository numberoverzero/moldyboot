import falcon

from .meta import tag
from ..models import InvalidParameter, KeyManager, NotSaved


class Keys:
    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        """Caller passed authentication, return the public key their signature passed with"""
        public_key = req.context["authentication"]["key"].public.exportKey(format="PEM").decode("utf-8")
        req.context["response"] = {"public_key": public_key}
        resp.status = falcon.HTTP_200

    def on_delete(self, req: falcon.Request, resp: falcon.Response):
        """Manually revoke a key"""
        key = req.context["authentication"]["key"]
        self.key_manager.revoke(key)
        resp.status = falcon.HTTP_200

    @tag("authentication-basic")
    def on_post(self, req: falcon.Request, resp: falcon.Response):
        """User logged in with username/password, persist the provided public key and return its id"""
        user_id = req.context["authentication"]["user_id"]
        body = req.context["body"].json
        try:
            public_key = body["public_key"]
        except KeyError:
            raise falcon.HTTPBadRequest("Missing required parameter", "Must provide a public key.")
        try:
            key = self.key_manager.new(user_id, public_key)
        # Can only be public_key, since user_id came from authentication
        except InvalidParameter:
            raise falcon.HTTPBadRequest("Invalid parameter", "Expected public key in PEM format.")
        except NotSaved:
            raise falcon.HTTPInternalServerError("Internal Server Error", "Failed to store public key")

        req.context["response"] = {"key_id": "{}@{}".format(user_id, key.key_id)}
        resp.status = falcon.HTTP_200
