import falcon

from .meta import tag
from ..models import NotSaved
from ..models.validation import InvalidParameter, validate
from ..models.key import KeyManager


class Keys:
    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        """Caller passed authentication, return the public key their signature passed with"""
        authenticated_info = req.context["authentication"]
        user_id = str(authenticated_info["user"])
        public_key = authenticated_info["key"].public
        public_key = public_key.exportKey(format="PEM").decode("utf-8")
        req.context["response"] = {"user_id": user_id, "public_key": public_key}
        resp.status = falcon.HTTP_200

    def on_delete(self, req: falcon.Request, resp: falcon.Response):
        """Manually revoke a key"""
        key = req.context["authentication"]["key"]
        self.key_manager.revoke(key)
        resp.status = falcon.HTTP_200

    @tag("authentication-basic")
    def on_post(self, req: falcon.Request, resp: falcon.Response):
        """User logged in with username/password, persist the provided public key and return its id"""
        # TODO move json loading to middleware
        body = req.context["body"].json
        try:
            public_key = body["public_key"]
        except KeyError:
            raise falcon.HTTPBadRequest("Missing required parameter", "Must provide a public key.")
        try:
            public_key = validate("public_key", public_key)
        except InvalidParameter:
            raise falcon.HTTPBadRequest("Invalid parameter", "Expected public key in PEM format.")

        user_id = req.context["authentication"]["user"]
        try:
            key = self.key_manager.new(user_id, public_key)
        except NotSaved:
            raise falcon.HTTPInternalServerError("Internal Server Error", "Please retry authentication")
        req.context["response"] = {"key_id": str(key.key_id), "until": key.until.isoformat()}
        resp.status = falcon.HTTP_200
