import falcon
import json

from gaas.security import signatures, passwords
from .resources import has_tag, get_metadata
from .models import NotFound
from .models.key import KeyManager
from .models.user import UserManager
from .models.validation import validate, InvalidParameter


def lowercase_headers(headers):
    return {key.lower(): value for key, value in headers.items()}


def fail(message):
    raise falcon.HTTPUnauthorized("Authentication failed", message, None)


def authenticate_signature(method, path, headers, body, headers_to_sign, key_manager: KeyManager):

    # 1) Check authorization header format
    if "authorization" not in headers:
        fail("Must provide 'authorization' header")
    try:
        authentication = validate("authorization_header", headers["authorization"])
    except InvalidParameter as exception:
        fail("Authorization header did not match required pattern {}".format(exception.message))

    # 2) Check user_id, key_id format
    try:
        user_id = validate("user_id", authentication["user_id"])
    except InvalidParameter as exception:
        fail("Authorization USER {}".format(exception.message))
    try:
        key_id = validate("key_id", authentication["key_id"])
    except InvalidParameter as exception:
        fail("Authorization KEYID {}".format(exception.message))

    # 3) Try to load public key
    try:
        key = key_manager.load(user_id, key_id)
    except NotFound:
        fail("Unknown USER, KEYID ({}, {})".format(user_id, key_id))

    # 4) Check signature
    try:
        signatures.verify(
            method, path, headers, body,
            key.public, authentication["signature"],
            authentication["headers"].split(" "),
            headers_to_sign)
    except signatures.BadSignature as exception:
        fail("Signature validation failed: {}".format(exception.args[0]))

    # Success!  Let callers know who was just authenticated
    return key


def authenticate_password(username, password, user_manager: UserManager):
    # 1) Check username (skip password; illegal values will fail the hash cmp anyway)
    try:
        username = validate("username", username)
    except InvalidParameter:
        fail("Invalid username/password")
    # 2) Check that user exists
    try:
        user = user_manager.load_by_name(username)
    except NotFound:
        fail("Invalid username/password")
    # 3) Compare passwords
    try:
        passwords.check(password, user.password_hash)
    except passwords.BadPassword:
        fail("Invalid username/password")
    # Success! Return user_id of the user that just authenticated
    return user.user_id


class Authentication:
    def __init__(self, key_manager: KeyManager, user_manager: UserManager):
        self.key_manager = key_manager
        self.user_manager = user_manager

    def process_resource(self, req: falcon.Request, resp: falcon.Response, resource, params):

        # Auth bypass (ie. email verification)
        if has_tag(resource, req.method, "authentication-skip"):
            return
        # Use basic auth instead of signature (ie. posting a new public key)
        elif has_tag(resource, req.method, "authentication-basic"):
            self._basic_auth(req)
        # Everyone else gets signature auth
        else:
            self._signature_auth(req, resource)

    def _basic_auth(self, req: falcon.Request):
        # TODO move json loading to different middleware
        body = json.loads(req.stream.read().decode("utf-8"))
        try:
            username = body["username"]
        except KeyError:
            fail("username is missing")
        try:
            password = body["password"]
        except KeyError:
            fail("password is missing")
        user_id = authenticate_password(username, password, self.user_manager)
        req.context["authentication"] = {"user": user_id}

    def _signature_auth(self, req: falcon.Request, resource):
        method = req.method
        path = req.path
        # query_string will always be a string, which means that omitted/empty will be conflated.
        # for example, "/path?" and "/path" will both have query_string ""
        if req.query_string:
            path += "?" + req.query_string
        headers = lowercase_headers(req.headers)
        body = req.stream.read().decode("utf-8")

        # Added with @resources.require_signed_header("some-header")
        try:
            additional_headers_to_sign = get_metadata(resource, method, "_additional_signed_headers")
        except AttributeError:
            additional_headers_to_sign = []
        key = authenticate_signature(method, path, headers, body, additional_headers_to_sign, self.key_manager)
        req.context["authentication"] = {"key": key, "user": key.user_id}
