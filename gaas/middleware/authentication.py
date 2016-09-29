import falcon

from ..controllers import InvalidParameter, KeyManager, NotFound, UserManager, validate
from ..resources import get_metadata, has_tag
from ..security import passwords, signatures


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

    # 2) Try to load public key
    user_id, key_id = authentication["user_id"], authentication["key_id"]
    try:
        key = key_manager.load(user_id, key_id)
    except InvalidParameter as exception:
        fail("{} must be a uuid but was '{}'".format(exception.parameter_name, exception.value))
    except NotFound:
        fail("Unknown USER, KEYID ({}, {})".format(user_id, key_id))

    # 3) Check signature
    try:
        signatures.verify(
            method=method,
            path=path,
            headers=headers,
            body=body,
            public_key=key.public,
            signature=authentication["signature"],
            signed_headers=authentication["headers"].split(" "),
            headers_to_sign=headers_to_sign)
    except signatures.BadSignature as exception:
        fail("Signature validation failed: {}".format(exception.args[0]))

    # Success!  Let callers know who was just authenticated
    return key


def authenticate_password(username, password, user_manager: UserManager):
    # 1) Check that user exists
    try:
        user = user_manager.load_by_name(username)
    except (InvalidParameter, NotFound):
        fail("Invalid username/password")
    # 2) Compare passwords
    try:
        passwords.check(password=password, expected_hash=user.password_hash)
    except passwords.BadPassword:
        fail("Invalid username/password")
    # Success! Return user_id of the user that just authenticated
    return user


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

        # Both basic auth and signature auth populate the auth context with a user.
        # Verifying the account's email is a required part of authentication
        user = req.context["authentication"]["user"]
        if not user.is_verified:
            fail("Account not verified")

    def _basic_auth(self, req: falcon.Request):
        body = req.context["body"].json
        try:
            username = body["username"]
        except KeyError:
            fail("username is missing")
        try:
            password = body["password"]
        except KeyError:
            fail("password is missing")
        user = authenticate_password(username, password, self.user_manager)
        req.context["authentication"] = {"user": user}

    def _signature_auth(self, req: falcon.Request, resource):
        method = req.method
        path = req.path
        # query_string will always be a string, which means that omitted/empty will be conflated.
        # for example, "/path?" and "/path" will both have query_string ""
        if req.query_string:
            path += "?" + req.query_string
        headers = lowercase_headers(req.headers)
        body = req.context["body"].str

        # Added with @resources.require_signed_header("some-header")
        try:
            additional_headers_to_sign = get_metadata(resource, method, "_additional_signed_headers")
        except AttributeError:
            additional_headers_to_sign = []
        key = authenticate_signature(method, path, headers, body, additional_headers_to_sign, self.key_manager)
        try:
            user = self.user_manager.load_by_id(key.user_id)
        except NotFound:
            fail("Unknown user")
        req.context["authentication"] = {"key": key, "user": user}
