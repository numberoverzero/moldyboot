import falcon
import functools

from ..controllers import InvalidParameter, KeyManager, NotFound, UserManager, validate
from ..resources import get_metadata, has_tag
from ..security import passwords, signatures

failure = functools.partial(falcon.HTTPUnauthorized, title="Authentication failed", challenges=None)


def lowercase_headers(headers):
    return {key.lower(): value for key, value in headers.items()}


def authenticate_signature(method, path, headers, body, headers_to_sign, key_manager: KeyManager):

    # 1) Check authorization header format
    if "authorization" not in headers:
        raise failure(description="Must provide 'authorization' header")
    try:
        authentication = validate("authorization_header", headers["authorization"])
    except InvalidParameter as exception:
        raise failure(description="Authorization header did not match required pattern {}".format(exception.message))

    # 2) Try to get public key
    user_id, key_id = authentication["user_id"], authentication["key_id"]
    try:
        key = key_manager.get_key(user_id, key_id)
    except InvalidParameter as exception:
        raise failure(description="{} must be a uuid but was '{}'".format(exception.parameter_name, exception.value))
    except NotFound:
        raise failure(description="Unknown USER, KEYID ({}, {})".format(user_id, key_id))

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
        raise failure(description="Signature validation failed: {}".format(exception.args[0]))

    # Success!  Let callers know who was just authenticated
    return key


def authenticate_password(username, password, user_manager: UserManager):
    # 0) username -> UserName
    try:
        username = user_manager.get_username(username)
    except (InvalidParameter, NotFound):
        raise failure(description="Invalid username/password")
    # 1) UserName -> User
    try:
        user = user_manager.get_user(username.user_id)
    except (InvalidParameter, NotFound):
        raise failure(description="Invalid username/password")

    # 2) Compare passwords
    try:
        passwords.check(password=password, expected_hash=user.password_hash)
    except passwords.BadPassword:
        raise failure(description="Invalid username/password")

    # Success! Return user_id of the user that just authenticated
    return user


class Authentication:
    def __init__(self, key_manager: KeyManager, user_manager: UserManager):
        self.key_manager = key_manager
        self.user_manager = user_manager

    def process_resource(self, req: falcon.Request, resp: falcon.Response, resource, params):
        if req.method.lower() == "options":
            # TODO CORS requests don't need to sign
            # TODO add unit test
            return
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
        user = req.context["authentication"]["user"]

        # Unverified users always fail authentication
        if not user.is_verified:
            raise failure(description="Account not verified")

        # Tombstoned users always fail authentication
        if user.is_deleted:
            raise failure(description="Account was deleted")

    def _basic_auth(self, req: falcon.Request):
        body = req.context["body"].json
        try:
            username = body["username"]
        except KeyError:
            raise failure(description="username is missing")
        try:
            password = body["password"]
        except KeyError:
            raise failure(description="password is missing")
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
            user = self.user_manager.get_user(key.user_id)
        except NotFound:
            raise failure(description="Unknown user")
        req.context["authentication"] = {"key": key, "user": user}
