import base64
import uuid
from unittest.mock import Mock

import falcon
import falcon.testing
import pendulum
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from tests.helpers import request, response, signed_request

from moldyboot.controllers import InvalidParameter, NotFound
from moldyboot.middleware.authentication import (
    Authentication,
    authenticate_password,
    authenticate_signature,
)
from moldyboot.models import Key, User, UserName
from moldyboot.security import passwords
from moldyboot.security.passwords import hash
from moldyboot.security.signatures import sign


SIGNATURE_MISMATCH_MESSAGE = (
    'Authorization header did not match required pattern '
    '^Signature headers="([^"]*)" id="([^@"]*)@([^"]*)" signature="([^"]*)"$')


def sha256(body):
    body = body or ""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(body.encode("utf-8"))
    return base64.b64encode(digest.finalize()).decode("utf-8")


def resource_with(*tags):
    mock_resource = Mock()
    mock_resource.on_get._tags = {*tags}
    mock_resource.on_get._additional_signed_headers = []
    return mock_resource


@pytest.fixture
def valid_request(rsa_priv):
    method = "post"
    path = "/some/path?query=string"
    body = "hello world"
    headers = {
        "x-date": pendulum.now().in_timezone("utc").isoformat(),
        "content-length": str(len(body)),
        "x-content-sha256": sha256(body)
    }
    user_id, key_id = uuid.uuid4(), uuid.uuid4()
    id = "{}@{}".format(user_id, key_id)
    sign(
        method=method,
        path=path,
        headers=headers,
        body=body,
        private_key=rsa_priv,
        id=id
    )
    return method, path, body, headers, user_id, key_id


def test_authenticate_signature_no_auth_header(valid_request, mock_key_manager):
    method, path, body, headers, *_ = valid_request
    del headers["authorization"]
    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert "Must provide 'authorization' header" == excinfo.value.description
    mock_key_manager.get_key.assert_not_called()


def test_authenticate_signature_invalid_auth_header(valid_request, mock_key_manager):
    method, path, body, headers, *_ = valid_request
    headers["authorization"] = headers["authorization"].replace("Signature", "Invalid")
    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert SIGNATURE_MISMATCH_MESSAGE == excinfo.value.description
    mock_key_manager.get_key.assert_not_called()


def test_authenticate_signature_invalid_id_format(rsa_priv, mock_key_manager):
    method = "post"
    path = "/some/path?query=string"
    body = "hello world"
    headers = {
        "x-date": pendulum.now().in_timezone("utc").isoformat(),
        "content-length": 0,
        "x-content-sha256": sha256(body)
    }
    key_id = "wrong-separator"
    sign(
        method=method,
        path=path,
        headers=headers,
        body=body,
        private_key=rsa_priv,
        id=key_id
    )

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert SIGNATURE_MISMATCH_MESSAGE == excinfo.value.description
    mock_key_manager.get_key.assert_not_called()


def test_authenticate_signature_invalid_param(rsa_priv, mock_key_manager):
    method = "post"
    path = "/some/path?query=string"
    body = "hello world"
    headers = {
        "x-date": pendulum.now().in_timezone("utc").isoformat(),
        "content-length": 0,
        "x-content-sha256": sha256(body)
    }
    key_uuid = uuid.uuid4()
    key_id = "bad-format@{}".format(key_uuid)
    sign(
        method=method,
        path=path,
        headers=headers,
        body=body,
        private_key=rsa_priv,
        id=key_id
    )
    mock_key_manager.get_key.side_effect = InvalidParameter("user_id", "bad-format", "test message")

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert "user_id must be a uuid but was 'bad-format'" == excinfo.value.description
    mock_key_manager.get_key.assert_called_once_with("bad-format", str(key_uuid))


def test_authenticate_signature_key_missing_or_expired(valid_request, mock_key_manager):
    method, path, body, headers, user_id, key_id = valid_request

    mock_key_manager.get_key.side_effect = NotFound

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert "Unknown USER, KEYID ({}, {})".format(user_id, key_id) == excinfo.value.description
    mock_key_manager.get_key.assert_called_once_with(str(user_id), str(key_id))


def test_authenticate_signature_invalid_signature(generate_key, valid_request, mock_key_manager):
    method, path, body, headers, user_id, key_id = valid_request

    wrong_public = generate_key().public_key()

    mock_key_manager.get_key.return_value = Key(user_id=user_id, key_id=key_id, public=wrong_public)

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert "Signature validation failed:" in excinfo.value.description
    mock_key_manager.get_key.assert_called_once_with(str(user_id), str(key_id))


def test_authenticate_signature_success(rsa_pub, valid_request, mock_key_manager):
    method, path, body, headers, user_id, key_id = valid_request

    key = Key(user_id=user_id, key_id=key_id, public=rsa_pub)
    mock_key_manager.get_key.return_value = key

    actual_key = authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert actual_key == key
    mock_key_manager.get_key.assert_called_once_with(str(user_id), str(key_id))


def test_authenticate_password_invalid_username(mock_user_manager):
    username = "0abc"
    password = "hunter2"
    mock_user_manager.get_username.side_effect = InvalidParameter("username", "0abc", "test message")

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_password(username, password, mock_user_manager)
    assert "Invalid username/password" in excinfo.value.description
    mock_user_manager.get_username.assert_called_once_with(username)
    mock_user_manager.get_user.assert_not_called()


def test_authenticate_password_username_missing(mock_user_manager):
    username = "abc"
    password = "hunter2"

    mock_user_manager.get_username.side_effect = NotFound

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_password(username, password, mock_user_manager)
    assert "Invalid username/password" in excinfo.value.description
    mock_user_manager.get_username.assert_called_once_with(username)
    mock_user_manager.get_user.assert_not_called()


def test_authenticate_password_user_missing(mock_user_manager):
    username = "abc"
    user_id = uuid.uuid4()
    password = "hunter2"

    mock_user_manager.get_username.return_value = UserName(username=username, user_id=user_id)
    mock_user_manager.get_user.side_effect = NotFound

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_password(username, password, mock_user_manager)
    assert "Invalid username/password" in excinfo.value.description
    mock_user_manager.get_username.assert_called_once_with(username)
    mock_user_manager.get_user.assert_called_once_with(user_id)


def test_authenticate_password_wrong_password(mock_user_manager):
    username = "abc"
    user_id = uuid.uuid4()
    password = "hunter2"
    wrong_hash = hash(password="*******", rounds=12)

    mock_user_manager.get_username.return_value = UserName(username=username, user_id=user_id)
    mock_user_manager.get_user.return_value = User(user_id=user_id, password_hash=wrong_hash)

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_password(username, password, mock_user_manager)
    assert "Invalid username/password" in excinfo.value.description
    mock_user_manager.get_username.assert_called_once_with(username)
    mock_user_manager.get_user.assert_called_once_with(user_id)


def test_authenticate_password_success(mock_user_manager):
    username = "abc"
    user_id = uuid.uuid4()
    password = "hunter2"
    correct_hash = hash(password=password, rounds=12)
    user = User(user_id=user_id, password_hash=correct_hash)

    mock_user_manager.get_username.return_value = UserName(username=username, user_id=user_id)
    mock_user_manager.get_user.return_value = User(user_id=user_id, password_hash=correct_hash)

    actual_user = authenticate_password(username, password, mock_user_manager)
    assert actual_user == user
    mock_user_manager.get_username.assert_called_once_with(username)
    mock_user_manager.get_user.assert_called_once_with(user_id)


# Middleware tests start here ========================================================================================

def test_authentication_middleware_bypass(mock_key_manager, mock_user_manager):
    """Resources can skip authentication with an explicit tag"""
    req, resp, resource = request(), response(), resource_with("authentication-skip")
    middleware = Authentication(mock_key_manager, mock_user_manager)

    middleware.process_resource(req, resp, resource, {})
    mock_key_manager.get_key.assert_not_called()
    mock_user_manager.assert_not_called()


def test_authentication_middleware_basic_success(mock_key_manager, mock_user_manager):
    """Resource can use (pseudo) Basic Authentication with an explicit tag"""
    username, user_id, password = "abcUser", uuid.uuid4(), "|-|unterZ"
    correct_hash = passwords.hash(password=password, rounds=12)
    user = User(user_id=user_id, password_hash=correct_hash)

    req = request(body={"username": username, "password": password})
    resp, resource = response(), resource_with("authentication-basic")
    middleware = Authentication(mock_key_manager, mock_user_manager)

    mock_user_manager.get_username.return_value = UserName(username=username, user_id=user_id)
    mock_user_manager.get_user.return_value = user

    middleware.process_resource(req, resp, resource, {})

    assert req.context["authentication"] == {"user": user}
    mock_user_manager.get_username.assert_called_once_with(username)
    mock_user_manager.get_user.assert_called_once_with(user_id)


def test_authentication_middleware_unverified(mock_key_manager, mock_user_manager):
    """Users that haven't verified their email accounts fail authentication"""
    username, user_id, password = "abcUser", uuid.uuid4(), "|-|unterZ"
    correct_hash = passwords.hash(password=password, rounds=12)
    user = User(user_id=user_id, password_hash=correct_hash, verification_code=uuid.uuid4())

    req = request(body={"username": username, "password": password})
    resp, resource = response(), resource_with("authentication-basic")
    middleware = Authentication(mock_key_manager, mock_user_manager)

    mock_user_manager.get_username.return_value = UserName(username=username, user_id=user_id)
    mock_user_manager.get_user.return_value = user

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        middleware.process_resource(req, resp, resource, {})
    assert excinfo.value.description == "Account not verified"

    mock_user_manager.get_username.assert_called_once_with(username)
    mock_user_manager.get_user.assert_called_once_with(user_id)


def test_authentication_middleware_deleted(mock_key_manager, mock_user_manager):
    """Users that are tombstoned fail authentication"""
    username, user_id, password = "abcUser", uuid.uuid4(), "|-|unterZ"
    correct_hash = passwords.hash(password=password, rounds=12)
    user = User(user_id=user_id, password_hash=correct_hash, deleted=True)

    req = request(body={"username": username, "password": password})
    resp, resource = response(), resource_with("authentication-basic")
    middleware = Authentication(mock_key_manager, mock_user_manager)

    mock_user_manager.get_username.return_value = UserName(username=username, user_id=user_id)
    mock_user_manager.get_user.return_value = user

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        middleware.process_resource(req, resp, resource, {})
    assert excinfo.value.description == "Account was deleted"

    mock_user_manager.get_username.assert_called_once_with(username)
    mock_user_manager.get_user.assert_called_once_with(user_id)


def test_authentication_middleware_basic_no_username(mock_key_manager, mock_user_manager):
    req = request(body={"password": "|-|unterZ"})
    resp, resource = response(), resource_with("authentication-basic")
    middleware = Authentication(mock_key_manager, mock_user_manager)

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        middleware.process_resource(req, resp, resource, {})
    assert excinfo.value.description == "username is missing"

    mock_user_manager.get_username.assert_not_called()
    mock_user_manager.get_user.assert_not_called()
    mock_key_manager.get_key.assert_not_called()


def test_authentication_middleware_basic_no_password(mock_key_manager, mock_user_manager):
    req = request(body={"username": "abcUser"})
    resp, resource = response(), resource_with("authentication-basic")
    middleware = Authentication(mock_key_manager, mock_user_manager)

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        middleware.process_resource(req, resp, resource, {})
    assert excinfo.value.description == "password is missing"

    mock_user_manager.get_username.assert_not_called()
    mock_user_manager.get_user.assert_not_called()
    mock_key_manager.get_key.assert_not_called()


def test_authentication_middleware_signature_success(rsa_priv, rsa_pub, mock_key_manager, mock_user_manager):
    # build a signed request
    user_id, key_id = uuid.uuid4(), uuid.uuid4()
    id = "{}@{}".format(user_id, key_id)
    req = signed_request(private_key=rsa_priv, key_id=id)

    # resource w/o tags defaults to signature-based auth
    resp, resource = response(), resource_with()

    key = Key(user_id=user_id, key_id=key_id, public=rsa_pub)
    mock_key_manager.get_key.return_value = key
    user = User(user_id=user_id)
    mock_user_manager.get_user.return_value = user

    middleware = Authentication(mock_key_manager, mock_user_manager)
    middleware.process_resource(req, resp, resource, {})

    mock_user_manager.get_user.assert_called_once_with(user_id)
    mock_key_manager.get_key.assert_called_once_with(str(user_id), str(key_id))
    assert req.context["authentication"] == {"key": key, "user": user}


def test_authentication_middleware_signature_unknown_user(rsa_priv, rsa_pub, mock_key_manager, mock_user_manager):
    # build a signed request
    user_id, key_id = uuid.uuid4(), uuid.uuid4()
    id = "{}@{}".format(user_id, key_id)
    req = signed_request(private_key=rsa_priv, key_id=id)

    # resource w/o tags defaults to signature-based auth
    resp, resource = response(), resource_with()

    key = Key(user_id=user_id, key_id=key_id, public=rsa_pub)
    mock_key_manager.get_key.return_value = key
    # signature matches but user_id is unknown
    mock_user_manager.get_user.side_effect = NotFound

    middleware = Authentication(mock_key_manager, mock_user_manager)
    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        middleware.process_resource(req, resp, resource, {})
    assert excinfo.value.description == "Unknown user"
    mock_user_manager.get_user.assert_called_once_with(user_id)
    mock_key_manager.get_key.assert_called_once_with(str(user_id), str(key_id))


def test_authentication_middleware_signature_failure(mock_key_manager, mock_user_manager):
    class Resource:
        # Implicit lack of additional headers to sign
        def on_get(self, req, resp):
            pass

    # forget to sign the request
    req, resp, resource = request(uri="/path?query=string"), response(), Resource()

    middleware = Authentication(mock_key_manager, mock_user_manager)

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        middleware.process_resource(req, resp, resource, {})
    assert excinfo.value.description == "Must provide 'authorization' header"

    mock_user_manager.get_user.assert_not_called()
    mock_key_manager.get_key.assert_not_called()
