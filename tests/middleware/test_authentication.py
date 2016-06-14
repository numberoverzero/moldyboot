import arrow
import base64
import falcon
import falcon.testing
import pytest
import uuid

from helpers import request, response, signed_request

from Crypto.Hash import SHA256
from unittest.mock import Mock

from gaas.middleware.authentication import Authentication, authenticate_password, authenticate_signature
from gaas.models import InvalidParameter, Key, NotFound, User
from gaas.security import passwords
from gaas.security.passwords import hash
from gaas.security.signatures import sign

SIGNATURE_MISMATCH_MESSAGE = (
    'Authorization header did not match required pattern '
    '^Signature headers="([^"]*)" id="([^@"]*)@([^"]*)" signature="([^"]*)"$')


def sha256(body):
    body = body or ""
    hash = SHA256.new(body.encode("utf-8")).digest()
    return base64.b64encode(hash).decode("utf-8")


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
        "x-date": arrow.now().to("utc").isoformat(),
        "content-length": str(len(body)),
        "x-content-sha256": sha256(body)
    }
    user_id, key_id = uuid.uuid4(), uuid.uuid4()
    id = "{}@{}".format(user_id, key_id)
    sign(method, path, headers, body, rsa_priv, id)
    return method, path, body, headers, user_id, key_id


def test_authenticate_signature_no_auth_header(valid_request, mock_key_manager):
    method, path, body, headers, *_ = valid_request
    del headers["authorization"]
    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert "Must provide 'authorization' header" == excinfo.value.description
    mock_key_manager.assert_not_called()


def test_authenticate_signature_invalid_auth_header(valid_request, mock_key_manager):
    method, path, body, headers, *_ = valid_request
    headers["authorization"] = headers["authorization"].replace("Signature", "Invalid")
    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert SIGNATURE_MISMATCH_MESSAGE == excinfo.value.description
    mock_key_manager.assert_not_called()


def test_authenticate_signature_invalid_id_format(rsa_priv, mock_key_manager):
    method = "post"
    path = "/some/path?query=string"
    body = "hello world"
    headers = {
        "x-date": arrow.now().to("utc").isoformat(),
        "content-length": 0,
        "x-content-sha256": sha256(body)
    }
    key_id = "wrong-separator"
    sign(method, path, headers, body, rsa_priv, key_id)

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert SIGNATURE_MISMATCH_MESSAGE == excinfo.value.description
    mock_key_manager.assert_not_called()


def test_authenticate_signature_invalid_param(rsa_priv, mock_key_manager):
    method = "post"
    path = "/some/path?query=string"
    body = "hello world"
    headers = {
        "x-date": arrow.now().to("utc").isoformat(),
        "content-length": 0,
        "x-content-sha256": sha256(body)
    }
    key_uuid = uuid.uuid4()
    key_id = "bad-format@{}".format(key_uuid)
    sign(method, path, headers, body, rsa_priv, key_id)
    mock_key_manager.load.side_effect = InvalidParameter("user_id", "bad-format", "test message")

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert "user_id must be a uuid but was 'bad-format'" == excinfo.value.description
    mock_key_manager.load.assert_called_once_with("bad-format", str(key_uuid))


def test_authenticate_signature_key_missing_or_expired(valid_request, mock_key_manager):
    method, path, body, headers, user_id, key_id = valid_request

    mock_key_manager.load.side_effect = NotFound

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert "Unknown USER, KEYID ({}, {})".format(user_id, key_id) == excinfo.value.description
    mock_key_manager.load.assert_called_once_with(str(user_id), str(key_id))


def test_authenticate_signature_invalid_signature(generate_key, valid_request, mock_key_manager):
    method, path, body, headers, user_id, key_id = valid_request

    wrong_public = generate_key().publickey()

    mock_key_manager.load.return_value = Key(user_id=user_id, key_id=key_id, public=wrong_public)

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert "Signature validation failed:" in excinfo.value.description
    mock_key_manager.load.assert_called_once_with(str(user_id), str(key_id))


def test_authenticate_signature_success(rsa_pub, valid_request, mock_key_manager):
    method, path, body, headers, user_id, key_id = valid_request

    key = Key(user_id=user_id, key_id=key_id, public=rsa_pub)
    mock_key_manager.load.return_value = key

    actual_key = authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert actual_key == key
    mock_key_manager.load.assert_called_once_with(str(user_id), str(key_id))


def test_authenticate_password_invalid_username(mock_user_manager):
    username = "0abc"
    password = "hunter2"
    mock_user_manager.load_by_name.side_effect = InvalidParameter("username", "0abc", "test message")

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_password(username, password, mock_user_manager)
    assert "Invalid username/password" in excinfo.value.description
    mock_user_manager.load_by_name.assert_called_once_with(username)


def test_authenticate_password_user_missing(mock_user_manager):
    username = "abc"
    password = "hunter2"

    mock_user_manager.load_by_name.side_effect = NotFound

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_password(username, password, mock_user_manager)
    assert "Invalid username/password" in excinfo.value.description
    mock_user_manager.load_by_name.assert_called_once_with(username)


def test_authenticate_password_wrong_password(mock_user_manager):
    username = "abc"
    password = "hunter2"
    wrong_hash = hash("*******", 12)

    mock_user_manager.load_by_name.return_value = User(user_id=uuid.uuid4(), password_hash=wrong_hash)

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_password(username, password, mock_user_manager)
    assert "Invalid username/password" in excinfo.value.description
    mock_user_manager.load_by_name.assert_called_once_with(username)


def test_authenticate_password_success(mock_user_manager):
    username = "abc"
    password = "hunter2"
    correct_hash = hash(password, 12)
    user = User(user_id=uuid.uuid4(), password_hash=correct_hash)

    mock_user_manager.load_by_name.return_value = user

    actual_user = authenticate_password(username, password, mock_user_manager)
    assert actual_user == user
    mock_user_manager.load_by_name.assert_called_once_with(username)


# Middleware tests start here ========================================================================================

def test_authentication_middleware_bypass(mock_key_manager, mock_user_manager):
    """Resources can skip authentication with an explicit tag"""
    req, resp, resource = request(), response(), resource_with("authentication-skip")
    middleware = Authentication(mock_key_manager, mock_user_manager)

    middleware.process_resource(req, resp, resource, {})
    mock_key_manager.assert_not_called()
    mock_user_manager.assert_not_called()


def test_authentication_middleware_basic_success(mock_key_manager, mock_user_manager):
    """Resource can use (pseudo) Basic Authentication with an explicit tag"""
    username, password = "abcUser", "|-|unterZ"
    correct_hash = passwords.hash(password, 12)
    user = User(user_id=uuid.uuid4(), password_hash=correct_hash)

    req = request(body={"username": username, "password": password})
    resp, resource = response(), resource_with("authentication-basic")
    middleware = Authentication(mock_key_manager, mock_user_manager)
    mock_user_manager.load_by_name.return_value = user

    middleware.process_resource(req, resp, resource, {})

    assert req.context["authentication"] == {"user": user}
    mock_key_manager.assert_not_called()
    mock_user_manager.load_by_name.assert_called_once_with(username)


def test_authentication_middleware_basic_no_username(mock_key_manager, mock_user_manager):
    req = request(body={"password": "|-|unterZ"})
    resp, resource = response(), resource_with("authentication-basic")
    middleware = Authentication(mock_key_manager, mock_user_manager)

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        middleware.process_resource(req, resp, resource, {})
    assert excinfo.value.description == "username is missing"

    mock_key_manager.assert_not_called()
    mock_user_manager.assert_not_called()


def test_authentication_middleware_basic_no_password(mock_key_manager, mock_user_manager):
    req = request(body={"username": "abcUser"})
    resp, resource = response(), resource_with("authentication-basic")
    middleware = Authentication(mock_key_manager, mock_user_manager)

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        middleware.process_resource(req, resp, resource, {})
    assert excinfo.value.description == "password is missing"

    mock_key_manager.assert_not_called()
    mock_user_manager.assert_not_called()


def test_authentication_middleware_signature_success(rsa_priv, rsa_pub, mock_key_manager, mock_user_manager):
    # build a signed request
    user_id, key_id = uuid.uuid4(), uuid.uuid4()
    id = "{}@{}".format(user_id, key_id)
    req = signed_request(private_key=rsa_priv, key_id=id)

    # resource w/o tags defaults to signature-based auth
    resp, resource = response(), resource_with()

    key = Key(user_id=user_id, key_id=key_id, public=rsa_pub)
    mock_key_manager.load.return_value = key

    middleware = Authentication(mock_key_manager, mock_user_manager)
    middleware.process_resource(req, resp, resource, {})

    mock_user_manager.assert_not_called()
    mock_key_manager.load.assert_called_once_with(str(user_id), str(key_id))
    assert req.context["authentication"] == {"key": key}


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

    mock_user_manager.assert_not_called()
    mock_key_manager.assert_not_called()
