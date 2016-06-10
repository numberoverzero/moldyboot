import arrow
import base64
import falcon
import falcon.testing
import json
import pytest
import uuid

import helpers

from Crypto.Hash import SHA256

from gaas.middleware.authentication import authenticate_password, authenticate_signature
from gaas.models import NotFound
from gaas.models.key import Key
from gaas.models.user import User
from gaas.resources import tag
from gaas.security.passwords import hash
from gaas.security.signatures import sign

SIGNATURE_MISMATCH_MESSAGE = (
    'Authorization header did not match required pattern '
    '^Signature headers="([^"]*)" id="([^@"]*)@([^"]*)" signature="([^"]*)"$')


def sha256(body):
    body = body or ""
    hash = SHA256.new(body.encode("utf-8")).digest()
    return base64.b64encode(hash).decode("utf-8")


def signed_env(method, path, headers, body, private_key, id):
    sign(method, path, headers, body, private_key, id)
    return helpers.build_env(method, path, headers, body)


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


def test_authenticate_signature_invalid_user_id(rsa_priv, mock_key_manager):
    method = "post"
    path = "/some/path?query=string"
    body = "hello world"
    headers = {
        "x-date": arrow.now().to("utc").isoformat(),
        "content-length": 0,
        "x-content-sha256": sha256(body)
    }
    key_id = "bad-format@{}".format(uuid.uuid4())
    sign(method, path, headers, body, rsa_priv, key_id)

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert "Authorization USER must be a UUID" == excinfo.value.description
    mock_key_manager.assert_not_called()


def test_authenticate_signature_invalid_key_id(rsa_priv, mock_key_manager):
    method = "post"
    path = "/some/path?query=string"
    body = "hello world"
    headers = {
        "x-date": arrow.now().to("utc").isoformat(),
        "content-length": 0,
        "x-content-sha256": sha256(body)
    }
    key_id = "{}@bad-format".format(uuid.uuid4())
    sign(method, path, headers, body, rsa_priv, key_id)

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert "Authorization KEYID must be a UUID" == excinfo.value.description
    mock_key_manager.load.assert_not_called()


def test_authenticate_signature_key_missing_or_expired(valid_request, mock_key_manager):
    method, path, body, headers, user_id, key_id = valid_request

    mock_key_manager.load.side_effect = NotFound

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert "Unknown USER, KEYID ({}, {})".format(user_id, key_id) == excinfo.value.description
    mock_key_manager.load.assert_called_once_with(user_id, key_id)


def test_authenticate_signature_invalid_signature(generate_key, valid_request, mock_key_manager):
    method, path, body, headers, user_id, key_id = valid_request

    _, wrong_public = generate_key()

    mock_key_manager.load.return_value = Key(user_id=user_id, key_id=key_id, public=wrong_public)

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert "Signature validation failed:" in excinfo.value.description
    mock_key_manager.load.assert_called_once_with(user_id, key_id)


def test_authenticate_signature_success(rsa_pub, valid_request, mock_key_manager):
    method, path, body, headers, user_id, key_id = valid_request

    key = Key(user_id=user_id, key_id=key_id, public=rsa_pub)
    mock_key_manager.load.return_value = key

    actual_key = authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert actual_key == key
    mock_key_manager.load.assert_called_once_with(user_id, key_id)


def test_authenticate_password_invalid_username(mock_user_manager):
    username = "0abc"
    password = "hunter2"

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_password(username, password, mock_user_manager)
    assert "Invalid username/password" in excinfo.value.description
    mock_user_manager.load_by_name.assert_not_called()


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
    user_id = uuid.uuid4()
    username = "abc"
    password = "hunter2"
    correct_hash = hash(password, 12)

    mock_user_manager.load_by_name.return_value = User(user_id=user_id, password_hash=correct_hash)

    actual_user_id = authenticate_password(username, password, mock_user_manager)
    assert actual_user_id == user_id
    mock_user_manager.load_by_name.assert_called_once_with(username)


def test_authentication_middleware_bypass(authentication_middleware):
    class Resource:
        @tag("authentication-skip")
        def on_get(self, req, resp):
            resp.data = b"skipped auth!"
            return falcon.HTTP_200
    resource = Resource()

    api = falcon.API(middleware=[authentication_middleware])
    api.add_route("/bypass", resource)
    env = helpers.build_env("get", "/bypass", dict(), "")
    response = falcon.testing.StartResponseMock()

    response_body = api(env, response)
    assert response_body == [b"skipped auth!"]


def test_authentication_middleware_basic_success(authentication_middleware, mock_user_manager):
    username = "abcUser"
    password = "|-|unterZ"
    correct_hash = hash(password, 12)
    user_id = uuid.uuid4()
    mock_user_manager.load_by_name.return_value = User(user_id=user_id, password_hash=correct_hash)

    class Resource:
        @tag("authentication-basic")
        def on_get(self, req, resp):
            assert req.context["authentication"] == {"user": user_id}
            resp.data = b"basic auth!"
            return falcon.HTTP_200
    resource = Resource()

    api = falcon.API(middleware=[authentication_middleware])
    api.add_route("/basic", resource)
    env = helpers.build_env("get", "/basic", dict(), json.dumps({"username": username, "password": password}))
    response = falcon.testing.StartResponseMock()

    response_body = api(env, response)
    assert response_body == [b"basic auth!"]


def test_authentication_middleware_basic_no_username(authentication_middleware, mock_user_manager):
    password = "|-|unterZ"
    correct_hash = hash(password, 12)
    user_id = uuid.uuid4()
    mock_user_manager.load_by_name.return_value = User(user_id=user_id, password_hash=correct_hash)

    class Resource:
        @tag("authentication-basic")
        def on_get(self, req, resp):
            assert req.context["authentication"] == {"user": user_id}
            resp.data = b"basic auth!"
            return falcon.HTTP_200
    resource = Resource()

    api = falcon.API(middleware=[authentication_middleware])
    api.add_route("/basic", resource)
    env = helpers.build_env("get", "/basic", dict(), json.dumps({"password": password}))
    response = falcon.testing.StartResponseMock()

    response_body = api(env, response)
    assert response.status == "401 Unauthorized"
    assert b"username is missing" in response_body[0]


def test_authentication_middleware_basic_no_password(authentication_middleware, mock_user_manager):
    username = "abcUser"
    password = "|-|unterZ"
    correct_hash = hash(password, 12)
    user_id = uuid.uuid4()
    mock_user_manager.load_by_name.return_value = User(user_id=user_id, password_hash=correct_hash)

    class Resource:
        @tag("authentication-basic")
        def on_get(self, req, resp):
            assert req.context["authentication"] == {"user": user_id}
            resp.data = b"basic auth!"
            return falcon.HTTP_200
    resource = Resource()

    api = falcon.API(middleware=[authentication_middleware])
    api.add_route("/basic", resource)
    env = helpers.build_env("get", "/basic", dict(), json.dumps({"username": username}))
    response = falcon.testing.StartResponseMock()

    response_body = api(env, response)
    assert response.status == "401 Unauthorized"
    assert b"password is missing" in response_body[0]


def test_authentication_middleware_signature_success(rsa_priv, rsa_pub, authentication_middleware, mock_key_manager):
    # Build the request
    method = "post"
    path = "https://127.0.0.1:443/some/path?query=string"
    body = "hello world"
    headers = {
        "x-date": arrow.now().to("utc").isoformat(),
        "content-length": str(len(body)),
        "x-content-sha256": sha256(body)
    }
    user_id, key_id = uuid.uuid4(), uuid.uuid4()
    id = "{}@{}".format(user_id, key_id)

    # Sign the request
    sign(method, path, headers, body, rsa_priv, id)
    # Build wsgi env from signed request, patch key loading
    env = helpers.build_env(method, path, headers, body)
    key = Key(user_id=user_id, key_id=key_id, public=rsa_pub)
    mock_key_manager.load.return_value = key

    # Build the api
    api = falcon.API(middleware=[authentication_middleware])
    resource = helpers.MockResource(status="200 TEST OK")
    mock_response = falcon.testing.StartResponseMock()
    api.add_route("/some/path", resource)

    # Execute the test
    api(env, mock_response)
    assert mock_response.status == "200 TEST OK"
    assert resource.captured_req.context["authentication"] == {"key": key, "user": user_id}


def test_authentication_middleware_signature_failure(rsa_pub, authentication_middleware, mock_key_manager):
    # Build the request
    method = "post"
    path = "https://127.0.0.1:443/some/path"
    body = "hello world"
    headers = {
        "x-date": arrow.now().to("utc").isoformat(),
        "content-length": str(len(body)),
        "x-content-sha256": sha256(body)
    }
    user_id, key_id = uuid.uuid4(), uuid.uuid4()

    # Forget to sign the request
    # Build wsgi env from unsigned request, patch key loading
    env = helpers.build_env(method, path, headers, body)
    mock_key_manager.load.return_value = Key(user_id=user_id, key_id=key_id, public=rsa_pub)

    # Build the api
    api = falcon.API(middleware=[authentication_middleware])
    resource = helpers.MockResource(status="200 TEST OK")
    response = falcon.testing.StartResponseMock()
    api.add_route("/some/path", resource)

    # Execute the test
    response_body = api(env, response)
    assert response.status == "401 Unauthorized"
    assert b"Must provide 'authorization' header" in response_body[0]
    # No request was captured because the resource wasn't invoked - failed at the Authentication middleware
    assert not hasattr(resource, "captured_req")
