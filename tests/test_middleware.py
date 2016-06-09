import base64
import uuid

import arrow
import falcon
import falcon.testing
import helpers
import pytest
from Crypto.Hash import SHA256

from gaas.middleware import authenticate_signature
from gaas.models import NotFound
from gaas.models.key import Key
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


def test_authenticate_no_auth_header(valid_request, mock_key_manager):
    method, path, body, headers, *_ = valid_request
    del headers["authorization"]
    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert "Must provide 'authorization' header" == excinfo.value.description
    mock_key_manager.assert_not_called()


def test_authenticate_invalid_auth_header(valid_request, mock_key_manager):
    method, path, body, headers, *_ = valid_request
    headers["authorization"] = headers["authorization"].replace("Signature", "Invalid")
    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert SIGNATURE_MISMATCH_MESSAGE == excinfo.value.description
    mock_key_manager.assert_not_called()


def test_authenticate_invalid_id_format(rsa_priv, mock_key_manager):
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


def test_authenticate_invalid_user_id(rsa_priv, mock_key_manager):
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


def test_authenticate_invalid_key_id(rsa_priv, mock_key_manager):
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
    mock_key_manager.assert_not_called()


def test_authenticate_key_missing_or_expired(valid_request, mock_key_manager):
    method, path, body, headers, user_id, key_id = valid_request

    def load(user_id, key_id):
        raise NotFound
    mock_key_manager.load.side_effect = load

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert "Unknown USER, KEYID ({}, {})".format(user_id, key_id) == excinfo.value.description
    mock_key_manager.load.assert_called_once_with(user_id, key_id)


def test_authenticate_invalid_signature(generate_key, valid_request, mock_key_manager):
    method, path, body, headers, user_id, key_id = valid_request

    _, wrong_public = generate_key()

    mock_key_manager.load.return_value = Key(user_id=user_id, key_id=key_id, public=wrong_public)

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert "Signature validation failed:" in excinfo.value.description
    mock_key_manager.load.assert_called_once_with(user_id, key_id)


def test_authenticate_success(rsa_pub, valid_request, mock_key_manager):
    method, path, body, headers, user_id, key_id = valid_request

    key = Key(user_id=user_id, key_id=key_id, public=rsa_pub)
    mock_key_manager.load.return_value = key

    actual_key = authenticate_signature(method, path, headers, body, [], mock_key_manager)
    assert actual_key == key
    mock_key_manager.load.assert_called_once_with(user_id, key_id)


def test_authentication_middleware_success(rsa_priv, rsa_pub, authentication_middleware, mock_key_manager):
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


def test_authentication_middleware_failure(rsa_pub, authentication_middleware, mock_key_manager):
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
