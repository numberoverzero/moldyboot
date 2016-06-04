import arrow
import base64
import falcon
import falcon.testing
import pytest
import uuid
from Crypto.Hash import SHA256

from gaas.models.key import Key
from gaas.middleware import authenticate
from gaas.signing import sign
import helpers
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
def valid_request(crypto_priv):
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
    sign(method, path, headers, body, crypto_priv, id)
    return method, path, body, headers, user_id, key_id


def test_authenticate_no_auth_header(valid_request, key_manager):
    method, path, body, headers, *_ = valid_request
    del headers["authorization"]
    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate(method, path, headers, body, [], key_manager)
    assert "Must provide 'authorization' header" == excinfo.value.description
    assert not key_manager.invoked


def test_authenticate_invalid_auth_header(valid_request, key_manager):
    method, path, body, headers, *_ = valid_request
    headers["authorization"] = headers["authorization"].replace("Signature", "Invalid")
    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate(method, path, headers, body, [], key_manager)
    assert SIGNATURE_MISMATCH_MESSAGE == excinfo.value.description
    assert not key_manager.invoked


def test_authenticate_invalid_id_format(crypto_priv, key_manager):
    method = "post"
    path = "/some/path?query=string"
    body = "hello world"
    headers = {
        "x-date": arrow.now().to("utc").isoformat(),
        "content-length": 0,
        "x-content-sha256": sha256(body)
    }
    key_id = "wrong-separator"
    sign(method, path, headers, body, crypto_priv, key_id)

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate(method, path, headers, body, [], key_manager)
    assert SIGNATURE_MISMATCH_MESSAGE == excinfo.value.description
    assert not key_manager.invoked


def test_authenticate_invalid_user_id(crypto_priv, key_manager):
    method = "post"
    path = "/some/path?query=string"
    body = "hello world"
    headers = {
        "x-date": arrow.now().to("utc").isoformat(),
        "content-length": 0,
        "x-content-sha256": sha256(body)
    }
    key_id = "bad-format@{}".format(uuid.uuid4())
    sign(method, path, headers, body, crypto_priv, key_id)

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate(method, path, headers, body, [], key_manager)
    assert "Authorization USER must be a UUID" == excinfo.value.description
    assert not key_manager.invoked


def test_authenticate_invalid_key_id(crypto_priv, key_manager):
    method = "post"
    path = "/some/path?query=string"
    body = "hello world"
    headers = {
        "x-date": arrow.now().to("utc").isoformat(),
        "content-length": 0,
        "x-content-sha256": sha256(body)
    }
    key_id = "{}@bad-format".format(uuid.uuid4())
    sign(method, path, headers, body, crypto_priv, key_id)

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate(method, path, headers, body, [], key_manager)
    assert "Authorization KEYID must be a UUID" == excinfo.value.description
    assert not key_manager.invoked


def test_authenticate_key_missing_or_expired(valid_request, key_manager):
    method, path, body, headers, user_id, key_id = valid_request

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate(method, path, headers, body, [], key_manager)
    assert "Unknown USER, KEYID ({}, {})".format(user_id, key_id) == excinfo.value.description
    assert [user_id, key_id] in key_manager.captured_load_args


def test_authenticate_invalid_signature(generate_key, valid_request, key_manager):
    method, path, body, headers, user_id, key_id = valid_request

    _, wrong_public = generate_key()
    key_manager.respond(user_id, key_id, Key(user_id=user_id, public=wrong_public))

    with pytest.raises(falcon.HTTPUnauthorized) as excinfo:
        authenticate(method, path, headers, body, [], key_manager)
    assert "Signature validation failed:" in excinfo.value.description
    assert [user_id, key_id] in key_manager.captured_load_args


def test_authenticate_success(crypto_pub, valid_request, key_manager):
    method, path, body, headers, user_id, key_id = valid_request

    key_manager.respond(user_id, key_id, Key(user_id=user_id, public=crypto_pub))

    authenticated_user_id = authenticate(method, path, headers, body, [], key_manager)
    assert authenticated_user_id == user_id
    assert [user_id, key_id] in key_manager.captured_load_args


def test_authentication_middleware_success(crypto_priv, crypto_pub, authentication_middleware, key_manager):
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
    sign(method, path, headers, body, crypto_priv, id)
    # Build wsgi env from signed request, patch key loading
    env = helpers.build_env(method, path, headers, body)
    key_manager.respond(user_id, key_id, Key(user_id=user_id, public=crypto_pub))

    # Build the api
    api = falcon.API(middleware=[authentication_middleware])
    resource = helpers.MockResource(status="200 TEST OK")
    mock_response = falcon.testing.StartResponseMock()
    api.add_route("/some/path", resource)

    # Execute the test
    api(env, mock_response)
    assert mock_response.status == "200 TEST OK"
    assert resource.captured_req.context["user_id"] == user_id


def test_authentication_middleware_failure(crypto_pub, authentication_middleware, key_manager):
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
    key_manager.respond(user_id, key_id, Key(user_id=user_id, public=crypto_pub))

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
