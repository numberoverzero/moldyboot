import arrow
import base64
import falcon
import falcon.testing
import pytest
import uuid
from Crypto.Hash import SHA256

from gaas.middleware import Authentication
from gaas.signing import sign
import helpers


def sha256(body):
    body = body or ""
    hash = SHA256.new(body.encode("utf-8")).digest()
    return base64.b64encode(hash).decode("utf-8")


def signed_env(method, path, headers, body, private_key, id):
    sign(method, path, headers, body, private_key, id)
    return helpers.build_env(method, path, headers, body)


@pytest.fixture
def patch_key_infra(mock_engine):
    """Prevent outbound calls when manipulating Keys"""
    def patch(public, user_id, key_id):
        def mock_load(item, *args, **kwargs):
            if item.user_id != user_id:
                raise AssertionError("Unexpected user_id")
            if item.key_id != key_id:
                raise AssertionError("Unexpected key_id")
            item.public = public
            item.until = arrow.now().replace(hours=1)
        mock_engine.load = mock_load

        def mock_save(*args, **kwargs):
            pass
        mock_engine.save = mock_save
    return patch


def test_authentication_success(patch_key_infra, crypto_priv, crypto_pub):
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
    patch_key_infra(crypto_pub, user_id, key_id)

    # Build the api
    api = falcon.API(middleware=[Authentication()])
    resource = helpers.MockResource(status="200 TEST OK")
    mock_response = falcon.testing.StartResponseMock()
    api.add_route("/some/path", resource)

    # Execute the test
    api(env, mock_response)
    assert mock_response.status == "200 TEST OK"
    assert resource.captured_req.context["user_id"] == user_id


def test_authentication_failure(patch_key_infra, crypto_pub):
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
    patch_key_infra(crypto_pub, user_id, key_id)

    # Build the api
    api = falcon.API(middleware=[Authentication()])
    resource = helpers.MockResource(status="200 TEST OK")
    response = falcon.testing.StartResponseMock()
    api.add_route("/some/path", resource)

    # Execute the test
    response_body = api(env, response)
    assert response.status == "401 Unauthorized"
    assert b"Must provide 'authorization' header" in response_body[0]
    # No request was captured because the resource wasn't invoked - failed at the Authentication middleware
    assert not hasattr(resource, "captured_req")
