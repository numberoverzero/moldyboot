import arrow
import base64
import bloop
import pytest
import uuid
from Crypto.Hash import SHA256

from gaas.handlers import authenticate, Unauthorized
from gaas.signing import sign


def sha256(body):
    body = body or ""
    hash = SHA256.new(body.encode("utf-8")).digest()
    return base64.b64encode(hash).decode("utf-8")


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
    sign(method, path, headers, body, [], crypto_priv, id)
    return method, path, body, headers, user_id, key_id


def test_authenticate_no_auth_header(valid_request):
    method, path, body, headers, *_ = valid_request
    del headers["authorization"]
    with pytest.raises(Unauthorized) as excinfo:
        authenticate(method, path, headers, body, [])
    assert "Must provide 'authorization' header" == str(excinfo.value)


def test_authenticate_invalid_auth_header(valid_request):
    method, path, body, headers, *_ = valid_request
    headers["authorization"] = headers["authorization"].replace("Signature", "Invalid")
    with pytest.raises(Unauthorized) as excinfo:
        authenticate(method, path, headers, body, [])
    assert ('Authorization header did not match required pattern '
            '^Signature headers="([^"]*)" id="([^"]*)" signature="([^"]*)"$') == str(excinfo.value)


def test_authenticate_invalid_id_format(crypto_priv):
    method = "post"
    path = "/some/path?query=string"
    body = "hello world"
    headers = {
        "x-date": arrow.now().to("utc").isoformat(),
        "content-length": 0,
        "x-content-sha256": sha256(body)
    }
    key_id = "wrong-separator"
    sign(method, path, headers, body, [], crypto_priv, key_id)

    with pytest.raises(Unauthorized) as excinfo:
        authenticate(method, path, headers, body, [])
    assert "Authorization 'id' does not match USER@KEYID format" == str(excinfo.value)


def test_authenticate_invalid_user_id(crypto_priv):
    method = "post"
    path = "/some/path?query=string"
    body = "hello world"
    headers = {
        "x-date": arrow.now().to("utc").isoformat(),
        "content-length": 0,
        "x-content-sha256": sha256(body)
    }
    key_id = "bad-format@{}".format(uuid.uuid4())
    sign(method, path, headers, body, [], crypto_priv, key_id)

    with pytest.raises(Unauthorized) as excinfo:
        authenticate(method, path, headers, body, [])
    assert "Authorization id USER must be a uuid" == str(excinfo.value)


def test_authenticate_invalid_key_id(crypto_priv):
    method = "post"
    path = "/some/path?query=string"
    body = "hello world"
    headers = {
        "x-date": arrow.now().to("utc").isoformat(),
        "content-length": 0,
        "x-content-sha256": sha256(body)
    }
    key_id = "{}@bad-format".format(uuid.uuid4())
    sign(method, path, headers, body, [], crypto_priv, key_id)

    with pytest.raises(Unauthorized) as excinfo:
        authenticate(method, path, headers, body, [])
    assert "Authorization id KEYID must be a uuid" == str(excinfo.value)


def test_authenticate_key_missing(valid_request, mock_engine):
    method, path, body, headers, user_id, key_id = valid_request

    def mock_load(item, consistent=None):
        raise bloop.NotModified("load", [item])
    mock_engine.load = mock_load

    with pytest.raises(Unauthorized) as excinfo:
        authenticate(method, path, headers, body, [])
    assert "Unknown USER, KEYID ({}, {})".format(user_id, key_id) == str(excinfo.value)


def test_authenticate_key_expired(crypto_pub, valid_request, mock_engine):
    method, path, body, headers, user_id, key_id = valid_request
    one_minute_ago = arrow.now().replace(minutes=-1)
    deleted = False

    def mock_load(item, consistent=None):
        item.public = crypto_pub
        item.until = one_minute_ago
    mock_engine.load = mock_load

    def mock_delete(item, atomic=None):
        nonlocal deleted
        deleted = True
    mock_engine.delete = mock_delete

    with pytest.raises(Unauthorized) as excinfo:
        authenticate(method, path, headers, body, [])
    assert "Unknown USER, KEYID ({}, {})".format(user_id, key_id) == str(excinfo.value)
    assert deleted


def test_authenticate_invalid_signature(generate_key, valid_request, mock_engine):
    method, path, body, headers, user_id, key_id = valid_request
    _, wrong_public = generate_key()
    one_hour = arrow.now().replace(hours=1)

    def mock_load(item, consistent=None):
        item.public = wrong_public
        item.until = one_hour
    mock_engine.load = mock_load

    with pytest.raises(Unauthorized) as excinfo:
        authenticate(method, path, headers, body, [])
    assert "Signature validation failed:" in str(excinfo.value)


def test_authenticate_success(crypto_pub, valid_request, mock_engine):
    method, path, body, headers, user_id, key_id = valid_request
    one_hour = arrow.now().replace(hours=1)

    def mock_load(item, consistent=None):
        item.public = crypto_pub
        item.until = one_hour
    mock_engine.load = mock_load

    def mock_save(item, condition=None, atomic=None):
        # The new expiration should be ~1 hour from now
        assert one_hour.replace(seconds=-10) <= item.until <= one_hour.replace(seconds=10)
    mock_engine.save = mock_save

    authenticate(method, path, headers, body, [])
