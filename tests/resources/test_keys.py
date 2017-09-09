import uuid

import falcon
import pendulum
import pytest
from cryptography.hazmat.primitives import serialization
from tests.helpers import request, response

from moldyboot.controllers import InvalidParameter, NotSaved
from moldyboot.models import Key, User
from moldyboot.resources.keys import Keys


def basic_auth_request(user, **kwargs):
    req = request(**kwargs)
    req.context["authentication"] = {"user": user}
    return req


def signed_auth_request(key, user, **kwargs):
    req = request(**kwargs)
    req.context["authentication"] = {"key": key, "user": user}
    return req


def test_on_get(mock_key_manager, rsa_pub):
    """Echoes the authenticated public key back at the user"""
    expiry = pendulum.now().in_timezone("utc").add(hours=1)
    key = Key(key_id=uuid.uuid4(), user_id=uuid.uuid4(), public=rsa_pub, until=expiry)
    user = User(user_id=key.user_id)
    req, resp = signed_auth_request(key, user), response()

    resource = Keys(mock_key_manager)
    resource.on_get(req, resp)

    assert req.context["response"] == {
        "fingerprint": key.compute_fingerprint(),
        "until": expiry.isoformat(),
        "key_id": "{}@{}".format(user.user_id, key.key_id)}
    assert resp.status == falcon.HTTP_200
    mock_key_manager.assert_not_called()


def test_on_delete(mock_key_manager, rsa_pub):
    """Manually revoke a key"""
    key = Key(user_id=uuid.uuid4(), public=rsa_pub)
    req, resp = signed_auth_request(key, None), response()

    resource = Keys(mock_key_manager)
    resource.on_delete(req, resp)

    assert "response" not in req.context
    assert resp.status == falcon.HTTP_200
    mock_key_manager.revoke.assert_called_once_with(key)


def test_on_post_no_public_key(mock_key_manager):
    """Upload a new key without a public_key in the body fails"""
    user = User(user_id=uuid.uuid4())
    req, resp = basic_auth_request(user), response()

    resource = Keys(mock_key_manager)

    with pytest.raises(falcon.HTTPBadRequest) as excinfo:
        resource.on_post(req, resp)

    assert excinfo.value.title == "Missing required parameter"
    assert excinfo.value.description == "Must provide a public key."
    mock_key_manager.new.assert_not_called()


def test_on_post_malformed_public_key(mock_key_manager):
    """Upload a new key with a non-pem formatted public key fails"""
    user = User(user_id=uuid.uuid4())
    public_key = "not in pem format"
    req, resp = basic_auth_request(user, body={"public_key": public_key}), response()

    resource = Keys(mock_key_manager)

    mock_key_manager.new.side_effect = InvalidParameter("public_key", public_key, "test message")

    with pytest.raises(falcon.HTTPBadRequest) as excinfo:
        resource.on_post(req, resp)

    assert excinfo.value.title == "Invalid parameter"
    assert excinfo.value.description == "Expected public key in PEM format."
    mock_key_manager.new.assert_called_once_with(user.user_id, public_key)


def test_on_post_fail_to_save(mock_key_manager):
    """Upload a new key but failure to persist"""
    user = User(user_id=uuid.uuid4())
    public_key = "not in pem format"
    req, resp = basic_auth_request(user, body={"public_key": public_key}), response()

    resource = Keys(mock_key_manager)

    mock_key_manager.new.side_effect = NotSaved(object())

    with pytest.raises(falcon.HTTPInternalServerError) as excinfo:
        resource.on_post(req, resp)

    assert excinfo.value.title == "Internal Server Error"
    assert excinfo.value.description == "Failed to store public key"
    mock_key_manager.new.assert_called_once_with(user.user_id, public_key)


def test_on_post(mock_key_manager, rsa_pub):
    """Upload a new key, returning user_id@key_id"""
    user = User(user_id=uuid.uuid4())
    key_id = uuid.uuid4()
    public_key = rsa_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    req, resp = basic_auth_request(user, body={"public_key": public_key}), response()

    expiry = pendulum.now().in_timezone("utc").add(hours=1)
    resource = Keys(mock_key_manager)
    mock_key_manager.new.return_value = Key(user_id=user.user_id, key_id=key_id, until=expiry)

    resource.on_post(req, resp)

    assert req.context["response"] == {
        "key_id": "{}@{}".format(user.user_id, key_id),
        "until": expiry.isoformat()
    }
    assert resp.status == falcon.HTTP_200
    mock_key_manager.new.assert_called_once_with(user.user_id, public_key)
