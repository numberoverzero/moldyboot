import falcon
import pytest
import uuid

from tests.helpers import request, response

from gaas.models import Key, User
from gaas.controllers import InvalidParameter, NotSaved
from gaas.resources.api.keys import Keys


def basic_auth_request(user, **kwargs):
    req = request(**kwargs)
    req.context["authentication"] = {"user": user}
    return req


def signed_auth_request(key, **kwargs):
    req = request(**kwargs)
    req.context["authentication"] = {"key": key}
    return req


def test_on_get(mock_key_manager, rsa_pub):
    """Echoes the authenticated public key back at the user"""
    key = Key(user_id=uuid.uuid4(), public=rsa_pub)
    req, resp = signed_auth_request(key), response()

    resource = Keys(mock_key_manager)
    resource.on_get(req, resp)

    public_key_str = rsa_pub.exportKey("PEM").decode("utf-8")

    assert req.context["response"] == {"public_key": public_key_str}
    assert resp.status == falcon.HTTP_200
    mock_key_manager.assert_not_called()


def test_on_delete(mock_key_manager, rsa_pub):
    """Manually revoke a key"""
    key = Key(user_id=uuid.uuid4(), public=rsa_pub)
    req, resp = signed_auth_request(key), response()

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
    """Upload a new key but fail to persist"""
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
    public_key = rsa_pub.exportKey("PEM").decode("utf-8")
    req, resp = basic_auth_request(user, body={"public_key": public_key}), response()

    resource = Keys(mock_key_manager)
    mock_key_manager.new.return_value = Key(user_id=user.user_id, key_id=key_id)

    resource.on_post(req, resp)

    assert req.context["response"] == {"key_id": "{}@{}".format(user.user_id, key_id)}
    assert resp.status == falcon.HTTP_200
    mock_key_manager.new.assert_called_once_with(user.user_id, public_key)
