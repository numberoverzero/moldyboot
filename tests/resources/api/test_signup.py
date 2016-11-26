import falcon
import pytest
import uuid

from moldyboot.controllers import AlreadyExists
from moldyboot.models import User
from moldyboot.resources.api.signup import Signup
from moldyboot.security import passwords


from tests.helpers import request, response


def valid_post_body():
    return {
        "username": "user",
        "password": "hunter2",
        "email": "user@domain.com"
    }


def test_on_post_no_username(mock_user_manager, mock_async_tasks):
    resource = Signup(mock_user_manager, mock_async_tasks)
    body = valid_post_body()
    del body["username"]
    req, resp = request(body=body), response()
    with pytest.raises(falcon.HTTPBadRequest) as excinfo:
        resource.on_post(req, resp)
    assert excinfo.value.title == "Missing required parameter"
    assert excinfo.value.description == "Must provide a username"


def test_on_post_no_password(mock_user_manager, mock_async_tasks):
    resource = Signup(mock_user_manager, mock_async_tasks)
    body = valid_post_body()
    del body["password"]
    req, resp = request(body=body), response()
    with pytest.raises(falcon.HTTPBadRequest) as excinfo:
        resource.on_post(req, resp)
    assert excinfo.value.title == "Missing required parameter"
    assert excinfo.value.description == "Must provide a password"


def test_on_post_no_email(mock_user_manager, mock_async_tasks):
    resource = Signup(mock_user_manager, mock_async_tasks)
    body = valid_post_body()
    del body["email"]
    req, resp = request(body=body), response()
    with pytest.raises(falcon.HTTPBadRequest) as excinfo:
        resource.on_post(req, resp)
    assert excinfo.value.title == "Missing required parameter"
    assert excinfo.value.description == "Must provide an email"


def test_on_post_user_exists(mock_user_manager, mock_async_tasks):
    resource = Signup(mock_user_manager, mock_async_tasks)

    mock_user_manager.new.side_effect = AlreadyExists()

    req, resp = request(body=valid_post_body()), response()
    with pytest.raises(falcon.HTTPBadRequest) as excinfo:
        resource.on_post(req, resp)
    assert excinfo.value.title == "Invalid parameter"
    assert excinfo.value.description == "Username 'user' is taken"
    mock_async_tasks.send_verification.assert_not_called()


def test_on_post_success(mock_user_manager, mock_async_tasks, monkeypatch):
    resource = Signup(mock_user_manager, mock_async_tasks)
    body = valid_post_body()

    mock_user_manager.new.return_value = User(user_id=uuid.uuid4())

    def mock_hash(*, password, rounds):
        assert password == body["password"]
        assert rounds >= 12
        return "some hash"
    monkeypatch.setattr(passwords, "hash", mock_hash)

    req, resp = request(body=body), response()
    resource.on_post(req, resp)
    assert resp.status == falcon.HTTP_200
    mock_async_tasks.send_verification.assert_called_once_with("user")
    mock_user_manager.new.assert_called_once_with(body["username"], body["email"], "some hash")
