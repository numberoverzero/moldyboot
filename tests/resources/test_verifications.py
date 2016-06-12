import falcon
import pytest
import uuid

from helpers import request, response

from gaas.models import InvalidParameter, NotFound, NotSaved, User
from gaas.resources import Verifications


def test_on_get_invalid_user_id(mock_user_manager):
    req, resp = request(), response()
    resource = Verifications(mock_user_manager)

    user_id = "not a uuid"
    code = uuid.uuid4()

    mock_user_manager.load_by_id.side_effect = InvalidParameter("user_id", user_id, "test message")

    with pytest.raises(falcon.HTTPBadRequest) as excinfo:
        resource.on_get(req, resp, user_id, code)
    assert excinfo.value.title == "Bad Request"
    assert excinfo.value.description == "user_id must be a uuid but was '{}'".format(user_id)
    mock_user_manager.load_by_id.assert_called_once_with(user_id)


def test_on_get_unknown_user_id(mock_user_manager):
    req, resp = request(), response()
    resource = Verifications(mock_user_manager)

    user_id = uuid.uuid4()
    code = uuid.uuid4()

    mock_user_manager.load_by_id.side_effect = NotFound(object())

    with pytest.raises(falcon.HTTPBadRequest) as excinfo:
        resource.on_get(req, resp, user_id, code)
    assert excinfo.value.title == "Bad Request"
    assert excinfo.value.description == "unknown user_id '{}'".format(user_id)
    mock_user_manager.load_by_id.assert_called_once_with(user_id)


def test_on_get_invalid_verification_code(mock_user_manager):
    req, resp = request(), response()
    resource = Verifications(mock_user_manager)

    user_id = uuid.uuid4()
    code = "not a uuid"

    user = User(user_id=user_id)
    mock_user_manager.load_by_id.return_value = user
    mock_user_manager.verify.side_effect = InvalidParameter("verification_code", code, "test message")

    with pytest.raises(falcon.HTTPBadRequest) as excinfo:
        resource.on_get(req, resp, user_id, code)
    assert excinfo.value.title == "Bad Request"
    assert excinfo.value.description == "verification_code must be a uuid but was '{}'".format(code)
    mock_user_manager.load_by_id.assert_called_once_with(user_id)
    mock_user_manager.verify.assert_called_once_with(user, code)


def test_on_get_verification_code_mismatch(mock_user_manager):
    req, resp = request(), response()
    resource = Verifications(mock_user_manager)

    user_id = uuid.uuid4()
    code = uuid.uuid4()

    user = User(user_id=user_id)
    mock_user_manager.load_by_id.return_value = user
    mock_user_manager.verify.side_effect = NotSaved(user)

    with pytest.raises(falcon.HTTPBadRequest) as excinfo:
        resource.on_get(req, resp, user_id, code)
    assert excinfo.value.title == "Bad Request"
    assert excinfo.value.description == "verification code doesn't match"
    mock_user_manager.load_by_id.assert_called_once_with(user_id)
    mock_user_manager.verify.assert_called_once_with(user, code)


def test_on_get_verification_success(mock_user_manager):
    req, resp = request(), response()
    resource = Verifications(mock_user_manager)

    user_id = uuid.uuid4()
    code = uuid.uuid4()

    user = User(user_id=user_id)
    mock_user_manager.load_by_id.return_value = user

    resource.on_get(req, resp, user_id, code)
    mock_user_manager.load_by_id.assert_called_once_with(user_id)
    mock_user_manager.verify.assert_called_once_with(user, code)
