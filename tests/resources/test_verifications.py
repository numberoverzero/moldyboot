import uuid

import falcon
import pytest

from moldyboot.controllers import InvalidParameter, NotFound, NotSaved
from moldyboot.models import User
from moldyboot.resources.verifications import Verifications
from tests.helpers import request, response


def test_on_get_invalid_user_id(mock_user_manager):
    req, resp = request(), response()
    resource = Verifications(mock_user_manager)

    user_id = "not a uuid"
    code = uuid.uuid4()

    mock_user_manager.get_user.side_effect = InvalidParameter("user_id", user_id, "test message")

    with pytest.raises(falcon.HTTPBadRequest) as excinfo:
        resource.on_get(req, resp, user_id, code)
    assert excinfo.value.title == "Bad Request"
    assert excinfo.value.description == "user_id must be a uuid but was '{}'".format(user_id)
    mock_user_manager.get_user.assert_called_once_with(user_id)


def test_on_get_unknown_user_id(mock_user_manager):
    req, resp = request(), response()
    resource = Verifications(mock_user_manager)

    user_id = uuid.uuid4()
    code = uuid.uuid4()

    mock_user_manager.get_user.side_effect = NotFound(object())

    with pytest.raises(falcon.HTTPBadRequest) as excinfo:
        resource.on_get(req, resp, user_id, code)
    assert excinfo.value.title == "Bad Request"
    assert excinfo.value.description == "unknown user_id '{}'".format(user_id)
    mock_user_manager.get_user.assert_called_once_with(user_id)


def test_on_get_invalid_verification_code(mock_user_manager):
    req, resp = request(), response()
    resource = Verifications(mock_user_manager)

    user_id = uuid.uuid4()
    code = "not a uuid"

    user = User(user_id=user_id)
    mock_user_manager.get_user.return_value = user
    mock_user_manager.verify.side_effect = InvalidParameter("verification_code", code, "test message")

    with pytest.raises(falcon.HTTPBadRequest) as excinfo:
        resource.on_get(req, resp, user_id, code)
    assert excinfo.value.title == "Bad Request"
    assert excinfo.value.description == "verification_code must be a uuid but was '{}'".format(code)
    mock_user_manager.get_user.assert_called_once_with(user_id)
    mock_user_manager.verify.assert_called_once_with(user, code)


def test_on_get_verification_code_mismatch(mock_user_manager):
    req, resp = request(), response()
    resource = Verifications(mock_user_manager)

    user_id = uuid.uuid4()
    code = uuid.uuid4()

    user = User(user_id=user_id)
    mock_user_manager.get_user.return_value = user
    mock_user_manager.verify.side_effect = NotSaved(user)

    with pytest.raises(falcon.HTTPBadRequest) as excinfo:
        resource.on_get(req, resp, user_id, code)
    assert excinfo.value.title == "Bad Request"
    assert excinfo.value.description == "verification code doesn't match"
    mock_user_manager.get_user.assert_called_once_with(user_id)
    mock_user_manager.verify.assert_called_once_with(user, code)


def test_on_get_verification_success(mock_user_manager):
    req, resp = request(), response()
    resource = Verifications(mock_user_manager)

    user_id = uuid.uuid4()
    code = uuid.uuid4()

    user = User(user_id=user_id)
    mock_user_manager.get_user.return_value = user

    resource.on_get(req, resp, user_id, code)
    assert resp.status == falcon.HTTP_200
    mock_user_manager.get_user.assert_called_once_with(user_id)
    mock_user_manager.verify.assert_called_once_with(user, code)
