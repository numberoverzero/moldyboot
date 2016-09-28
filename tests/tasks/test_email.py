import pytest
import uuid

from unittest.mock import Mock

from gaas.controllers import InvalidParameter, NotFound
from gaas.models import User
from gaas.tasks.email import inject_dependencies, send_verification_email


@pytest.fixture
def render():
    return Mock()


@pytest.fixture(autouse=True)
def inject_mocks(boto3_session, mock_user_manager, render):
    inject_dependencies(session=boto3_session, user_manager=mock_user_manager, render=render)


@pytest.fixture
def ses(boto3_session):
    return boto3_session.client("ses")


def test_username_invalid(ses, mock_user_manager):
    port = 12345
    username = "-unknown+user"
    mock_user_manager.load_by_name.side_effect = InvalidParameter("username", username, "test message")

    send_verification_email(username, port)

    mock_user_manager.load_by_name.assert_called_once_with(username)
    ses.send_email.assert_not_called()


def test_username_not_found(ses, mock_user_manager):
    port = 12345

    username = "user"
    mock_user_manager.load_by_name.side_effect = NotFound

    send_verification_email(username, port)

    mock_user_manager.load_by_name.assert_called_once_with(username)
    ses.send_email.assert_not_called()


def test_already_verified(ses, mock_user_manager):
    port = 12345
    username = "user"
    # No verification_code
    mock_user_manager.load_by_name.return_value = User(user_id=uuid.uuid4(), email="user@domain.com")

    send_verification_email(username, port)

    mock_user_manager.load_by_name.assert_called_once_with(username)
    ses.send_email.assert_not_called()


def test_email_success(ses, mock_user_manager, render):
    port = 12345
    username = "user"
    user_id = uuid.uuid4()
    email = "user@domain.com"
    verification_code = uuid.uuid4()
    verification_url = "http://localhost:12345/verify/{}/{}".format(user_id, verification_code)
    user = User(user_id=user_id, verification_code=verification_code, email=email)
    mock_user_manager.load_by_name.return_value = user

    rendered = "stub render"
    render.return_value = rendered

    send_verification_email(username, port)

    mock_user_manager.load_by_name.assert_called_once_with(username)
    render.assert_any_call("verify-email.txt", username=username, verification_url=verification_url)
    render.assert_any_call("verify-email.html", username=username, verification_url=verification_url)
    ses.send_email.assert_called_once_with(**{
        "Source": "gaas-support@moldyboot.com",
        "Destination": {"ToAddresses": [email]},
        "Message": {
            "Subject": {"Data": "Please verify your email", "Charset": "UTF-8"},
            "Body": {
                "Text": {"Data": rendered, "Charset": "UTF-8"},
                "Html": {"Data": rendered, "Charset": "UTF-8"}
            }
        },
        "ReplyToAddresses": ["gaas-support@moldyboot.com"],
        "ReturnPath": "gaas-support+bounce@moldyboot.com"
    })
