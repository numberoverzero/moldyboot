import pytest
import rq
import uuid

from gaas.config import api_endpoint
from gaas.controllers import InvalidParameter, NotFound
from gaas.models import User
from gaas.tasks import AsyncTasks, RedisContext, _send_verification
from gaas.templates import render

from unittest.mock import Mock


@pytest.fixture
def queue():
    return Mock(spec=rq.Queue)


@pytest.fixture
def ses(boto3_session):
    return boto3_session.client("ses")


@pytest.fixture
def async_tasks(queue):
    return AsyncTasks(queue)


@pytest.yield_fixture
def redis_context(mock_user_manager, boto3_session):
    RedisContext.initialize(mock_user_manager, boto3_session, api_endpoint)
    yield RedisContext.singleton
    RedisContext.singleton = None


def test_scheduler_send_email(async_tasks, queue):
    """Ensure the request to send email is sent to the queue"""
    username = "user"
    async_tasks.send_verification(username)
    queue.enqueue.assert_called_with(_send_verification, username)


def test_username_invalid(ses, mock_user_manager, redis_context):
    username = "-unknown+user"
    mock_user_manager.load_by_name.side_effect = InvalidParameter("username", username, "test message")

    _send_verification(username)

    mock_user_manager.load_by_name.assert_called_once_with(username)
    ses.send_email.assert_not_called()


def test_username_not_found(ses, mock_user_manager, redis_context):
    username = "user"
    mock_user_manager.load_by_name.side_effect = NotFound

    _send_verification(username)

    mock_user_manager.load_by_name.assert_called_once_with(username)
    ses.send_email.assert_not_called()


def test_already_verified(ses, mock_user_manager, redis_context):
    username = "user"
    # No verification_code
    mock_user_manager.load_by_name.return_value = User(user_id=uuid.uuid4(), email="user@domain.com")

    _send_verification(username)

    mock_user_manager.load_by_name.assert_called_once_with(username)
    ses.send_email.assert_not_called()


def test_email_success(ses, mock_user_manager, redis_context):
    username = "user"
    user_id = uuid.uuid4()
    email = "user@domain.com"
    verification_code = uuid.uuid4()
    verification_url = "{}/verify/{}/{}".format(api_endpoint.geturl(), user_id, verification_code)
    user = User(user_id=user_id, verification_code=verification_code, email=email)
    mock_user_manager.load_by_name.return_value = user

    _send_verification(username)

    mock_user_manager.load_by_name.assert_called_once_with(username)
    expected_txt = render("verify-email.txt", username=username, verification_url=verification_url)
    expected_html = render("verify-email.html", username=username, verification_url=verification_url)
    ses.send_email.assert_called_once_with(**{
        "Source": "gaas-support@moldyboot.com",
        "Destination": {"ToAddresses": [email]},
        "Message": {
            "Subject": {"Data": "Please verify your email", "Charset": "UTF-8"},
            "Body": {
                "Text": {"Data": expected_txt, "Charset": "UTF-8"},
                "Html": {"Data": expected_html, "Charset": "UTF-8"}
            }
        },
        "ReplyToAddresses": ["gaas-support@moldyboot.com"],
        "ReturnPath": "gaas-support+bounce@moldyboot.com"
    })
