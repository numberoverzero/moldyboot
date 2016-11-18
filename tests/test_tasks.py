import pytest
import rq
import uuid

from gaas import templates
from gaas.config import api_endpoint
from gaas.controllers import InvalidParameter, NotFound, NotSaved
from gaas.models import Key, User, UserName
from gaas.tasks import AsyncTasks, RedisContext, Result, _delete_user, _send_verification


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


@pytest.fixture
def redis_context(mock_user_manager, mock_key_manager, boto3_session):
    RedisContext.initialize(
        user_manager=mock_user_manager,
        key_manager=mock_key_manager,
        session=boto3_session,
        endpoint=api_endpoint
    )


@pytest.yield_fixture(autouse=True)
def clear_redis_context():
    yield
    RedisContext.singleton = None


# Result ====================================================================================================== Result

def test_result_of():
    sentinel = object()
    result = Result.of(sentinel)
    assert result.value is sentinel


def test_result_empty():
    assert Result.empty.value is None


def test_result_failed_default():
    result = Result.failed()
    with pytest.raises(RuntimeError):
        getattr(result, "value")


def test_result_failed_custom():
    result = Result.failed(ValueError("hello"))
    with pytest.raises(ValueError) as excinfo:
        getattr(result, "value")
    assert excinfo.value.args == ("hello", )


# RedisContext ========================================================================================== RedisContext

def test_double_context_initialize(mock_user_manager, mock_key_manager, boto3_session):
    RedisContext.initialize(mock_user_manager, mock_key_manager, boto3_session, api_endpoint)
    with pytest.raises(RuntimeError):
        RedisContext.initialize(mock_user_manager, mock_key_manager, boto3_session, api_endpoint)


def test_not_initialized():
    with pytest.raises(RuntimeError):
        _send_verification("user")


# AsyncTasks ============================================================================================== AsyncTasks

def test_async_send_email(async_tasks, queue):
    """Ensure the request to send email is sent to the queue"""
    username = "user"
    async_tasks.send_verification(username)
    queue.enqueue.assert_called_with(_send_verification, username)


def test_async_delete_user(async_tasks, queue):
    """Ensure the request to delete a user is sent to the queue"""
    username = "user"
    async_tasks.delete_user(username)
    queue.enqueue.assert_called_with(_delete_user, username)


# send verification ================================================================================ send verification

def test_email_username_invalid(ses, mock_user_manager, redis_context):
    username = "-unknown+user"
    mock_user_manager.get_username.side_effect = InvalidParameter("username", username, "test message")

    _send_verification(username)

    mock_user_manager.get_username.assert_called_once_with(username)
    ses.send_email.assert_not_called()


def test_email_username_not_found(ses, mock_user_manager, redis_context):
    username = "user"
    mock_user_manager.get_username.side_effect = NotFound

    _send_verification(username)

    mock_user_manager.get_username.assert_called_once_with(username)
    ses.send_email.assert_not_called()


def test_email_already_verified(ses, mock_user_manager, redis_context):
    username = "user"
    user_id = uuid.uuid4()
    # No verification_code
    mock_user_manager.get_username.return_value = UserName(username=username, user_id=user_id)
    mock_user_manager.get_user.return_value = User(user_id=user_id, email="user@domain.com")

    _send_verification(username)

    mock_user_manager.get_username.assert_called_once_with(username)
    mock_user_manager.get_user.assert_called_once_with(user_id)
    ses.send_email.assert_not_called()


def test_email_success(ses, mock_user_manager, redis_context):
    username = "user"
    user_id = uuid.uuid4()
    email = "user@domain.com"
    verification_code = uuid.uuid4()
    verification_url = "{}/verify/{}/{}".format(api_endpoint.geturl(), user_id, verification_code)
    mock_user_manager.get_username.return_value = UserName(username=username, user_id=user_id)
    mock_user_manager.get_user.return_value = User(user_id=user_id,
                                                   verification_code=verification_code,
                                                   email=email)

    _send_verification(username)

    mock_user_manager.get_username.assert_called_once_with(username)
    mock_user_manager.get_user.assert_called_once_with(user_id)
    expected_txt = templates.render(
        "verify-email.txt",
        {"username": username, "verification_url": verification_url})
    expected_html = templates.render(
        "verify-email.html",
        {"username": username, "verification_url": verification_url})
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


# delete user ============================================================================================ delete user

def test_delete_user_invalid_username(mock_user_manager, mock_key_manager, redis_context):
    username = "-unknown+user"
    mock_user_manager.get_username.side_effect = InvalidParameter("username", username, "test message")

    _delete_user(username)

    mock_user_manager.get_username.assert_called_once_with(username)
    mock_user_manager.delete_user.assert_not_called()
    mock_key_manager.list_keys.assert_not_called()
    mock_key_manager.revoke.assert_not_called()


def test_delete_user_unknown_username(mock_user_manager, mock_key_manager, redis_context):
    username = "user"
    mock_user_manager.get_username.side_effect = NotFound

    _delete_user(username)

    mock_user_manager.get_username.assert_called_once_with(username)
    mock_user_manager.delete_user.assert_not_called()
    mock_key_manager.list_keys.assert_not_called()
    mock_key_manager.revoke.assert_not_called()


def test_delete_user_not_exists(mock_user_manager, mock_key_manager, redis_context):
    username = "user"
    user_id = uuid.uuid4()
    mock_user_manager.get_username.return_value = UserName(username=username, user_id=user_id)
    mock_user_manager.delete_user.side_effect = NotSaved(object())

    _delete_user(username)

    mock_user_manager.get_username.assert_called_once_with(username)
    mock_user_manager.delete_user.assert_called_once_with(user_id)
    mock_key_manager.list_keys.assert_not_called()
    mock_key_manager.revoke.assert_not_called()


def test_delete_user_keys(mock_user_manager, mock_key_manager, redis_context):
    username = "user"
    user_id = uuid.uuid4()
    first_key_id = uuid.uuid4()
    second_key_id = uuid.uuid4()
    keys = [
        Key(user_id=user_id, key_id=first_key_id),
        Key(user_id=user_id, key_id=second_key_id)
    ]
    mock_user_manager.get_username.return_value = UserName(username=username, user_id=user_id)
    mock_key_manager.list_keys.return_value = keys
    mock_key_manager.revoke.side_effect = [NotSaved(keys[0]), keys[1]]

    _delete_user(username)

    mock_user_manager.get_username.assert_called_once_with(username)
    mock_user_manager.delete_user.assert_called_once_with(user_id)
    mock_key_manager.list_keys.assert_called_once_with(user_id)
    assert mock_key_manager.revoke.call_count == 2
