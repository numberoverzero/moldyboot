import pytest
import rq

from unittest.mock import Mock

from gaas.tasks import Scheduler
from gaas.tasks.email import send_verification_email


@pytest.fixture
def scheduler():
    queue = Mock(spec=rq.Queue)
    return Scheduler(queue)


def test_scheduler_send_email(scheduler):
    username = "foo-bar"
    scheduler.send_verification_email(username)
    scheduler.queue.enqueue.assert_called_with(send_verification_email, username)
