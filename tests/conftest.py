import bloop
import pytest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from unittest.mock import Mock

import gaas.controllers.key
import gaas.controllers.user
import gaas.middleware
import gaas.models
import gaas.models.key
import gaas.models.user
import gaas.tasks


@pytest.fixture(scope="session")
def generate_key():
    """Returns a function for generating keys"""
    return lambda bits=1024: rsa.generate_private_key(
        public_exponent=66537,
        key_size=bits,
        backend=default_backend()
    )


@pytest.fixture(scope="session")
def rsa_priv(generate_key):
    return generate_key()


@pytest.fixture(scope="session")
def rsa_pub(rsa_priv):
    return rsa_priv.public_key()


@pytest.fixture
def mock_engine():
    return Mock(spec=bloop.Engine)


@pytest.fixture
def mock_async_tasks():
    return Mock(spec=gaas.tasks.AsyncTasks)


@pytest.fixture
def mock_key_manager():
    return Mock(spec=gaas.controllers.key.KeyManager)


@pytest.fixture
def mock_user_manager():
    return Mock(spec=gaas.controllers.user.UserManager)


@pytest.fixture
def key_manager(mock_engine):
    return gaas.controllers.key.KeyManager(mock_engine)


@pytest.fixture
def user_manager(mock_engine):
    return gaas.controllers.user.UserManager(mock_engine)


@pytest.fixture
def authentication_middleware(mock_key_manager, mock_user_manager):
    return gaas.middleware.Authentication(mock_key_manager, mock_user_manager)


@pytest.fixture
def boto3_session():
    return Mock()
