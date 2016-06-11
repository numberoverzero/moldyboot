import bloop
import pytest

from Crypto.PublicKey import RSA
from unittest.mock import Mock

import gaas.middleware
import gaas.models
import gaas.models.key
import gaas.models.user


@pytest.fixture(scope="session")
def generate_key():
    """Returns a function for generating keys"""
    return lambda bits=1024: RSA.generate(bits)


@pytest.fixture(scope="session")
def rsa_priv(generate_key):
    return generate_key()


@pytest.fixture(scope="session")
def rsa_pub(rsa_priv):
    return rsa_priv.publickey()


@pytest.fixture
def mock_engine():
    return Mock(spec=bloop.Engine)


@pytest.fixture
def mock_key_manager():
    return Mock(spec=gaas.models.key.KeyManager)


@pytest.fixture
def mock_user_manager():
    return Mock(spec=gaas.models.user.UserManager)


@pytest.fixture
def key_manager(mock_engine):
    return gaas.models.key.KeyManager(mock_engine)


@pytest.fixture
def user_manager(mock_engine):
    return gaas.models.user.UserManager(mock_engine)


@pytest.fixture
def authentication_middleware(mock_key_manager, mock_user_manager):
    return gaas.middleware.Authentication(mock_key_manager, mock_user_manager)
