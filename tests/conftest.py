import bloop
import gaas.models
import gaas.models.key
import gaas.models.user
import gaas.middleware
import pytest
from unittest.mock import Mock
from Crypto.PublicKey import RSA


@pytest.fixture(scope="session")
def generate_key():
    """Returns a function for generating keys"""
    def _generate_key(bits=1024):
        """Returns private, public"""
        pair = RSA.generate(bits)
        return pair, pair.publickey()
    return _generate_key


@pytest.fixture(scope="session")
def rsa_pair(generate_key):
    return generate_key()


@pytest.fixture(scope="session")
def rsa_priv(rsa_pair):
    return rsa_pair[0]


@pytest.fixture(scope="session")
def rsa_pub(rsa_pair):
    return rsa_pair[1]


@pytest.fixture
def mock_engine():
    return Mock(spec=bloop.Engine)


@pytest.fixture
def mock_key_manager():
    return Mock(spec=gaas.models.key.KeyManager)


@pytest.fixture
def key_manager(mock_engine):
    return gaas.models.key.KeyManager(mock_engine)


@pytest.fixture
def user_manager(mock_engine):
    return gaas.models.user.UserManager(mock_engine)


@pytest.fixture
def authentication_middleware(mock_key_manager):
    return gaas.middleware.Authentication(mock_key_manager)
