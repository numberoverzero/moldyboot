import bloop
import gaas.models
import gaas.models.key
import gaas.middleware
import pytest
from Crypto.PublicKey import RSA


class MockEngine(bloop.Engine):
    # Lack of client is intentional - there should be no downstream calls
    def __init__(self, real_engine: bloop.Engine):
        self.real_engine = real_engine
        self.temp_config = []
        # Don't call super().__init__ since we don't want to set up a real client

    @property
    def type_engine(self):
        return self.real_engine.type_engine

    @property
    def model(self):
        return self.real_engine.model

    @property
    def unbound_models(self):
        return self.real_engine.unbound_models

    @property
    def models(self):
        return self.real_engine.models

    @property
    def config(self):
        return self.real_engine.config

    def context(self, **config):
        self.temp_config.append(config)
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.temp_config.pop()
        return False


class MockKeyManager:
    def __init__(self):
        self.captured_load_args = []
        self._responses = {}

    def load(self, user_id, key_id):
        self.captured_load_args.append([user_id, key_id])
        try:
            return self._responses[(user_id, key_id)]
        except KeyError:
            raise gaas.models.NotFound

    def respond(self, user_id, key_id, key):
        self._responses[(user_id, key_id)] = key

    @property
    def invoked(self):
        return bool(self.captured_load_args)


@pytest.fixture(scope="session")
def generate_key():
    """Returns a function for generating keys"""
    def _generate_key(bits=1024):
        """Returns private, public"""
        pair = RSA.generate(bits)
        return pair, pair.publickey()
    return _generate_key


@pytest.fixture(scope="session")
def crypto_pair(generate_key):
    return generate_key()


@pytest.fixture(scope="session")
def crypto_priv(crypto_pair):
    return crypto_pair[0]


@pytest.fixture(scope="session")
def crypto_pub(crypto_pair):
    return crypto_pair[1]


@pytest.yield_fixture
def mock_engine():
    mock_engine = MockEngine(gaas.models.engine)
    real_engine = gaas.models.engine

    # Replace references where engine is already imported
    gaas.models.engine = mock_engine
    gaas.models.key.engine = mock_engine

    yield mock_engine

    # Undo patch
    gaas.models.engine = real_engine
    gaas.models.key.engine = real_engine


@pytest.fixture
def key_manager():
    return MockKeyManager()


@pytest.fixture
def authentication_middleware(key_manager):
    return gaas.middleware.Authentication(key_manager)
