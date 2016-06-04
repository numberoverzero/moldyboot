import gaas.models
import gaas.models.key
import gaas.middleware
import pytest
from Crypto.PublicKey import RSA


class MockEngine:
    def __init__(self):
        self.captured_load_args = []
        self.captured_save_args = []
        self.captured_delete_args = []

    def on_load(self, item, *args, **kwargs):
        pass

    def load(self, item, *args, **kwargs):
        self.captured_load_args.append([item, args, kwargs])
        self.on_load(item, *args, **kwargs)

    def on_save(self, item, *args, **kwargs):
        pass

    def save(self, item, *args, **kwargs):
        self.captured_save_args.append([item, args, kwargs])
        self.on_save(item, *args, **kwargs)

    def on_delete(self, item, *args, **kwargs):
        pass

    def delete(self, item, *args, **kwargs):
        self.captured_delete_args.append([item, args, kwargs])
        self.on_delete(item, *args, **kwargs)


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


@pytest.fixture
def engine():
    return MockEngine()


@pytest.fixture
def key_manager():
    return MockKeyManager()


@pytest.fixture
def authentication_middleware(key_manager):
    return gaas.middleware.Authentication(key_manager)
