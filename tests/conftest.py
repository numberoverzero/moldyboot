import pytest
from Crypto.PublicKey import RSA


@pytest.fixture
def generate_key():
    """Returns a function for generating keys"""
    def _generate_key(bits=1024):
        """Returns private, public"""
        pair = RSA.generate(bits)
        return pair, pair.publickey()
    return _generate_key


@pytest.fixture
def crypto_pair(generate_key):
    return generate_key()


@pytest.fixture
def crypto_priv(crypto_pair):
    return crypto_pair[0]


@pytest.fixture
def crypto_pub(crypto_pair):
    return crypto_pair[1]
