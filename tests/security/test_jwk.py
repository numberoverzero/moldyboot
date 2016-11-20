from gaas.security.jwk import dump_public_key, load_public_key

from cryptography.hazmat.backends import default_backend

from tests.helpers import as_der


def test_public_key(rsa_pub):
    """round trip public key through jwk"""
    public_jwk = dump_public_key(rsa_pub)
    same_pub = load_public_key(public_jwk, backend=default_backend())
    assert as_der(rsa_pub) == as_der(same_pub)
