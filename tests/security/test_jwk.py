from moldyboot.security.jwk import (
    dump_private_key,
    dump_public_key,
    load_private_key,
    load_public_key,
)

from cryptography.hazmat.backends import default_backend


def test_public_key(rsa_pub):
    """round trip public key through jwk"""
    public_jwk = dump_public_key(rsa_pub)
    same_pub = load_public_key(public_jwk, backend=default_backend())
    assert rsa_pub.public_numbers() == same_pub.public_numbers()


def test_private_key(rsa_priv):
    """round trip private key through jwk"""
    private_jwk = dump_private_key(rsa_priv)
    same_priv = load_private_key(private_jwk, backend=default_backend())
    assert rsa_priv.private_numbers() == same_priv.private_numbers()
