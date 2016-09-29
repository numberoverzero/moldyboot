import bcrypt
import pytest

from gaas.security.passwords import BadPassword, check, hash


def test_hash_small_rounds():
    with pytest.raises(BadPassword):
        hash(password="some password", rounds=10)


def test_hash_str():
    password = "s3cr3t!"
    hashed = hash(password=password, rounds=12)
    assert bcrypt.hashpw(password.encode("utf-8"), hashed) == hashed


def test_hash_bytes():
    password = b"s3cr3t!"
    hashed = hash(password=password, rounds=12)
    assert bcrypt.hashpw(password, hashed) == hashed


def test_check_fails():
    password = b"hunter2"
    wrong_password = b"*******"
    expected_hash = bcrypt.hashpw(password, bcrypt.gensalt(12))

    with pytest.raises(BadPassword):
        check(password=wrong_password, expected_hash=expected_hash)


def test_check_str():
    password = "hunter2"
    expected_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")
    check(password=password, expected_hash=expected_hash)


def test_check_hash_and_check():
    password = "hunter2"
    hashed = hash(password=password, rounds=12)
    check(password=password, expected_hash=hashed)
