import bcrypt
import pytest

from gaas.security.password import hash, check, BadPassword


def test_hash_small_rounds():
    with pytest.raises(BadPassword):
        hash("some password", 10)


def test_hash_str():
    password = "s3cr3t!"
    hashed = hash(password, 12).encode("utf-8")
    assert bcrypt.hashpw(password.encode("utf-8"), hashed) == hashed


def test_hash_bytes():
    password = b"s3cr3t!"
    hashed = hash(password, 12).encode("utf-8")
    assert bcrypt.hashpw(password, hashed) == hashed


def test_check_fails():
    password = b"hunter2"
    wrong_password = b"*******"
    expected_hash = bcrypt.hashpw(password, bcrypt.gensalt(12))

    with pytest.raises(BadPassword):
        check(wrong_password, expected_hash)


def test_check_str():
    password = "hunter2"
    expected_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")
    check(password, expected_hash)


def test_check_hash_and_check():
    password = "hunter2"
    hashed = hash(password, 12)
    check(password, hashed)
