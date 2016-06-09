import bcrypt
from typing import Union


class BadPassword(Exception):
    pass


def hash(password: Union[str, bytes], rounds):
    if rounds < 12:
        raise BadPassword("Tried to generate weak salt with < 12 rounds")
    if isinstance(password, str):
        password = password.encode("utf-8")
    hashed = bcrypt.hashpw(password, bcrypt.gensalt(rounds))
    return hashed


def check(password: Union[str, bytes], expected_hash: Union[str, bytes]):
    if isinstance(password, str):
        password = password.encode("utf-8")
    if isinstance(expected_hash, str):
        expected_hash = expected_hash.encode("utf-8")
    matches = bcrypt.hashpw(password, expected_hash) == expected_hash
    if not matches:
        raise BadPassword("Password does not match expected_hash")
