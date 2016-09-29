import re
import uuid

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import serialization

validators = {}
__all__ = ["validate", "InvalidParameter"]


# Signature headers="{}" id="{}" signature="{}"
SIGNATURE_PATTERN = re.compile(
    """
    ^
    Signature
    \s
    headers="(?P<headers>[^"]*)"
    \s
    id="(?P<user_id>[^@"]*)@(?P<key_id>[^"]*)"
    \s
    signature="(?P<signature>[^"]*)"
    $
    """, re.VERBOSE)
SIGNATURE_PATTERN_HUMAN = """^Signature headers="([^"]*)" id="([^@"]*)@([^"]*)" signature="([^"]*)"$"""
# maximum 16 characters, must start with an alphabetic.  lower, upper, digits only.
USERNAME_PATTERN = re.compile("^[a-zA-Z][a-zA-Z0-9]{2,15}$")
# $2b$\d\d$[53 non-standard base64]
BCRYPT_HASH_PATTERN = re.compile(b"^\$2b\$\d\d\$[a-zA-Z0-9/.]{53}$")


class Result:
    def __init__(self, *, value, error):
        self.value = value
        self.error = error

    @classmethod
    def of(cls, value):
        return cls(value=value, error=None)

    @classmethod
    def error(cls, err):
        return cls(value=None, error=err)


class InvalidParameter(Exception):
    def __init__(self, parameter_name, value, message):
        super().__init__(parameter_name, value, message)
        self.parameter_name = parameter_name
        self.value = value
        self.message = message


def validate(parameter_name, value):
    result = validators[parameter_name](value)
    if result.error:
        raise InvalidParameter(parameter_name, value, result.error)
    return result.value


def _validate_uuid(value):
    if isinstance(value, uuid.UUID):
        return Result.of(value)
    try:
        return Result.of(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        return Result.error("must be a UUID")
validators["user_id"] = _validate_uuid
validators["key_id"] = _validate_uuid
validators["verification_code"] = _validate_uuid


def _validate_authorization_header(signature):
    match = SIGNATURE_PATTERN.match(signature)
    if not match:
        return Result.error(SIGNATURE_PATTERN_HUMAN)
    return Result.of(match.groupdict())
validators["authorization_header"] = _validate_authorization_header


def _validate_email(email):
    if "@" not in email or len(email) < 3:
        return Result.error("must contain @ and be at least 3 characters")
    return Result.of(email)
validators["email"] = _validate_email


def _validate_username(username):
    if not USERNAME_PATTERN.match(username):
        return Result.error("must start with a letter; only letters and digits; between 3 and 16 characters long")
    return Result.of(username)
validators["username"] = _validate_username


def _validate_public_key(public):
    if isinstance(public, RSAPublicKey):
        return Result.of(public)
    if isinstance(public, str):
        public = public.encode("utf-8")
    for loader in [
        serialization.load_pem_public_key,
        serialization.load_der_public_key,
        serialization.load_ssh_public_key
    ]:
        try:
            return Result.of(loader(
                data=public,
                backend=default_backend()
            ))
        except (ValueError, UnsupportedAlgorithm):
            continue
    return Result.error("Malformed public key")

validators["public_key"] = _validate_public_key


def _validate_password_hash(password_hash):
    if isinstance(password_hash, str):
        password_hash = password_hash.encode("utf-8")
    if not BCRYPT_HASH_PATTERN.match(password_hash):
        return Result.error("Must be a password hash (did you forget to bcrypt?)")
    return Result.of(password_hash)
validators["password_hash"] = _validate_password_hash
