import re
import uuid
from Crypto.PublicKey import RSA

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
    match = USERNAME_PATTERN.match(username)
    if not match:
        return Result.error("must start with a letter; only letters and digits; between 3 and 16 characters long")
    return Result.of(username)
validators["username"] = _validate_username


def _validate_public(public):
    if isinstance(public, RSA._RSAobj):
        return Result.of(public.publickey())
    try:
        return Result.of(RSA.importKey(public))
    except (ValueError, IndexError, TypeError):
        return Result.error("invalid format")
validators["public_key"] = _validate_public
