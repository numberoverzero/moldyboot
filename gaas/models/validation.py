import re
import uuid
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


def validate_uuid(value):
    try:
        return Result.of(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        return Result.error("must be a UUID")
validators["user_id"] = validate_uuid
validators["key_id"] = validate_uuid


def validate_authorization_header(signature):
    match = SIGNATURE_PATTERN.match(signature)
    if not match:
        return Result.error(SIGNATURE_PATTERN_HUMAN)
    return Result.of(match.groupdict())
validators["authorization_header"] = validate_authorization_header
