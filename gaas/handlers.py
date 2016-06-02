from .models import NotFound
from .models.key import Key
from .signing import verify, BadSignature
from typing import Sequence, Dict, Optional
import re
import uuid

# Signature headers="{}" keyId="{}" signature="{}"
SIGNATURE_PATTERN = re.compile(
    """
    ^
    Signature
    \s
    headers="(?P<headers>[^"]*)"
    \s
    id="(?P<id>[^"]*)"
    \s
    signature="(?P<signature>[^"]*)"
    $
    """, re.VERBOSE)
SIGNATURE_PATTERN_HUMAN = """^Signature headers="([^"]*)" id="([^"]*)" signature="([^"]*)"$"""


class Unauthorized(Exception):
    pass


def authenticate(
        method: str,
        path: str,
        headers: Dict,
        body: Optional[str],
        headers_to_sign: Sequence[str]):
    # 1) Check authorization header format
    if "authorization" not in headers:
        raise Unauthorized("Must provide 'authorization' header")
    authentication = SIGNATURE_PATTERN.match(headers["authorization"])
    if not authentication:
        raise Unauthorized("Authorization header did not match required pattern {}".format(SIGNATURE_PATTERN_HUMAN))
    authentication = authentication.groupdict()
    # 2) Check user_id, key_id format
    try:
        user_id, key_id = authentication["id"].split("@")
    except ValueError:
        raise Unauthorized("Authorization 'id' does not match USER@KEYID format")
    try:
        user_id = uuid.UUID(user_id)
    except ValueError:
        raise Unauthorized("Authorization id USER must be a uuid")
    try:
        key_id = uuid.UUID(key_id)
    except ValueError:
        raise Unauthorized("Authorization id KEYID must be a uuid")

    # 3) Check public key
    try:
        key = Key.load(user_id=user_id, key_id=key_id)
    except NotFound:
        # Didn't find a key
        raise Unauthorized("Unknown USER, KEYID ({}, {})".format(user_id, key_id))
    if key.expired:
        # Effectively the same as not finding it
        key.revoke()
        raise Unauthorized("Unknown USER, KEYID ({}, {})".format(user_id, key_id))

    # 4) Check signature
    try:
        verify(
            method, path, headers, body,
            key.public, authentication["signature"],
            authentication["headers"].split(" "),
            headers_to_sign)
    except BadSignature as exception:
        raise Unauthorized("Signature validation failed: {}".format(exception.args[0]))

    # Success!
    key.refresh()

    # Let callers know who was just authenticated
    return user_id
