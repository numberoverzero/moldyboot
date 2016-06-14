import base64
import uuid

import bcrypt
import pytest

from gaas.controllers import InvalidParameter, validate

valid_uuids = [
    uuid.uuid1(),
    uuid.uuid4()
]

invalid_uuids = [
    None,
    "",
    "not a uuid",
]

valid_usernames = ["abc", "aaa", "a00"]
invalid_usernames = ["", "aa", "ab!", "0ab"]

invalid_emails = ["", "a@", "@a", "aaa"]
valid_emails = ["a@c", "!@!", "@@@"]


invalid_signatures = [
    "",
    # missing sections
    '''Signature headers="" id="@"''',
    '''Signature headers="" signature=""''',
    '''Signature id="@" signature=""''',
    # out of order
    '''Signature id="@" headers="" signature=""''',
    # capitalization
    '''Signature HEADERS="" ID="@" SIGNATURE=""''',
    # quote style
    """Signature headers='' id='@' signature=''""",
    # bad id
    '''Signature headers="" id="" signature=""''',
    # extra whitespace
    '''   Signature headers="" id="@" signature=""''',
    '''Signature headers=""    id="@" signature=""''',
    '''Signature headers="" id="@" signature=""   '''
]


def test_validate_unknown_parameter():
    with pytest.raises(KeyError):
        validate("not a real parameter name", "unused value")


@pytest.mark.parametrize("parameter_name", ["user_id", "key_id", "verification_code"])
@pytest.mark.parametrize("valid_uuid", valid_uuids)
def test_valid_uuid(parameter_name, valid_uuid):
    same = validate(parameter_name, valid_uuid)
    also_same = validate(parameter_name, str(valid_uuid))
    assert valid_uuid == same == also_same


@pytest.mark.parametrize("parameter_name", ["user_id", "key_id"])
@pytest.mark.parametrize("invalid_uuid", invalid_uuids)
def test_invalid_uuid(parameter_name, invalid_uuid):
    with pytest.raises(InvalidParameter) as excinfo:
        validate(parameter_name, invalid_uuid)
    exception = excinfo.value
    assert parameter_name == exception.parameter_name
    assert invalid_uuid == exception.value
    assert "must be a UUID" == exception.message


@pytest.mark.parametrize("invalid_signature", invalid_signatures)
def test_invalid_authorization_header(invalid_signature):
    with pytest.raises(InvalidParameter) as excinfo:
        validate("authorization_header", invalid_signature)
    assert "authorization_header" == excinfo.value.parameter_name
    assert invalid_signature == excinfo.value.value


def test_valid_authorization_header():
    valid = '''Signature headers="a" id="b@c" signature="d"'''
    expected = {
        "headers": "a",
        "user_id": "b",
        "key_id": "c",
        "signature": "d"}
    actual = validate("authorization_header", valid)
    assert actual == expected


@pytest.mark.parametrize("valid_email", valid_emails)
def test_valid_email(valid_email):
    assert validate("email", valid_email) == valid_email


@pytest.mark.parametrize("invalid_email", invalid_emails)
def test_invalid_email(invalid_email):
    with pytest.raises(InvalidParameter) as excinfo:
        validate("email", invalid_email)
    assert "email" == excinfo.value.parameter_name


@pytest.mark.parametrize("valid_username", valid_usernames)
def test_valid_username(valid_username):
    assert validate("username", valid_username) == valid_username


@pytest.mark.parametrize("invalid_username", invalid_usernames)
def test_invalid_username(invalid_username):
    with pytest.raises(InvalidParameter) as excinfo:
        validate("username", invalid_username)
    assert "username" == excinfo.value.parameter_name


def test_valid_public_key(rsa_pub):
    valid_keys = [
        rsa_pub,
        rsa_pub.exportKey("DER"),
        rsa_pub.exportKey("PEM"),
        rsa_pub.exportKey("PEM").decode("utf-8")
    ]
    for valid_key in valid_keys:
        assert validate("public_key", valid_key) == rsa_pub


def test_invalid_public_key(rsa_pub):
    # base64 of DER encoding fails (just use PEM)
    encoded_bytes = base64.b64encode(rsa_pub.exportKey("DER"))

    invalid_keys = [
        encoded_bytes,
        encoded_bytes.decode("utf-8"),  # as string
        "",
        b""
    ]

    for invalid_key in invalid_keys:
        with pytest.raises(InvalidParameter) as excinfo:
            validate("public_key", invalid_key)
        assert "public_key" == excinfo.value.parameter_name


def test_valid_password_hash():
    hash = bcrypt.hashpw(b"hunter2", bcrypt.gensalt(4))
    assert hash == validate("password_hash", hash)
    assert hash == validate("password_hash", hash.decode("utf-8"))


def test_invalid_password_hash():
    invalid_hashes = [
        "$2a$06$" + "a"*53,  # Wrong type (2a, not 2b)
        "$2b$aa$" + "a"*53,  # rounds must be decimals
        "$2b$06$" + "a"*52,  # Wrong salt+hash length
        "$2b$o6$" + "a"*54,  # Wrong salt+hash length
        "$2b$o6$" + "?"*53,  # Invalid base64 character
        "$2b$o6$" + "+"*53,  # Nonstandard b64 doesn't include +
    ]

    for invalid_hash in invalid_hashes:
        with pytest.raises(InvalidParameter) as excinfo:
            validate("password_hash", invalid_hash)
        assert "password_hash" == excinfo.value.parameter_name
