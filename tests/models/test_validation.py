import pytest
import uuid
from gaas.models.validation import validate, InvalidParameter


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


@pytest.mark.parametrize("parameter_name", ["user_id", "key_id"])
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
