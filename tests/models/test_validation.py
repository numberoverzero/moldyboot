import pytest
import uuid
from gaas.models.validation import validate, InvalidParameter


def test_validate_unknown_parameter():
    with pytest.raises(KeyError):
        validate("not a real parameter name", "unused value")


def test_validate_user_id():
    invalid = [
        None,
        "",
        "not a uuid",
    ]
    valid = [
        uuid.uuid1(),
        uuid.uuid4()
    ]

    for value in invalid:
        with pytest.raises(InvalidParameter) as excinfo:
            validate("user_id", value)
        exception = excinfo.value
        assert "user_id" == exception.parameter_name
        assert value == exception.value
        assert "must be a UUID" == exception.message

    for value in valid:
        same = validate("user_id", value)
        also_same = validate("user_id", str(value))
        assert value == same == also_same


def test_validate_authorization_header():
    invalid = [
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
        '''Signature headers="" id="@" signature=""   ''',
    ]
    valid = '''Signature headers="a" id="b@c" signature="d"'''

    for value in invalid:
        with pytest.raises(InvalidParameter) as excinfo:
            validate("authorization_header", value)
        assert "authorization_header" == excinfo.value.parameter_name
        assert value == excinfo.value.value

    expected = {
        "headers": "a",
        "user_id": "b",
        "key_id": "c",
        "signature": "d"}
    actual = validate("authorization_header", valid)
    assert actual == expected
