import functools
import io
import json
import pytest

from ..helpers import request, response

from unittest.mock import Mock

from gaas.middleware.translate_json import BodyWrapper, TranslateJSON

# This patch is because every other middleware/request test will want to configure req.context["body"] as if
# TranslateJSON processed the body.  To test this middleware, though, we set inject_body_context to false.
request = functools.partial(request, inject_body_context=False)


def stream(string: str):
    return io.BytesIO(string.encode("utf-8"))


def test_single_read():
    mock_stream = Mock(spec=io.BytesIO)
    mock_stream.read.return_value = json.dumps({"key": "value"}).encode("utf-8")

    body = BodyWrapper(mock_stream)
    assert body.json == {"key": "value"}
    # Uses cached value
    assert body.json == {"key": "value"}
    mock_stream.read.assert_called_once_with()


def test_empty_body():
    body = BodyWrapper(stream(""))
    assert body.str == ""
    assert body.json == dict()


def test_empty_json():
    body = BodyWrapper(stream(json.dumps({})))
    assert body.str == "{}"
    assert body.json == dict()


def test_not_json():
    body = BodyWrapper(stream("not json"))

    # We're fine as long as we never inspect it as json
    assert body.str == "not json"

    with pytest.raises(ValueError):
        body.json


def test_magic_str_raises():
    """Because __str__ is ambiguous (did you want the dumped json?  not equal for an empty string; refuse to guess"""
    body = BodyWrapper(stream(json.dumps({"key": "value"})))
    with pytest.raises(AttributeError):
        str(body)


def test_json_middleware_req():
    blob = {"hello": "world"}
    req, resp = request(body=blob), response()

    middleware = TranslateJSON()
    middleware.process_request(req, resp)

    assert req.context["body"].str == json.dumps(blob)
    assert req.context["body"].json == blob


def test_json_middleware_resp_json():
    blob = {"hello": "world"}
    middleware = TranslateJSON()
    req, resp, resource = request(), response(), object()
    req.context["response"] = blob

    middleware.process_response(req, resp, resource)

    assert resp.body == json.dumps(blob)


def test_json_middleware_resp_empty():
    middleware = TranslateJSON()
    req, resp, resource = request(), response(), object()
    resp.body = "placeholder"

    middleware.process_response(req, resp, resource)

    # middleware didn't modify the body since there was no "response" in the req
    assert resp.body == "placeholder"
