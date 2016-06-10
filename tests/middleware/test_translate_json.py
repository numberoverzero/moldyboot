import falcon
import falcon.testing
import io
import json
import pytest

import helpers

from unittest.mock import Mock

from gaas.middleware.translate_json import BodyWrapper, TranslateJSON


def stream(string: str):
    return io.BytesIO(string.encode("utf-8"))


def bytes_json(blob: dict):
    return json.dumps(blob).encode("utf-8")


def env_with(string: str):
    return helpers.build_env("get", "/path", dict(), string)


def test_single_read():
    mock_stream = Mock(spec=io.BytesIO)
    mock_stream.read.return_value = bytes_json({"key": "value"})

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


def test_json_middleware():
    class Resource:
        def on_get(self, req, resp):
            blob = req.context["body"].json
            if blob["respond_json"]:
                req.context["response"] = {"hello": "world"}
            else:
                resp.body = "hello world"
            return falcon.HTTP_200

    api = falcon.API(middleware=[TranslateJSON()])
    api.add_route("/path", Resource())

    # req.context["response"] is serialized
    env = env_with(json.dumps({"respond_json": True}))
    response = falcon.testing.StartResponseMock()
    response_body = api(env, response)
    assert response_body[0] == b'''{"hello": "world"}'''

    # no req.context["response"] to serialize
    env = env_with(json.dumps({"respond_json": False}))
    response = falcon.testing.StartResponseMock()

    response_body = api(env, response)
    assert response_body[0] == b"hello world"
