import falcon
import falcon.testing
import falcon.testing.resource
import io
import json
import sys
import uritools

from cryptography.hazmat.primitives import serialization

from gaas.middleware import BodyWrapper
from gaas.security import signatures


def build_env(method="GET", uri="/", headers=None, body=""):
    uri = uritools.urisplit(uri)
    path = uri.path
    query = uri.query or ""
    scheme = uri.scheme or "https"
    port = uri.port or ("80" if scheme == "http" else "443")
    host = uri.host or "host-placeholder.com"
    if isinstance(body, (list, dict)):
        body = json.dumps(body)
    body = (body or "").encode("utf-8")
    headers = headers or {}
    env = {
        "CONTENT_LENGTH": str(len(body)),
        "HTTP_HOST": host + ":" + port,
        "HTTP_USER_AGENT": "host-agent-placeholder",
        "PATH_INFO": path,
        "QUERY_STRING": query or "",
        "RAW_URI": "/",
        "REMOTE_ADDR": "127.0.0.1",
        "REMOTE_PORT": "65432",
        "REQUEST_METHOD": method.upper(),
        "SCRIPT_NAME": "",
        "SERVER_NAME": host,
        "SERVER_PORT": port,
        "SERVER_PROTOCOL": "HTTP/1.1",
        "SERVER_SOFTWARE": "server-software-placeholder",

        "wsgi.version": (1, 0),
        "wsgi.url_scheme": scheme,
        "wsgi.input": io.BytesIO(body),
        "wsgi.errors": sys.stderr,
        "wsgi.multithread": False,
        "wsgi.multiprocess": True,
        "wsgi.run_once": False
    }
    for key, value in headers.items():
        key = key.upper().replace("-", "_")
        value = (value or "").strip()
        if key == "CONTENT_LENGTH" or key == "CONTENT_TYPE":
            env[key] = value
        else:
            env["HTTP_" + key] = value

    return env


def request(method="GET", uri="/", headers=None, body="", inject_body_context=True):
    """If inject_body_context, set req.context["body"] to a BodyWrapper, as TranslateJSON would"""
    req = falcon.Request(build_env(method, uri, headers, body))
    if inject_body_context:
        req.context["body"] = BodyWrapper(req.stream)
    return req


def signed_request(method="GET", uri="/", headers=None, body="", private_key=None, key_id=None):
    headers = headers or dict()
    signatures.sign(method, uri, headers, body, private_key, key_id)
    return request(method, uri, headers, body)


def response():
    return falcon.Response()


class MockResource(falcon.testing.SimpleTestResource):
    @falcon.before(falcon.testing.capture_responder_args)
    @falcon.before(falcon.testing.resource.set_resp_defaults)
    def on_post(self, req, resp, **kwargs):
        pass


def as_der(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
