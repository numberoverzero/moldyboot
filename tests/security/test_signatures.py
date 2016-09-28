import arrow
import base64
import pytest
import re

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from gaas.security.signatures import BadSignature, sign, verify

PATH = "/some/path/?query=string&another=value"
SIGNATURE_PATTERN = re.compile(
    """^Signature headers="(?P<headers>[^"]*)" id="(?P<id>[^"]*)" signature="(?P<signature>[^"]*)"$""")
MINIMUM_SIGNED_HEADERS = ["x-date", "(request-target)", "content-length", "x-content-sha256"]


def extract_signed_headers(string):
    return SIGNATURE_PATTERN.match(string).groupdict()["headers"].split(" ")


def extract_signature(string):
    return SIGNATURE_PATTERN.match(string).groupdict()["signature"]


def sha256(body):
    body = body or ""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(body.encode("utf-8"))
    return base64.b64encode(digest.finalize()).decode("utf-8")


def test_sign_fails_missing_header(rsa_priv):
    method = "get"
    headers = {}
    body = None
    headers_to_sign = ["missing-header", "x-date", "(request-target)", "x-content-sha256", "content-length"]
    key_id = "user:some-key-id"
    with pytest.raises(BadSignature):
        sign(method, PATH, headers, body, rsa_priv, key_id, headers_to_sign)


def test_sign_populates_missing_headers(rsa_priv):
    method = "get"
    headers = {}
    body = None
    headers_to_sign = []
    key_id = "user:some-key-id"
    sign(method, PATH, headers, body, rsa_priv, key_id, headers_to_sign)

    assert headers["x-content-sha256"] == sha256(body)
    assert headers["content-length"] == "0"

    now = arrow.now()
    x_date = arrow.get(headers["x-date"])
    assert now.replace(seconds=-10) <= x_date <= now.replace(seconds=10)

    assert "authorization" in headers


def test_sign_uses_provided_invalid_headers(rsa_priv):
    # sign doesn't replace provided headers, even if they're invalid
    method = "get"
    headers = {
        "content-length": "not a length",
        "x-content-sha256": "not a b64 sha256",
        "x-date": "not an ISO8601 UTC date"
    }
    body = "hello"
    headers_to_sign = []
    key_id = "user:some-key-id"
    sign(method, PATH, headers, body, rsa_priv, key_id, headers_to_sign)
    assert headers["content-length"] == "not a length"
    assert headers["x-content-sha256"] == "not a b64 sha256"
    assert headers["x-date"] == "not an ISO8601 UTC date"


def test_verify_fails_missing_header(rsa_pub):
    # Unlike sign, this doesn't populate minimum headers like
    # x-date, x-content-sha256, content-length
    method = "get"
    headers = {}
    body = None
    headers_to_sign = []
    signature = sha256(body)
    with pytest.raises(BadSignature) as excinfo:
        verify(method, PATH, headers, body, rsa_pub, signature, MINIMUM_SIGNED_HEADERS, headers_to_sign)
    assert "Request was missing required header" in str(excinfo.value)


def test_verify_fails_missing_signed_header(rsa_pub):
    method = "get"
    headers = {
        "content-length": "0",
        "x-content-sha256": sha256(""),
        "x-date": arrow.now().to("utc").isoformat()}
    body = None
    headers_to_sign = []
    # Pretend the generated signature forgot to sign the last header
    signed_headers = MINIMUM_SIGNED_HEADERS[:-1]
    signature = sha256(body)
    with pytest.raises(BadSignature) as excinfo:
        verify(method, PATH, headers, body, rsa_pub, signature, signed_headers, headers_to_sign)
    assert "Signature did not include all required headers" in str(excinfo.value)


def test_verify_fails_expired_date(rsa_pub):
    method = "get"
    headers = {
        "content-length": "0",
        "x-content-sha256": sha256(""),
        "x-date": arrow.now().replace(hours=1).to("utc").isoformat()}
    body = None
    headers_to_sign = []
    signature = sha256("")
    with pytest.raises(BadSignature) as excinfo:
        verify(method, PATH, headers, body, rsa_pub, signature, MINIMUM_SIGNED_HEADERS, headers_to_sign)
    assert "x-date not within 5 minutes of current time" in str(excinfo.value)


def test_verify_fails_invalid_date(rsa_pub):
    method = "get"
    headers = {
        "content-length": "0",
        "x-content-sha256": sha256(""),
        "x-date": "invalid format"}
    body = None
    headers_to_sign = []
    signature = sha256("")
    with pytest.raises(BadSignature) as excinfo:
        verify(method, PATH, headers, body, rsa_pub, signature, MINIMUM_SIGNED_HEADERS, headers_to_sign)
    assert "x-date must be ISO8601 UTC" in str(excinfo.value)


def test_verify_fails_wrong_body_sha(rsa_pub):
    method = "get"
    headers = {
        "content-length": "9",
        "x-content-sha256": sha256(""),
        "x-date": arrow.now().to("utc").isoformat()}
    body = "not empty"
    headers_to_sign = []
    signature = sha256("")
    with pytest.raises(BadSignature) as excinfo:
        verify(method, PATH, headers, body, rsa_pub, signature, MINIMUM_SIGNED_HEADERS, headers_to_sign)
    message = str(excinfo.value)
    assert "x-content-sha256 mismatch" in message
    assert sha256("") in message
    assert sha256(body) in message


def test_verify_fails_wrong_body_length(rsa_pub):
    method = "get"
    headers = {
        "content-length": "2",
        "x-content-sha256": sha256("not empty"),
        "x-date": arrow.now().to("utc").isoformat()}
    body = "not empty"
    headers_to_sign = []
    signature = sha256("")
    with pytest.raises(BadSignature) as excinfo:
        verify(method, PATH, headers, body, rsa_pub, signature, MINIMUM_SIGNED_HEADERS, headers_to_sign)
    message = str(excinfo.value)
    assert "content-length mismatch" in message
    assert "2" in message
    assert "9" in message


def test_verify_fails_invalid_body_length(rsa_pub):
    method = "get"
    headers = {
        "content-length": "not an int",
        "x-content-sha256": sha256("not empty"),
        "x-date": arrow.now().to("utc").isoformat()}
    body = "not empty"
    headers_to_sign = []
    signature = sha256("")
    with pytest.raises(BadSignature) as excinfo:
        verify(method, PATH, headers, body, rsa_pub, signature, MINIMUM_SIGNED_HEADERS, headers_to_sign)
    assert "content-length must be an integer" == str(excinfo.value)


def test_verify_fails_bad_signature(rsa_pub):
    method = "get"
    headers = {
        "content-length": "0",
        "x-content-sha256": sha256(""),
        "x-date": arrow.now().to("utc").isoformat()}
    body = None
    headers_to_sign = []
    signature = sha256("")
    with pytest.raises(BadSignature) as excinfo:
        verify(method, PATH, headers, body, rsa_pub, signature, MINIMUM_SIGNED_HEADERS, headers_to_sign)
    assert "Signatures do not match." in str(excinfo.value)


def test_sign_and_verify(rsa_priv, rsa_pub):
    method = "get"
    path = "/path/segment"
    headers = {
        "content-length": "0",
        "x-content-sha256": sha256(""),
        "x-date": arrow.now().to("utc").isoformat()}
    body = None
    headers_to_sign = []
    key_id = "user:key-id"

    sign(method, path, headers, body, rsa_priv, key_id, headers_to_sign)

    signature = extract_signature(headers["authorization"])
    signed_headers = extract_signed_headers(headers["authorization"])

    verify(method, path, headers, body, rsa_pub, signature, signed_headers, headers_to_sign)
