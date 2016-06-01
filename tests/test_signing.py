import arrow
import base64
import pytest
import re
import uritools
from Crypto.Hash import SHA256
from gaas.signing import sign, verify, BadSignature

URI = uritools.urisplit(
    "https://host.com/some/path/?query=string&another=value")
SIGNATURE_PATTERN = re.compile(
    """^Signature\sheaders="(?P<headers>[^"]*)"\sid="(?P<id>[^"]*)"\ssignature="(?P<signature>[^"]*)"$""")
MINIMUM_SIGNED_HEADERS = ["x-date", "(request-target)", "content-length", "x-content-sha256"]


def extract_signed_headers(authorization):
    return SIGNATURE_PATTERN.match(authorization).groupdict()["headers"].split(" ")


def extract_signature(authorization):
    return SIGNATURE_PATTERN.match(authorization).groupdict()["signature"]


def sha256(body):
    body = body or ""
    hash = SHA256.new(body.encode("utf-8")).digest()
    return base64.b64encode(hash).decode("utf-8")


def test_sign_fails_missing_header(crypto_priv):
    method = "get"
    headers = {}
    body = None
    headers_to_sign = ["missing-header"]
    key_id = "user:some-key-id"
    with pytest.raises(BadSignature):
        sign(method, URI, headers, body, headers_to_sign, crypto_priv, key_id)


def test_sign_populates_missing_headers(crypto_priv):
    method = "get"
    headers = {}
    body = None
    headers_to_sign = []
    key_id = "user:some-key-id"
    sign(method, URI, headers, body, headers_to_sign, crypto_priv, key_id)

    assert headers["x-content-sha256"] == sha256(body)
    assert headers["content-length"] == "0"

    now = arrow.now()
    x_date = arrow.get(headers["x-date"])
    assert now.replace(seconds=-10) <= x_date <= now.replace(seconds=10)

    assert "authorization" in headers


def test_sign_uses_provided_invalid_sha256(crypto_priv):
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
    sign(method, URI, headers, body, headers_to_sign, crypto_priv, key_id)
    assert headers["content-length"] == "not a length"
    assert headers["x-content-sha256"] == "not a b64 sha256"
    assert headers["x-date"] == "not an ISO8601 UTC date"


def test_verify_fails_missing_header(crypto_pub):
    # Unlike sign, this doesn't populate minimum headers like
    # x-date, x-content-sha256, content-length
    method = "get"
    headers = {}
    body = None
    headers_to_sign = []
    signature = sha256(body)
    with pytest.raises(BadSignature) as excinfo:
        verify(method, URI, headers, body, headers_to_sign, crypto_pub, signature, MINIMUM_SIGNED_HEADERS)
    assert "Request was missing required header" in str(excinfo.value)


def test_verify_fails_missing_signed_header(crypto_pub):
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
        verify(method, URI, headers, body, headers_to_sign, crypto_pub, signature, signed_headers)
    assert "Signature did not include all required headers" in str(excinfo.value)


def test_verify_fails_expired_date(crypto_pub):
    method = "get"
    headers = {
        "content-length": "0",
        "x-content-sha256": sha256(""),
        "x-date": arrow.now().replace(hours=1).to("utc").isoformat()}
    body = None
    headers_to_sign = []
    signature = sha256("")
    with pytest.raises(BadSignature) as excinfo:
        verify(method, URI, headers, body, headers_to_sign, crypto_pub, signature, MINIMUM_SIGNED_HEADERS)
    assert "x-date not within 5 minutes of current time" in str(excinfo.value)


def test_verify_fails_invalid_date(crypto_pub):
    method = "get"
    headers = {
        "content-length": "0",
        "x-content-sha256": sha256(""),
        "x-date": "invalid format"}
    body = None
    headers_to_sign = []
    signature = sha256("")
    with pytest.raises(BadSignature) as excinfo:
        verify(method, URI, headers, body, headers_to_sign, crypto_pub, signature, MINIMUM_SIGNED_HEADERS)
    assert "x-date must be ISO8601 UTC" in str(excinfo.value)


def test_verify_fails_wrong_body_sha(crypto_pub):
    method = "get"
    headers = {
        "content-length": "0",
        "x-content-sha256": sha256(""),
        "x-date": arrow.now().to("utc").isoformat()}
    body = "not empty"
    headers_to_sign = []
    signature = sha256("")
    with pytest.raises(BadSignature) as excinfo:
        verify(method, URI, headers, body, headers_to_sign, crypto_pub, signature, MINIMUM_SIGNED_HEADERS)
    message = str(excinfo.value)
    assert "x-content-sha256 mismatch" in message
    assert sha256("") in message
    assert sha256(body) in message


def test_verify_fails_bad_signature(crypto_pub):
    method = "get"
    headers = {
        "content-length": "0",
        "x-content-sha256": sha256(""),
        "x-date": arrow.now().to("utc").isoformat()}
    body = None
    headers_to_sign = []
    signature = sha256("")
    with pytest.raises(BadSignature) as excinfo:
        verify(method, URI, headers, body, headers_to_sign, crypto_pub, signature, MINIMUM_SIGNED_HEADERS)
    assert "Signatures do not match." in str(excinfo.value)


def test_sign_and_verify(crypto_priv, crypto_pub):
    method = "get"
    uri = uritools.urisplit("https://host.com/path/segment")
    headers = {
        "content-length": "0",
        "x-content-sha256": sha256(""),
        "x-date": arrow.now().to("utc").isoformat()}
    body = None
    headers_to_sign = []
    key_id = "user:key-id"

    sign(method, uri, headers, body, headers_to_sign, crypto_priv, key_id)

    signature = extract_signature(headers["authorization"])
    signed_headers = extract_signed_headers(headers["authorization"])

    verify(method, uri, headers, body, headers_to_sign, crypto_pub, signature, signed_headers)
