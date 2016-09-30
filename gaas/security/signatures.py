import arrow
import arrow.parser
import base64
import uritools

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from typing import Sequence, Dict, Optional, MutableSequence

__all__ = ["sign", "verify"]

# These must be signed on every request
_MINIMUM_HEADERS = ["x-date", "(request-target)", "content-length", "x-content-sha256"]


class BadSignature(Exception):
    pass


def sign(*,
         method: str,
         path: str,
         headers: Dict,
         body: Optional[str],
         private_key: RSAPrivateKey,
         id: str,
         headers_to_sign: Optional[Sequence[str]]=None):
    """
    Computes the signature, and injects the Authorization header (and some
    missing headers) into the provided headers dict.  You MUST include all
    headers in this dictionary in the signed request.
    """
    method = method.lower()
    headers_to_sign = (headers_to_sign or [])[:]
    # 1) The list of headers to sign must include the minimum signing headers
    _ensure_minimum_headers(headers_to_sign)
    # 2) The minimum headers can always be populated automatically
    _populate_missing_headers(headers, body)
    # 3) Raise if any additional headers to sign are missing
    _check_missing_headers(headers, headers_to_sign)
    # 4) Build a signature from the available headers
    signing_string = _build_signing_string(method, path, headers, headers_to_sign)
    # 5) Sign with private key
    signature = private_key.sign(
        signing_string,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    _insert_authorization_header(headers, headers_to_sign, signature, id)


def verify(*,
           method: str,
           path: str,
           headers: Dict,
           body: Optional[str],
           public_key: RSAPublicKey,
           signature: str,
           signed_headers: Sequence[str],
           headers_to_sign: Optional[Sequence[str]]=None):
    """
    Throws BadSignature with detailed info if any part of the signature
    verification fails.
    """
    now = arrow.now()
    method = method.lower()
    headers_to_sign = (headers_to_sign or [])[:]

    # 0) Fix content-length header, since clients and http servers do weird things to it.
    #    Most of them omit this header when 0 or on gets, but it MUST be present for signing.
    headers["content-length"] = headers.get("content-length", "") or "0"

    # 1) The list of headers to sign must include the minimum signing headers
    _ensure_minimum_headers(headers_to_sign)
    # 2) Raise if any additional headers to sign are missing, or the signed headers don't include the headers to sign
    _check_missing_headers(headers, headers_to_sign, signed_headers=signed_headers)
    # 3) Raise if the x-date header is out of bounds, or the body hash is wrong
    _verify_date(headers, now)
    _verify_body(headers, body)

    # 4) Build the expected signature from the available headers
    signing_string = _build_signing_string(method, path, headers, headers_to_sign, signed_headers=signed_headers)
    # 5) Verify the expected signature against the provided signature
    try:
        public_key.verify(
            base64.b64decode(signature.encode("utf-8")),
            signing_string,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        raise BadSignature("Signatures do not match.")


def _ensure_minimum_headers(headers_to_sign: MutableSequence[str]):
    for header in _MINIMUM_HEADERS:
        if header not in headers_to_sign:
            headers_to_sign.append(header)


def _populate_missing_headers(headers: Dict[str, str], body: Optional[str]=None):
    headers.setdefault("x-date", arrow.now().to("utc").isoformat())
    headers.setdefault("content-length", str(0 if not body else len(body)))
    headers.setdefault("x-content-sha256", _compute_body_hash(body))


def _check_missing_headers(
        headers: Dict[str, str],
        headers_to_sign: Sequence[str],
        signed_headers: Optional[Sequence[str]]=None):
    signed_headers = signed_headers or headers_to_sign
    for header in headers_to_sign:
        if header == "(request-target)":
            continue
        if header not in headers:
            raise BadSignature("Request was missing required header {}".format(header))
    if set(signed_headers) < set(headers_to_sign):
        raise BadSignature("Signature did not include all required headers ({})".format(" ".join(headers_to_sign)))


def _compute_body_hash(body: str) -> str:
    body = body or ""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(body.encode("utf-8"))
    return base64.b64encode(digest.finalize()).decode("utf-8")


def _build_signing_string(
        method: str, path: str, headers: Dict[str, str],
        headers_to_sign: Sequence[str], signed_headers: Optional[Sequence[str]]=None) -> bytes:
    # When signed_headers are passed, that ordering is used (verify)
    # Otherwise, the headers to sign are used for ordering (sign)
    if signed_headers:
        header_names = signed_headers
    else:
        header_names = headers_to_sign
    pieces = []
    line_format = "{}: {}"
    for header_name in header_names:
        if header_name == "(request-target)":
            value = _build_request_target(method, path)
        else:
            value = headers[header_name]
        pieces.append(line_format.format(header_name, value))
    return "\n".join(pieces).encode("utf-8")


def _build_request_target(method: str, path: str) -> str:
    parts = uritools.urisplit(path)
    if parts.query:
        target = parts.path + "?" + parts.query
    else:
        target = parts.path
    return "{} {}".format(method, target)


def _insert_authorization_header(headers: Dict[str, str], headers_to_sign: Sequence[str], signature: bytes, id: str):
    signature = base64.b64encode(signature).decode("utf-8")
    auth_format = "Signature headers=\"{}\" id=\"{}\" signature=\"{}\""
    headers["authorization"] = auth_format.format(" ".join(headers_to_sign), id, signature)


def _verify_date(headers: Dict[str, str], now: arrow.Arrow):
    iso8601_date = headers["x-date"]
    try:
        date = arrow.get(iso8601_date)
    except arrow.parser.ParserError:
        raise BadSignature("x-date must be ISO8601 UTC")
    # TODO offset should be loaded from config
    within_range = now.replace(minutes=-5) <= date <= now.replace(minutes=5)
    if not within_range:
        raise BadSignature("x-date not within 5 minutes of current time")


def _verify_body(headers: Dict[str, str], body: str):
    body = body or ""
    header_x_content_sha256 = headers["x-content-sha256"]
    header_content_length = headers["content-length"]
    try:
        header_content_length = int(header_content_length)
    except ValueError:
        raise BadSignature("content-length must be an integer")

    actual_body_length = len(body)
    actual_body_hash = _compute_body_hash(body)
    if actual_body_length != header_content_length:
        raise BadSignature(
            "content-length mismatch (length is {} but header was {})".format(
                actual_body_length, header_content_length))
    if actual_body_hash != header_x_content_sha256:
        raise BadSignature(
            "x-content-sha256 mismatch (computed {} but header was {})".format(
                actual_body_hash, header_x_content_sha256))
