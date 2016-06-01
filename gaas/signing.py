import arrow
import base64
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
# These must be signed on every request
_MINIMUM_HEADERS = [
    "x-date", "(request-target)",
    "content-length", "x-content-sha256"]


class BadSignature(Exception):
    pass


def sign(method, uri, headers, body, headers_to_sign, private_key, key_id):
    """
    Computes the signature, and injects the Authorization header (and some
    missing headers) into the provided headers dict.  You MUST include all
    headers in this dictionary in the signed request.
    """
    method = method.lower()
    # 1) The list of headers to sign must include the minimum signing headers
    _ensure_minimum_headers(headers_to_sign)
    # 2) The minimum headers can always be populated automatically
    _populate_missing_headers(headers, body)
    # 3) Raise if any additional headers to sign are missing
    _check_missing_headers(headers, headers_to_sign)
    # 4) Build a signature from the available headers
    signing_string = _build_signing_string(
        method, uri, headers, headers_to_sign)
    # 5) Sign with private key
    key = PKCS1_PSS.new(private_key)
    hash = SHA256.new(signing_string)
    signature = key.sign(hash)
    _insert_authorization_header(headers, headers_to_sign, signature, key_id)


def verify(method, uri, headers, body, headers_to_sign, public_key, signature):
    """
    Throws BadSignature with detailed info if any part of the signature
    verification fails.
    """
    now = arrow.now()
    method = method.lower()
    # 1) The list of headers to sign must include the minimum signing headers
    _ensure_minimum_headers(headers_to_sign)
    # 2) Raise if any additional headers to sign are missing
    _check_missing_headers(headers, headers_to_sign)
    # 3) Raise if the x-date header is out of bounds, or the body hash is wrong
    _verify_date(headers["x-date"], now)
    _verify_body(headers["x-content-sha256"], body)
    # 4) Build the expected signature from the available headers
    signing_string = _build_signing_string(
        method, uri, headers, headers_to_sign)
    # 5) Verify the expected signature against the provided signature
    key = PKCS1_PSS.new(public_key)
    hash = SHA256.new(signing_string)
    if not key.verify(hash, base64.b64decode(signature.encode("utf-8"))):
        raise BadSignature("Signatures do not match.")


def _ensure_minimum_headers(headers_to_sign):
    for header in _MINIMUM_HEADERS:
        if header not in headers_to_sign:
            headers_to_sign.append(header)


def _populate_missing_headers(headers, body):
    headers.setdefault("x-date", arrow.now().to("utc").isoformat())
    headers.setdefault("content-length", str(0 if not body else len(body)))
    headers.setdefault("x-content-sha256", _compute_body_hash(body))


def _check_missing_headers(headers, headers_to_sign):
    for header in headers_to_sign:
        if header == "(request-target)":
            continue
        if header not in headers:
            raise BadSignature("Missing required header {}".format(header))


def _compute_body_hash(body):
    body = body or ""
    hash = SHA256.new(body.encode("utf-8"))
    return base64.b64encode(hash.digest()).decode("utf-8")


def _build_signing_string(method, uri, headers, headers_to_sign):
    pieces = []
    line_format = "{}: {}"
    for header_name in headers_to_sign:
        if header_name == "(request-target)":
            value = _build_request_target(method, uri)
        else:
            value = headers[header_name]
        pieces.append(line_format.format(header_name, value))
    return "\n".join(pieces).encode("utf-8")


def _build_request_target(method, uri):
    if uri.query:
        target = uri.path + "?" + uri.query
    else:
        target = uri.path
    return "{} {}".format(method, target)


def _insert_authorization_header(headers, headers_to_sign, signature, key_id):
    signature = base64.b64encode(signature).decode("utf-8")
    auth_format = "Signature headers=\"{}\" keyId=\"{}\" signature=\"{}\""
    headers["authorization"] = auth_format.format(
        " ".join(headers_to_sign), key_id, signature)


def _verify_date(iso8601_date, now):
    try:
        date = arrow.get(iso8601_date)
    except arrow.parser.ParserError:
        raise BadSignature("x-date must be ISO8601 UTC")
    # TODO offset should be loaded from config
    within_range = now.replace(minutes=-5) <= date <= now.replace(minutes=5)
    if not within_range:
        raise BadSignature("x-date not within 5 minutes of current time")


def _verify_body(body_hash, body):
    actual_body_hash = _compute_body_hash(body)
    if body_hash != actual_body_hash:
        raise BadSignature(
            "x-content-sha256 mismatch (computed {} but header was {})".format(
                body_hash, actual_body_hash))
