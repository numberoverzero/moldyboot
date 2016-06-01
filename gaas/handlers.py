from .models.key import Key


def authenticate(method, uri, headers, body, headers_to_sign):
    # TODO parse user_id from headers
    # TODO parse key_id from Authorization header
    # TODO load key using key_id
    # TODO check key expiry
    # TODO parse signature from Authorization header
    # TODO if signature matches trigger async key refresh
    pass
