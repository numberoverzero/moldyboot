import functools

# While a whitelist isn't strictly required, it takes care of typos
# without requiring an additional import, like an Enum would.
_allowed_tags = {
    "authentication-skip",  # no authentication required
    "authentication-basic"  # use basic instead of signature authentication
}

# While a whitelist isn't strictly required, it takes care of typos
# without requiring an additional import, like an Enum would.
_available_metadata = {
    "_tags",
    "_additional_signed_headers"
}


def get_metadata(resource, verb: str, attr: str):
    """
    Example
    -------

        class Resource:
            @tag("authentication-basic")
            def on_post(self):
                pass
        resource = Resource()
        get_metadata(resource, "POST", "_tags")

        # AttributeError
        get_metadata(resource, "GET", "_tags")

        # AttributeError
        get_metadata(resource, "POST", "_unknown")
    """
    attr = attr.lower()
    if attr not in _available_metadata:
        raise ValueError("Unknown metadata {}".format(attr))
    func = getattr(resource, "on_"+verb.lower())
    return getattr(func, attr)


def store_metadata(func, attr: str, default):
    attr = attr.lower()
    if attr not in _available_metadata:
        raise ValueError("Unknown metadata {}".format(attr))
    value = getattr(func, attr, default)
    setattr(func, attr, value)
    return value


def tag(resource_tag: str, func=None):
    resource_tag = resource_tag.lower()
    if resource_tag not in _allowed_tags:
        raise ValueError("Unknown tag {}".format(resource_tag))
    if not func:
        return functools.partial(tag, resource_tag)
    # Second call through functools.partial, or func was provided directly
    store_metadata(func, "_tags", set()).add(resource_tag)
    return func


def has_tag(resource, verb: str, resource_tag: str):
    try:
        return resource_tag.lower() in get_metadata(resource, verb, "_tags")
    except AttributeError:
        return False


def require_signed_header(header: str, func=None):
    header = header.lower()
    if func is None:
        return functools.partial(require_signed_header, header)
    store_metadata(func, "_additional_signed_headers", set()).add(header)
    return func
