import functools

_allowed_tags = set([
    "authentication-skip",  # no authentication required
    "authentication-basic"  # use basic instead of signature authentication
])


def tag(resource_tag, func=None):
    resource_tag = resource_tag.lower()
    if resource_tag not in _allowed_tags:
        raise ValueError("Unknown tag {}".format(resource_tag))
    if not func:
        return functools.partial(tag, resource_tag)
    # Second call through functools.partial, or func was provided directly
    if not hasattr(func, "_tags"):
        func._tags = set()
    func._tags.add(resource_tag)
    return func


def has_tag(resource, verb, resource_tag):
    verb = verb.lower()
    try:
        function = getattr(resource, "on_"+verb)
        return resource_tag.lower() in function._tags
    # Raised by both looking up on_* and _tags
    except AttributeError:
        return False
