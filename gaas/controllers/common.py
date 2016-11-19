import bloop


class AlreadyExists(Exception):
    pass


class NotFound(Exception):
    pass


class NotSaved(Exception):
    def __init__(self, obj):
        self.obj = obj
        super().__init__(obj)


def persist_unique(obj, engine, field, rnd, max_tries=10):
    tries = max(max_tries, 0)
    condition = if_not_exist(obj)
    while tries:
        setattr(obj, field, rnd())
        try:
            engine.save(obj, condition=condition)
            return obj
        except bloop.ConstraintViolation:
            tries -= 1
    raise NotSaved(obj)


def if_not_exist(obj):
    """Construct a condition that expects hash (and range, if there is one) to be None"""
    # http://bloop.readthedocs.io/en/latest/user/patterns.html#generic-if-not-exist
    condition = bloop.Condition()
    for key in obj.Meta.keys:
        condition &= key.is_(None)
    return condition
