import bloop

BaseModel = bloop.new_base()


class NotFound(Exception):
    pass


class NotSaved(Exception):
    def __init__(self, obj):
        self.obj = obj
        super().__init__(obj)


class AlreadyExists(Exception):
    pass


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
    hash_key = obj.Meta.hash_key
    range_key = obj.Meta.range_key
    condition = hash_key.is_(None)
    if range_key:
        condition &= range_key.is_(None)
    return condition


def query_one(engine: bloop.Engine, index, key_condition):
    """query_one(engine, Model.by_id, Model.user_id=='foo')"""
    # TODO: use query.one when implemented
    # https://github.com/numberoverzero/bloop/issues/40
    query = engine.query(index).key(key_condition)
    result = None
    try:
        for item in query.all(prefetch=2):
            # Uh-oh! found more than one item!
            if result is not None:
                raise NotFound
            result = item
        return result
    # https://github.com/numberoverzero/bloop/issues/41
    except ValueError:
        raise NotFound
