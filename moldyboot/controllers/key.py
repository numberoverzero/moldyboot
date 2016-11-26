import arrow
import bloop
import uuid
from typing import Union, Sequence, Optional

from .common import persist_unique, NotFound, NotSaved
from .validation import validate
from ..models import Key


class KeyManager:
    def __init__(self, engine: bloop.Engine):
        self.engine = engine

    def new(self, user_id: Union[str, uuid.UUID], public: Union[str, bytes]) -> Key:
        # 1) Validate user_id, public
        user_id = validate("user_id", user_id)
        public = validate("public_key", public)
        # 2) Store key
        key = Key(user_id=user_id, public=public, until=arrow.now().replace(hours=1))
        persist_unique(key, self.engine, "key_id", uuid.uuid4)
        return key

    def get_key(self, user_id: Union[str, uuid.UUID], key_id: Union[str, uuid.UUID]) -> Key:
        user_id = validate("user_id", user_id)
        key_id = validate("key_id", key_id)

        key = Key(user_id=user_id, key_id=key_id)
        try:
            self.engine.load(key, consistent=True)
        except bloop.MissingObjects:
            raise NotFound
        if key.is_expired:
            self.revoke(key)
            raise NotFound
        else:
            self.refresh(key)
            return key

    def list_keys(self, user_id: Union[str, uuid.UUID]) -> Sequence[Key]:
        user_id = validate("user_id", user_id)
        return self.engine.query(
            Key,
            key=Key.user_id == user_id,
        )

    def revoke(self, key: Key, force: Optional[bool]=False) -> Key:
        # By default revokes are atomic, so that we don't accidentally blow away a key
        # just after someone uses it.
        # However, there are cases where we need to unconditionally delete a key.
        try:
            self.engine.delete(key, atomic=not force)
        except bloop.ConstraintViolation:
            raise NotSaved(key)
        return key

    def refresh(self, key: Key):
        # TODO should push to an async task queue, not blocking
        # TODO offset should be loaded from config
        # TODO handle bloop.ConstraintViolation
        now = arrow.now()
        key.until = now.replace(hours=1)
        not_expired = Key.until >= now
        self.engine.save(key, condition=not_expired, atomic=True)
