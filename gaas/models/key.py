import arrow
import bloop
from bloop import Column, UUID, DateTime, Binary
from Crypto.PublicKey import RSA

from . import BaseModel, NotFound
from .validation import validate


class PublicKeyType(Binary):
    """Stored in Dynamo in DER.  Locally, an RSA._RSAobj"""
    python_type = RSA._RSAobj

    def dynamo_load(self, value: str, *, context=None, **kwargs):
        value = super().dynamo_load(value, context=context, **kwargs)
        return RSA.importKey(value)

    def dynamo_dump(self, value: RSA._RSAobj, *, context=None, **kwargs):
        value = value.exportKey(format="DER")
        return super().dynamo_dump(value, context=context, **kwargs)


class Key(BaseModel):
    class Meta:
        # TODO should be loaded from config
        table_name = "gaas-keys"
        write_units = 1
        read_units = 1

    user_id = Column(UUID, hash_key=True, name='u')
    key_id = Column(UUID, range_key=True, name='k')
    public = Column(PublicKeyType, name='p')
    until = Column(DateTime, name='e')

    @property
    def expired(self):
        return arrow.now() > self.until


class KeyManager:
    def __init__(self, engine: bloop.Engine):
        self.engine = engine

    def load(self, user_id, key_id):
        user_id = validate("user_id", user_id)
        key_id = validate("key_id", key_id)

        key = Key(user_id=user_id, key_id=key_id)
        try:
            self.engine.load(key, consistent=True)
        except bloop.NotModified:
            raise NotFound
        if key.expired:
            self._revoke(key)
            raise NotFound
        else:
            self._refresh(key)
            return key

    def _revoke(self, key):
        # TODO should push to an async task queue, not blocking
        # TODO handle bloop.ConstraintViolation
        # Atomic because it's possible someone refreshed the key just after a load, and this revoke
        # shouldn't apply. Only revoke keys that meet whatever criteria tried to clean them up initially.
        self.engine.delete(key, atomic=True)

    def _refresh(self, key):
        # TODO should push to an async task queue, not blocking
        # TODO offset should be loaded from config
        # TODO handle bloop.ConstraintViolation
        now = arrow.now()
        key.until = now.replace(hours=1)
        not_expired = Key.until >= now
        self.engine.save(key, condition=not_expired, atomic=True)
