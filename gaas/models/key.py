import arrow
import uuid
from bloop import Column, UUID, DateTime, Binary, NotModified
from Crypto.PublicKey import pubkey
from Crypto.PublicKey import RSA
from . import engine, NotFound


class PublicKeyType(Binary):
    """Stored in Dynamo in DER.  Locally, an RSA._RSAobj"""
    python_type = pubkey.pubkey

    def dynamo_load(self, value: str, *, context=None, **kwargs):
        value = super().dynamo_load(value, context=context, **kwargs)
        return RSA.importKey(value)

    def dynamo_dump(self, value: pubkey.pubkey, *, context=None, **kwargs):
        value = value.exportKey(format="DER")
        return super().dynamo_dump(value, context=context, **kwargs)


class Key(engine.model):
    class Meta:
        # TODO should be loaded from config
        table_name = "gaas-keys"
        write_units = 1
        read_units = 1

    user_id = Column(UUID, hash_key=True, name='u')
    key_id = Column(UUID, range_key=True, name='k')
    public = Column(PublicKeyType, name='p')
    until = Column(DateTime, name='e')

    @classmethod
    def load(cls, user_id: uuid.UUID, key_id: uuid.UUID):
        key = cls(user_id=user_id, key_id=key_id)
        try:
            engine.load(key, consistent=True)
        except NotModified:
            raise NotFound
        return key

    def refresh(self):
        # TODO should push to an async task queue, not blocking
        now = arrow.now()
        # TODO offset should be loaded from config
        self.until = now.replace(hours=1)
        not_expired = Key.until >= now
        # TODO handle bloop.ConstraintViolation
        engine.save(self, condition=not_expired, atomic=True)

    def revoke(self):
        # TODO should push to an async task queue, not blocking
        # TODO handle bloop.ConstraintViolation
        # Atomic because it's possible someone refreshed the key just after a load, and this revoke
        # shouldn't apply. Only revoke keys that meet whatever criteria tried to clean them up initially.
        engine.delete(self, atomic=True)

    @property
    def expired(self):
        return arrow.now() > self.until
