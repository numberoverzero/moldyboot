import arrow

from bloop import Column, UUID, DateTime, Binary
from Crypto.PublicKey import pubkey
from Crypto.PublicKey import RSA
from . import engine


class PublicKeyType(Binary):
    """Stored in Dynamo in DER.  Locally, an RSA._RSAobj"""
    python_type = pubkey.pubkey

    def dynamo_load(self, value, *, context=None, **kwargs):
        value = super().dynamo_load(value, context=context, **kwargs)
        return RSA.importKey(value)

    def dynamo_dump(self, value, *, context=None, **kwargs):
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

    def refresh(self):
        # TODO should push to an async task queue, not blocking
        now = arrow.now()
        # TODO offset should be loaded from config
        self.until = now.replace(hours=1)
        not_expired = Key.until >= now
        # TODO handle bloop.ConstraintViolation
        with engine.context(atomic=True) as atomic:
            atomic.save(self, condition=not_expired)

    @property
    def expired(self):
        return arrow.now() > self.until
