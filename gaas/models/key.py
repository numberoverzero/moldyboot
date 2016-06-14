import arrow
from Crypto.PublicKey import RSA
from bloop import Binary, Column, DateTime, UUID

from .common import BaseModel


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
    def is_expired(self):
        return arrow.now() > self.until
