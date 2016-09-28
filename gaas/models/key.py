import arrow
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import serialization
from bloop import Binary, Column, DateTime, UUID

from .common import BaseModel


class PublicKeyType(Binary):
    """Stored in Dynamo in DER.  Locally, an RSAPublicKey"""
    python_type = RSAPublicKey

    def dynamo_load(self, value: str, *, context=None, **kwargs) -> RSAPublicKey:
        value = super().dynamo_load(value, context=context, **kwargs)
        return serialization.load_der_public_key(
            data=value,
            backend=default_backend()
        )

    def dynamo_dump(self, value: RSAPublicKey, *, context=None, **kwargs) -> str:
        value = value.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
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
