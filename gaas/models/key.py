import arrow
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import serialization
from bloop import Binary, Column, DateTime, UUID

from .common import BaseModel


def as_bytes(public: RSAPublicKey):
    return public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


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
        value = as_bytes(value)
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

    def __eq__(self, other):
        if not isinstance(other, Key):
            return False
        missing = object()
        for attr in ["user_id", "key_id", "until"]:
            self_value = getattr(self, attr, missing)
            other_value = getattr(other, attr, missing)
            if self_value != other_value:
                return False
        # Can't do a simple == comparison here because we need to compare the bytes
        self_public = getattr(self, "public", missing)
        other_public = getattr(other, "public", missing)
        if (self_public is missing) != (other_public is missing):
            # Only 1 is missing
            return False
        if self_public is missing:
            # Both missing, they're equal
            return True
        # Both exist, compare byte values
        return as_bytes(self_public) == as_bytes(other_public)
    __hash__ = BaseModel.__hash__
