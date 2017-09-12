from bloop import UUID, Binary, Boolean, Column, GlobalSecondaryIndex, String
from bloop.ext.pendulum import DateTime

from .common import BaseModel


class UserName(BaseModel):
    class Meta:
        table_name = "users.names"
    username = Column(String, hash_key=True, name="n")
    user_id = Column(UUID, name="u")
    created = Column(DateTime, name="c")

    by_user_id = GlobalSecondaryIndex(
        projection="keys", hash_key="user_id", name="by_u")


class User(BaseModel):
    class Meta:
        table_name = "users"
    user_id = Column(UUID, hash_key=True, name="u")
    password_hash = Column(Binary, name="p")
    email = Column(String, name="e")
    verification_code = Column(UUID, name="v")
    deleted = Column(Boolean, name="d")

    @property
    def is_verified(self):
        # bloop doesn't set attrs when values are missing
        return getattr(self, "verification_code", None) is None

    @property
    def is_deleted(self):
        # bloop doesn't set attrs when values are missing
        return getattr(self, "deleted", False) is True
