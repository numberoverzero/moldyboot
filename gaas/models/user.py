from bloop import Binary, Column, DateTime, String, UUID

from .common import BaseModel


class UserName(BaseModel):
    class Meta:
        # TODO should be loaded from config
        table_name = "gaas-user-names"
        write_units = 1
        read_units = 1
    username = Column(String, hash_key=True, name="n")
    user_id = Column(UUID, name="u")
    created = Column(DateTime, name="c")


class User(BaseModel):
    class Meta:
        # TODO should be loaded from config
        table_name = "gaas-users"
        write_units = 1
        read_units = 1
    user_id = Column(UUID, hash_key=True, name="u")
    password_hash = Column(Binary, name="p")
    email = Column(String, name="e")
    verification_code = Column(UUID, name="v")

    @property
    def is_verified(self):
        # bloop doesn't set attrs when values are missing
        return getattr(self, "verification_code", None) is None
