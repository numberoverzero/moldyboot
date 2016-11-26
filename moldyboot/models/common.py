import bloop

__all__ = ["BaseModel"]


class BaseModel(bloop.BaseModel):
    class Meta:
        abstract = True

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        for column in self.Meta.columns:
            name = column.model_name
            if getattr(self, name, None) != getattr(other, name, None):
                return False
        return True
