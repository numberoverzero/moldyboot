import bloop


__all__ = ["BaseModel"]


@bloop.before_create_table.connect
def apply_table_prefix(_, model, **__):
    prefix = "mb."
    model.Meta.table_name = prefix + model.Meta.table_name


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


class StringEnum(bloop.String):
    """See http://bloop.readthedocs.io/en/latest/user/types.html#example-string-enum"""
    def __init__(self, enum_cls):
        self.enum_cls = enum_cls
        super().__init__()

    def dynamo_dump(self, value, *, context, **kwargs):
        if value is None:
            return value
        value = value.name
        return super().dynamo_dump(value, context=context, **kwargs)

    def dynamo_load(self, value, *, context, **kwargs):
        if value is None:
            return value
        value = super().dynamo_load(value, context=context, **kwargs)
        return self.enum_cls[value]


class S3Location(bloop.String):
    def dynamo_dump(self, value, *, context, **kwargs):
        if value is None:
            return value
        value = "{Bucket}::{Key}".format(**value)
        return super().dynamo_dump(value, context=context, **kwargs)

    def dynamo_load(self, value, *, context, **kwargs):
        if value is None:
            return value
        value = super().dynamo_load(value, context=context, **kwargs)
        bucket, key = value.split("::")
        return {
            "Bucket": bucket,
            "Key": key
        }
