import pytest

from bloop import Column, Integer, ConstraintViolation, GlobalSecondaryIndex, new_base
from unittest.mock import MagicMock

from gaas.models import NotFound, NotSaved, if_not_exist, persist_unique, query_one


@pytest.fixture
def model(mock_engine):
    class Model(new_base()):
        id = Column(Integer, hash_key=True)
        data = Column(Integer)

        by_data = GlobalSecondaryIndex(hash_key="data")

    mock_engine.bind(base=Model)
    return Model


def test_if_not_exist(mock_engine):
    """Condition uses hash or hash & range depending on model"""
    class HashOnly(new_base()):
        id = Column(Integer, hash_key=True)

    class HashAndRange(new_base()):
        h = Column(Integer, hash_key=True)
        r = Column(Integer, range_key=True)

    mock_engine.bind(base=HashOnly)
    mock_engine.bind(base=HashAndRange)

    assert if_not_exist(HashOnly()) == HashOnly.id.is_(None)
    assert if_not_exist(HashAndRange()) == HashAndRange.h.is_(None) & HashAndRange.r.is_(None)


def test_persist_no_tries(mock_engine, model):
    """If tries is 0, the field is never set"""
    obj = model(id=4)
    with pytest.raises(NotSaved) as excinfo:
        persist_unique(obj, mock_engine, "data", lambda: 7, 0)
    assert excinfo.value.obj is obj
    assert not hasattr(obj, "data")
    mock_engine.save.assert_not_called()


def test_persist_success(mock_engine, model):
    obj = model(id=4)

    persist_unique(obj, mock_engine, "data", lambda: 7, 1)
    assert obj.data == 7
    mock_engine.save.assert_called_once_with(obj, condition=model.id.is_(None))


def test_persist_max_tries(mock_engine, model):
    """raises NotSaved after max_tries"""
    obj = model(id=4)
    mock_engine.save.side_effect = ConstraintViolation("save", obj)
    with pytest.raises(NotSaved) as excinfo:
        persist_unique(obj, mock_engine, "data", lambda: 7, 2)
    assert excinfo.value.obj is obj
    assert mock_engine.save.call_count == 2


def test_persist_calls_rnd(mock_engine, model):
    """each try calls rnd() for a new value"""
    calls = []

    def rnd():
        value = len(calls)
        calls.append(value)
        return value

    obj = model(id=4)
    mock_engine.save.side_effect = ConstraintViolation("save", obj)
    with pytest.raises(NotSaved):
        persist_unique(obj, mock_engine, "data", rnd, 2)
    assert mock_engine.save.call_count == 2
    assert calls == [0, 1]


def test_query_one_none_found(mock_engine, model):
    mock_query = MagicMock()
    mock_key = MagicMock()
    mock_all = MagicMock()

    # engine.query(...).key(...).all(...)
    mock_engine.query.return_value = mock_query
    mock_query.key.return_value = mock_key
    mock_key.all.return_value = mock_all
    mock_all.__iter__.side_effect = ValueError

    with pytest.raises(NotFound):
        query_one(mock_engine, model.by_data, model.data == 3)


def test_query_one_multiple_found(mock_engine, model):
    mock_query = MagicMock()
    mock_key = MagicMock()
    mock_all = MagicMock()

    # engine.query(...).key(...).all(...)
    mock_engine.query.return_value = mock_query
    mock_query.key.return_value = mock_key
    mock_key.all.return_value = mock_all
    mock_all.__iter__.return_value = iter(["first", "second"])

    with pytest.raises(NotFound):
        query_one(mock_engine, model.by_data, model.data == 3)


def test_query_one_success(mock_engine, model):
    mock_query = MagicMock()
    mock_key = MagicMock()
    mock_all = MagicMock()

    # engine.query(...).key(...).all(...)
    mock_engine.query.return_value = mock_query
    mock_query.key.return_value = mock_key
    mock_key.all.return_value = mock_all
    mock_all.__iter__.return_value = iter(["first"])

    result = query_one(mock_engine, model.by_data, model.data == 3)
    assert result == "first"
