import pytest
from gaas.resources import tag, has_tag, _allowed_tags


@pytest.yield_fixture(autouse=True)
def allow_tag():
    """Allow the use of different tags without including them in the prod tag set"""
    testing_tags = {"test"}
    _allowed_tags.add("test")

    def add_tag(tag):
        """Allow methods to add extra tags if needed"""
        testing_tags.add(tag)
        _allowed_tags.add(tag)

    yield add_tag

    try:
        for tag in testing_tags:
            _allowed_tags.remove(tag)
    except KeyError:
        pass


def test_tag_unknown():
    with pytest.raises(ValueError):
        class Resource:
            @tag("what is this I don't even")
            def on_post(self):
                pass


def test_tag_partial():
    class Resource:
        def on_post(self):
            pass
    # First call returns a functools.partial that can be invoked to include the func parameter
    on_post = tag("test")(Resource.on_post)
    assert on_post is Resource.on_post


def test_tags_stored_on_function():
    class Resource:
        @tag("test")
        def on_post(self):
            pass
    resource = Resource()
    assert resource.on_post._tags == {"test"}


def test_tags_multiple(allow_tag):
    allow_tag("also-test")

    class Resource:
        @tag("test")
        @tag("also-test")
        def on_post(self):
            pass
    assert Resource().on_post._tags == {"test", "also-test"}


def test_has_tag():
    class Resource:
        @tag("test")
        def on_post(self):
            pass
    resource = Resource()

    assert has_tag(resource, "post", "test")
    assert not has_tag(resource, "post", "unknown")
    assert not has_tag(resource, "get", "test")
