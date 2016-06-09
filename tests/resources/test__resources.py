import pytest
from gaas.resources import _allowed_tags, get_metadata, has_tag, require_signed_header, store_metadata, tag


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
        for test_tag in testing_tags:
            _allowed_tags.remove(test_tag)
    except KeyError:
        pass


def test_get_metadata_unknown():
    class Resource:
        def on_get(self):
            pass
    resource = Resource()
    with pytest.raises(ValueError):
        get_metadata(resource, "get", "unknown-metadata")


def test_get_metadata_tags():
    class Resource:
        def on_get(self):
            pass
    resource = Resource()
    with pytest.raises(AttributeError):
        get_metadata(resource, "get", "_tags")


def test_store_metadata_unknown():
    class Resource:
        def on_get(self):
            pass

    with pytest.raises(ValueError):
        store_metadata(Resource.on_get, "unknown-metadata", set())


def test_store_metadata_exists():
    class Resource:
        def on_get(self):
            pass

    first = object()
    second = object()
    assert store_metadata(Resource.on_get, "_tags", first) is first
    assert store_metadata(Resource.on_get, "_tags", second) is first
    resource = Resource()
    assert get_metadata(resource, "get", "_tags") is first


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


def test_require_signed_header():
    class Resource:
        @require_signed_header("some-header")
        def on_post(self):
            pass
    resource = Resource()
    assert "some-header" in get_metadata(resource, "POST", "_additional_signed_headers")
