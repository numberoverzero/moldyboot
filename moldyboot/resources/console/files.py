from typing import Sequence

import falcon
import re
from ... import templates


def content_type(filename):
    if filename.endswith("html"):
        return "text/html"
    elif filename.endswith("js"):
        return "application/javascript"
    elif filename.endswith("css"):
        return "text/css"
    raise ValueError("Unknown content-type for file {!r}".format(filename))


class FileRenderer:
    def __init__(self, context):
        self.context = context

    def __call__(self, filename):
        return templates.render(filename, self.context)

    def static(self, filename, cache=False):
        return StaticFileResource(self, filename, cache=cache)

    def dynamic(self, *whitelist):
        return DynamicFileResource(self, whitelist)


class StaticFileResource:
    def __init__(self, renderer: FileRenderer, filename: str, cache: bool=False):
        self.render = renderer
        self.filename = filename
        self.content_type = content_type(filename)
        self.cache = None
        self._use_cached = cache

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        body = self.cache
        if body is None:
            body = self.render(self.filename)
            if self._use_cached:
                self.cache = body
        resp.body = body
        resp.status = falcon.HTTP_200
        resp.set_header("content-type", self.content_type)


class DynamicFileResource:
    def __init__(self, renderer: FileRenderer, whitelist: Sequence[str]):
        self.render = renderer
        self.whitelist = re.compile("|".join(whitelist))

    def on_get(self, req: falcon.Request, resp: falcon.Response, filename):
        if not self.whitelist.match(filename):
            raise falcon.HTTPNotFound()
        resp.body = self.render(filename)
        resp.status = falcon.HTTP_200
        resp.set_header("content-type", content_type(filename))
