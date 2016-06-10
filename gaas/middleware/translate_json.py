import falcon
import json


class TranslateJSON:
    def process_request(self, req: falcon.Request, resp: falcon.Response):
        req.context["body"] = BodyWrapper(req.stream)

    def process_response(self, req: falcon.Request, resp: falcon.Response, resource):
        if "response" not in req.context:
            return
        resp.body = json.dumps(req.context["response"])


class BodyWrapper:
    def __init__(self, stream):
        self._body = stream.read().decode("utf-8")
        self._json = None

    def __str__(self):
        return self._body

    @property
    def json(self):
        if self._json is None:
            if not self._body:
                self._json = {}
            else:
                self._json = json.loads(self._body)
        return self._json
