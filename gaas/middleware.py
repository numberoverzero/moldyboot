import falcon
from .handlers import authenticate, Unauthorized


def lowercase_headers(headers):
    return {key.lower(): value for key, value in headers.items()}


class Authentication:
    def process_resource(self, req: falcon.Request, resp: falcon.Response, resource, params):
        method = req.method
        path = req.path
        # query_string will always be a string, which means that omitted/empty will be conflated.
        # for example, "/path?" and "/path" will both have query_string ""
        if req.query_string:
            path += "?" + req.query_string
        headers = lowercase_headers(req.headers)
        body = req.stream.read().decode("utf-8")
        additional_headers_to_sign = getattr(resource, "signed_headers", [])

        try:
            authenticated_user = authenticate(method, path, headers, body, additional_headers_to_sign)
        except Unauthorized as exception:
            # TODO see if resource allows Basic Authorization and retry authentication
            raise falcon.HTTPUnauthorized("Authentication failed", exception.args[0], None)
        req.context["user_id"] = authenticated_user
