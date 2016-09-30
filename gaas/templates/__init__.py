import os
import pystache
HERE = os.path.abspath(os.path.dirname(__file__))


def _path(filename):
    return os.path.join(HERE, "data", filename)


def _load(template):
    with open(_path(template)) as file:
        return file.read()


def render(filename, context):
    return pystache.render(_load(filename), context)
