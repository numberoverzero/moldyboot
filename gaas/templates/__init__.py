import os
HERE = os.path.abspath(os.path.dirname(__file__))

__all__ = ["load", "render"]


def path(filename):
    return os.path.join(HERE, "data", filename)


whitelist_templates = [
    "verify-email.html",
    "verify-email.txt"
]


def load(template):
    if template not in whitelist_templates:
        raise ValueError("Unknown template {!r}".format(template))
    with open(path(template)) as file:
        return file.read()


def render(template, *args, **kwargs):
    template = load(template)
    return template.format(*args, **kwargs)
