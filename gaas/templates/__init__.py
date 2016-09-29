import os
HERE = os.path.abspath(os.path.dirname(__file__))


def _path(filename):
    return os.path.join(HERE, "data", filename)


def _load(template):
    with open(_path(template)) as file:
        return file.read()


verify_email_html = _load("verify-email.html")
verify_email_txt = _load("verify-email.txt")
