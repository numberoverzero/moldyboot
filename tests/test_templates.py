import pytest
import textwrap
import uuid

from gaas.templates import load, render


def test_load_unknown():
    with pytest.raises(ValueError):
        load(str(uuid.uuid4()))


@pytest.mark.parametrize("template_name", ["verify-email.html", "verify-email.txt"])
def test_load_verify_email(template_name):
    template = load(template_name)
    assert "{username}" in template
    assert "{verification_url}" in template


def test_render_verify_text():
    output = render("verify-email.txt", username="test-name", verification_url="test-url")
    expected = textwrap.dedent("""
    Hello test-name,

    Please visit test-url to verify your email address.

    Thank you,

    gaas
    """)[1:]  # Strip first \n since we need all of the lines to have the same leading indentation
    assert output == expected
