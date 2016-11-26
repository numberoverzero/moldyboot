import pytest
import textwrap

from moldyboot import templates


@pytest.mark.parametrize("template_name", ["verify-email.html", "verify-email.txt"])
def test_load_verify_email(template_name):
    template = templates._load(template_name)
    assert "{username}" in template
    assert "{verification_url}" in template


def test_render_verify_text():
    output = templates.render(
        "verify-email.txt",
        {"username": "test-name", "verification_url": "test-url"}
    )
    expected = textwrap.dedent("""
    Hello test-name,

    Please visit test-url to verify your email address.

    Thank you,

    Moldyboot Staff
    """)[1:]  # Strip first \n since we need all of the lines to have the same leading indentation
    assert output == expected
