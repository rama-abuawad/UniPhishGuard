from app.ai import _model_text
from app.html_text import visible_html_text
from app.schemas import EmailAddress, EmailAnalysisRequest, LinkInfo


def _email(**values):
    return EmailAnalysisRequest(sender=EmailAddress(email="sender@example.com"), **values)


def test_scripts_styles_comments_and_hidden_text_are_removed():
    html = "<!-- secret --><style>.x{}</style><script>steal()</script><p hidden>hidden phish</p><p>Visible notice</p>"
    assert visible_html_text(html) == "Visible notice"


def test_html_entities_are_decoded():
    assert visible_html_text("<p>Research &amp; Development</p>") == "Research & Development"


def test_plain_and_html_body_are_not_duplicated():
    text = _model_text(_email(body="Visible notice", body_html="<p>Visible notice</p>"))
    assert text.count("visible notice") == 1


def test_visible_link_text_and_destination_domain_are_preserved():
    text = _model_text(_email(links=[LinkInfo(text="ADU portal", href="https://evil.example/login")]))
    assert "adu portal" in text
    assert "evil.example" in text
    assert "/login" not in text
