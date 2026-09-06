from urllib.parse import quote

import pytest

from app import analyzer
from app.schemas import EmailAddress, EmailAnalysisRequest, LinkInfo


def wrapped(destination):
    return "https://eur05.safelinks.protection.outlook.com/?url=" + quote(destination, safe="") + "&data=example"


@pytest.fixture
def account_review(monkeypatch):
    # Isolate the rule from the text model: this request must produce its own
    # URL warning even when the model misses the wording.
    monkeypatch.setattr(analyzer, "predict_email_risk", lambda email: ("legitimate", 0.1))
    monkeypatch.setattr(analyzer, "explain_email_risk", lambda email: [])
    return EmailAnalysisRequest(
        subject="Security Verification Test",
        sender=EmailAddress(name="Test Sender", email="sender@gmail.com"),
        body=("Dear Student, A security review found unusual activity associated with your "
              "university account. Please review your account status using the test link below. "
              "This message requires your attention within 24 hours to avoid temporary access restrictions."),
        headers_status="not_available",
    )


@pytest.mark.parametrize("use_wrapper", [False, True])
@pytest.mark.parametrize("destination", ["https://account-review.example.com/", "https://outside.example/check"])
def test_external_account_review_has_its_own_url_evidence(account_review, use_wrapper, destination):
    url = wrapped(destination) if use_wrapper else destination
    account_review.links = [LinkInfo(text=url, href=url)]
    result = analyzer.analyze_email(account_review)
    warnings = [i for i in result.indicators if i.code == "url_university_account_external"]
    assert len(warnings) == 1
    assert destination.split("/")[2] in warnings[0].message
    assert "safelinks.protection.outlook.com" not in warnings[0].message
    assert result.risk_score >= 25
    assert any(c.code == "urls" and c.score >= 25 for c in result.score_breakdown)
    assert not any(i.code in {"encoded_url", "link_text_destination_mismatch"} for i in result.indicators)


def test_screenshot_with_saved_model_output_shows_destination(account_review, monkeypatch):
    monkeypatch.setattr(analyzer, "predict_email_risk", lambda email: ("phishing", 0.9983237922371385))
    url = wrapped("https://account-review.example.com/")
    account_review.body += " " + url
    account_review.links = [LinkInfo(text=url, href=url)]
    result = analyzer.analyze_email(account_review)
    assert any("account-review.example.com" in reason for reason in result.top_reasons)
    assert result.risk_score >= 55


@pytest.mark.parametrize("destination", ["https://portal.adu.ac.ae/account", "https://login.microsoftonline.com/"])
def test_expected_university_or_microsoft_destination_is_not_flagged(account_review, destination):
    url = wrapped(destination)
    account_review.links = [LinkInfo(text=url, href=url)]
    result = analyzer.analyze_email(account_review)
    assert not any(i.code == "url_university_account_external" for i in result.indicators)


@pytest.mark.parametrize("body", [
    "University students are invited to our conference. See the event website.",
    "Please review your account status on our shopping website.",
    "Today's university account security workshop covers phishing awareness.",
])
def test_unrelated_external_links_are_not_account_requests(account_review, body):
    account_review.body = body
    url = wrapped("https://events.example.com/")
    account_review.links = [LinkInfo(text=url, href=url)]
    result = analyzer.analyze_email(account_review)
    assert not any(i.code == "url_university_account_external" for i in result.indicators)


def test_approved_action_link_does_not_make_external_footer_suspicious(account_review):
    account_review.links = [
        LinkInfo(text="Review your account", href="https://portal.adu.ac.ae/"),
        LinkInfo(text="Privacy policy", href="https://policy.example/privacy"),
    ]
    result = analyzer.analyze_email(account_review)
    assert not any(i.code == "url_university_account_external" for i in result.indicators)


def test_warning_cannot_be_hidden_by_adding_approved_link(account_review):
    account_review.links = [
        LinkInfo(text="Review your account", href=wrapped("https://outside.example/")),
        LinkInfo(text="University homepage", href="https://adu.ac.ae/"),
    ]
    result = analyzer.analyze_email(account_review)
    assert any(i.code == "url_university_account_external" for i in result.indicators)
