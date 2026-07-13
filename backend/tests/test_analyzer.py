from app.analyzer import analyze_email
from app.models import EmailAnalysisRequest, EmailAddress


def test_flags_high_risk_email() -> None:
    result = analyze_email(
        EmailAnalysisRequest(
            subject="Urgent password verification required",
            sender=EmailAddress(name="IT", email="it@university.edu"),
            reply_to="helpdesk@example.net",
            body="Click http://192.168.1.10/login to verify your account.",
            headers="Authentication-Results: spf=pass dkim=pass dmarc=fail",
            attachments=[],
        )
    )

    assert result.risk_score >= 55
    assert result.verdict in {"Likely phishing", "High-risk phishing"}
    assert any(indicator.code == "reply_to_mismatch" for indicator in result.indicators)
    assert any(indicator.code == "dmarc_failed" for indicator in result.indicators)


def test_legitimate_email_stays_low_risk() -> None:
    result = analyze_email(
        EmailAnalysisRequest(
            subject="Class schedule update",
            sender=EmailAddress(name="Registrar", email="registrar@university.edu"),
            reply_to="registrar@university.edu",
            body="Your class schedule has been updated in the student portal.",
            headers="Authentication-Results: spf=pass dkim=pass dmarc=pass",
            attachments=[],
        )
    )

    assert result.risk_score < 25
    assert result.verdict == "Likely legitimate"
