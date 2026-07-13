from pathlib import Path
from uuid import uuid4

from app.analyzer import analyze_email
from app import db
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


def test_adu_tuition_email_is_not_marked_phishing() -> None:
    result = analyze_email(
        EmailAnalysisRequest(
            subject="Updated Tuition Fees - Academic Year 2025-2026",
            sender=EmailAddress(name="Finance", email="finance@info.adu.ac.ae"),
            reply_to="finance@info.adu.ac.ae",
            body=(
                "Dear Student, tuition fees for the academic year 2025-2026 "
                "are available on the ADU website. Please click Tuition Fees "
                "https://click.info.adu.ac.ae/open.aspx and make payment using "
                "the secure Online Payment Gateway. Include your student ID."
            ),
            headers="Authentication-Results: spf=pass dkim=pass dmarc=pass",
            attachments=[],
        )
    )

    assert result.risk_score < 25
    assert result.verdict == "Likely legitimate"
    assert result.ai_prediction == "legitimate"


def test_saves_scan_history(monkeypatch) -> None:
    test_db = Path(__file__).resolve().parents[1] / f"test_history_{uuid4().hex}.db"
    monkeypatch.setattr(db, "DB_PATH", test_db)
    email = EmailAnalysisRequest(
        subject="Urgent password verification required",
        sender=EmailAddress(name="IT", email="it@university.edu"),
        reply_to="helpdesk@example.net",
        body="Click http://192.168.1.10/login to verify your account.",
        headers="Authentication-Results: spf=pass dkim=pass dmarc=fail",
        attachments=[],
    )
    result = analyze_email(email)

    scan_id, scanned_at = db.save_scan(email, result)
    history = db.get_history()

    assert scan_id == 1
    assert scanned_at
    assert history[0].subject == email.subject
    assert history[0].risk_score == result.risk_score
