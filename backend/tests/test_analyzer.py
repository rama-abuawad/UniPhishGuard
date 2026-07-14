from pathlib import Path
from uuid import uuid4

from app.analyzer import analyze_email
from app import db
from app.models import AttachmentInfo, EmailAnalysisRequest, EmailAddress


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


def test_keywords_alone_do_not_make_email_suspicious() -> None:
    result = analyze_email(
        EmailAnalysisRequest(
            subject="Internship and scholarship workshop",
            sender=EmailAddress(name="Career Office", email="career@university.edu"),
            reply_to="career@university.edu",
            body=(
                "The HR team will explain internship applications, scholarship options, "
                "and Microsoft 365 tools during tomorrow's student workshop."
            ),
            headers="Authentication-Results: spf=pass dkim=pass dmarc=pass",
            attachments=[],
        )
    )

    assert result.risk_score < 25
    assert result.verdict == "Likely legitimate"
    assert result.threat_categories == []
    assert all(indicator.code != "ai_phishing_signal" for indicator in result.indicators)


def test_external_internship_schedule_email_stays_legitimate() -> None:
    result = analyze_email(
        EmailAnalysisRequest(
            subject="Internship Visit Schedule Reminder",
            sender=EmailAddress(name="Prosper Yeng", email="prosper@example.com"),
            reply_to="prosper@example.com",
            body=(
                "Dear Internship Students, I hope you are doing well at your internship placements. "
                "Please provide contacts of your company supervisors in the excel sheet and add "
                "the google map locations to your companies. The form url remains: "
                "https://studentsaduac-my.sharepoint.com/Summer-2506-Internship-Visit-Schedule.xlsx"
            ),
            headers="Authentication-Results: spf=pass dkim=pass dmarc=pass",
            attachments=[
                AttachmentInfo(
                    name="Summer 2506 Internship Visit Schedule.xlsx",
                    content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    size=35000,
                )
            ],
        )
    )

    assert result.risk_score < 25
    assert result.verdict == "Likely legitimate"
    assert result.threat_categories == []
    assert result.indicators == []


def test_detects_university_domain_impersonation_and_categories() -> None:
    result = analyze_email(
        EmailAnalysisRequest(
            subject="ADU IT Helpdesk Microsoft 365 password reset",
            sender=EmailAddress(name="ADU IT Helpdesk", email="support@adu-help.com"),
            reply_to="support@adu-help.com",
            body=(
                "Your Microsoft 365 account will be locked. "
                "Sign in at https://aduniversity-login.com/office to verify your password."
            ),
            headers="Authentication-Results: spf=pass dkim=pass dmarc=pass",
            attachments=[],
        )
    )

    category_codes = {category.code for category in result.threat_categories}
    assert result.risk_score >= 55
    assert result.threat_level.code in {"high_risk", "critical"}
    assert "credential_theft" in category_codes
    assert "microsoft_login_scam" in category_codes
    assert any(indicator.code == "university_domain_impersonation" for indicator in result.indicators)
    assert any(indicator.code == "fake_university_service" for indicator in result.indicators)


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
