from pathlib import Path
from uuid import uuid4

from app import analyzer
from app.analyzer import analyze_email
from app import db
from app.schemas import AttachmentInfo, EmailAnalysisRequest, EmailAddress, LinkInfo


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


def test_dkim_warning_is_clear_to_user() -> None:
    result = analyze_email(
        EmailAnalysisRequest(
            subject="Project update",
            sender=EmailAddress(name="Instructor", email="instructor@university.edu"),
            reply_to="instructor@university.edu",
            body="Please review the project update before class.",
            headers="Authentication-Results: spf=pass dkim=fail dmarc=pass",
            attachments=[],
        )
    )

    dkim_indicator = next(indicator for indicator in result.indicators if indicator.code == "dkim_failed")
    assert "email signature could not be verified" in dkim_indicator.message
    assert "forwarding or sender setup issues" in dkim_indicator.message


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


def test_ai_phishing_signal_cannot_score_zero(monkeypatch) -> None:
    monkeypatch.setattr(analyzer, "predict_email_risk", lambda email: ("phishing", 0.99))

    result = analyze_email(
        EmailAnalysisRequest(
            subject="Account expiry notice",
            sender=EmailAddress(name="Support", email="support@outlook.com"),
            body="Your account expires today. Please sign in to keep access.",
            headers="Authentication-Results: spf=pass dkim=pass dmarc=pass",
        )
    )

    assert result.risk_score >= 25
    assert result.verdict != "Likely legitimate"
    assert any(indicator.code == "ai_phishing_signal" for indicator in result.indicators)


def test_visible_adu_link_pointing_elsewhere_is_high_risk(monkeypatch) -> None:
    monkeypatch.setattr(analyzer, "predict_email_risk", lambda email: ("legitimate", 0.70))

    result = analyze_email(
        EmailAnalysisRequest(
            subject="ADU portal update",
            sender=EmailAddress(name="External", email="notice@example.com"),
            body="Please open ADU Portal.",
            body_html='<a href="https://evil-login.example.com">https://students.adu.ac.ae</a>',
            headers="Authentication-Results: spf=pass dkim=pass dmarc=pass",
            links=[LinkInfo(text="https://students.adu.ac.ae", href="https://evil-login.example.com")],
        )
    )

    mismatch = next(indicator for indicator in result.indicators if indicator.code == "link_text_destination_mismatch")
    assert result.risk_score >= 55
    assert "students.adu.ac.ae" in mismatch.message
    assert "evil-login.example.com" in mismatch.message


def test_free_outlook_sender_is_not_trusted_sender(monkeypatch) -> None:
    monkeypatch.setattr(analyzer, "predict_email_risk", lambda email: ("legitimate", 0.70))

    result = analyze_email(
        EmailAnalysisRequest(
            subject="ADU password check",
            sender=EmailAddress(name="ADU IT", email="adu.helpdesk@outlook.com"),
            body="ADU IT needs you to verify your password today.",
            headers="Authentication-Results: spf=pass dkim=pass dmarc=pass",
        )
    )

    assert any(indicator.code == "untrusted_university_branding" for indicator in result.indicators)


def test_double_extension_is_reported_before_generic_extension(monkeypatch) -> None:
    monkeypatch.setattr(analyzer, "predict_email_risk", lambda email: ("legitimate", 0.70))

    result = analyze_email(
        EmailAnalysisRequest(
            subject="Invoice",
            sender=EmailAddress(name="Vendor", email="vendor@example.com"),
            body="See attached invoice.",
            headers="Authentication-Results: spf=pass dkim=pass dmarc=pass",
            attachments=[AttachmentInfo(name="invoice.pdf.exe", content_type="application/octet-stream")],
        )
    )

    assert result.indicators[0].code == "double_extension_attachment"
    assert result.risk_score >= 30


def test_unavailable_headers_are_not_treated_as_passed(monkeypatch) -> None:
    monkeypatch.setattr(analyzer, "predict_email_risk", lambda email: ("legitimate", 0.70))

    result = analyze_email(
        EmailAnalysisRequest(
            subject="Project note",
            sender=EmailAddress(name="Teacher", email="teacher@adu.ac.ae"),
            body="Please review the note.",
            headers="",
            headers_status="not_available",
        )
    )

    assert any(indicator.code == "auth_headers_not_checked" for indicator in result.indicators)


def test_auth_required_blocks_history(monkeypatch) -> None:
    from fastapi import HTTPException
    import app.main as main

    monkeypatch.setattr(main, "REQUIRE_AUTH", True)
    monkeypatch.setattr(main, "API_TOKEN", "test-token")
    monkeypatch.setattr(main, "_REQUESTS", {})

    class Request:
        client = type("Client", (), {"host": "127.0.0.1"})()

    try:
        main.current_user(Request(), authorization=None)
    except HTTPException as error:
        assert error.status_code == 401
    else:
        raise AssertionError("Missing token should be blocked")

    try:
        main.current_user(Request(), authorization="Bearer wrong")
    except HTTPException as error:
        assert error.status_code == 403
    else:
        raise AssertionError("Wrong token should be blocked")


def test_forwarded_mixed_authentication_is_inconclusive_not_auto_phishing(monkeypatch) -> None:
    monkeypatch.setattr(analyzer, "predict_email_risk", lambda email: ("legitimate", 0.80))

    result = analyze_email(
        EmailAnalysisRequest(
            subject="Forwarded class note",
            sender=EmailAddress(name="Professor", email="professor@adu.ac.ae"),
            body="Forwarded class note attached for your review.",
            headers=(
                "ARC-Authentication-Results: i=1; mx.example; spf=fail smtp.mailfrom=old-forwarder.net; "
                "dkim=pass header.d=adu.ac.ae; dmarc=pass header.from=adu.ac.ae\n"
                "Authentication-Results: mx.example; spf=pass smtp.mailfrom=adu.ac.ae; "
                "dkim=pass header.d=adu.ac.ae; dmarc=pass header.from=adu.ac.ae"
            ),
        )
    )

    assert result.risk_score < 25
    assert not any(indicator.code == "spf_failed" for indicator in result.indicators)
    assert any(indicator.code == "spf_inconclusive" for indicator in result.indicators)


def test_punycode_lookalike_link_is_high_risk(monkeypatch) -> None:
    monkeypatch.setattr(analyzer, "predict_email_risk", lambda email: ("legitimate", 0.70))

    result = analyze_email(
        EmailAnalysisRequest(
            subject="ADU portal",
            sender=EmailAddress(name="Notice", email="notice@example.com"),
            body="Open https://xn--adu-login-9db.com now.",
            headers="Authentication-Results: spf=pass dkim=pass dmarc=pass",
        )
    )

    assert any(indicator.code == "punycode_domain" for indicator in result.indicators)
    assert result.risk_score >= 55


def test_url_shortener_to_login_page_is_suspicious(monkeypatch) -> None:
    monkeypatch.setattr(analyzer, "predict_email_risk", lambda email: ("phishing", 0.82))

    result = analyze_email(
        EmailAnalysisRequest(
            subject="Password reset",
            sender=EmailAddress(name="Helpdesk", email="helpdesk@example.com"),
            body="Reset your password here https://bit.ly/adu-login today.",
            headers="Authentication-Results: spf=pass dkim=pass dmarc=pass",
        )
    )

    assert any(indicator.code == "url_shortener" for indicator in result.indicators)
    assert result.risk_score >= 25


def test_attachment_mime_mismatch_is_flagged(monkeypatch) -> None:
    monkeypatch.setattr(analyzer, "predict_email_risk", lambda email: ("legitimate", 0.70))

    result = analyze_email(
        EmailAnalysisRequest(
            subject="Document",
            sender=EmailAddress(name="Sender", email="sender@example.com"),
            body="See attached PDF.",
            headers="Authentication-Results: spf=pass dkim=pass dmarc=pass",
            attachments=[AttachmentInfo(name="document.pdf", content_type="application/x-msdownload")],
        )
    )

    assert any(indicator.code == "attachment_mime_mismatch" for indicator in result.indicators)


def test_history_is_separated_by_user(monkeypatch) -> None:
    test_db = Path(__file__).resolve().parents[1] / f"test_history_{uuid4().hex}.db"
    monkeypatch.setattr(db, "DB_PATH", test_db)
    email = EmailAnalysisRequest(
        subject="User scoped scan",
        sender=EmailAddress(name="IT", email="it@example.com"),
        body="Check this.",
        headers="Authentication-Results: spf=pass dkim=pass dmarc=pass",
    )
    result = analyze_email(email)

    db.save_scan(email, result, user_id="user-a")

    assert len(db.get_history(user_id="user-a")) == 1
    assert db.get_history(user_id="user-b") == []


def test_rate_limit_blocks_repeated_requests(monkeypatch) -> None:
    from fastapi import HTTPException
    import app.main as main

    monkeypatch.setattr(main, "_REQUESTS", {})
    monkeypatch.setattr(main, "RATE_LIMIT_MAX_REQUESTS", 1)

    main._check_rate_limit("tester")
    try:
        main._check_rate_limit("tester")
    except HTTPException as error:
        assert error.status_code == 429
    else:
        raise AssertionError("Expected rate limit to block second request")


def test_long_sharepoint_url_does_not_crash(monkeypatch) -> None:
    monkeypatch.setattr(analyzer, "predict_email_risk", lambda email: ("legitimate", 0.70))
    long_url = "https://studentsaduac-my.sharepoint.com/:x:/r/personal/student/Documents/file.xlsx?" + ("a" * 700)

    result = analyze_email(
        EmailAnalysisRequest(
            subject="Internship visit schedule",
            sender=EmailAddress(name="Prosper Yeng", email="prosper@example.com"),
            body=f"The form url remains: {long_url}",
            body_html=f'<a href="{long_url}">Summer 2506 Internship Visit Schedule.xlsx</a>',
            headers="Authentication-Results: spf=pass dkim=pass dmarc=pass",
        )
    )

    assert result.url_count == 1
    assert result.verdict == "Likely legitimate"


def test_very_long_email_body_still_scans(monkeypatch) -> None:
    monkeypatch.setattr(analyzer, "predict_email_risk", lambda email: ("legitimate", 0.70))

    result = analyze_email(
        EmailAnalysisRequest(
            subject="Long newsletter",
            sender=EmailAddress(name="Conference", email="conference@example.com"),
            body="Conference update. " * 20000,
            headers="Authentication-Results: spf=pass dkim=pass dmarc=pass",
        )
    )

    assert result.verdict == "Likely legitimate"
