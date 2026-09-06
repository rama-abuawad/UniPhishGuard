"""Regression coverage for the payment-receipt false positive (scan 97)."""

import pytest

from app import analyzer
from app.schemas import AttachmentInfo, EmailAddress, EmailAnalysisRequest


@pytest.fixture
def receipt(monkeypatch):
    # Replay the saved scan's model output; the raw message/MIME type is not
    # retained in history. Exercise plausible generic metadata separately.
    monkeypatch.setattr(analyzer, "predict_email_risk", lambda email: ("phishing", 0.797826631875797))
    monkeypatch.setattr(analyzer, "explain_email_risk", lambda email: [])
    return EmailAnalysisRequest(
        subject="Payment Receipt",
        sender=EmailAddress(name="Finance", email="finance@adu.ac.ae"),
        body=(
            "Dear Rama D. A. Abuawad, Please find the attached receipt. "
            "If you need to get it stamped, Please visit the Finance department. "
            "Regards, ADU Finance department. Note: This is an System generated "
            "email, kindly don't reply to this email."
        ),
        headers="Authentication-Results: untrusted.example; spf=pass dkim=pass dmarc=pass",
        attachments=[AttachmentInfo(name="ADU_ST_RCPT.pdf", content_type="application/octet-stream")],
    )


@pytest.mark.parametrize("content_type", [
    None, "", "application/octet-stream", "application/x-octet-stream",
    "binary/octet-stream", " Application/Octet-Stream ; name=receipt.pdf",
    "application/pdf", "application/pdf; name=receipt.pdf", "application/x-pdf",
])
def test_receipt_with_unspecified_or_pdf_type_is_low_risk(receipt, content_type):
    receipt.attachments[0].content_type = content_type
    result = analyzer.analyze_email(receipt)
    assert result.verdict == "Low Risk"
    assert result.risk_score < 25
    assert not any(item.code == "attachment_mime_mismatch" for item in result.indicators)
    assert result.ai_prediction == "phishing"
    assert result.ai_confidence == 0.797826631875797
    # Missing trusted authentication/content must remain explicit limitations.
    assert result.authentication_status != "passed"
    assert result.analysis_completeness == "partial"


@pytest.mark.parametrize("ext", [".pdf", ".docx", ".xlsx", ".jpg", ".txt"])
def test_generic_mime_is_unknown_for_other_file_extensions(ext):
    assert not analyzer._mime_extension_mismatch(ext, "application/octet-stream")


@pytest.mark.parametrize("content_type", ["application/x-msdownload", "text/html", "image/png"])
def test_actual_conflicting_mime_still_warns(receipt, content_type):
    receipt.attachments[0].content_type = content_type
    result = analyzer.analyze_email(receipt)
    assert any(item.code == "attachment_mime_mismatch" for item in result.indicators)
    assert result.risk_score >= 55


def test_generic_mime_does_not_hide_dangerous_filename(receipt):
    receipt.attachments[0].name = "ADU_ST_RCPT.pdf.exe"
    result = analyzer.analyze_email(receipt)
    assert any(item.code == "double_extension_attachment" for item in result.indicators)
    assert result.risk_score >= 55


@pytest.mark.parametrize("confidence, minimum", [(0.90, 25), (0.95, 55)])
def test_strong_text_only_evidence_still_warns(receipt, monkeypatch, confidence, minimum):
    monkeypatch.setattr(analyzer, "predict_email_risk", lambda email: ("phishing", confidence))
    result = analyzer.analyze_email(receipt)
    assert result.risk_score >= minimum


def test_authentication_failure_still_corroborates_model(receipt):
    receipt.headers = "Authentication-Results: spf.protection.outlook.com; dmarc=fail header.from=adu.ac.ae"
    result = analyzer.analyze_email(receipt)
    assert result.authentication_status == "failed"
    assert result.risk_score >= 55
