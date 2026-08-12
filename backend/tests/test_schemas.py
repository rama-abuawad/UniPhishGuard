import pytest
from pydantic import ValidationError

from app.schemas import AttachmentInfo, EmailAddress, EmailAnalysisRequest, LinkInfo


def _email(**updates):
    values = {"sender": EmailAddress(email="student@example.com"), "body": "hello"}
    values.update(updates)
    return EmailAnalysisRequest(**values)


def test_invalid_sender_email_rejected():
    with pytest.raises(ValidationError):
        EmailAddress(email="not-an-email")


def test_oversized_subject_rejected():
    with pytest.raises(ValidationError):
        _email(subject="x" * 999)


def test_oversized_body_rejected():
    with pytest.raises(ValidationError):
        _email(body="x" * 200_001)


def test_too_many_links_rejected():
    with pytest.raises(ValidationError):
        _email(links=[LinkInfo(href="https://example.com") for _ in range(101)])


def test_excessively_long_url_rejected():
    with pytest.raises(ValidationError):
        LinkInfo(href="https://example.com/" + "x" * 4_100)


def test_too_many_attachments_rejected():
    with pytest.raises(ValidationError):
        _email(attachments=[AttachmentInfo(name=f"{index}.txt") for index in range(51)])


def test_malformed_attachment_metadata_rejected():
    with pytest.raises(ValidationError):
        AttachmentInfo(name="", size=-1)


def test_unsupported_url_scheme_rejected():
    with pytest.raises(ValidationError):
        LinkInfo(href="javascript:alert(1)")


def test_invalid_capability_status_rejected():
    with pytest.raises(ValidationError):
        _email(attachment_content_status="pretend-checked")
