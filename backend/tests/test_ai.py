from pathlib import Path

import pytest

from app import ai
from app.schemas import EmailAddress, EmailAnalysisRequest


def test_valid_model_checksum():
    ai._verify_model_integrity()


def test_modified_model_is_rejected(monkeypatch):
    original = ai._sha256
    monkeypatch.setattr(ai, "_sha256", lambda path: "modified-checksum" if path == ai.MODEL_PATH else original(path))
    with pytest.raises(RuntimeError, match="checksum"):
        ai._verify_model_integrity()


def test_missing_integrity_data_is_rejected(monkeypatch):
    monkeypatch.setattr(ai, "INTEGRITY_PATH", Path("missing-integrity-file.json"))
    monkeypatch.setenv("APP_ENV", "production")
    with pytest.raises(RuntimeError, match="integrity"):
        ai._verify_model_integrity()


def test_production_rejects_sklearn_version_mismatch(monkeypatch):
    monkeypatch.setattr(ai, "METRICS_PATH", Path(__file__).parent / "fixtures" / "incompatible_metrics.json")
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("ALLOW_MODEL_VERSION_MISMATCH", raising=False)
    with pytest.raises(RuntimeError, match="scikit-learn"):
        ai._check_model_metadata()


def test_modified_metrics_are_rejected(monkeypatch):
    original = ai._sha256
    monkeypatch.setattr(ai, "_sha256", lambda path: "modified-checksum" if path == ai.METRICS_PATH else original(path))
    with pytest.raises(RuntimeError, match="metrics checksum"):
        ai._verify_model_integrity()


def test_explanation_uses_active_model_features():
    evidence = ai.explain_email_risk(EmailAnalysisRequest(
        subject="Urgent verify account",
        sender=EmailAddress(email="sender@example.com"),
        body="Your password expires. Login immediately to verify account.",
    ))
    assert evidence
    assert any(term in " ".join(evidence) for term in ("account", "password", "verify", "login"))


def test_model_text_defangs_active_indicators():
    text = ai._model_text(EmailAnalysisRequest(
        subject="Account notice",
        sender=EmailAddress(email="sender@example.com"),
        body="Visit https://portal.example/reset from 192.0.2.1 or email help@example.com",
    ))
    assert "https://" not in text
    assert "192.0.2.1" not in text
    assert "help@example.com" not in text
    assert "URL" in text and "IP_ADDRESS" in text and "EMAIL" in text
