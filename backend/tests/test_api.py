import json
import sqlite3
import pytest
from fastapi import HTTPException
from fastapi.responses import JSONResponse

from app import main


def test_health_endpoints():
    assert main.health() == {"status": "ok"}
    assert main.health_live() == {"status": "live"}


def test_structured_error_does_not_expose_log_path():
    response = main._error_response(500, "SCAN_FAILED", "The email could not be analyzed.", "request-123")
    payload = json.loads(response.body)
    assert payload == {"code": "SCAN_FAILED", "message": "The email could not be analyzed.", "request_id": "request-123"}
    assert "backend/data" not in response.body.decode()
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"


def test_development_headers_do_not_include_hsts(monkeypatch):
    assert main.APP_ENV == "development"


def test_readiness_checks_model_integrity_and_database():
    response = main.health_ready()
    assert isinstance(response, JSONResponse)
    assert response.status_code == 200
    payload = json.loads(response.body)
    assert payload["artifact_integrity"] is True
    assert payload["database"] == "ok"


def test_readiness_fails_when_database_is_unavailable(monkeypatch):
    monkeypatch.setattr(main, "database_ready", lambda: False)
    response = main.health_ready()
    assert response.status_code == 503
    assert json.loads(response.body)["database"] == "unavailable"


def test_request_id_accepts_safe_value_and_replaces_unsafe_value():
    assert main._safe_request_id("request-123") == "request-123"
    generated = main._safe_request_id("bad\r\nX-Forged: value")
    assert generated != "bad\r\nX-Forged: value"
    assert len(generated) == 32


def test_history_failure_does_not_discard_completed_analysis(monkeypatch):
    from app.schemas import EmailAddress, EmailAnalysisRequest

    def fail_history(*args, **kwargs):
        raise sqlite3.OperationalError("locked")

    monkeypatch.setattr(main, "save_scan", fail_history)
    result = main._analyze_email_route(
        EmailAnalysisRequest(
            subject="Class reminder",
            sender=EmailAddress(email="teacher@example.com"),
            body="Class starts tomorrow.",
            headers="Authentication-Results: spf.protection.outlook.com; spf=pass dkim=pass dmarc=pass",
        ),
        "user-a",
        "request-123",
    )
    assert result.verdict
    assert result.scan_id is None


def test_auth_required_without_provider_is_rejected(monkeypatch):
    monkeypatch.setattr(main, "ENTRA_TENANT_ID", "")
    monkeypatch.setattr(main, "ENTRA_CLIENT_ID", "")
    monkeypatch.setattr(main, "API_TOKEN", "")
    with pytest.raises(HTTPException) as error:
        main._validate_bearer_token("anything")
    assert error.value.status_code == 503


@pytest.mark.parametrize("origins", [[], ["*"], ["http://addin.example.edu"], ["https://addin.example.edu/path"], ["https://your-addin-site.example.com"], ["https://addin.invalid"], ["https://addin.test"]])
def test_production_origins_reject_unsafe_or_placeholder_values(origins):
    with pytest.raises(RuntimeError):
        main._validate_production_origins(origins)


def test_production_origins_accept_real_https_origin():
    main._validate_production_origins(["https://addin.example.edu"])


def test_production_authserv_ids_must_be_explicit(monkeypatch):
    monkeypatch.delenv("TRUSTED_AUTHSERV_IDS", raising=False)
    with pytest.raises(RuntimeError, match="explicit TRUSTED_AUTHSERV_IDS"):
        main._validate_production_authserv_ids()


@pytest.mark.parametrize("value", ["mx.example", "example.com", "mail.example.com", "gateway.invalid", "gateway.test"])
def test_production_authserv_ids_reject_placeholders(monkeypatch, value):
    monkeypatch.setenv("TRUSTED_AUTHSERV_IDS", value)
    with pytest.raises(RuntimeError, match="real, verified"):
        main._validate_production_authserv_ids()


def test_production_authserv_ids_accept_verified_gateway(monkeypatch):
    monkeypatch.setenv("TRUSTED_AUTHSERV_IDS", "mail-gateway.example.edu")
    main._validate_production_authserv_ids()
