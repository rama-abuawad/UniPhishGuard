import json
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
