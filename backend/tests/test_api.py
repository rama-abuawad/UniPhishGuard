import json

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
