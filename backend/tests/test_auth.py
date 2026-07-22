from fastapi import HTTPException

from app import main


class Request:
    client = type("Client", (), {"host": "127.0.0.1"})()
    headers = {}


def test_anonymous_production_style_request_is_rejected(monkeypatch):
    monkeypatch.setattr(main, "REQUIRE_AUTH", True); main.RATE_LIMITER.reset()
    try: main.current_user(Request(), authorization=None, x_uniphishguard_user="victim")
    except HTTPException as error: assert error.status_code == 401
    else: raise AssertionError("Anonymous request was accepted")


def test_identity_header_cannot_override_authenticated_user(monkeypatch):
    monkeypatch.setattr(main, "REQUIRE_AUTH", True); monkeypatch.setattr(main, "API_TOKEN", "valid"); main.RATE_LIMITER.reset()
    assert main.current_user(Request(), authorization="Bearer valid", x_uniphishguard_user="victim") == "authenticated-user"


def test_invalid_token_is_rejected(monkeypatch):
    monkeypatch.setattr(main, "REQUIRE_AUTH", True); monkeypatch.setattr(main, "API_TOKEN", "valid"); main.RATE_LIMITER.reset()
    try: main.current_user(Request(), authorization="Bearer wrong")
    except HTTPException as error: assert error.status_code == 403
    else: raise AssertionError("Invalid token was accepted")
