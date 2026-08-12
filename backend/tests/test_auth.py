from fastapi import HTTPException
import asyncio
import pytest

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


def test_production_startup_fails_without_entra_configuration(monkeypatch):
    monkeypatch.setattr(main, "APP_ENV", "production")
    monkeypatch.setattr(main, "ENTRA_TENANT_ID", "")
    monkeypatch.setattr(main, "ENTRA_CLIENT_ID", "")

    async def start():
        async with main.lifespan(main.app):
            pass

    with pytest.raises(RuntimeError, match="ENTRA_TENANT_ID"):
        asyncio.run(start())


def test_entra_token_without_identity_claim_is_rejected(monkeypatch):
    class KeyClient:
        def get_signing_key_from_jwt(self, token):
            return type("SigningKey", (), {"key": "key"})()

    monkeypatch.setattr(main, "ENTRA_TENANT_ID", "tenant")
    monkeypatch.setattr(main, "ENTRA_CLIENT_ID", "client")
    monkeypatch.setattr(main, "_JWK_CLIENT", KeyClient())
    monkeypatch.setattr(main.jwt, "decode", lambda *args, **kwargs: {"tid": "tenant"})
    with pytest.raises(HTTPException) as error:
        main._validate_entra_token("token")
    assert error.value.status_code == 403
