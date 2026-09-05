from contextlib import asynccontextmanager
import hmac
import os
from pathlib import Path
import re
import sqlite3
from urllib.parse import urlsplit
from uuid import uuid4

import jwt
from jwt import PyJWKClient
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .ai import MODEL_PATH, _load_model, _verify_model_integrity
from .analyzer import analyze_email
from .db import clear_history, database_ready, get_history, init_db, save_scan
from .schemas import EmailAnalysisRequest, EmailAnalysisResponse, HistoryItem
from .rate_limit import LocalRateLimiter
from .logging_config import configure_logger


APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
if APP_ENV not in {"development", "testing", "production"}:
    raise RuntimeError("APP_ENV must be development, testing, or production.")
API_TOKEN = os.getenv("UNIPHISHGUARD_API_TOKEN", "").strip()
ENTRA_TENANT_ID = os.getenv("ENTRA_TENANT_ID", "").strip()
ENTRA_CLIENT_ID = os.getenv("ENTRA_CLIENT_ID", "").strip()
REQUIRE_AUTH = (
    APP_ENV == "production"
    or
    os.getenv("REQUIRE_AUTH", "false").lower() == "true"
    or bool(API_TOKEN)
    or bool(ENTRA_TENANT_ID and ENTRA_CLIENT_ID)
)
MAX_REQUEST_BYTES = int(os.getenv("MAX_REQUEST_BYTES", "8000000"))
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "30"))
if MAX_REQUEST_BYTES < 1 or MAX_REQUEST_BYTES > 100_000_000:
    raise RuntimeError("MAX_REQUEST_BYTES must be between 1 and 100000000.")
if RATE_LIMIT_MAX_REQUESTS < 1 or RATE_LIMIT_MAX_REQUESTS > 100_000:
    raise RuntimeError("RATE_LIMIT_MAX_REQUESTS must be between 1 and 100000.")
RATE_LIMITER = LocalRateLimiter(RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECONDS)
_JWK_CLIENT: PyJWKClient | None = None
OUTLOOK_ADDIN_DIR = Path(__file__).resolve().parents[2] / "outlook-addin"
ERROR_LOG_PATH = Path(__file__).resolve().parents[1] / "data" / "errors.log"
LOGGER = configure_logger(ERROR_LOG_PATH, APP_ENV)
LOCAL_ORIGINS = [
    "https://localhost:3000",
    "https://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
CONFIGURED_ORIGINS = [origin.strip().rstrip("/") for origin in os.getenv("ALLOWED_ORIGINS", "").split(",") if origin.strip()]
CORS_ORIGINS = CONFIGURED_ORIGINS if APP_ENV == "production" else [*LOCAL_ORIGINS, *CONFIGURED_ORIGINS]
RESERVED_HOSTS = {"example.com", "example.net", "example.org", "localhost"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    _validate_authentication_configuration()
    if APP_ENV == "production":
        if not (ENTRA_TENANT_ID and ENTRA_CLIENT_ID):
            raise RuntimeError("Production requires ENTRA_TENANT_ID and ENTRA_CLIENT_ID.")
        history_secret = os.getenv("HISTORY_HMAC_SECRET", "")
        if len(history_secret) < 32 or history_secret == "local-dev-history-secret":
            raise RuntimeError("Production requires a strong HISTORY_HMAC_SECRET of at least 32 characters.")
        _validate_production_origins(CORS_ORIGINS)
        _validate_production_authserv_ids()
    LOGGER.info("application_start environment=%s authentication_required=%s", APP_ENV, REQUIRE_AUTH)
    _load_model()
    init_db()
    yield


app = FastAPI(
    title="UniPhishGuard API",
    description="Backend API for UniPhishGuard email checking.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["POST", "GET", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-UniPhishGuard-User", "X-Request-ID"],
)

if OUTLOOK_ADDIN_DIR.exists():
    app.mount("/addin", StaticFiles(directory=OUTLOOK_ADDIN_DIR), name="addin")


@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    request_id = _safe_request_id(request.headers.get("X-Request-ID"))
    request.state.request_id = request_id
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            length = int(content_length)
            if length < 0:
                return _error_response(400, "INVALID_CONTENT_LENGTH", "Invalid Content-Length header.", request_id)
            if length > MAX_REQUEST_BYTES:
                return _error_response(413, "REQUEST_TOO_LARGE", "Request is too large.", request_id)
        except ValueError:
            return _error_response(400, "INVALID_CONTENT_LENGTH", "Invalid Content-Length header.", request_id)
    body = await request.body()
    if len(body) > MAX_REQUEST_BYTES:
        return _error_response(413, "REQUEST_TOO_LARGE", "Request is too large.", request_id)
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    if APP_ENV == "production" and request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.url.path.startswith("/addin/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' https://appsforoffice.microsoft.com https://ajax.aspnetcdn.com; "
            "style-src 'self' 'unsafe-inline'; connect-src https:; img-src 'self' data:; "
            "object-src 'none'; base-uri 'none'"
        )
    else:
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response


def current_user(
    request: Request,
    authorization: str | None = Header(default=None),
    x_uniphishguard_user: str | None = Header(default=None),
) -> str:
    if not REQUIRE_AUTH:
        user = (x_uniphishguard_user or "local")[:160]
        _check_rate_limit(request, user)
        return user

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Authentication is required.")

    token = authorization.split(" ", 1)[1].strip()
    token_user = _validate_bearer_token(token)
    user = (token_user or "authenticated-user")[:160]
    _check_rate_limit(request, user)
    return user


def _check_rate_limit(request: Request, user: str) -> None:
    address = request.client.host if request.client else "local"
    if not RATE_LIMITER.check(f"{user}|{address}"):
        raise HTTPException(status_code=429, detail="Too many requests. Please wait and try again.")


def _validate_bearer_token(token: str) -> str:
    if ENTRA_TENANT_ID and ENTRA_CLIENT_ID:
        return _validate_entra_token(token)

    if API_TOKEN:
        if not hmac.compare_digest(token, API_TOKEN):
            raise HTTPException(status_code=403, detail="Invalid API token.")
        return "authenticated-user"

    raise HTTPException(status_code=503, detail="Authentication provider is not configured.")


def _validate_entra_token(token: str) -> str:
    global _JWK_CLIENT

    issuer = f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/v2.0"
    jwks_url = f"{issuer}/discovery/v2.0/keys"

    try:
        if _JWK_CLIENT is None:
            _JWK_CLIENT = PyJWKClient(jwks_url)
        signing_key = _JWK_CLIENT.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=ENTRA_CLIENT_ID,
            issuer=issuer,
        )
    except Exception as error:
        raise HTTPException(status_code=403, detail="Invalid Microsoft sign-in token.") from error

    if claims.get("tid") and str(claims["tid"]).lower() != ENTRA_TENANT_ID.lower():
        raise HTTPException(status_code=403, detail="Microsoft token tenant does not match configuration.")
    identity = claims.get("preferred_username") or claims.get("upn") or claims.get("oid")
    if not identity:
        raise HTTPException(status_code=403, detail="Microsoft token does not contain a supported user identity claim.")
    return str(identity)


@app.get("/health", summary="Service health", description="Returns a basic liveness result without inspecting the model.")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/live", summary="Liveness probe", description="Indicates that the API process is running.")
def health_live() -> dict[str, str]:
    return {"status": "live"}


@app.get("/health/ready", summary="Readiness probe", description="Verifies model and metrics integrity, model loading, database access, and critical configuration.")
def health_ready():
    model_exists = MODEL_PATH.exists()
    model_ready = False
    integrity_ready = False
    if model_exists:
        try:
            _verify_model_integrity()
            integrity_ready = True
            _load_model()
            model_ready = True
        except Exception:
            model_ready = False
    db_ready = database_ready()
    configuration_ready = APP_ENV != "production" or bool(ENTRA_TENANT_ID and ENTRA_CLIENT_ID and len(os.getenv("HISTORY_HMAC_SECRET", "")) >= 32)
    ready = model_ready and integrity_ready and db_ready and configuration_ready
    payload = {
        "status": "ready" if ready else "degraded",
        "environment": APP_ENV,
        "database": "ok" if db_ready else "unavailable",
        "model_exists": model_exists,
        "model_ready": model_ready,
        "artifact_integrity": integrity_ready,
        "configuration_ready": configuration_ready,
        "api_version": "v1",
    }
    return JSONResponse(status_code=200 if ready else 503, content=payload)


def _analyze_email_route(email: EmailAnalysisRequest, user_id: str, request_id: str = "unknown") -> EmailAnalysisResponse:
    try:
        result = analyze_email(email)
    except Exception as error:
        _log_scan_error(error, request_id)
        raise HTTPException(
            status_code=500,
            detail={"code": "SCAN_FAILED", "message": "The email could not be analyzed."},
        ) from error

    try:
        scan_id, scanned_at = save_scan(email, result, user_id=user_id)
    except (sqlite3.Error, OSError) as error:
        # History is auxiliary. A temporary storage failure must not discard a
        # completed security analysis or make Outlook report that scanning failed.
        LOGGER.warning(
            "history_save_failed exception_type=%s",
            type(error).__name__,
            extra={"request_id": request_id},
        )
        return result
    return result.model_copy(update={"scan_id": scan_id, "scanned_at": scanned_at})


@app.post("/analyze-email", response_model=EmailAnalysisResponse, summary="Analyze an email", description="Estimates phishing risk using the saved text model and local rules, then stores limited redacted history.", responses={401: {"description": "Authentication required"}, 413: {"description": "Request too large"}, 422: {"description": "Invalid email schema"}, 429: {"description": "Rate limit exceeded"}, 500: {"description": "Analysis failed; response includes a request ID"}})
def analyze(request: Request, email: EmailAnalysisRequest, user_id: str = Depends(current_user)) -> EmailAnalysisResponse:
    return _analyze_email_route(email, user_id, request.state.request_id)


@app.post("/api/v1/analyze-email", response_model=EmailAnalysisResponse, summary="Analyze an email (v1)", description="Versioned form of the email risk-analysis endpoint.")
def analyze_v1(request: Request, email: EmailAnalysisRequest, user_id: str = Depends(current_user)) -> EmailAnalysisResponse:
    return _analyze_email_route(email, user_id, request.state.request_id)


@app.get("/history", response_model=list[HistoryItem], summary="Recent scan history", description="Returns only the authenticated user's limited, redacted scan history.")
def history(user_id: str = Depends(current_user)) -> list[HistoryItem]:
    return get_history(user_id=user_id)


@app.get("/api/v1/history", response_model=list[HistoryItem], summary="Recent scan history (v1)", description="Versioned history endpoint; production requires a verified Microsoft identity.")
def history_v1(user_id: str = Depends(current_user)) -> list[HistoryItem]:
    return get_history(user_id=user_id)


@app.delete("/api/v1/history")
def delete_history(user_id: str = Depends(current_user)) -> dict[str, int]:
    return {"deleted": clear_history(user_id=user_id)}


def _log_scan_error(error: Exception, request_id: str = "unknown") -> None:
    # Never include request bodies, headers, tokens, or attachment data.
    LOGGER.exception("scan_failed exception_type=%s", type(error).__name__, extra={"request_id": request_id})


def _error_response(status_code: int, code: str, message: str, request_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"code": code, "message": message, "request_id": request_id},
        headers={
            "X-Request-ID": request_id,
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        },
    )


def _safe_request_id(value: str | None) -> str:
    value = (value or "").strip()
    if value and len(value) <= 80 and re.fullmatch(r"[A-Za-z0-9._:-]+", value):
        return value
    return uuid4().hex


def _validate_production_origins(origins: list[str]) -> None:
    if not origins:
        raise RuntimeError("Production requires at least one ALLOWED_ORIGINS value.")
    for origin in origins:
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
            or origin == "*"
            or _is_reserved_hostname(parsed.hostname)
        ):
            raise RuntimeError("Production ALLOWED_ORIGINS values must be real HTTPS origins without paths.")


def _validate_authentication_configuration() -> None:
    if bool(ENTRA_TENANT_ID) != bool(ENTRA_CLIENT_ID):
        raise RuntimeError("ENTRA_TENANT_ID and ENTRA_CLIENT_ID must be configured together.")
    if REQUIRE_AUTH and not (API_TOKEN or (ENTRA_TENANT_ID and ENTRA_CLIENT_ID)):
        raise RuntimeError("Authentication is required but no authentication provider is configured.")


def _validate_production_authserv_ids() -> None:
    raw = os.getenv("TRUSTED_AUTHSERV_IDS", "").strip()
    if not raw:
        raise RuntimeError("Production requires explicit TRUSTED_AUTHSERV_IDS from verified inbound mail headers.")
    values = [value.strip().lower() for value in raw.split(",") if value.strip()]
    if not values or any(_is_reserved_hostname(value) for value in values):
        raise RuntimeError("TRUSTED_AUTHSERV_IDS must contain real, verified mail-gateway identifiers.")


def _is_reserved_hostname(value: str) -> bool:
    hostname = value.rstrip(".").lower()
    return hostname in RESERVED_HOSTS or any(
        hostname.endswith(suffix)
        for suffix in (".example", ".example.com", ".example.net", ".example.org", ".invalid", ".localhost", ".test")
    )
