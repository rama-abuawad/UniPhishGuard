from contextlib import asynccontextmanager
import os
import time
from pathlib import Path
import traceback
from uuid import uuid4

import jwt
from jwt import PyJWKClient
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .ai import MODEL_PATH, _load_model
from .analyzer import analyze_email
from .db import clear_history, get_history, init_db, save_scan
from .schemas import EmailAnalysisRequest, EmailAnalysisResponse, HistoryItem
from .rate_limit import LocalRateLimiter


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
MAX_REQUEST_BYTES = int(os.getenv("MAX_REQUEST_BYTES", "1000000"))
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "30"))
RATE_LIMITER = LocalRateLimiter(RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECONDS)
_JWK_CLIENT: PyJWKClient | None = None
OUTLOOK_ADDIN_DIR = Path(__file__).resolve().parents[2] / "outlook-addin"
ERROR_LOG_PATH = Path(__file__).resolve().parents[1] / "data" / "errors.log"


@asynccontextmanager
async def lifespan(app: FastAPI):
    if APP_ENV == "production":
        if not (ENTRA_TENANT_ID and ENTRA_CLIENT_ID):
            raise RuntimeError("Production requires ENTRA_TENANT_ID and ENTRA_CLIENT_ID.")
        history_secret = os.getenv("HISTORY_HMAC_SECRET", "")
        if len(history_secret) < 32 or history_secret == "local-dev-history-secret":
            raise RuntimeError("Production requires a strong HISTORY_HMAC_SECRET of at least 32 characters.")
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
    allow_origins=[
        "https://localhost:3000",
        "https://127.0.0.1:3000",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        *[
            origin.strip()
            for origin in os.getenv("ALLOWED_ORIGINS", "").split(",")
            if origin.strip()
        ],
    ],
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

if OUTLOOK_ADDIN_DIR.exists():
    app.mount("/addin", StaticFiles(directory=OUTLOOK_ADDIN_DIR), name="addin")


@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or uuid4().hex
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
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
            "default-src 'self'; script-src 'self' https://appsforoffice.microsoft.com; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self' https://localhost:8000; frame-ancestors https://outlook.office.com https://outlook.office365.com"
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
    if os.getenv("TRUST_PROXY_HEADERS", "false").lower() == "true":
        address = request.headers.get("X-Forwarded-For", address).split(",", 1)[0].strip()
    if not RATE_LIMITER.check(f"{user}|{address}"):
        raise HTTPException(status_code=429, detail="Too many requests. Please wait and try again.")


def _validate_bearer_token(token: str) -> str:
    if ENTRA_TENANT_ID and ENTRA_CLIENT_ID:
        return _validate_entra_token(token)

    if API_TOKEN and token != API_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid API token.")

    return "authenticated-user"


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
    except jwt.PyJWTError as error:
        raise HTTPException(status_code=403, detail="Invalid Microsoft sign-in token.") from error

    return str(
        claims.get("preferred_username")
        or claims.get("upn")
        or claims.get("oid")
        or "authenticated-user"
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/live")
def health_live() -> dict[str, str]:
    return {"status": "live"}


@app.get("/health/ready")
def health_ready() -> dict[str, str | bool]:
    model_exists = MODEL_PATH.exists()
    model_ready = False
    if model_exists:
        try:
            _load_model()
            model_ready = True
        except Exception:
            model_ready = False
    return {
        "status": "ready" if model_ready else "degraded",
        "database": "ok",
        "model_exists": model_exists,
        "model_ready": model_ready,
        "api_version": "v1",
    }


def _analyze_email_route(email: EmailAnalysisRequest, user_id: str) -> EmailAnalysisResponse:
    try:
        result = analyze_email(email)
        scan_id, scanned_at = save_scan(email, result, user_id=user_id)
        return result.model_copy(update={"scan_id": scan_id, "scanned_at": scanned_at})
    except Exception as error:
        _log_scan_error(error)
        raise HTTPException(
            status_code=500,
            detail={"code": "SCAN_FAILED", "message": "The email could not be analyzed."},
        ) from error


@app.post("/analyze-email", response_model=EmailAnalysisResponse)
def analyze(email: EmailAnalysisRequest, user_id: str = Depends(current_user)) -> EmailAnalysisResponse:
    return _analyze_email_route(email, user_id)


@app.post("/api/v1/analyze-email", response_model=EmailAnalysisResponse)
def analyze_v1(email: EmailAnalysisRequest, user_id: str = Depends(current_user)) -> EmailAnalysisResponse:
    return _analyze_email_route(email, user_id)


@app.get("/history", response_model=list[HistoryItem])
def history(user_id: str = Depends(current_user)) -> list[HistoryItem]:
    return get_history(user_id=user_id)


@app.get("/api/v1/history", response_model=list[HistoryItem])
def history_v1(user_id: str = Depends(current_user)) -> list[HistoryItem]:
    return get_history(user_id=user_id)


@app.delete("/api/v1/history")
def delete_history(user_id: str = Depends(current_user)) -> dict[str, int]:
    return {"deleted": clear_history(user_id=user_id)}


def _log_scan_error(error: Exception) -> None:
    ERROR_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with ERROR_LOG_PATH.open("a", encoding="utf-8") as file:
        file.write("\n--- scan error ---\n")
        file.write(time.strftime("%Y-%m-%d %H:%M:%S"))
        file.write(f"\n{type(error).__name__}: {error}\n")
        file.write(traceback.format_exc())


def _error_response(status_code: int, code: str, message: str, request_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message, "request_id": request_id}},
        headers={"X-Request-ID": request_id},
    )
