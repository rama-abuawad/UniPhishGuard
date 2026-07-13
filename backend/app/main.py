from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .analyzer import analyze_email
from .db import get_history, init_db, save_scan
from .models import EmailAnalysisRequest, EmailAnalysisResponse, HistoryItem


@asynccontextmanager
async def lifespan(app: FastAPI):
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
    ],
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze-email", response_model=EmailAnalysisResponse)
def analyze(email: EmailAnalysisRequest) -> EmailAnalysisResponse:
    result = analyze_email(email)
    scan_id, scanned_at = save_scan(email, result)
    return result.model_copy(update={"scan_id": scan_id, "scanned_at": scanned_at})


@app.get("/history", response_model=list[HistoryItem])
def history() -> list[HistoryItem]:
    return get_history()
